// Copyright(C) Facebook, Inc. and its affiliates.
use crate::aggregators::{CertificatesAggregator, VotesAggregator};
use crate::error::{DagError, DagResult};
use crate::messages::{Certificate, Header, ProposalParents, Vote};
use crate::primary::{PrimaryMessage, Round};
use crate::synchronizer::Synchronizer;
use async_recursion::async_recursion;
use bytes::Bytes;
use config::Committee;
use crypto::Hash as _;
use crypto::{Digest, PublicKey, SignatureService};
use log::{debug, error, warn};
use network::{CancelHandler, ReliableSender};
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use store::Store;
use tokio::sync::mpsc::{Receiver, Sender};

#[cfg(test)]
#[path = "tests/core_tests.rs"]
pub mod core_tests;

pub struct Core {
    /// The public key of this primary.
    name: PublicKey,
    /// The committee information.
    committee: Committee,
    /// The persistent storage.
    store: Store,
    /// Handles synchronization with other nodes and our workers.
    synchronizer: Synchronizer,
    /// Service to sign headers.
    signature_service: SignatureService,
    /// The current consensus round (used for cleanup).
    consensus_round: Arc<AtomicU64>,
    /// The depth of the garbage collector.
    gc_depth: Round,

    /// Receiver for dag messages (headers, votes, certificates).
    rx_primaries: Receiver<PrimaryMessage>,
    /// Receives loopback headers from the `HeaderWaiter`.
    rx_header_waiter: Receiver<Header>,
    /// Receives loopback certificates from the `CertificateWaiter`.
    rx_certificate_waiter: Receiver<Certificate>,
    /// Receives our newly created headers from the `Proposer`.
    rx_proposer: Receiver<Header>,
    /// Output all certificates to the consensus layer.
    tx_consensus: Sender<Certificate>,
    /// Send valid parent snapshots to the `Proposer` (along with their round).
    tx_proposer: Sender<(ProposalParents, Round)>,

    /// The last garbage collected round.
    gc_round: Round,
    /// The authors of the last voted headers.
    last_voted: HashMap<Round, HashSet<PublicKey>>,
    /// The set of headers we are currently processing.
    processing: HashMap<Round, HashSet<Digest>>,
    /// Our locally proposed headers waiting for quorum (keyed by header id).
    pending_headers: HashMap<Digest, Header>,
    /// One vote aggregator per locally proposed header.
    votes_aggregators: HashMap<Digest, VotesAggregator>,
    /// Aggregates certificates to use as parents for new headers.
    certificates_aggregators: HashMap<Round, Box<CertificatesAggregator>>,
    /// A network sender to send the batches to the other workers.
    network: ReliableSender,
    /// Keeps the cancel handlers of the messages we sent.
    cancel_handlers: HashMap<Round, Vec<CancelHandler>>,
}

impl Core {
    fn node_index(&self, key: &PublicKey) -> Option<usize> {
        self.committee
            .authorities
            .keys()
            .position(|authority| authority == key)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn spawn(
        name: PublicKey,
        committee: Committee,
        store: Store,
        synchronizer: Synchronizer,
        signature_service: SignatureService,
        consensus_round: Arc<AtomicU64>,
        gc_depth: Round,
        rx_primaries: Receiver<PrimaryMessage>,
        rx_header_waiter: Receiver<Header>,
        rx_certificate_waiter: Receiver<Certificate>,
        rx_proposer: Receiver<Header>,
        tx_consensus: Sender<Certificate>,
        tx_proposer: Sender<(ProposalParents, Round)>,
    ) {
        tokio::spawn(async move {
            Self {
                name,
                committee,
                store,
                synchronizer,
                signature_service,
                consensus_round,
                gc_depth,
                rx_primaries,
                rx_header_waiter,
                rx_certificate_waiter,
                rx_proposer,
                tx_consensus,
                tx_proposer,
                gc_round: 0,
                last_voted: HashMap::with_capacity(2 * gc_depth as usize),
                processing: HashMap::with_capacity(2 * gc_depth as usize),
                pending_headers: HashMap::with_capacity(2 * gc_depth as usize),
                votes_aggregators: HashMap::with_capacity(2 * gc_depth as usize),
                certificates_aggregators: HashMap::with_capacity(2 * gc_depth as usize),
                network: ReliableSender::new(),
                cancel_handlers: HashMap::with_capacity(2 * gc_depth as usize),
            }
            .run()
            .await;
        });
    }

    async fn process_own_header(&mut self, header: Header) -> DagResult<()> {
        // Track this locally proposed header independently so votes on current/future headers
        // can be aggregated in parallel.
        self.pending_headers
            .insert(header.id.clone(), header.clone());
        self.votes_aggregators
            .entry(header.id.clone())
            .or_insert_with(VotesAggregator::new);

        // Broadcast the new header in a reliable manner:
        // 1. Primary receives parents from `CertificateAggregator`
        // 2. Proposer creates header and sends it here
        // 3. Core broadcasts header to all other primaries
        debug!(
            "Broadcasting header {} (round {}) to other primaries",
            header.id, header.round
        );
        let addresses: Vec<_> = self
            .committee
            .others_primaries(&self.name)
            .iter()
            .map(|(_, x)| x.primary_to_primary)
            .collect();
        let bytes = bincode::serialize(&PrimaryMessage::Header(header.clone()))
            .expect("Failed to serialize our own header");
        // Send to each primary individually so we can log per-node success/failure.
        let header_id = header.id.clone();
        let header_round = header.round;
        for address in addresses {
            let handler = self.network.send(address, Bytes::from(bytes.clone())).await;
            let id = header_id.clone();
            tokio::spawn(async move {
                match handler.await {
                    Ok(_) => {
                        debug!(
                            "Header {} (round {}) successfully delivered to primary {}",
                            id, header_round, address
                        );
                    }
                    Err(_) => {
                        debug!(
                            "Header {} (round {}) delivery to primary {} was canceled or failed",
                            id, header_round, address
                        );
                    }
                }
            });
        }

        // Process the header.
        self.process_header(&header).await
    }

    async fn resolve_step_vertex_label(&mut self, digest: &Digest) -> String {
        match self.store.read(digest.to_vec()).await {
            Ok(Some(bytes)) => {
                if let Ok(header) = bincode::deserialize::<Header>(&bytes) {
                    let node_id = self.node_index(&header.author).unwrap_or(999);
                    return format!("[{},{}]", header.round, node_id);
                }
                if let Ok(certificate) = bincode::deserialize::<Certificate>(&bytes) {
                    let node_id = self.node_index(&certificate.origin()).unwrap_or(999);
                    return format!("[{},{}]", certificate.round(), node_id);
                }
                format!("{:?}", digest)
            }
            _ => format!("{:?}", digest),
        }
    }

    async fn resolve_step_vertex_labels(&mut self, digests: &[Digest]) -> Vec<String> {
        let mut labels = Vec::with_capacity(digests.len());
        for digest in digests {
            labels.push(self.resolve_step_vertex_label(digest).await);
        }
        labels.sort();
        labels
    }

    async fn log_parent_provenance(&mut self, target_round: Round, parents: &ProposalParents) {
        let proposal_round = target_round + 1;
        if !self.committee.is_solid_step(proposal_round) || !log::log_enabled!(log::Level::Debug) {
            return;
        }

        let mut direct_weak_only = Vec::new();
        let mut relay_only = Vec::new();
        let mut both = Vec::new();
        for (digest, source) in &parents.solid_step_sources {
            if source.is_both() {
                both.push(digest.clone());
            } else if source.is_direct_weak_only() {
                direct_weak_only.push(digest.clone());
            } else if source.is_relay_only() {
                relay_only.push(digest.clone());
            }
        }

        let direct_weak_only = self.resolve_step_vertex_labels(&direct_weak_only).await;
        let relay_only = self.resolve_step_vertex_labels(&relay_only).await;
        let both = self.resolve_step_vertex_labels(&both).await;

        debug!(
            "CRITICAL_PARENT_PROVENANCE target_round={} proposal_round={} step_vertices={} weak_only={} relay_only={} both={} weak_only_vertices=[{}] relay_only_vertices=[{}] both_vertices=[{}]",
            target_round,
            proposal_round,
            parents.solid_step_sources.len(),
            direct_weak_only.len(),
            relay_only.len(),
            both.len(),
            direct_weak_only.join(", "),
            relay_only.join(", "),
            both.join(", ")
        );
    }

    #[async_recursion]
    async fn process_header(&mut self, header: &Header) -> DagResult<()> {
        let origin_node = self
            .node_index(&header.author)
            .map_or_else(|| "unknown".to_string(), |idx| idx.to_string());
        debug!(
            "Received header {} (origin Node{}, round {}): entering processing pipeline",
            header.id, origin_node, header.round
        );
        debug!("Processing {:?}", header);
        // Indicate that we are processing this header.
        self.processing
            .entry(header.round)
            .or_insert_with(HashSet::new)
            .insert(header.id.clone());

        // Ensure we have the parents. If at least one parent is missing, the synchronizer returns an empty
        // vector; it will gather the missing parents (as well as all ancestors) from other nodes and then
        // reschedule processing of this header.
        let parents = self.synchronizer.get_parents(header).await?;
        if parents.is_empty() {
            debug!(
                "Header {} (round {}) suspended in synchronizer: missing parent(s), will be retried by HeaderWaiter",
                header.id,
                header.round
            );
            return Ok(());
        }

        // Check the parent certificates. We allow commit-time weak edges from the whole
        // solid-wave window, but only the solid-step window contributes to processing.
        let round = header.round as u64;
        let solid_step_length = self.committee.solid_step_length();
        let solid_wave_length = self.committee.solid_wave_length();
        let is_solid_step = self.committee.is_solid_step(round);
        let step_index: Round = ((round - 1) % solid_step_length) + 1;
        let wave_index: Round = ((round - 1) % solid_wave_length) + 1;
        let regular_weak_start: Round = round.saturating_sub(step_index);
        let commit_weak_start: Round = round.saturating_sub(wave_index);

        let mut stake = 0u64;
        let mut solid_step_union = HashSet::new();

        for x in &parents {
            ensure!(
                x.round() >= commit_weak_start && x.round() < round,
                DagError::MalformedHeader(header.id.clone())
            );
            if x.round() >= regular_weak_start {
                stake += self.committee.stake(&x.origin()) as u64;
                if is_solid_step {
                    solid_step_union.extend(x.header.solid_step_vertices_merged.iter().cloned());
                }
            }
        }

        let threshold = self.committee.processing_threshold(round);
        if is_solid_step {
            ensure!(
                solid_step_union.len() >= threshold as usize,
                DagError::HeaderRequiresQuorum(header.id.clone())
            );
        } else {
            ensure!(
                stake >= threshold as u64,
                DagError::HeaderRequiresQuorum(header.id.clone())
            );
        }

        // Ensure we have the payload. If we don't, the synchronizer will ask our workers to get it, and then
        // reschedule processing of this header once we have it.
        if self.synchronizer.missing_payload(header).await? {
            debug!(
                "Header {} (round {}) suspended in synchronizer: missing payload, will be retried by HeaderWaiter, header={:?}",
                header.id,
                header.round,
                header
            );
            return Ok(());
        }

        // Store the header.
        let bytes = bincode::serialize(header).expect("Failed to serialize header");
        self.store.write(header.id.to_vec(), bytes).await;

        // Check if we can vote for this header.
        let already_voted = self
            .last_voted
            .entry(header.round)
            .or_insert_with(HashSet::new)
            .contains(&header.author);

        if already_voted {
            debug!(
                "Discarding header {} (round {}): already voted for author in this round",
                header.id, header.round
            );
        } else {
            // Mark that we're voting for this author in this round.
            self.last_voted
                .entry(header.round)
                .or_insert_with(HashSet::new)
                .insert(header.author);

            // Make a vote and send it to the header's creator.
            let vote = Vote::new(header, &self.name, &mut self.signature_service).await;
            debug!(
                "Created vote {:?} for header {} (round {})",
                vote, header.id, header.round
            );
            if vote.origin == self.name {
                debug!(
                    "Processing own vote for header {} (round {}) locally",
                    header.id, header.round
                );
                self.process_vote(vote)
                    .await
                    .expect("Failed to process our own vote");
            } else {
                let address = self
                    .committee
                    .primary(&header.author)
                    .expect("Author of valid header is not in the committee")
                    .primary_to_primary;
                let bytes = bincode::serialize(&PrimaryMessage::Vote(vote))
                    .expect("Failed to serialize our own vote");
                let handler = self.network.send(address, Bytes::from(bytes)).await;
                debug!(
                    "Forwarding vote for header {} (round {}) to primary at {}",
                    header.id, header.round, address
                );
                self.cancel_handlers
                    .entry(header.round)
                    .or_insert_with(Vec::new)
                    .push(handler);
            }
        }
        Ok(())
    }

    #[async_recursion]
    async fn process_vote(&mut self, vote: Vote) -> DagResult<()> {
        debug!("Processing {:?}", vote);
        let vote_id = vote.id.clone();

        let header = match self.pending_headers.get(&vote_id) {
            Some(header) => header.clone(),
            None => {
                debug!(
                    "Ignoring vote for unknown/local-untracked header {} (round {})",
                    vote_id, vote.round
                );
                return Ok(());
            }
        };

        // Add it to the votes' aggregator and try to make a new certificate.
        let aggregator = self
            .votes_aggregators
            .entry(vote_id.clone())
            .or_insert_with(VotesAggregator::new);
        if let Some(certificate) = aggregator.append(vote, &self.committee, &header)? {
            self.pending_headers.remove(&vote_id);
            self.votes_aggregators.remove(&vote_id);
            let origin = certificate.origin();
            let origin_node = self
                .node_index(&origin)
                .map_or_else(|| "unknown".to_string(), |idx| idx.to_string());
            debug!(
                "Created certificate {} (origin Node{}, round {})",
                certificate.header.id,
                origin_node,
                certificate.round()
            );
            debug!(
                "Assembled {:?}, generated by node {} and header round is {}",
                certificate,
                certificate.origin(),
                header.round
            );

            // Broadcast the certificate:
            // 1. Local node assembles certificate from votes
            // 2. Certificate is broadcast to all other primaries
            // 3. Each primary delivers it to `Core::process_certificate`
            let cert_id = certificate.header.id.clone();
            let cert_round = certificate.round();
            debug!(
                "Broadcasting certificate {} (round {}) to other primaries",
                cert_id, cert_round
            );
            let addresses: Vec<_> = self
                .committee
                .others_primaries(&self.name)
                .iter()
                .map(|(_, x)| x.primary_to_primary)
                .collect();
            let bytes = bincode::serialize(&PrimaryMessage::Certificate(certificate.clone()))
                .expect("Failed to serialize our own certificate");
            for address in addresses {
                let handler = self.network.send(address, Bytes::from(bytes.clone())).await;
                let id = cert_id.clone();
                tokio::spawn(async move {
                    match handler.await {
                        Ok(_) => {
                            debug!(
                                "Certificate {} (round {}) successfully delivered to primary {}",
                                id, cert_round, address
                            );
                        }
                        Err(_) => {
                            debug!(
                                "Certificate {} (round {}) delivery to primary {} was canceled or failed",
                                id, cert_round, address
                            );
                        }
                    }
                });
            }

            // Process the new certificate.
            self.process_certificate(certificate)
                .await
                .expect("Failed to process valid certificate");
        }
        Ok(())
    }

    #[async_recursion]
    async fn process_certificate(&mut self, certificate: Certificate) -> DagResult<()> {
        let origin = certificate.origin();
        let origin_node = self
            .node_index(&origin)
            .map_or_else(|| "unknown".to_string(), |idx| idx.to_string());
        debug!(
            "Received certificate {} (origin Node{}, round {}): entering processing pipeline",
            certificate.header.id,
            origin_node,
            certificate.round()
        );
        debug!("Processing {:?}", certificate);

        // Process the header embedded in the certificate if we haven't already voted for it (if we already
        // voted, it means we already processed it). Since this header got certified, we are sure that all
        // the data it refers to (ie. its payload and its parents) are available. We can thus continue the
        // processing of the certificate even if we don't have them in store right now.
        if !self
            .processing
            .get(&certificate.header.round)
            .map_or_else(|| false, |x| x.contains(&certificate.header.id))
        {
            // This function may still throw an error if the storage fails.
            self.process_header(&certificate.header).await?;
        }

        // Ensure we have all the ancestors of this certificate yet. If we don't, the synchronizer will gather
        // them and trigger re-processing of this certificate.
        if !self.synchronizer.deliver_certificate(&certificate).await? {
            debug!(
                "Certificate {} (round {}) suspended in synchronizer: missing ancestor certificates, will be retried by CertificateWaiter",
                certificate.header.id,
                certificate.round()
            );
            return Ok(());
        }

        // Store the certificate.
        let bytes = bincode::serialize(&certificate).expect("Failed to serialize certificate");
        self.store.write(certificate.digest().to_vec(), bytes).await;

        // Aggregate certificates by their own round instead of a single global current_round.
        // Whichever round reaches the unlock condition first can be dispatched to proposer first.
        let target_round_start = certificate.round();
        let target_round_end = target_round_start + self.committee.solid_wave_length();
        for target_round in target_round_start..target_round_end {
            if let Some(parents) = self
                .certificates_aggregators
                .entry(target_round)
                .or_insert_with(|| Box::new(CertificatesAggregator::new(target_round)))
                .append(certificate.clone(), &self.committee)?
            {
                self.log_parent_provenance(target_round, &parents).await;
                // Send it to the `Proposer`.
                self.tx_proposer
                    .send((parents, target_round))
                    .await
                    .expect("Failed to send certificate");
            }
        }

        // Debug: resolve each solid_step_vertex in the merge to [round, node_id].
        // let current_round = target_round + 1;
        // if current_round % self.committee.solid_step_length() == 0 && current_round > 1 {
        //     if let Some(agg) = self.certificates_aggregators.get(&target_round) {
        //         if let Some(digests) = agg.last_solid_step_union_digests() {
        //             let mut vertices = Vec::with_capacity(digests.len());
        //             for digest in digests {
        //                 if let Ok(Some(bytes)) = self.store.read(digest.to_vec()).await {
        //                     if let Ok(cert) = bincode::deserialize::<Certificate>(&bytes) {
        //                         let node_id = self.node_index(&cert.origin()).unwrap_or(999);
        //                         vertices.push(format!("[{},{}]", cert.round(), node_id));
        //                         debug!(
        //                             "solid_step_vertex {} -> [{},{}]",
        //                             digest,
        //                             cert.round(),
        //                             node_id
        //                         );
        //                     }
        //                 }
        //             }
        //             if !vertices.is_empty() {
        //                 debug!(
        //                     "solid_step_union (round {}): {}",
        //                     current_round,
        //                     vertices.join(", ")
        //                 );
        //             }
        //         }
        //     }
        // }

        // Send it to the consensus layer.
        let id = certificate.header.id.clone();
        let origin = certificate.origin();
        let origin_node = self
            .node_index(&origin)
            .map_or_else(|| "unknown".to_string(), |idx| idx.to_string());
        debug!(
            "Delivered certificate {} (origin Node{}, round {}) to the consensus",
            id,
            origin_node,
            certificate.round()
        );
        if let Err(e) = self.tx_consensus.send(certificate).await {
            warn!(
                "Failed to deliver certificate {} to the consensus: {}",
                id, e
            );
        }
        Ok(())
    }

    fn sanitize_header(&mut self, header: &Header) -> DagResult<()> {
        ensure!(
            self.gc_round <= header.round,
            DagError::TooOld(header.id.clone(), header.round)
        );

        // Verify the header's signature.
        header.verify(&self.committee)?;

        // TODO [issue #3]: Prevent bad nodes from sending junk headers with high round numbers.

        Ok(())
    }

    fn sanitize_vote(&mut self, vote: &Vote) -> DagResult<()> {
        // ensure!(
        //     self.current_header.round >= vote.round,
        //     DagError::TooOld(vote.digest(), vote.round)
        // );

        // Ensure we receive a vote on the expected header.
        // ensure!(
        //     // vote.id == self.current_header.id
        //     //     && vote.origin == self.current_header.author
        //     //     && vote.round == self.current_header.round,
        //     vote.id == self.current_header.id
        //         && vote.origin == self.current_header.author,
        //     DagError::UnexpectedVote(vote.id.clone())
        // );

        // // Verify the vote.
        vote.verify(&self.committee).map_err(DagError::from);
        Ok(())
    }

    fn sanitize_certificate(&mut self, certificate: &Certificate) -> DagResult<()> {
        ensure!(
            self.gc_round <= certificate.round(),
            DagError::TooOld(certificate.digest(), certificate.round())
        );

        // Verify the certificate (and the embedded header).
        certificate.verify(&self.committee).map_err(DagError::from)
    }

    // Main loop listening to incoming messages.
    pub async fn run(&mut self) {
        loop {
            let result = tokio::select! {
                // We receive here messages from other primaries.
                Some(message) = self.rx_primaries.recv() => {
                    match message {
                        PrimaryMessage::Header(header) => {
                            let origin_node = self
                                .node_index(&header.author)
                                .map_or_else(|| "unknown".to_string(), |idx| idx.to_string());
                            debug!(
                                "Channel recv header {} (origin Node{}, round {})",
                                header.id,
                                origin_node,
                                header.round
                            );
                            match self.sanitize_header(&header) {
                                Ok(()) => self.process_header(&header).await,
                                Err(e) => {
                                    debug!(
                                        "Discarding header {} (round {}) in sanitize_header: {}",
                                        header.id,
                                        header.round,
                                        e
                                    );
                                    Err(e)
                                }
                            }

                        },
                        PrimaryMessage::Vote(vote) => {
                            match self.sanitize_vote(&vote) {
                                Ok(()) => self.process_vote(vote).await,
                                Err(e) => {
                                    debug!(
                                        "Discarding vote for header {:?} in sanitize_vote: {}",
                                        vote.id,
                                        e
                                    );
                                    Err(e)
                                }
                            }
                        },
                        PrimaryMessage::Certificate(certificate) => {
                            let origin = certificate.origin();
                            let origin_node = self
                                .node_index(&origin)
                                .map_or_else(|| "unknown".to_string(), |idx| idx.to_string());
                            debug!(
                                "Channel recv certificate {} (origin Node{}, round {})",
                                certificate.header.id,
                                origin_node,
                                certificate.round()
                            );
                            match self.sanitize_certificate(&certificate) {
                                Ok(()) =>  self.process_certificate(certificate).await,
                                Err(e) => {
                                    debug!(
                                        "Discarding certificate {} (round {}) in sanitize_certificate: {}",
                                        certificate.header.id,
                                        certificate.round(),
                                        e
                                    );
                                    Err(e)
                                }
                            }
                        },
                        _ => panic!("Unexpected core message")
                    }
                },

                // We receive here loopback headers from the `HeaderWaiter`. Those are headers for which we interrupted
                // execution (we were missing some of their dependencies) and we are now ready to resume processing.
                Some(header) = self.rx_header_waiter.recv() => {
                    let origin_node = self
                        .node_index(&header.author)
                        .map_or_else(|| "unknown".to_string(), |idx| idx.to_string());
                    debug!(
                        "Channel recv header(waiter) {} (origin Node{}, round {})",
                        header.id,
                        origin_node,
                        header.round
                    );
                    self.process_header(&header).await
                },

                // We receive here loopback certificates from the `CertificateWaiter`. Those are certificates for which
                // we interrupted execution (we were missing some of their ancestors) and we are now ready to resume
                // processing.
                Some(certificate) = self.rx_certificate_waiter.recv() => {
                    let origin = certificate.origin();
                    let origin_node = self
                        .node_index(&origin)
                        .map_or_else(|| "unknown".to_string(), |idx| idx.to_string());
                    debug!(
                        "Channel recv certificate(waiter) {} (origin Node{}, round {})",
                        certificate.header.id,
                        origin_node,
                        certificate.round()
                    );
                    self.process_certificate(certificate).await
                },

                // We also receive here our new headers created by the `Proposer`.
                Some(header) = self.rx_proposer.recv() => self.process_own_header(header).await,
            };
            match result {
                Ok(()) => (),
                Err(DagError::StoreError(e)) => {
                    error!("{}", e);
                    panic!("Storage failure: killing node.");
                }
                Err(e @ DagError::TooOld(..)) => debug!("{}", e),
                Err(e) => warn!("{}", e),
            }

            // Cleanup internal state.
            let round = self.consensus_round.load(Ordering::Relaxed);
            if round > self.gc_depth {
                let gc_round = round - self.gc_depth;
                self.last_voted.retain(|k, _| k >= &gc_round);
                self.processing.retain(|k, _| k >= &gc_round);
                self.certificates_aggregators.retain(|k, _| k >= &gc_round);
                self.cancel_handlers.retain(|k, _| k >= &gc_round);
                self.pending_headers.retain(|_, h| h.round >= gc_round);
                let active_header_ids: HashSet<Digest> =
                    self.pending_headers.keys().cloned().collect();
                self.votes_aggregators
                    .retain(|digest, _| active_header_ids.contains(digest));
                self.gc_round = gc_round;
            }
        }
    }
}
