// Copyright(C) Facebook, Inc. and its affiliates.
use crate::error::{DagError, DagResult};
use crate::messages::{Certificate, Header, ProposalParents, StepVertexSource, Vote};
use crate::primary::Round;
use config::{Committee, Stake};
use crypto::Hash as _;
use crypto::{Digest, PublicKey, Signature};
use log::debug;
use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

/// Aggregates votes for a particular header into a certificate.
pub struct VotesAggregator {
    weight: Stake,
    votes: Vec<(PublicKey, Signature)>,
    used: HashSet<PublicKey>,
}

impl VotesAggregator {
    pub fn new() -> Self {
        Self {
            weight: 0,
            votes: Vec::new(),
            used: HashSet::new(),
        }
    }

    pub fn append(
        &mut self,
        vote: Vote,
        committee: &Committee,
        header: &Header,
    ) -> DagResult<Option<Certificate>> {
        let author = vote.author;

        // Ensure it is the first time this authority votes.
        ensure!(self.used.insert(author), DagError::AuthorityReuse(author));

        self.votes.push((author, vote.signature));
        self.weight += committee.stake(&author);
        debug!(
            "VotesAggregator: received vote for header {} (round {}), votes in this round for this header: {} (weight={})",
            header.id,
            header.round,
            self.votes.len(),
            self.weight
        );
        if self.weight >= committee.quorum_threshold() {
            self.weight = 0; // Ensures quorum is only reached once.
            return Ok(Some(Certificate {
                header: header.clone(),
                votes: self.votes.clone(),
            }));
        }
        Ok(None)
    }
}

/// Aggregate certificates and check if we reach a quorum.
pub struct CertificatesAggregator {
    expected_round: Round,
    weight: Stake,
    certificates: Vec<Digest>,
    weak_certificates: Vec<Digest>,
    used: HashSet<PublicKey>,
    has_quorum: bool,
    /// Wait for several seconds after meeting the condition
    quorum_reached_time: Option<Instant>,
    wait_duration: Duration,
    /// Incremental union of parents' solid-step summaries for the proposal round.
    solid_step_union: HashSet<Digest>,
    /// Tracks whether each solid-step vertex arrived via direct weak edges, intermediate relay,
    /// or both. This lets us check whether the sigma=2 intermediate layer is actually helping.
    solid_step_sources: HashMap<Digest, StepVertexSource>,
    /// Incremental union of parents' solid-wave summaries for the proposal round.
    solid_wave_union: HashSet<Digest>,
    /// Last computed union of parents' solid_step_vertices_merged on solid rounds
    /// (for debug / final_dag display).
    last_union_set: Option<Vec<Digest>>,
}

impl CertificatesAggregator {
    pub fn new(expected_round: Round) -> Self {
        Self {
            expected_round,
            weight: 0,
            certificates: Vec::new(),
            weak_certificates: Vec::new(),
            used: HashSet::new(),
            has_quorum: false,
            quorum_reached_time: None,
            wait_duration: Duration::from_millis(20),
            solid_step_union: HashSet::new(),
            solid_step_sources: HashMap::new(),
            solid_wave_union: HashSet::new(),
            last_union_set: None,
        }
    }

    /// Returns the last computed union of parents' solid_step_vertices_merged
    /// (when advancing to a solid round). Used by core to resolve digests to
    /// [round, node_id] for debug and final_dag.
    pub fn last_solid_step_union_digests(&self) -> Option<&[Digest]> {
        self.last_union_set.as_deref()
    }

    fn extend_step_union(&mut self, certificate: &Certificate, source: StepVertexSource) {
        let vertices = if certificate.header.solid_step_vertices_merged.is_empty() {
            &certificate.header.solid_step_vertices
        } else {
            &certificate.header.solid_step_vertices_merged
        };

        for digest in vertices {
            self.solid_step_union.insert(digest.clone());
            self.solid_step_sources
                .entry(digest.clone())
                .or_default()
                .merge(source);
        }
    }

    fn extend_wave_union(&mut self, certificate: &Certificate) {
        if certificate.header.solid_wave_vertices_merged.is_empty() {
            self.solid_wave_union
                .extend(certificate.header.solid_wave_vertices.iter().cloned());
        } else {
            self.solid_wave_union.extend(
                certificate
                    .header
                    .solid_wave_vertices_merged
                    .iter()
                    .cloned(),
            );
        }
    }

    pub fn append(
        &mut self,
        certificate: Certificate,
        committee: &Committee,
    ) -> DagResult<Option<ProposalParents>> {
        let origin = certificate.origin();

        // Ensure it is the first time this authority votes as a strong edge.
        if certificate.round() == self.expected_round && !self.used.insert(origin) {
            return Ok(None);
        }

        // Accept parents from the whole solid-wave window, but only the newer
        // solid-step sub-window contributes to processing/solid-step checks.
        let current_round = self.expected_round + 1;
        let step_len = committee.solid_step_length();
        let wave_len = committee.solid_wave_length();
        let step_index: Round = ((current_round - 1) % step_len) + 1;
        let wave_index: Round = ((current_round - 1) % wave_len) + 1;
        let regular_weak_start: Round = current_round.saturating_sub(step_index);
        let commit_weak_start: Round = current_round.saturating_sub(wave_index);

        // Add the certificate to the appropriate list.
        if certificate.round() == self.expected_round {
            self.certificates.push(certificate.digest());
            self.extend_step_union(&certificate, StepVertexSource::relay_merged());
            self.extend_wave_union(&certificate);
            self.weight += committee.stake(&origin);
        } else if certificate.round() >= regular_weak_start
            && certificate.round() < self.expected_round
        {
            self.certificates.push(certificate.digest());
            self.weak_certificates.push(certificate.digest());
            self.extend_step_union(&certificate, StepVertexSource::direct_weak());
            self.extend_wave_union(&certificate);
        } else if certificate.round() >= commit_weak_start
            && certificate.round() < regular_weak_start
        {
            self.certificates.push(certificate.digest());
            self.weak_certificates.push(certificate.digest());
            self.extend_wave_union(&certificate);
        } else {
            return Ok(None);
        }
        debug!(
            "Current round: {}, regular weak range: [{}..={}), commit-only weak range: [{}..={})",
            current_round,
            regular_weak_start,
            self.expected_round,
            commit_weak_start,
            regular_weak_start
        );

        let threshold = committee.processing_threshold(current_round);
        let is_solid_step = committee.is_solid_step(current_round);
        debug!(
            "Advance to round {}: require weight >= {}, solid_step={})",
            current_round, threshold, is_solid_step
        );
        if is_solid_step {
            self.last_union_set = Some(self.solid_step_union.iter().cloned().collect());
            self.has_quorum = self.solid_step_union.len()
                >= committee.processing_threshold(current_round) as usize;
            debug!(
                "Current round: {}, The number of merged solid-step vertices is {}",
                current_round,
                self.solid_step_union.len()
            );
        } else {
            self.has_quorum = self.weight >= committee.processing_threshold(current_round);
            debug!(
                "Current round: {}, The weight is {}, self_has_quorum: {}",
                current_round, self.weight, self.has_quorum
            );
        }
        // Modify processing condition
        // if self.expected_round % committee.solid_step_length() as u64 == 1 && self.expected_round > 1 {
        //     if self.certificates..solid_step_vertices.len() >= committee.processing_threshold(self.expected_round as u64) {
        //         self.has_quorum = true;
        //     }
        // } else {
        //     if self.weight >= committee.processing_threshold(self.expected_round as u64) {
        //         self.has_quorum = true;
        //     }
        // }

        if self.has_quorum {
            if self.quorum_reached_time.is_none() {
                self.quorum_reached_time = Some(Instant::now());
            }
            let mut proposal_parents = ProposalParents::from(self.certificates.clone());
            proposal_parents.solid_step_union = self.solid_step_union.clone();
            proposal_parents.solid_step_sources = self.solid_step_sources.clone();
            proposal_parents.solid_wave_union = self.solid_wave_union.clone();
            // if self.quorum_reached_time.unwrap().elapsed() >= self.wait_duration || self.weight >= committee.max_threshold() {
            return Ok(Some(proposal_parents));
            // }
        }
        Ok(None)
    }
}
