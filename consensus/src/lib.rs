// Copyright(C) Facebook, Inc. and its affiliates.
use config::{Committee, Stake};
use crypto::Hash as _;
use crypto::{Digest, PublicKey};
use log::{debug, info, warn};
use primary::{Certificate, Round};
use std::cmp::max;
use std::collections::{BTreeSet, HashMap, HashSet};
use tokio::sync::mpsc::{Receiver, Sender};

#[cfg(test)]
#[path = "tests/consensus_tests.rs"]
pub mod consensus_tests;

/// The representation of the DAG in memory.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CommitStatus {
    OneValent = 0,
    ZeroValent = 1,
    Bivalent = 2,
    Pending = 3,
}

type DagEntry = (Digest, Certificate, CommitStatus);
type Dag = HashMap<Round, HashMap<PublicKey, DagEntry>>;
type DagPosition = (Round, PublicKey);

/// The state that needs to be persisted for crash-recovery.
struct State {
    /// The highest round among all committed certificates. This is used for GC only.
    last_committed_certificate_round: Round,
    /// The round of the last leader whose commit path was accepted.
    last_committed_leader_round: Round,
    // Keeps the last committed round for each authority. This map is used to clean up the dag and
    // ensure we don't commit twice the same certificate.
    last_committed: HashMap<PublicKey, Round>,
    /// Keeps the latest committed certificate (and its parents) for every authority. Anything older
    /// must be regularly cleaned up through the function `update`.
    dag: Dag,
    /// Fast lookup for parent certificate digests.
    certificate_index: HashMap<Digest, DagPosition>,
    /// Fast lookup for both certificate digests and header ids. Used by logging / visualization.
    digest_index: HashMap<Digest, DagPosition>,
    /// Rounds that need fallback (slow-path) decisions because fast-path was undecidable.
    slow_path_pending_rounds: BTreeSet<Round>,
}

impl State {
    fn new(genesis: Vec<Certificate>) -> Self {
        let mut state = Self {
            last_committed_certificate_round: 0,
            last_committed_leader_round: 0,
            last_committed: HashMap::new(),
            dag: HashMap::new(),
            certificate_index: HashMap::new(),
            digest_index: HashMap::new(),
            slow_path_pending_rounds: BTreeSet::new(),
        };

        for certificate in genesis {
            state.insert(certificate);
        }

        state.last_committed = state
            .dag
            .get(&0)
            .into_iter()
            .flat_map(|genesis_round| genesis_round.iter())
            .map(|(author, (_, certificate, _))| (*author, certificate.round()))
            .collect();
        state
    }

    fn insert(&mut self, certificate: Certificate) {
        let round = certificate.round();
        let origin = certificate.origin();
        let certificate_digest = certificate.digest();
        let header_id = certificate.header.id.clone();

        if let Some((old_digest, old_certificate, _old_status)) =
            self.dag.entry(round).or_insert_with(HashMap::new).insert(
                origin,
                (
                    certificate_digest.clone(),
                    certificate,
                    CommitStatus::Pending,
                ),
            )
        {
            self.remove_indexes(&old_digest, &old_certificate.header.id);
        }

        let position = (round, origin);
        self.certificate_index
            .insert(certificate_digest.clone(), position);
        self.digest_index
            .insert(certificate_digest.clone(), position);
        self.digest_index.insert(header_id, position);
    }

    fn remove_indexes(&mut self, certificate_digest: &Digest, header_id: &Digest) {
        self.certificate_index.remove(certificate_digest);
        self.digest_index.remove(certificate_digest);
        self.digest_index.remove(header_id);
    }

    fn find_certificate(&self, certificate_digest: &Digest) -> Option<&DagEntry> {
        let (round, author) = self.certificate_index.get(certificate_digest)?;
        self.dag.get(round)?.get(author)
    }

    fn find_digest(&self, digest: &Digest) -> Option<DagPosition> {
        self.digest_index.get(digest).copied()
    }

    /// Record that a certificate has been committed without cleaning the DAG yet.
    fn record_commit(&mut self, certificate: &Certificate) {
        self.last_committed
            .entry(certificate.origin())
            .and_modify(|r| *r = max(*r, certificate.round()))
            .or_insert_with(|| certificate.round());

        self.last_committed_certificate_round = *self.last_committed.values().max().unwrap();
    }

    /// Clean up internal DAG state using the rounds recorded as committed.
    fn cleanup_committed_history(&mut self, gc_depth: Round) {
        let last_committed_certificate_round = self.last_committed_certificate_round;
        let last_committed = &self.last_committed;
        let mut removed = Vec::new();

        self.dag.retain(|round, authorities| {
            let keep_round = *round + gc_depth >= last_committed_certificate_round;

            authorities.retain(|author, (digest, certificate, _status)| {
                let keep_certificate =
                    keep_round && *round >= last_committed.get(author).copied().unwrap_or_default();
                if !keep_certificate {
                    removed.push((digest.clone(), certificate.header.id.clone()));
                }
                keep_certificate
            });

            !authorities.is_empty()
        });

        for (certificate_digest, header_id) in removed {
            self.remove_indexes(&certificate_digest, &header_id);
        }
    }

    fn update_last_committed_leader(&mut self, leader_round: Round) {
        self.last_committed_leader_round = max(self.last_committed_leader_round, leader_round);
    }

    fn set_commit_status(&mut self, certificate: &Certificate, status: CommitStatus) {
        if let Some((_, _, current_status)) = self
            .dag
            .get_mut(&certificate.round())
            .and_then(|round_map| round_map.get_mut(&certificate.origin()))
        {
            *current_status = status;
        }
    }
}

pub struct Consensus {
    /// The committee information.
    committee: Committee,
    /// Authorities in deterministic order for leader election.
    authorities: Vec<PublicKey>,
    /// Cache of authority -> node id used by logs and visualization.
    author_to_node: HashMap<PublicKey, usize>,
    /// The depth of the garbage collector.
    gc_depth: Round,

    /// Receives new certificates from the primary. The primary should send us new certificates only
    /// if it already sent us its whole history.
    rx_primary: Receiver<Certificate>,
    /// Outputs the sequence of ordered certificates to the primary (for cleanup and feedback).
    tx_primary: Sender<Certificate>,
    /// Outputs the sequence of ordered certificates to the application layer.
    tx_output: Sender<Certificate>,

    /// The genesis certificates.
    genesis: Vec<Certificate>,
}

impl Consensus {
    fn current_normal_leader_round(&self, round: Round) -> Option<Round> {
        let step_length = self.committee.solid_step_length();
        let wave_length = self.committee.solid_wave_length();
        if round < step_length {
            return None;
        }
        let r = round - step_length;
        if r % wave_length != 0 || r < 2 * wave_length {
            return None;
        }
        Some(r - wave_length)
    }

    pub fn spawn(
        committee: Committee,
        gc_depth: Round,
        rx_primary: Receiver<Certificate>,
        tx_primary: Sender<Certificate>,
        tx_output: Sender<Certificate>,
    ) {
        let authorities: Vec<_> = committee.authorities.keys().copied().collect();
        let author_to_node = authorities
            .iter()
            .copied()
            .enumerate()
            .map(|(index, authority)| (authority, index))
            .collect();
        tokio::spawn(async move {
            Self {
                committee: committee.clone(),
                authorities,
                author_to_node,
                gc_depth,
                rx_primary,
                tx_primary,
                tx_output,
                genesis: Certificate::genesis(&committee),
            }
            .run()
            .await;
        });
    }

    async fn run(&mut self) {
        // The consensus state (everything else is immutable).
        let mut state = State::new(self.genesis.clone());

        // Listen to incoming certificates.
        while let Some(certificate) = self.rx_primary.recv().await {
            debug!("Processing {:?}", certificate);
            let round = certificate.round();

            // Add the new certificate to the local storage.
            state.insert(certificate);

            // Fast Path
            self.fast_path(round, &mut state).await;
            // Slow Path (fallback for rounds that fast-path cannot decide).
            self.slow_path(round, &mut state).await;
        }
    }

    async fn emit_commits(&self, path: &str, certificates: Vec<Certificate>) {
        for certificate in certificates {
            let node_id = self.author_to_node_id(certificate.origin());
            info!(
                "DAG_COMMITTED path={} round={} node={} digest={:?}",
                path,
                certificate.round(),
                node_id,
                certificate.digest()
            );
            #[cfg(not(feature = "benchmark"))]
            info!("Committed {}", certificate.header);

            #[cfg(feature = "benchmark")]
            for batch in certificate.header.payload.keys() {
                info!(
                    "Committed {} -> batch_size={}B",
                    certificate.header,
                    batch.len()
                );
            }

            self.tx_primary
                .send(certificate.clone())
                .await
                .expect("Failed to send certificate to primary");

            if let Err(e) = self.tx_output.send(certificate).await {
                warn!("Failed to output certificate: {}", e);
            }
        }
    }

    async fn fast_path(&self, round: Round, state: &mut State) {
        if round == 0 || round <= state.last_committed_certificate_round {
            return;
        }
        let Some(current_round_map) = state.dag.get(&round) else {
            return;
        };
        let current_round_certificates: Vec<Certificate> = current_round_map
            .values()
            .map(|(_, cert, _)| cert.clone())
            .collect();
        let current_round_stake: Stake = current_round_certificates
            .iter()
            .map(|x| self.committee.stake(&x.origin()))
            .sum();
        if round > 1 && current_round_stake < self.committee.quorum_threshold() {
            return;
        }

        let r = round - 1;
        let Some(previous_round_map) = state.dag.get(&r) else {
            debug!(
                "Skipping fast path for round {} because round {} is missing from the DAG",
                round, r
            );
            return;
        };
        let previous_round_certificates: Vec<Certificate> = previous_round_map
            .values()
            .map(|(_, cert, _)| cert.clone())
            .collect();

        // Go-style fast decide:
        // - decide 1 if support >= N-F
        // - decide 0 if reject  >= N-F
        // - fallback otherwise
        let threshold = self.committee.quorum_threshold();
        let mut decide_one = Vec::new();
        let mut decide_zero = Vec::new();
        let mut undecided = Vec::new();

        for certificate in &previous_round_certificates {
            let candidate_header_id = certificate.header.id.clone();
            let candidate_digest = certificate.digest();
            let support_stake: Stake = current_round_certificates
                .iter()
                .filter(|x| {
                    x.header.solid_step_vertices.contains(&candidate_header_id)
                        || x.header.solid_step_vertices.contains(&candidate_digest)
                })
                .map(|x| self.committee.stake(&x.origin()))
                .sum();
            let reject_stake = current_round_stake.saturating_sub(support_stake);

            if support_stake >= threshold {
                decide_one.push(certificate.clone());
            } else if reject_stake >= threshold {
                decide_zero.push(certificate.clone());
            } else {
                undecided.push(certificate.clone());
            }
        }

        for certificate in &decide_one {
            state.set_commit_status(certificate, CommitStatus::OneValent);
        }
        for certificate in &decide_zero {
            state.set_commit_status(certificate, CommitStatus::ZeroValent);
        }
        for certificate in &undecided {
            state.set_commit_status(certificate, CommitStatus::Bivalent);
        }

        info!(
            "FAST_PATH_CHECK round={} threshold={} undecided={} decide_zero={} decide_one={}",
            round,
            threshold,
            undecided.len(),
            decide_zero.len(),
            decide_one.len()
        );

        if undecided.is_empty() {
            // Commit decide-one certificates and their reachable ancestors.
            let to_commit = self.collect_fast_path_commits(&decide_one, state);
            let mut committed = Vec::new();
            for certificate in to_commit {
                state.record_commit(&certificate);
                committed.push(certificate);
            }
            state.cleanup_committed_history(self.gc_depth);
            self.emit_commits("fast", committed).await;
        } else {
            // Fallback to slow path on the undecidable target round.
            state.slow_path_pending_rounds.insert(r);
            info!(
                "FAST_PATH_DEFER round={} fallback_round={} undecided={}",
                round,
                r,
                undecided.len()
            );
        }
    }

    async fn slow_path(&self, current_round: Round, state: &mut State) {
        if state.slow_path_pending_rounds.is_empty() {
            return;
        }

        let threshold = self.committee.validity_threshold();
        let step_length = self.committee.solid_step_length().max(1);
        let pending_rounds: Vec<Round> = state.slow_path_pending_rounds.iter().copied().collect();
        let mut resolved_rounds = Vec::new();

        for round in pending_rounds {
            if round == 0 || round <= state.last_committed_certificate_round {
                resolved_rounds.push(round);
                continue;
            }

            let support_round = round + 1;
            let leader_round = round + 2 * step_length;
            if leader_round > current_round {
                continue;
            }

            let Some((leader_digest, leader_cert, _)) = self.leader(leader_round, &state.dag)
            else {
                continue;
            };
            let leader = leader_cert.clone();
            let leader_header_id = leader.header.id.clone();
            let leader_digest = leader_digest.clone();

            let Some(support_round_map) = state.dag.get(&support_round) else {
                continue;
            };
            let support_round_certificates: Vec<Certificate> = support_round_map
                .values()
                .map(|(_, cert, _)| cert.clone())
                .collect();
            let support_round_stake: Stake = support_round_certificates
                .iter()
                .map(|x| self.committee.stake(&x.origin()))
                .sum();
            if support_round_stake < self.committee.quorum_threshold() {
                continue;
            }

            let Some(round_map) = state.dag.get(&round) else {
                resolved_rounds.push(round);
                continue;
            };
            let target_round_certificates: Vec<Certificate> = round_map
                .values()
                .map(|(_, cert, _)| cert.clone())
                .collect();

            let mut decide_one = Vec::new();
            let mut decide_zero = Vec::new();

            for certificate in target_round_certificates {
                let existing_status = state
                    .dag
                    .get(&certificate.round())
                    .and_then(|m| m.get(&certificate.origin()))
                    .map(|(_, _, status)| *status)
                    .unwrap_or(CommitStatus::Pending);

                if existing_status == CommitStatus::OneValent {
                    decide_one.push(certificate.clone());
                    continue;
                }
                if existing_status == CommitStatus::ZeroValent {
                    decide_zero.push(certificate.clone());
                    continue;
                }

                let candidate_header_id = certificate.header.id.clone();
                let candidate_digest = certificate.digest();
                let connected_stake: Stake = support_round_certificates
                    .iter()
                    .filter(|x| {
                        x.header.solid_step_vertices.contains(&candidate_header_id)
                            || x.header.solid_step_vertices.contains(&candidate_digest)
                    })
                    .filter(|x| self.linked(x, &leader, state))
                    .map(|x| self.committee.stake(&x.origin()))
                    .sum();

                if connected_stake >= threshold {
                    state.set_commit_status(&certificate, CommitStatus::OneValent);
                    decide_one.push(certificate);
                } else {
                    state.set_commit_status(&certificate, CommitStatus::ZeroValent);
                    decide_zero.push(certificate);
                }
            }

            info!(
                "SLOW_PATH_CHECK round={} leader_round={} leader_node={} threshold={} decide_zero={} decide_one={} leader_header={:?} leader_digest={:?}",
                round,
                leader_round,
                self.author_to_node_id(leader.origin()),
                threshold,
                decide_zero.len(),
                decide_one.len(),
                leader_header_id,
                leader_digest
            );

            let to_commit = self.collect_fast_path_commits(&decide_one, state);
            let mut committed = Vec::new();
            for certificate in to_commit {
                state.record_commit(&certificate);
                committed.push(certificate);
            }
            state.cleanup_committed_history(self.gc_depth);
            self.emit_commits("slow", committed).await;
            resolved_rounds.push(round);
        }

        for round in resolved_rounds {
            state.slow_path_pending_rounds.remove(&round);
        }
    }

    /// Map authority public key to node id (0..n-1), same as visualize_dag / extract_dag_out.
    fn author_to_node_id(&self, author: PublicKey) -> usize {
        self.author_to_node.get(&author).copied().unwrap_or(999)
    }

    /// Returns the certificate (and the certificate's digest) originated by the leader of the
    /// specified round (if any).
    fn leader<'a>(&self, round: Round, dag: &'a Dag) -> Option<&'a DagEntry> {
        // Experimental setting: keep deterministic round-robin leader election.
        #[cfg(test)]
        let coin = 0;
        #[cfg(not(test))]
        let coin = round;

        // Elect the leader.
        let leader = self.authorities[coin as usize % self.authorities.len()];

        // Return its certificate and the certificate's digest.
        dag.get(&round).map(|x| x.get(&leader)).flatten()
    }

    /// Order leader certificates to commit, mirroring Narwhal's `order_leaders` with step
    /// `solid_wave_length`: walk rounds from `last_committed_leader_round + solid_wave_length`
    /// up to (exclusive) the current leader round, stepping backward by `solid_wave_length`, and
    /// chain predecessors via `linked`.
    fn order_leaders(&self, leader: &Certificate, state: &State) -> Vec<Certificate> {
        let wave = self.committee.solid_wave_length() as usize;
        if wave == 0 {
            return vec![leader.clone()];
        }
        let start = state
            .last_committed_leader_round
            .saturating_add(wave as u64);
        let end_round = leader.round();
        let mut to_commit = vec![leader.clone()];
        let mut cur = leader;
        for r in (start..end_round).rev().step_by(wave) {
            let (_, prev_leader, _) = match self.leader(r, &state.dag) {
                Some(x) => x,
                None => continue,
            };
            if self.linked(cur, prev_leader, state) {
                to_commit.push(prev_leader.clone());
                cur = prev_leader;
            }
        }
        debug!(
            "order_leaders: chain_len={} tip_round={} last_committed_leader_round={} gap_rounds={} step={}",
            to_commit.len(),
            end_round,
            state.last_committed_leader_round,
            end_round.saturating_sub(state.last_committed_leader_round),
            wave
        );
        to_commit
    }

    /// Find a parent certificate by digest in any ancestor round (< child_round).
    fn find_parent_certificate<'a>(
        &self,
        state: &'a State,
        child_round: Round,
        parent_digest: &Digest,
    ) -> Option<&'a DagEntry> {
        if child_round <= 1 {
            return None;
        }
        state
            .find_certificate(parent_digest)
            .filter(|(_, certificate, _)| certificate.round() < child_round)
    }

    /// Checks if there is a path between two leaders.
    /// Unlike the original implementation, this traversal follows weak edges too.
    fn linked(&self, leader: &Certificate, prev_leader: &Certificate, state: &State) -> bool {
        let target = prev_leader.digest();
        let mut stack = vec![leader];
        let mut visited = HashSet::new();

        while let Some(current) = stack.pop() {
            let current_digest = current.digest();
            if !visited.insert(current_digest.clone()) {
                continue;
            }
            if current_digest == target {
                return true;
            }

            for parent in &current.header.parents {
                if let Some((_, parent_cert, _)) =
                    self.find_parent_certificate(state, current.round(), parent)
                {
                    stack.push(parent_cert);
                }
            }
        }
        false
    }

    /// Flatten the dag referenced by the input certificate. This is a classic depth-first search (pre-order):
    /// https://en.wikipedia.org/wiki/Tree_traversal#Pre-order
    fn order_dag(&self, leader: &Certificate, state: &State) -> Vec<Certificate> {
        debug!("Processing sub-dag of {:?}", leader);
        let mut ordered = Vec::new();
        let mut already_ordered: HashSet<Digest> = HashSet::new();

        let mut buffer = vec![leader];
        while let Some(x) = buffer.pop() {
            let x_digest = x.digest();
            let already_committed = state
                .last_committed
                .get(&x.origin())
                .map_or(false, |r| *r >= x.round());
            if already_ordered.contains(&x_digest) || already_committed {
                continue;
            }
            already_ordered.insert(x_digest);

            debug!("Sequencing {:?}", x);
            ordered.push(x.clone());
            for parent in &x.header.parents {
                let (digest, certificate, status) =
                    match self.find_parent_certificate(state, x.round(), parent) {
                        Some(x) => x,
                        None => continue, // Parent already GC'ed or not in local DAG.
                    };

                if *status == CommitStatus::ZeroValent {
                    continue;
                }

                // We skip the certificate if we (1) already processed it or (2) we reached a round that we already
                // committed for this authority.
                let mut skip = already_ordered.contains(digest);
                skip |= state
                    .last_committed
                    .get(&certificate.origin())
                    .map_or(false, |r| *r >= certificate.round());
                if !skip {
                    buffer.push(certificate);
                }
            }
        }

        // Ensure we do not commit garbage collected certificates.
        ordered.retain(|x| x.round() + self.gc_depth >= state.last_committed_certificate_round);

        // Ordering the output by round is not really necessary but it makes the commit sequence prettier.
        ordered.sort_by_key(|x| x.round());
        ordered
    }

    fn collect_fast_path_commits(
        &self,
        one_valent: &[Certificate],
        state: &State,
    ) -> Vec<Certificate> {
        let mut to_commit = Vec::new();
        let mut seen = HashSet::new();

        for certificate in one_valent {
            for ancestor in self.order_dag(certificate, state) {
                if seen.insert(ancestor.digest()) {
                    to_commit.push(ancestor);
                }
            }
        }

        to_commit.sort_by_key(|certificate| certificate.round());
        to_commit
    }

    fn visualize_dag(&self, state: &State, current_round: Round) {
        // from current_round to round 1, reverse
        for round in (1..=current_round).rev() {
            if state.dag.contains_key(&round) {
                let round_certs = state.dag.get(&round).unwrap();
                let mut round_output = format!("Round {}:", round);
                let mut vertices = Vec::new();

                let mut sorted_certs: Vec<_> = round_certs.iter().collect();
                sorted_certs.sort_by_key(|(author, _)| *author);

                for (author, (_cert_digest, certificate, status)) in sorted_certs {
                    let node_id = self.author_to_node.get(author).unwrap_or(&999);
                    let vertex_name = format!("Vertex{}", node_id);

                    // find the parent nodes
                    let mut parents = Vec::new();
                    let mut weak_parents = Vec::new();
                    for parent_digest in &certificate.header.parents {
                        // find the parent certificate in the dag
                        if let Some((parent_round, parent_author)) =
                            self.find_certificate_in_dag(state, parent_digest)
                        {
                            let parent_node_id =
                                self.author_to_node.get(&parent_author).unwrap_or(&999);
                            let is_weak = parent_round + 1 != round;
                            if is_weak {
                                let weak_entry = format!("[w{},{}]", parent_round, parent_node_id);
                                parents.push(weak_entry.clone());
                                weak_parents.push(weak_entry);
                            } else {
                                parents.push(format!("[{},{}]", parent_round, parent_node_id));
                            }
                        } else {
                            // if the block is genesis, do not need to output
                            if round != 1 {
                                parents.push("[?,?]".to_string());
                            }
                        }
                    }

                    let parent_str = if parents.is_empty() {
                        "[]".to_string()
                    } else {
                        format!("[{}]", parents.join(", "))
                    };

                    // Resolve each solid_wave_vertex digest to [round, node_id] for explicit display.
                    let mut solid_vertices = Vec::new();
                    for digest in &certificate.header.solid_wave_vertices {
                        if let Some((r, author)) = self.find_certificate_in_dag(state, digest) {
                            let n = self.author_to_node.get(&author).unwrap_or(&999);
                            solid_vertices.push(format!("[{},{}]", r, n));
                        } else {
                            solid_vertices.push("[?,?]".to_string());
                        }
                    }
                    let solid_str = if solid_vertices.is_empty() {
                        "".to_string()
                    } else {
                        format!(" solid=[{}]", solid_vertices.join(", "))
                    };

                    // Resolve each merged solid_wave_vertex digest to [round, node_id].
                    let mut merged_vertices = Vec::new();
                    for digest in &certificate.header.solid_wave_vertices_merged {
                        if let Some((r, author)) = self.find_certificate_in_dag(state, digest) {
                            let n = self.author_to_node.get(&author).unwrap_or(&999);
                            merged_vertices.push(format!("[{},{}]", r, n));
                        } else {
                            merged_vertices.push("[?,?]".to_string());
                        }
                    }
                    let merged_str = if merged_vertices.is_empty() {
                        "".to_string()
                    } else {
                        format!(" merged=[{}]", merged_vertices.join(", "))
                    };

                    let status_str = match status {
                        CommitStatus::OneValent => " one-valent",
                        CommitStatus::ZeroValent => " zero-valent",
                        CommitStatus::Bivalent => " bivalent",
                        CommitStatus::Pending => "",
                    };

                    let vertex_str = if weak_parents.is_empty() {
                        format!(
                            "({}){} (solid_wave_vertices: {}){}{}{}",
                            vertex_name,
                            parent_str,
                            certificate.header.solid_wave_vertices.len(),
                            solid_str,
                            merged_str,
                            status_str
                        )
                    } else {
                        format!(
                            "({}){} weak=[{}] (solid_wave_vertices: {}){}{}{}",
                            vertex_name,
                            parent_str,
                            weak_parents.join(", "),
                            certificate.header.solid_wave_vertices.len(),
                            solid_str,
                            merged_str,
                            status_str
                        )
                    };
                    vertices.push(vertex_str);
                }

                if !vertices.is_empty() {
                    round_output.push_str(&format!(" {} ", vertices.join(" --- ")));
                    info!("{}", round_output);
                }
            }
        }
    }

    fn find_certificate_in_dag(
        &self,
        state: &State,
        digest: &Digest,
    ) -> Option<(Round, PublicKey)> {
        state.find_digest(digest)
    }

    fn render_digest_set(&self, state: &State, digests: &HashSet<Digest>) -> String {
        let mut resolved = Vec::with_capacity(digests.len());
        for digest in digests {
            if let Some((round, author)) = self.find_certificate_in_dag(state, digest) {
                resolved.push(format!("[{},{}]", round, self.author_to_node_id(author)));
            } else {
                resolved.push("[?,?]".to_string());
            }
        }
        resolved.sort();
        resolved.join(", ")
    }
}
