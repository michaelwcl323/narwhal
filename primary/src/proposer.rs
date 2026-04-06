// Copyright(C) Facebook, Inc. and its affiliates.
use crate::messages::{Certificate, Header, ProposalParents};
use crate::primary::Round;
use config::{Committee, WorkerId};
use crypto::Hash as _;
use crypto::{Digest, PublicKey, SignatureService};
use log::debug;
#[cfg(feature = "benchmark")]
use log::info;
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::time::{sleep_until, Duration, Instant};

#[cfg(test)]
#[path = "tests/proposer_tests.rs"]
pub mod proposer_tests;

/// The proposer creates new headers and send them to the core for broadcasting and further processing.
pub struct Proposer {
    /// The public key of this primary.
    name: PublicKey,
    /// Node index for logging.
    node_id: Option<usize>,
    /// Service to sign headers.
    signature_service: SignatureService,
    /// The size of the headers' payload.
    header_size: usize,
    /// The maximum delay to wait for batches' digests.
    max_header_delay: u64,

    /// Receives the parents to include in the next header (along with their round number).
    rx_core: Receiver<(ProposalParents, Round)>,
    /// Receives the batches' digests from our workers.
    rx_workers: Receiver<(Digest, WorkerId)>,
    /// Sends newly created headers to the `Core`.
    tx_core: Sender<Header>,

    /// Unlocked proposal rounds waiting to be materialized into headers.
    unlocked_rounds: HashMap<Round, UnlockedRound>,
    /// Tracks which rounds this proposer has already materialized.
    proposed_rounds: HashSet<Round>,
    /// Monotonic unlock order used to preserve "first unlocked, first proposed".
    next_unlock_order: u64,
    /// Holds the batches' digests waiting to be included in the next header.
    digests: VecDeque<(Digest, WorkerId)>,
    /// Keeps track of the size (in bytes) of batches' digests that we received so far.
    payload_size: usize,
    /// The solid step length.
    solid_step_length: u64,
    /// The solid wave length.
    solid_wave_length: u64,
    /// Short grace period after parents become ready to absorb late certificates.
    parent_grace_delay: Duration,
    /// Highest wave observed locally; older-wave parent updates are stale once a newer wave arrives.
    latest_observed_wave: Round,
}

struct UnlockedRound {
    parents: Vec<Digest>,
    solid_step_union: HashSet<Digest>,
    solid_wave_union: HashSet<Digest>,
    ready_since: Instant,
    unlock_order: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RoundClass {
    Bootstrap,
    Critical,
    Intermediate,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ProposalDecision {
    round: Round,
    include_payload: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum StaleWavePolicy {
    KeepWholeWave,
    KeepOnlyRound(Round),
    DropWholeWave,
}

impl Proposer {
    #[allow(clippy::too_many_arguments)]
    pub fn spawn(
        name: PublicKey,
        committee: &Committee,
        signature_service: SignatureService,
        header_size: usize,
        max_header_delay: u64,
        rx_core: Receiver<(ProposalParents, Round)>,
        rx_workers: Receiver<(Digest, WorkerId)>,
        tx_core: Sender<Header>,
        _store: store::Store,
    ) {
        let node_id = committee
            .authorities
            .keys()
            .position(|authority| authority == &name);
        let genesis = Certificate::genesis(committee)
            .iter()
            .map(|x| x.digest())
            .collect();
        let solid_step_length = committee.solid_step_length() as u64;
        let solid_wave_length = committee.solid_wave_length() as u64;
        // Disable the parent grace delay so newly unlocked rounds can be proposed immediately.
        let parent_grace_delay_ms = 100;

        let mut unlocked_rounds = HashMap::new();
        unlocked_rounds.insert(
            1,
            UnlockedRound {
                parents: genesis,
                solid_step_union: HashSet::new(),
                solid_wave_union: HashSet::new(),
                ready_since: Instant::now(),
                unlock_order: 0,
            },
        );

        tokio::spawn(async move {
            Self {
                name,
                node_id,
                signature_service,
                header_size,
                max_header_delay,
                rx_core,
                rx_workers,
                tx_core,
                unlocked_rounds,
                proposed_rounds: HashSet::new(),
                next_unlock_order: 1,
                digests: VecDeque::with_capacity(2 * header_size),
                payload_size: 0,
                solid_step_length,
                solid_wave_length,
                parent_grace_delay: Duration::from_millis(parent_grace_delay_ms),
                latest_observed_wave: 0,
            }
            .run()
            .await;
        });
    }

    fn merge_parents(existing: &mut Vec<Digest>, parents: Vec<Digest>) -> (usize, usize) {
        let old_len = existing.len();
        let mut merged: HashSet<Digest> = existing.drain(..).collect();
        merged.extend(parents);
        let merged_len = merged.len();
        *existing = merged.into_iter().collect();
        (old_len, merged_len)
    }

    fn merge_unlocked_round(state: &mut UnlockedRound, update: ProposalParents) -> (usize, usize) {
        let solid_step_old_len = state.solid_step_union.len();
        let solid_wave_old_len = state.solid_wave_union.len();
        let (_old_len, _merged_len) = Self::merge_parents(&mut state.parents, update.parents);
        state.solid_step_union.extend(update.solid_step_union);
        state.solid_wave_union.extend(update.solid_wave_union);
        (
            state
                .solid_step_union
                .len()
                .saturating_sub(solid_step_old_len),
            state
                .solid_wave_union
                .len()
                .saturating_sub(solid_wave_old_len),
        )
    }

    fn round_class(&self, round: Round) -> RoundClass {
        if round == 1 {
            RoundClass::Bootstrap
        } else if self.is_critical_round(round) {
            RoundClass::Critical
        } else {
            RoundClass::Intermediate
        }
    }

    fn is_critical_round(&self, round: Round) -> bool {
        round > 1 && round % self.solid_step_length == 0
    }

    fn is_intermediate_round(&self, round: Round) -> bool {
        round > 1 && !self.is_critical_round(round)
    }

    fn next_critical_round(&self, round: Round) -> Option<Round> {
        if !self.is_intermediate_round(round) {
            return None;
        }

        Some(((round / self.solid_step_length) + 1) * self.solid_step_length)
    }

    fn critical_round_started(&self, round: Round) -> bool {
        self.unlocked_rounds
            .keys()
            .chain(self.proposed_rounds.iter())
            .any(|candidate| self.is_critical_round(*candidate) && *candidate >= round)
    }

    fn is_obsolete_intermediate_round(&self, round: Round) -> bool {
        self.next_critical_round(round)
            .map(|next_critical| self.critical_round_started(next_critical))
            .unwrap_or(false)
    }

    fn drop_obsolete_intermediate_rounds(&mut self, critical_round: Round) {
        let stale_rounds: Vec<_> = self
            .unlocked_rounds
            .keys()
            .copied()
            .filter(|round| {
                self.next_critical_round(*round)
                    .map(|next_critical| next_critical <= critical_round)
                    .unwrap_or(false)
            })
            .collect();

        for stale_round in stale_rounds {
            self.unlocked_rounds.remove(&stale_round);
            debug!(
                "Dropping stale intermediate round {} because critical round {} already started",
                stale_round, critical_round
            );
        }
    }

    fn is_round_ready(&self, round: Round, state: &UnlockedRound) -> bool {
        round == 1 || state.ready_since.elapsed() >= self.parent_grace_delay
    }

    fn next_recheck_deadline(&self, payload_deadline: Instant) -> Instant {
        let mut next_deadline = payload_deadline;

        for (round, state) in &self.unlocked_rounds {
            if self.proposed_rounds.contains(round) || state.parents.is_empty() {
                continue;
            }

            let ready_deadline = if *round == 1 {
                Instant::now()
            } else {
                state.ready_since + self.parent_grace_delay
            };
            if ready_deadline < next_deadline {
                next_deadline = ready_deadline;
            }
        }

        next_deadline
    }

    fn wave_of(&self, round: Round) -> Round {
        if self.solid_wave_length == 0 {
            return 0;
        }

        round.saturating_sub(1) / self.solid_wave_length
    }

    fn highest_unlocked_critical_round_in_wave(&self, wave: Round) -> Option<Round> {
        self.unlocked_rounds
            .keys()
            .copied()
            .filter(|round| self.wave_of(*round) == wave && self.is_critical_round(*round))
            .max()
    }

    fn highest_unfinished_critical_round_in_wave(&self, wave: Round) -> Option<Round> {
        let wave_start = wave.saturating_mul(self.solid_wave_length).saturating_add(1);
        let wave_end = wave_start
            .saturating_add(self.solid_wave_length.saturating_sub(1));

        (wave_start..=wave_end)
            .rev()
            .find(|round| {
                self.is_critical_round(*round) && !self.proposed_rounds.contains(round)
            })
    }

    fn wave_has_proposed_critical_round(&self, wave: Round) -> bool {
        self.proposed_rounds
            .iter()
            .any(|round| self.wave_of(*round) == wave && self.is_critical_round(*round))
    }

    fn stale_wave_policy(&self, wave: Round) -> StaleWavePolicy {
        if self.wave_has_proposed_critical_round(wave) {
            self.highest_unfinished_critical_round_in_wave(wave)
                .map(StaleWavePolicy::KeepOnlyRound)
                .unwrap_or(StaleWavePolicy::DropWholeWave)
        } else if let Some(retained_round) = self.highest_unlocked_critical_round_in_wave(wave) {
            StaleWavePolicy::KeepOnlyRound(retained_round)
        } else {
            StaleWavePolicy::KeepWholeWave
        }
    }

    fn drop_stale_wave_rounds(&mut self) {
        if self.latest_observed_wave == 0 {
            return;
        }

        let stale_waves: HashSet<_> = self
            .unlocked_rounds
            .keys()
            .copied()
            .map(|round| self.wave_of(round))
            .filter(|wave| *wave < self.latest_observed_wave)
            .collect();

        for stale_wave in stale_waves {
            match self.stale_wave_policy(stale_wave) {
                StaleWavePolicy::KeepWholeWave => {
                    debug!(
                        "Retaining stale wave {} because it does not yet contain a critical round",
                        stale_wave
                    );
                }
                StaleWavePolicy::KeepOnlyRound(retained_round) => {
                    let stale_rounds: Vec<_> = self
                        .unlocked_rounds
                        .keys()
                        .copied()
                        .filter(|round| {
                            self.wave_of(*round) == stale_wave && *round != retained_round
                        })
                        .collect();

                    for stale_round in stale_rounds {
                        self.unlocked_rounds.remove(&stale_round);
                        debug!(
                            "Discarding parents for stale round {} because wave {} lags active wave {} and critical round {} is being retained",
                            stale_round, stale_wave, self.latest_observed_wave, retained_round
                        );
                    }
                }
                StaleWavePolicy::DropWholeWave => {
                    let stale_rounds: Vec<_> = self
                        .unlocked_rounds
                        .keys()
                        .copied()
                        .filter(|round| self.wave_of(*round) == stale_wave)
                        .collect();

                    for stale_round in stale_rounds {
                        self.unlocked_rounds.remove(&stale_round);
                        debug!(
                            "Discarding parents for stale round {} because wave {} already has a critical round and lags active wave {}",
                            stale_round, stale_wave, self.latest_observed_wave
                        );
                    }
                }
            }
        }
    }

    fn unlock_round(&mut self, round: Round, parent_update: ProposalParents) {
        let round_wave = self.wave_of(round);
        if round_wave < self.latest_observed_wave {
            match self.stale_wave_policy(round_wave) {
                StaleWavePolicy::KeepWholeWave => {}
                StaleWavePolicy::KeepOnlyRound(retained_round) if round == retained_round => {}
                StaleWavePolicy::KeepOnlyRound(retained_round) => {
                    self.unlocked_rounds.remove(&round);
                    debug!(
                        "Discarding parents for round {} because wave {} is older than active wave {} and critical round {} is being retained",
                        round, round_wave, self.latest_observed_wave, retained_round
                    );
                    return;
                }
                StaleWavePolicy::DropWholeWave => {
                    self.unlocked_rounds.remove(&round);
                    debug!(
                        "Discarding parents for round {} because wave {} is older than active wave {} and already has a critical round",
                        round, round_wave, self.latest_observed_wave
                    );
                    return;
                }
            }
        }

        if round_wave > self.latest_observed_wave {
            self.latest_observed_wave = round_wave;
            self.drop_stale_wave_rounds();
        }

        if self.proposed_rounds.contains(&round) {
            debug!(
                "Received stale parents for already proposed round {}",
                round
            );
            return;
        }

        if self.is_intermediate_round(round) && self.is_obsolete_intermediate_round(round) {
            self.unlocked_rounds.remove(&round);
            debug!(
                "Discarding intermediate round {} because its next critical round has already started",
                round
            );
            return;
        }

        if self.is_critical_round(round) {
            self.drop_obsolete_intermediate_rounds(round);
        }

        match self.unlocked_rounds.get_mut(&round) {
            Some(state) => {
                let old_len = state.parents.len();
                let (step_growth, wave_growth) = Self::merge_unlocked_round(state, parent_update);
                let merged_len = state.parents.len();
                debug!(
                    "Refreshing parents for unlocked round {} before proposal (old={}, merged={}, solid_step+={}, solid_wave+={})",
                    round, old_len, merged_len, step_growth, wave_growth
                );
            }
            None => {
                let unlock_order = self.next_unlock_order;
                self.next_unlock_order += 1;
                self.unlocked_rounds.insert(
                    round,
                    UnlockedRound {
                        parents: parent_update.parents,
                        solid_step_union: parent_update.solid_step_union,
                        solid_wave_union: parent_update.solid_wave_union,
                        ready_since: Instant::now(),
                        unlock_order,
                    },
                );
                debug!(
                    "Unlocked proposal round {} (unlock order {})",
                    round, unlock_order
                );
            }
        }
    }

    fn next_proposal_round(
        &self,
        timer_expired: bool,
        enough_digests: bool,
    ) -> Option<ProposalDecision> {
        let payload_trigger = timer_expired || enough_digests;
        let has_payload = !self.digests.is_empty();

        if let Some((round, _)) = self
            .unlocked_rounds
            .iter()
            .filter(|(round, state)| {
                !self.proposed_rounds.contains(round) && !state.parents.is_empty()
            })
            .filter(|(round, state)| {
                self.round_class(**round) == RoundClass::Bootstrap
                    && self.is_round_ready(**round, state)
            })
            .min_by_key(|(_, state)| state.unlock_order)
        {
            return Some(ProposalDecision {
                round: *round,
                include_payload: false,
            });
        }

        if !payload_trigger {
            return None;
        }

        let critical_round = self
            .unlocked_rounds
            .iter()
            .filter(|(round, state)| {
                !self.proposed_rounds.contains(round)
                    && !state.parents.is_empty()
                    && self.round_class(**round) == RoundClass::Critical
                    && self.is_round_ready(**round, state)
            })
            .min_by_key(|(_, state)| state.unlock_order)
            .map(|(round, _)| *round);

        let intermediate_round = self
            .unlocked_rounds
            .iter()
            .filter(|(round, state)| {
                !self.proposed_rounds.contains(round)
                    && !state.parents.is_empty()
                    && self.round_class(**round) == RoundClass::Intermediate
                    && self.is_round_ready(**round, state)
            })
            .min_by_key(|(_, state)| state.unlock_order)
            .map(|(round, _)| *round);

        let selected_round = match (critical_round, intermediate_round) {
            (Some(critical_round), Some(_)) if has_payload => Some(critical_round),
            (_, Some(intermediate_round)) => Some(intermediate_round),
            (Some(critical_round), None) => Some(critical_round),
            (None, None) => None,
        }?;

        Some(ProposalDecision {
            round: selected_round,
            include_payload: has_payload,
        })
    }

    fn take_payload_for_header(&mut self) -> BTreeMap<Digest, WorkerId> {
        self.payload_size = 0;
        self.digests.drain(..).collect()
    }

    async fn make_header(
        &mut self,
        round: Round,
        unlocked_round: UnlockedRound,
        include_payload: bool,
    ) {
        // Make a new header.
        let payload = if include_payload {
            self.take_payload_for_header()
        } else {
            BTreeMap::new()
        };
        let mut header = Header::new(
            self.name,
            round,
            payload,
            unlocked_round.parents.iter().cloned().collect(),
            &mut self.signature_service,
        )
        .await;
        let origin_node = self
            .node_id
            .map_or_else(|| "unknown".to_string(), |idx| idx.to_string());
        debug!(
            "Created {:?} header {} (origin Node{}, round {}, payload_entries={})",
            self.round_class(round),
            header.id,
            origin_node,
            header.round,
            header.payload.len()
        );
        debug!("Created {:?}", header);

        // Maintain solid_step / solid_wave metadata according to the intended semantics:
        // - round 1: vertices = parents, merged = parents
        // - end rounds (r % len == 0): vertices = union(parent.merged), merged = {header}
        // - all other rounds: vertices = merged = union(parent.merged)
        debug!("the number of the parents is {}", header.parents.len());

        let is_solid_step_init_round =
            round == 1 || (round > 1 && round % self.solid_step_length == 0);
        let is_solid_wave_end_round =
            round == 1 || (round > 1 && round % self.solid_wave_length == 0);
        if round == 1 {
            let parent_set: HashSet<Digest> = unlocked_round.parents.into_iter().collect();
            header.store_solid_step_vertex(parent_set.clone());
            header.store_solid_step_merged_vertices(parent_set.clone());
            header.store_solid_wave_vertex(parent_set.clone());
            header.store_solid_wave_merged_vertices(parent_set);
        } else if is_solid_step_init_round {
            header.store_solid_step_vertex(unlocked_round.solid_step_union);

            let mut self_only: HashSet<Digest> = HashSet::new();
            self_only.insert(header.id.clone());
            header.store_solid_step_merged_vertices(self_only);
        } else {
            header.store_solid_step_vertex(unlocked_round.solid_step_union.clone());
            header.store_solid_step_merged_vertices(unlocked_round.solid_step_union);
        }
        if is_solid_wave_end_round {
            header.store_solid_wave_vertex(unlocked_round.solid_wave_union);

            let mut self_only: HashSet<Digest> = HashSet::new();
            self_only.insert(header.id.clone());
            header.store_solid_wave_merged_vertices(self_only);
        } else {
            header.store_solid_wave_vertex(unlocked_round.solid_wave_union.clone());
            header.store_solid_wave_merged_vertices(unlocked_round.solid_wave_union);
        }
        debug!(
            "Current round: {}, solid_step_vertices={}, solid_wave_vertices={}",
            round,
            header.solid_step_vertices.len(),
            header.solid_wave_vertices.len()
        );

        #[cfg(feature = "benchmark")]
        for digest in header.payload.keys() {
            // NOTE: This log entry is used to compute performance.
            info!("Created {} -> {:?}", header, digest);
        }

        // Send the new header to the `Core` that will broadcast and process it.
        self.tx_core
            .send(header)
            .await
            .expect("Failed to send header");
    }

    // Main loop listening to incoming messages.
    pub async fn run(&mut self) {
        debug!("Dag starting with bootstrap round 1 unlocked");

        let mut payload_deadline = Instant::now() + Duration::from_millis(self.max_header_delay);
        let timer = sleep_until(payload_deadline);
        tokio::pin!(timer);

        loop {
            let enough_digests = self.payload_size >= self.header_size;
            let timer_expired = Instant::now() >= payload_deadline;
            self.drop_stale_wave_rounds();
            if let Some(decision) = self.next_proposal_round(timer_expired, enough_digests) {
                self.latest_observed_wave =
                    self.latest_observed_wave.max(self.wave_of(decision.round));
                if decision.round != 1 {
                    debug!(
                        "Proposing {:?} round {} (payload={}, timer_expired={}, enough_digests={})",
                        self.round_class(decision.round),
                        decision.round,
                        decision.include_payload,
                        timer_expired,
                        enough_digests
                    );
                }

                let proposal_state = self
                    .unlocked_rounds
                    .remove(&decision.round)
                    .expect("Unlocked round disappeared unexpectedly");
                self.make_header(decision.round, proposal_state, decision.include_payload)
                    .await;
                self.proposed_rounds.insert(decision.round);
                if decision.include_payload && self.is_critical_round(decision.round) {
                    self.drop_obsolete_intermediate_rounds(decision.round);
                }
                payload_deadline = Instant::now() + Duration::from_millis(self.max_header_delay);

                continue;
            }

            let next_deadline = self.next_recheck_deadline(payload_deadline);
            timer.as_mut().reset(next_deadline);

            tokio::select! {
                Some((parent_update, round)) = self.rx_core.recv() => {
                    let proposal_round = round + 1;
                    self.unlock_round(proposal_round, parent_update);
                }
                Some((digest, worker_id)) = self.rx_workers.recv() => {
                    self.payload_size += digest.size();
                    self.digests.push_back((digest, worker_id));
                }
                () = &mut timer => {
                    // Nothing to do.
                }
            }
        }
    }
}
