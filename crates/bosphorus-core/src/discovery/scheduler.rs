use std::time::Instant;

use crate::config::DiscoveryTuning;
use crate::conntrack::FlowOutcome;
use crate::profile::{NetPhase, ScoredStrategy, SeedTier, TargetState, TrialKind, VerdictTiming};
use crate::strategy::generator::is_overlap_family;
use crate::strategy::{DefaultGenerator, Strategy, StrategyId};

use super::verdict;

/// Candidate acceptance gate for a target. Overlap-family strategies feed the
/// server junk bytes in the overlap region; a first-received-wins server
/// (guessed initial TTL 128 = Windows) would keep them and break the handshake.
fn accept_for(server_initial_ttl: Option<u8>) -> impl Fn(&Strategy) -> bool {
    move |s: &Strategy| !(server_initial_ttl == Some(128) && is_overlap_family(s))
}

/// What the scheduler wants tried next for a target.
pub struct Assignment {
    /// `None` = passthrough control (no mutation).
    pub id: Option<StrategyId>,
    pub strategy: Option<Strategy>,
    pub kind: TrialKind,
    /// A state transition this `assign` caused that the caller should log
    /// (`Exhausted` when the sweep ran out here, `Revived` when a grid bump put
    /// an exhausted target back into `Discover`). Transitions caused by a
    /// verdict come from [`Scheduler::record`] instead.
    pub event: Option<DiscoveryEvent>,
    /// `Some` when this candidate was taken from the seed list (out of grid
    /// order) rather than the grid sweep — the tier it came from.
    pub seed_tier: Option<SeedTier>,
    /// This target's measured DPI-injector distance, if it has one yet — see
    /// [`TargetState::injector_hops`]. Always mirrors the target's current
    /// value regardless of which branch below produced the assignment (set
    /// once, after the `match`, not per literal).
    pub discovered_ttl: Option<u8>,
}

/// The state transition a `record` caused (for logging).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiscoveryEvent {
    /// Probe succeeded — target is not blocked.
    NotBlocked,
    /// Probe failed — target is blocked; grid sweep begins.
    Blocked,
    /// The naked `Probe` was skipped: a high-confidence same-network seed
    /// (`DomainSibling` / `HouseStrategy`) was applied on the very first
    /// contact instead. The target went straight to `Discover`.
    ProbeSkipped { via: SeedTier },
    /// A candidate failed; moving to the next.
    NextCandidate { tried: usize, total: usize },
    /// A candidate reached the promotion threshold. `via_seed` is set when the
    /// promoted candidate came from the seed list (and, for `DomainSibling` /
    /// `HouseStrategy`, was promoted on its first success).
    Promoted { strategy: String, after: u8, via_seed: Option<SeedTier> },
    /// The active strategy failed too many times; back to discovery.
    Demoted { strategy: String },
    /// Every grid candidate was tried and none worked.
    Exhausted { tried: usize },
    /// The live grid grew past what was swept at exhaustion; the target
    /// re-entered `Discover` (with `tried` preserved).
    Revived { new_total: usize, untried: usize },
    /// Active strategy had a transient failure.
    ActiveFailure { count: u8 },
    /// Nothing changed (e.g. `Inconclusive`).
    Noted,
}

pub struct Scheduler {
    pub tuning: DiscoveryTuning,
}

/// Upper bound on `Explore` verdicts before a `Discover` sweep is declared
/// exhausted, even while some candidates still look retryable. Each grid
/// candidate can be handed out at most `1 + suspect_retries` times (a transient
/// `Blackhole` is forgiven that many times before its own failure count parks
/// it), so once that many verdicts have come back the sweep has run its course.
/// Guards against a livelock where forgiven candidates keep `tried` short.
fn sweep_budget_spent(ts: &TargetState, gen: &DefaultGenerator, tuning: &DiscoveryTuning) -> bool {
    let trials: u32 = ts.scores.values().map(|s| s.trials).sum();
    let budget = (gen.len() as u32).saturating_mul(1 + tuning.suspect_retries as u32);
    trials >= budget
}

/// Pick the first seed that is a live grid strategy, not already ruled
/// out / in-flight, and allowed by `accept`.
fn pick_seed(
    priority: &[(StrategyId, SeedTier)],
    skip: &[StrategyId],
    gen: &DefaultGenerator,
    accept: &dyn Fn(&Strategy) -> bool,
) -> Option<(StrategyId, SeedTier)> {
    priority.iter().copied().find(|(sid, _)| {
        if skip.contains(sid) {
            return false;
        }
        match gen.get_by_id(*sid) {
            Some(s) => accept(s),
            None => false,
        }
    })
}

impl Scheduler {
    /// Pick the next trial for `ts` with no seed list (the grid sweep only).
    pub fn assign(
        &self,
        ts: &mut TargetState,
        gen: &DefaultGenerator,
        now: Instant,
    ) -> Assignment {
        self.assign_seeded(ts, gen, &[], now)
    }

    /// Pick the next trial for `ts`. In `Discover`, a `priority` seed (a strategy
    /// that worked on a sibling target, most-confident first) is offered before
    /// the grid sweep; the seed's [`SeedTier`] is recorded on `ts` so
    /// [`record_timed`](Self::record_timed) can promote it sooner. A seed that
    /// is already tried / in-flight / gated / renumbered-away is skipped and the
    /// grid sweep proceeds exactly as before.
    pub fn assign_seeded(
        &self,
        ts: &mut TargetState,
        gen: &DefaultGenerator,
        priority: &[(StrategyId, SeedTier)],
        now: Instant,
    ) -> Assignment {
        ts.expire_in_flight(now, self.tuning.in_flight_ttl);
        let revived = Self::revive_if_grid_grew(ts, gen);

        let mut a = match ts.phase {
            NetPhase::Probe => {
                // Phase 2 (b): if a high-confidence same-network seed exists
                // (`DomainSibling` / `HouseStrategy`, i.e. proven on an
                // Active-with-strategy target — `build_seeds` never sources from
                // Active-passthrough), skip the naked Probe. Confirming "yes,
                // blocked" with a bare ClientHello just costs one RST plus a
                // client retry against a host that then rotates away.
                let hi: Vec<(StrategyId, SeedTier)> =
                    priority.iter().copied().filter(|(_, t)| t.is_high_confidence()).collect();
                let accept = accept_for(ts.server_initial_ttl);
                match pick_seed(&hi, &ts.skip_ids(), gen, &accept) {
                    Some((sid, tier)) => {
                        ts.phase = NetPhase::Discover;
                        ts.seeded.insert(sid, tier);
                        Assignment {
                            id: Some(sid),
                            strategy: gen.get_by_id(sid).cloned(),
                            kind: TrialKind::Explore,
                            event: Some(DiscoveryEvent::ProbeSkipped { via: tier }),
                            seed_tier: Some(tier),
                            discovered_ttl: None,
                        }
                    }
                    None => Assignment {
                        id: None,
                        strategy: None,
                        kind: TrialKind::Control,
                        event: None,
                        seed_tier: None,
                        discovered_ttl: None,
                    },
                }
            }
            NetPhase::Active => match ts.active {
                None => Assignment {
                    id: None,
                    strategy: None,
                    kind: TrialKind::Exploit,
                    event: None,
                    seed_tier: None,
                    discovered_ttl: None,
                },
                Some(sid) => Assignment {
                    id: Some(sid),
                    strategy: ts.scores.get(&sid).map(|s| s.strategy.clone()),
                    kind: TrialKind::Exploit,
                    event: None,
                    seed_tier: None,
                    discovered_ttl: None,
                },
            },
            NetPhase::Discover => {
                let accept = accept_for(ts.server_initial_ttl);
                let skip = ts.skip_ids();
                if let Some((sid, tier)) = pick_seed(priority, &skip, gen, &accept) {
                    ts.seeded.insert(sid, tier);
                    Assignment {
                        id: Some(sid),
                        strategy: gen.get_by_id(sid).cloned(),
                        kind: TrialKind::Explore,
                        event: None,
                        seed_tier: Some(tier),
                        discovered_ttl: None,
                    }
                } else {
                    match gen.next_candidate(&skip, &accept) {
                        Some(s) => Assignment {
                            id: Some(s.id()),
                            strategy: Some(s.clone()),
                            kind: TrialKind::Explore,
                            event: None,
                            seed_tier: None,
                            discovered_ttl: None,
                        },
                        None => {
                            // Nothing to hand out. Either every candidate is
                            // ruled out / its trial budget is spent
                            // (-> Exhausted), or the rest are just in-flight on
                            // sibling connections (-> passthrough, stay Discover).
                            if gen.next_candidate(&ts.tried, &accept).is_none()
                                || sweep_budget_spent(ts, gen, &self.tuning)
                            {
                                ts.phase = NetPhase::Exhausted;
                                ts.grid_size_at_exhaustion = Some(gen.len());
                                let tried = ts.tried.len();
                                ts.compact();
                                Assignment {
                                    id: None,
                                    strategy: None,
                                    kind: TrialKind::Control,
                                    event: Some(DiscoveryEvent::Exhausted { tried }),
                                    seed_tier: None,
                                    discovered_ttl: None,
                                }
                            } else {
                                Assignment {
                                    id: None,
                                    strategy: None,
                                    kind: TrialKind::Control,
                                    event: None,
                                    seed_tier: None,
                                    discovered_ttl: None,
                                }
                            }
                        }
                    }
                }
            }
            NetPhase::Exhausted => Assignment {
                id: None,
                strategy: None,
                kind: TrialKind::Control,
                event: None,
                seed_tier: None,
                discovered_ttl: None,
            },
        };

        if revived.is_some() {
            a.event = revived;
        }
        // Set once, here, rather than per match arm above: every branch shares
        // the same target, so its measured injector distance (if any) always
        // applies, whichever branch produced the assignment.
        a.discovered_ttl = ts.injector_hops;
        ts.mark_assigned(a.id, now);
        a
    }

    /// If `ts` is `Exhausted` and the live grid is now larger than it was when
    /// the sweep ran out, return it to `Discover` with `tried` preserved (only
    /// not-yet-tried candidates will be picked). Returns the `Revived` event.
    ///
    /// Dormant within a single run: the generator is immutable, so this only
    /// ever fires once M8 reloads a persisted `TargetState` under a bigger grid.
    fn revive_if_grid_grew(
        ts: &mut TargetState,
        gen: &DefaultGenerator,
    ) -> Option<DiscoveryEvent> {
        if ts.phase != NetPhase::Exhausted {
            return None;
        }
        let prev = ts.grid_size_at_exhaustion?;
        if gen.len() <= prev {
            return None;
        }
        ts.phase = NetPhase::Discover;
        ts.grid_size_at_exhaustion = None;
        ts.consecutive_failure = 0;
        let untried = gen.all().iter().filter(|s| !ts.tried.contains(&s.id())).count();
        Some(DiscoveryEvent::Revived { new_total: gen.len(), untried })
    }

    /// Feed back a flow's verdict, with no timing information (synthetic
    /// verdicts, tests). See [`record_timed`](Self::record_timed).
    pub fn record(
        &self,
        ts: &mut TargetState,
        gen: &DefaultGenerator,
        id: Option<StrategyId>,
        outcome: FlowOutcome,
        now: Instant,
    ) -> DiscoveryEvent {
        self.record_timed(ts, gen, id, outcome, VerdictTiming::NONE, now)
    }

    /// Feed back a flow's verdict along with its [`VerdictTiming`] (latency +
    /// ClientHello retransmit count), which is folded into the candidate's
    /// [`StrategyQuality`](crate::profile::StrategyQuality). Timing is recorded
    /// but does **not** yet influence promotion.
    pub fn record_timed(
        &self,
        ts: &mut TargetState,
        gen: &DefaultGenerator,
        id: Option<StrategyId>,
        outcome: FlowOutcome,
        timing: VerdictTiming,
        now: Instant,
    ) -> DiscoveryEvent {
        ts.updated_at = now;
        let ok = verdict::is_success(outcome);
        let fail = verdict::is_failure(outcome);
        if !ok && !fail {
            return DiscoveryEvent::Noted; // Inconclusive
        }

        // Set once, like server_initial_ttl: the first clean DPI-reset
        // fingerprint for this target is kept for the rest of the session.
        if ts.injector_hops.is_none() {
            if let Some(hops) = timing.injector_hops {
                ts.injector_hops = Some(hops);
            }
        }

        if let Some(sid) = id {
            let strat = gen
                .all()
                .iter()
                .find(|s| s.id() == sid)
                .cloned()
                .unwrap_or_else(Strategy::m4_fixed);
            ts.scores
                .entry(sid)
                .or_insert_with(|| ScoredStrategy::new(strat))
                .note(ok, now, timing);
            // Its verdict is in — it no longer blocks a sibling connection.
            ts.clear_in_flight(sid);
        }

        match ts.phase {
            NetPhase::Probe => {
                ts.consecutive_failure = 0;
                if ok {
                    ts.phase = NetPhase::Active;
                    ts.active = None;
                    DiscoveryEvent::NotBlocked
                } else {
                    ts.phase = NetPhase::Discover;
                    DiscoveryEvent::Blocked
                }
            }
            NetPhase::Discover => {
                if ok {
                    ts.consecutive_failure = 0;
                    if let Some(sid) = id {
                        // The streak is per-candidate (bumped by `note` above):
                        // a seeded candidate (proven on a same-network sibling)
                        // promotes on its first success, a grid-swept one still
                        // needs `promote_after_success` — but only *this*
                        // candidate's own successes count. Under the parallel
                        // sweep, another candidate succeeding once must not push
                        // this one over the line.
                        let streak =
                            ts.scores.get(&sid).map(|s| s.consecutive_success).unwrap_or(0);
                        let via_seed = ts.seeded.get(&sid).copied();
                        let threshold = via_seed
                            .map(|t| t.promote_threshold(self.tuning.promote_after_success))
                            .unwrap_or(self.tuning.promote_after_success);
                        if streak >= threshold {
                            ts.phase = NetPhase::Active;
                            ts.active = Some(sid);
                            ts.in_flight.clear();
                            let strategy = ts
                                .scores
                                .get(&sid)
                                .map(|s| s.strategy.describe())
                                .unwrap_or_default();
                            ts.compact(); // keep only the promoted strategy's score
                            return DiscoveryEvent::Promoted { strategy, after: streak, via_seed };
                        }
                    }
                    DiscoveryEvent::Noted
                } else {
                    // `note(ok = false)` already reset this candidate's streak.
                    if let Some(sid) = id {
                        // A `DpiReset` / build error is a deliberate, repeatable
                        // signal — park the candidate now. A `Blackhole` may be
                        // momentary loss; forgive it `suspect_retries` times
                        // (its own failure count then crosses the line).
                        let park = !matches!(outcome, FlowOutcome::Blackhole)
                            || ts.scores.get(&sid).map(|s| s.failures()).unwrap_or(0)
                                > self.tuning.suspect_retries as u32;
                        if park && !ts.tried.contains(&sid) {
                            ts.tried.push(sid);
                        }
                    }
                    let accept = accept_for(ts.server_initial_ttl);
                    if gen.next_candidate(&ts.tried, &accept).is_none()
                        || sweep_budget_spent(ts, gen, &self.tuning)
                    {
                        ts.phase = NetPhase::Exhausted;
                        ts.grid_size_at_exhaustion = Some(gen.len());
                        let tried = ts.tried.len();
                        ts.compact();
                        DiscoveryEvent::Exhausted { tried }
                    } else {
                        DiscoveryEvent::NextCandidate { tried: ts.tried.len(), total: gen.len() }
                    }
                }
            }
            NetPhase::Active => {
                if ok {
                    ts.consecutive_failure = 0;
                    DiscoveryEvent::Noted
                } else {
                    ts.consecutive_failure = ts.consecutive_failure.saturating_add(1);
                    if ts.consecutive_failure >= self.tuning.demote_after_failure {
                        let strategy = ts
                            .active
                            .and_then(|sid| ts.scores.get(&sid))
                            .map(|s| s.strategy.describe())
                            .unwrap_or_default();
                        ts.phase = NetPhase::Discover;
                        ts.active = None;
                        ts.tried.clear();
                        ts.in_flight.clear();
                        ts.consecutive_failure = 0;
                        ts.compact(); // active = None -> drops every stale score
                        DiscoveryEvent::Demoted { strategy }
                    } else {
                        DiscoveryEvent::ActiveFailure { count: ts.consecutive_failure }
                    }
                }
            }
            NetPhase::Exhausted => DiscoveryEvent::Noted,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::EvasionConfig;
    use crate::strategy::generator::{DesyncKind, GridAxes};
    use crate::strategy::model::{SendOrder, SplitAnchor};
    use std::time::Duration;

    /// `n` candidates: `frag@<off>` for each offset, all wrong-seq.
    fn tiny_gen_n(offsets: &[u16]) -> DefaultGenerator {
        DefaultGenerator::with_axes(&GridAxes {
            frag_anchor: offsets.iter().map(|o| Some(SplitAnchor::AbsoluteOffset(*o))).collect(),
            frag_reverse: vec![false],
            desync: vec![DesyncKind::WrongSeq],
            repeats: vec![1],
            order: vec![SendOrder::FakeThenReal],
            frag_multi: vec![],
            overlap_anchors: vec![],
            overlap_seqovl: vec![],
            tls_pad_anchors: vec![],
            tls_pad_desync: vec![],
            aggressive_fake_anchors: vec![],
            aggressive_fake_desync: vec![],
        })
    }

    fn tiny_gen() -> DefaultGenerator {
        // 2 candidates only: frag@2 and frag@3, both with wrong-seq.
        tiny_gen_n(&[2, 3])
    }

    fn sched() -> Scheduler {
        Scheduler { tuning: EvasionConfig::default().discovery }
    }

    fn now() -> Instant {
        Instant::now()
    }

    /// Drive `ts` from fresh to `Exhausted` against `g`.
    fn exhaust(s: &Scheduler, ts: &mut TargetState, g: &DefaultGenerator, t: Instant) {
        s.assign(ts, g, t);
        s.record(ts, g, None, FlowOutcome::DpiReset, t); // Probe -> Discover
        loop {
            let a = s.assign(ts, g, t);
            match a.id {
                Some(id) => {
                    s.record(ts, g, Some(id), FlowOutcome::DpiReset, t);
                }
                None => break,
            }
        }
    }

    #[test]
    fn probe_success_marks_not_blocked() {
        let g = tiny_gen();
        let s = sched();
        let mut ts = TargetState::new("open.example".into(), now());

        let a = s.assign(&mut ts, &g, now());
        assert_eq!(a.kind, TrialKind::Control);
        assert!(a.strategy.is_none());

        let ev = s.record(&mut ts, &g, None, FlowOutcome::Success, now());
        assert_eq!(ev, DiscoveryEvent::NotBlocked);
        assert_eq!(ts.phase, NetPhase::Active);
        assert_eq!(ts.active, None);
    }

    #[test]
    fn blocked_target_finds_and_promotes_a_working_candidate() {
        let g = tiny_gen();
        let s = sched(); // promote_after_success = 2
        let mut ts = TargetState::new("blocked.example".into(), now());

        // Probe fails -> Blocked / Discover.
        s.assign(&mut ts, &g, now());
        assert_eq!(s.record(&mut ts, &g, None, FlowOutcome::DpiReset, now()), DiscoveryEvent::Blocked);
        assert_eq!(ts.phase, NetPhase::Discover);

        // candidate 0 fails -> NextCandidate.
        let a0 = s.assign(&mut ts, &g, now());
        assert_eq!(a0.kind, TrialKind::Explore);
        let id0 = a0.id.unwrap();
        assert!(matches!(
            s.record(&mut ts, &g, Some(id0), FlowOutcome::DpiReset, now()),
            DiscoveryEvent::NextCandidate { .. }
        ));

        // candidate 1 succeeds twice -> Promoted.
        let a1 = s.assign(&mut ts, &g, now());
        let id1 = a1.id.unwrap();
        assert_ne!(id0, id1);
        assert_eq!(s.record(&mut ts, &g, Some(id1), FlowOutcome::Success, now()), DiscoveryEvent::Noted);
        let ev = s.record(&mut ts, &g, Some(id1), FlowOutcome::Success, now());
        assert!(matches!(ev, DiscoveryEvent::Promoted { .. }));
        assert_eq!(ts.phase, NetPhase::Active);
        assert_eq!(ts.active, Some(id1));

        // Active demotes after 3 failures.
        for i in 1..=3 {
            let a = s.assign(&mut ts, &g, now());
            assert_eq!(a.kind, TrialKind::Exploit);
            let ev = s.record(&mut ts, &g, a.id, FlowOutcome::DpiReset, now());
            if i < 3 {
                assert_eq!(ev, DiscoveryEvent::ActiveFailure { count: i });
            } else {
                assert!(matches!(ev, DiscoveryEvent::Demoted { .. }));
            }
        }
        assert_eq!(ts.phase, NetPhase::Discover);
        assert!(ts.tried.is_empty(), "demote clears tried for a fresh sweep");
    }

    #[test]
    fn all_candidates_fail_leads_to_exhausted() {
        let g = tiny_gen(); // 2 candidates
        let s = sched();
        let mut ts = TargetState::new("stubborn.example".into(), now());

        s.assign(&mut ts, &g, now());
        s.record(&mut ts, &g, None, FlowOutcome::DpiReset, now()); // Blocked

        let a0 = s.assign(&mut ts, &g, now());
        assert!(matches!(
            s.record(&mut ts, &g, a0.id, FlowOutcome::DpiReset, now()),
            DiscoveryEvent::NextCandidate { .. }
        ));
        let a1 = s.assign(&mut ts, &g, now());
        // Both fail with a deliberate reset -> each parks on the first failure.
        // (The `Blackhole` one-retry path has its own tests below.)
        let ev = s.record(&mut ts, &g, a1.id, FlowOutcome::DpiReset, now());
        assert_eq!(ev, DiscoveryEvent::Exhausted { tried: 2 });
        assert_eq!(ts.phase, NetPhase::Exhausted);

        // Further assigns are inert controls.
        let a2 = s.assign(&mut ts, &g, now());
        assert!(a2.strategy.is_none() && a2.kind == TrialKind::Control);
    }

    // --- M7d: parallel sweep ---

    #[test]
    fn concurrent_assigns_get_distinct_candidates() {
        let (g, s) = (tiny_gen(), sched());
        let t0 = Instant::now();
        let mut ts = TargetState::new("t".into(), t0);
        s.assign(&mut ts, &g, t0);
        s.record(&mut ts, &g, None, FlowOutcome::DpiReset, t0); // -> Discover

        let a = s.assign(&mut ts, &g, t0);
        let b = s.assign(&mut ts, &g, t0);
        assert_ne!(a.id.unwrap(), b.id.unwrap(), "two unresolved trials explore different candidates");
        assert_eq!(ts.in_flight.len(), 2);
    }

    #[test]
    fn record_clears_in_flight_and_moves_on() {
        let (g, s) = (tiny_gen(), sched());
        let t0 = Instant::now();
        let mut ts = TargetState::new("t".into(), t0);
        s.assign(&mut ts, &g, t0);
        s.record(&mut ts, &g, None, FlowOutcome::DpiReset, t0);

        let a = s.assign(&mut ts, &g, t0);
        let id0 = a.id.unwrap();
        assert_eq!(ts.in_flight.len(), 1);

        s.record(&mut ts, &g, Some(id0), FlowOutcome::DpiReset, t0);
        assert!(ts.in_flight.is_empty());
        assert!(ts.tried.contains(&id0));

        let b = s.assign(&mut ts, &g, t0);
        assert_ne!(b.id.unwrap(), id0);
    }

    #[test]
    fn in_flight_expires_and_the_candidate_returns() {
        let (g, s) = (tiny_gen(), sched()); // in_flight_ttl = 15s
        let t0 = Instant::now();
        let mut ts = TargetState::new("t".into(), t0);
        s.assign(&mut ts, &g, t0);
        s.record(&mut ts, &g, None, FlowOutcome::DpiReset, t0);

        let id0 = s.assign(&mut ts, &g, t0).id.unwrap();
        let id1 = s.assign(&mut ts, &g, t0).id.unwrap();
        assert_ne!(id0, id1);

        // 16s later both unresolved trials have expired; the sweep re-offers id0.
        let later = t0 + Duration::from_secs(16);
        assert_eq!(s.assign(&mut ts, &g, later).id, Some(id0));
    }

    #[test]
    fn saturated_in_flight_passes_through_without_exhausting() {
        let (g, s) = (tiny_gen(), sched()); // 2 candidates
        let t0 = Instant::now();
        let mut ts = TargetState::new("t".into(), t0);
        s.assign(&mut ts, &g, t0);
        s.record(&mut ts, &g, None, FlowOutcome::DpiReset, t0);

        assert!(s.assign(&mut ts, &g, t0).id.is_some());
        assert!(s.assign(&mut ts, &g, t0).id.is_some());

        // Third concurrent connection: nothing free, but nothing has failed.
        let c = s.assign(&mut ts, &g, t0);
        assert!(c.id.is_none() && c.strategy.is_none() && c.kind == TrialKind::Control);
        assert!(c.event.is_none());
        assert_eq!(ts.phase, NetPhase::Discover, "not exhausted — the rest are just in flight");
    }

    // --- M7d: grid-growth revival ---

    #[test]
    fn exhausted_target_revives_when_the_grid_grows() {
        let s = sched();
        let t0 = Instant::now();
        let mut ts = TargetState::new("t".into(), t0);

        exhaust(&s, &mut ts, &tiny_gen_n(&[2, 3]), t0);
        assert_eq!(ts.phase, NetPhase::Exhausted);
        assert_eq!(ts.grid_size_at_exhaustion, Some(2));
        assert_eq!(ts.tried.len(), 2);

        // Next assign sees a 3-candidate grid -> revived, tried preserved.
        let g3 = tiny_gen_n(&[2, 3, 4]);
        let a = s.assign(&mut ts, &g3, t0);
        assert_eq!(ts.phase, NetPhase::Discover);
        assert_eq!(ts.tried.len(), 2, "tried is NOT cleared");
        assert!(matches!(
            a.event,
            Some(DiscoveryEvent::Revived { new_total: 3, untried: 1 })
        ));
        let fresh = a.id.expect("a candidate was handed out");
        assert!(!ts.tried.contains(&fresh), "only a not-yet-tried candidate is picked");
    }

    #[test]
    fn compact_on_exhaustion_drops_every_per_candidate_score() {
        let g = tiny_gen_n(&[2, 3, 4, 5]);
        let s = sched();
        let t0 = Instant::now();
        let mut ts = TargetState::new("x".into(), t0);

        exhaust(&s, &mut ts, &g, t0);
        assert_eq!(ts.phase, NetPhase::Exhausted);
        assert!(ts.scores.is_empty(), "exhausted target keeps no per-candidate scores");
        assert_eq!(ts.scores.capacity(), 0, "and the map allocation is released");
        // `tried` ids are still there (they drive grid-growth revival).
        assert_eq!(ts.tried.len(), 4);
        assert!(ts.best().is_none());
    }

    #[test]
    fn compact_on_promotion_keeps_only_the_promoted_score() {
        let g = tiny_gen_n(&[2, 3, 4, 5]);
        let s = sched(); // promote_after_success = 2
        let t0 = Instant::now();
        let mut ts = TargetState::new("y".into(), t0);

        s.assign(&mut ts, &g, t0);
        s.record(&mut ts, &g, None, FlowOutcome::DpiReset, t0); // -> Discover

        let a0 = s.assign(&mut ts, &g, t0);
        s.record(&mut ts, &g, a0.id, FlowOutcome::DpiReset, t0); // cand 0 fails -> scored
        let a1 = s.assign(&mut ts, &g, t0);
        s.record(&mut ts, &g, a1.id, FlowOutcome::Success, t0);
        let ev = s.record(&mut ts, &g, a1.id, FlowOutcome::Success, t0); // promote

        assert!(matches!(ev, DiscoveryEvent::Promoted { .. }));
        assert_eq!(ts.phase, NetPhase::Active);
        assert_eq!(ts.scores.len(), 1, "only the promoted strategy's score survives");
        assert!(ts.scores.contains_key(&a1.id.unwrap()));
        // The promoted strategy is still resolvable for the Exploit assignment.
        let a = s.assign(&mut ts, &g, t0);
        assert_eq!(a.id, a1.id);
        assert!(a.strategy.is_some());
    }

    #[test]
    fn compact_on_demotion_clears_scores() {
        let g = tiny_gen_n(&[2, 3, 4, 5]);
        let s = sched(); // demote_after_failure = 3
        let t0 = Instant::now();
        let mut ts = TargetState::new("z".into(), t0);

        // Promote cand 0, then fail it 3x -> Demoted.
        s.assign(&mut ts, &g, t0);
        s.record(&mut ts, &g, None, FlowOutcome::DpiReset, t0);
        let a0 = s.assign(&mut ts, &g, t0);
        s.record(&mut ts, &g, a0.id, FlowOutcome::Success, t0);
        s.record(&mut ts, &g, a0.id, FlowOutcome::Success, t0); // promote
        for _ in 0..3 {
            let a = s.assign(&mut ts, &g, t0);
            s.record(&mut ts, &g, a.id, FlowOutcome::DpiReset, t0);
        }
        assert_eq!(ts.phase, NetPhase::Discover, "demoted");
        assert!(ts.scores.is_empty(), "demote wipes the score map for a fresh sweep");
        assert!(ts.tried.is_empty());
    }

    #[test]
    fn exhausted_stays_exhausted_when_the_grid_is_unchanged() {
        let s = sched();
        let t0 = Instant::now();
        let mut ts = TargetState::new("t".into(), t0);
        let g = tiny_gen();

        exhaust(&s, &mut ts, &g, t0);
        assert_eq!(ts.phase, NetPhase::Exhausted);

        let a = s.assign(&mut ts, &g, t0 + Duration::from_secs(60));
        assert_eq!(ts.phase, NetPhase::Exhausted);
        assert!(a.event.is_none() && a.id.is_none());
    }

    // ---- Phase 2 (b): Probe-skip on a high-confidence seed -----------------

    fn id0(g: &DefaultGenerator) -> StrategyId {
        g.all()[0].id()
    }

    #[test]
    fn probe_is_skipped_for_a_high_confidence_seed_and_promotes_on_first_success() {
        let s = sched();
        let g = tiny_gen();
        let t = now();
        let mut ts = TargetState::new("c-fra15.discord.media".into(), t);
        let seed = id0(&g);

        let a = s.assign_seeded(&mut ts, &g, &[(seed, SeedTier::DomainSibling)], t);
        assert_eq!(a.id, Some(seed));
        assert_eq!(a.kind, TrialKind::Explore);
        assert_eq!(a.seed_tier, Some(SeedTier::DomainSibling));
        assert!(matches!(a.event, Some(DiscoveryEvent::ProbeSkipped { via: SeedTier::DomainSibling })));
        assert_eq!(ts.phase, NetPhase::Discover, "went straight to Discover, no naked Probe");
        assert_eq!(ts.seeded.get(&seed).copied(), Some(SeedTier::DomainSibling));

        // First success => Promoted via the seed (threshold 1), not after 2.
        let ev = s.record(&mut ts, &g, Some(seed), FlowOutcome::Success, t);
        assert!(matches!(
            ev,
            DiscoveryEvent::Promoted { after: 1, via_seed: Some(SeedTier::DomainSibling), .. }
        ));
        assert_eq!(ts.phase, NetPhase::Active);
        assert_eq!(ts.active, Some(seed));
    }

    #[test]
    fn house_strategy_tier_also_skips_the_probe() {
        let s = sched();
        let g = tiny_gen();
        let t = now();
        let mut ts = TargetState::new("t".into(), t);
        let a = s.assign_seeded(&mut ts, &g, &[(id0(&g), SeedTier::HouseStrategy)], t);
        assert!(matches!(a.event, Some(DiscoveryEvent::ProbeSkipped { via: SeedTier::HouseStrategy })));
        assert_eq!(ts.phase, NetPhase::Discover);
    }

    #[test]
    fn no_seed_leaves_the_probe_byte_for_byte_unchanged() {
        let s = sched();
        let g = tiny_gen();
        let t = now();

        let mut a_ts = TargetState::new("t".into(), t);
        let a = s.assign_seeded(&mut a_ts, &g, &[], t);
        let mut b_ts = TargetState::new("t".into(), t);
        let b = s.assign(&mut b_ts, &g, t);

        assert!(a.id.is_none() && a.event.is_none() && a.seed_tier.is_none());
        assert_eq!(a.kind, TrialKind::Control);
        assert_eq!(a.id, b.id);
        assert_eq!(a_ts.phase, NetPhase::Probe, "no seed => still a naked Probe");
        assert_eq!(a_ts.phase, b_ts.phase);
    }

    #[test]
    fn ip_proximity_seed_is_not_confident_enough_to_skip_the_probe() {
        let s = sched();
        let g = tiny_gen();
        let t = now();
        let mut ts = TargetState::new("t".into(), t);
        let a = s.assign_seeded(&mut ts, &g, &[(id0(&g), SeedTier::IpProximity)], t);
        assert!(a.id.is_none() && a.event.is_none());
        assert_eq!(ts.phase, NetPhase::Probe);
    }

    #[test]
    fn isp_pool_seed_is_not_confident_enough_to_skip_the_probe() {
        let s = sched();
        let g = tiny_gen();
        let t = now();
        let mut ts = TargetState::new("t".into(), t);
        let a = s.assign_seeded(&mut ts, &g, &[(id0(&g), SeedTier::IspPool)], t);
        assert!(a.id.is_none() && a.event.is_none(), "cross-network prior earns its Probe");
        assert_eq!(ts.phase, NetPhase::Probe);
        // In Discover it IS offered, at the default threshold.
        ts.phase = NetPhase::Discover;
        let b = s.assign_seeded(&mut ts, &g, &[(id0(&g), SeedTier::IspPool)], t);
        assert_eq!(b.id, Some(id0(&g)));
        assert_eq!(b.seed_tier, Some(SeedTier::IspPool));
    }

    #[test]
    fn a_probe_skip_seed_that_fails_falls_through_to_the_grid() {
        let s = sched();
        let g = tiny_gen(); // frag@2, frag@3
        let t = now();
        let mut ts = TargetState::new("t".into(), t);
        let seed = id0(&g);

        s.assign_seeded(&mut ts, &g, &[(seed, SeedTier::DomainSibling)], t);
        let ev = s.record(&mut ts, &g, Some(seed), FlowOutcome::DpiReset, t);
        assert!(matches!(ev, DiscoveryEvent::NextCandidate { .. }));
        assert!(ts.tried.contains(&seed));
        assert_eq!(ts.scores.get(&seed).map(|s| s.consecutive_success), Some(0));
        assert_eq!(ts.phase, NetPhase::Discover);

        // Next assign is a plain grid candidate, not the failed seed.
        let a = s.assign_seeded(&mut ts, &g, &[(seed, SeedTier::DomainSibling)], t);
        assert!(a.id.is_some() && a.id != Some(seed));
        assert_eq!(a.seed_tier, None);
    }

    #[test]
    fn demote_still_fires_after_a_probe_skip_promotion() {
        let s = sched();
        let g = tiny_gen();
        let t = now();
        let mut ts = TargetState::new("t".into(), t);
        let seed = id0(&g);

        s.assign_seeded(&mut ts, &g, &[(seed, SeedTier::HouseStrategy)], t);
        s.record(&mut ts, &g, Some(seed), FlowOutcome::Success, t); // -> Active
        assert_eq!(ts.phase, NetPhase::Active);

        let mut last = DiscoveryEvent::Noted;
        for _ in 0..s.tuning.demote_after_failure {
            last = s.record(&mut ts, &g, Some(seed), FlowOutcome::DpiReset, t);
        }
        assert!(matches!(last, DiscoveryEvent::Demoted { .. }));
        assert_eq!(ts.phase, NetPhase::Discover);
        assert!(ts.tried.is_empty(), "demote clears the sweep");
    }

    // ---- consecutive-success is per-candidate, not per-target ---------------

    #[test]
    fn parallel_sweep_does_not_promote_a_candidate_on_another_candidates_success() {
        let s = sched(); // promote_after_success = 2
        let g = tiny_gen();
        let t = now();
        let mut ts = TargetState::new("blocked.example".into(), t);

        // Probe -> Discover.
        s.assign(&mut ts, &g, t);
        s.record(&mut ts, &g, None, FlowOutcome::DpiReset, t);

        // Two concurrent Explore trials pick distinct candidates A, B.
        let a = s.assign(&mut ts, &g, t).id.unwrap();
        let b = s.assign(&mut ts, &g, t).id.unwrap();
        assert_ne!(a, b);
        assert_eq!(ts.in_flight.len(), 2);

        // A succeeds once — one ServerHello, below the threshold.
        assert_eq!(s.record(&mut ts, &g, Some(a), FlowOutcome::Success, t), DiscoveryEvent::Noted);
        assert_eq!(ts.phase, NetPhase::Discover);

        // B succeeds once. It has a SINGLE ServerHello, so it must NOT promote.
        // Before the fix the shared counter is at 2 here and B is promoted.
        assert_eq!(
            s.record(&mut ts, &g, Some(b), FlowOutcome::Success, t),
            DiscoveryEvent::Noted,
            "B promoted on one success, riding A's tally"
        );
        assert_eq!(ts.phase, NetPhase::Discover);
        assert_eq!(ts.active, None);

        // A's OWN second success crosses A's own threshold -> A is promoted.
        let ev = s.record(&mut ts, &g, Some(a), FlowOutcome::Success, t);
        assert!(
            matches!(ev, DiscoveryEvent::Promoted { after: 2, via_seed: None, .. }),
            "got {ev:?}"
        );
        assert_eq!(ts.phase, NetPhase::Active);
        assert_eq!(ts.active, Some(a));
    }

    #[test]
    fn a_parallel_grid_success_does_not_inflate_a_seeds_promotion_count() {
        let s = sched();
        let g = tiny_gen();
        let t = now();
        let mut ts = TargetState::new("c-fra.discord.media".into(), t);
        let seed = g.all()[0].id();
        let grid = g.all()[1].id();

        // Probe-skip on the seed -> Discover, seed recorded in `seeded`.
        s.assign_seeded(&mut ts, &g, &[(seed, SeedTier::HouseStrategy)], t);
        // A parallel grid candidate is handed out too.
        let a = s.assign_seeded(&mut ts, &g, &[(seed, SeedTier::HouseStrategy)], t);
        assert_eq!(a.id, Some(grid));

        // The grid candidate succeeds once (does not promote — needs 2).
        assert_eq!(
            s.record(&mut ts, &g, Some(grid), FlowOutcome::Success, t),
            DiscoveryEvent::Noted
        );

        // The seed's OWN first success promotes it — and `after` is 1, not 2.
        // Before the fix the grid success pushed the shared counter to 1, so the
        // seed crossed at a reported `after: 2`.
        let ev = s.record(&mut ts, &g, Some(seed), FlowOutcome::Success, t);
        assert!(
            matches!(
                ev,
                DiscoveryEvent::Promoted { after: 1, via_seed: Some(SeedTier::HouseStrategy), .. }
            ),
            "got {ev:?}"
        );
        assert_eq!(ts.active, Some(seed));
    }

    // ---- Phase 2 (2C): one-retry on a transient Blackhole -------------------

    #[test]
    fn a_single_blackhole_keeps_the_candidate_in_play_a_second_parks_it() {
        let s = sched(); // suspect_retries = 1
        let g = tiny_gen();
        let t = now();
        let mut ts = TargetState::new("t".into(), t);
        s.assign(&mut ts, &g, t);
        s.record(&mut ts, &g, None, FlowOutcome::DpiReset, t); // Probe -> Discover

        let id = s.assign(&mut ts, &g, t).id.unwrap();

        // First Blackhole: forgiven — not ruled out, and the sweep re-offers it.
        assert!(matches!(
            s.record(&mut ts, &g, Some(id), FlowOutcome::Blackhole, t),
            DiscoveryEvent::NextCandidate { .. }
        ));
        assert!(!ts.tried.contains(&id), "one Blackhole does not rule the candidate out");
        assert_eq!(s.assign(&mut ts, &g, t).id, Some(id), "the sweep re-offers it");

        // Second Blackhole: now parked.
        s.record(&mut ts, &g, Some(id), FlowOutcome::Blackhole, t);
        assert!(ts.tried.contains(&id), "a second Blackhole rules it out");
    }

    #[test]
    fn dpi_reset_and_tls_error_still_park_a_candidate_on_the_first_failure() {
        let s = sched();
        let g = tiny_gen_n(&[2, 3, 4]);
        let t = now();

        for outcome in [FlowOutcome::DpiReset, FlowOutcome::TlsError] {
            let mut ts = TargetState::new("t".into(), t);
            s.assign(&mut ts, &g, t);
            s.record(&mut ts, &g, None, FlowOutcome::DpiReset, t);
            let id = s.assign(&mut ts, &g, t).id.unwrap();
            s.record(&mut ts, &g, Some(id), outcome, t);
            assert!(
                ts.tried.contains(&id),
                "{outcome:?} rules the candidate out on the first failure (only Blackhole is forgiven)"
            );
        }
    }

    #[test]
    fn the_trial_budget_forces_exhaustion_even_while_candidates_look_retryable() {
        let s = sched(); // suspect_retries = 1 -> budget = 3 * 2 = 6 verdicts
        let g = tiny_gen_n(&[2, 3, 4]);
        let t = now();
        let mut ts = TargetState::new("t".into(), t);
        s.assign(&mut ts, &g, t);
        s.record(&mut ts, &g, None, FlowOutcome::DpiReset, t); // -> Discover

        let ids: Vec<StrategyId> = g.all().iter().map(|x| x.id()).collect();

        // Park candidates 0 and 1 with two Blackholes each (4 verdicts).
        for id in &ids[..2] {
            s.record(&mut ts, &g, Some(*id), FlowOutcome::Blackhole, t);
            s.record(&mut ts, &g, Some(*id), FlowOutcome::Blackhole, t);
        }
        // Candidate 2: one Blackhole -> still a live Suspect (not in `tried`).
        let ev = s.record(&mut ts, &g, Some(ids[2]), FlowOutcome::Blackhole, t);
        assert!(matches!(ev, DiscoveryEvent::NextCandidate { .. }));
        assert!(!ts.tried.contains(&ids[2]));
        assert_eq!(ts.phase, NetPhase::Discover);

        // One more late verdict for the already-parked candidate 0 takes the
        // total to the budget (6). Candidate 2 still looks retryable, but the
        // sweep must terminate rather than loop on it forever.
        let ev = s.record(&mut ts, &g, Some(ids[0]), FlowOutcome::Blackhole, t);
        assert!(matches!(ev, DiscoveryEvent::Exhausted { .. }), "got {ev:?}");
        assert_eq!(ts.phase, NetPhase::Exhausted, "trial budget spent -> Exhausted");
    }
}
