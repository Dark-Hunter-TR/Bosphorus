//! Automatic multi-strategy discovery: for each target, probe whether it is
//! blocked, then sweep the candidate grid until one strategy works, then lock
//! it in. In-memory only in M6 (M8 persists per network fingerprint).

mod scheduler;
mod verdict;

pub use scheduler::{Assignment, DiscoveryEvent, Scheduler};
pub use verdict::{is_failure, is_success, score_delta, VerdictTiming};

pub use crate::profile::SeedTier;

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use parking_lot::Mutex;

use crate::config::EvasionConfig;
use crate::conntrack::FlowOutcome;
use crate::profile::persist::{PersistedScore, PersistedTarget, ProfileFile};
use crate::profile::{IspPool, NetPhase, ScoredStrategy, StrategyQuality, TargetState};
use crate::strategy::{DefaultGenerator, StrategyId};

pub struct Discovery {
    generator: DefaultGenerator,
    scheduler: Scheduler,
    targets: Mutex<HashMap<String, TargetState>>,
    /// Cross-network ISP seed pool (feature C). `None` unless the CLI was given
    /// `--isp <name>`. Write-once at startup; read (lock-free) on every `assign`.
    isp_pool: OnceLock<Arc<IspPool>>,
}

impl Discovery {
    pub fn new(cfg: &EvasionConfig) -> Self {
        Self {
            generator: DefaultGenerator::new(cfg),
            scheduler: Scheduler { tuning: cfg.discovery.clone() },
            targets: Mutex::new(HashMap::new()),
            isp_pool: OnceLock::new(),
        }
    }

    #[cfg(test)]
    pub(crate) fn with_generator(
        generator: DefaultGenerator,
        tuning: crate::config::DiscoveryTuning,
    ) -> Self {
        Self {
            generator,
            scheduler: Scheduler { tuning },
            targets: Mutex::new(HashMap::new()),
            isp_pool: OnceLock::new(),
        }
    }

    /// Attach the cross-network ISP seed pool. Idempotent: a second call is a
    /// no-op (the pool is write-once). Called at startup and, on a live rebind,
    /// re-applied to the new session's `Discovery`.
    pub fn set_isp_pool(&self, pool: Arc<IspPool>) {
        let _ = self.isp_pool.set(pool);
    }

    /// `(promoted id, its score)` for every `Active`-with-strategy target — the
    /// raw material the CLI folds into the ISP seed pool at shutdown.
    pub fn promoted_for_isp(&self) -> Vec<(StrategyId, ScoredStrategy)> {
        self.targets
            .lock()
            .values()
            .filter(|ts| ts.phase == NetPhase::Active)
            .filter_map(|ts| {
                let id = ts.active?;
                Some((id, ts.scores.get(&id)?.clone()))
            })
            .collect()
    }

    pub fn grid_len(&self) -> usize {
        self.generator.len()
    }

    /// Number of tracked targets (for the `bosphorus::mem` digest).
    pub fn target_count(&self) -> usize {
        self.targets.lock().len()
    }

    /// Current phase of one target, if tracked (cheap — no summary build).
    pub fn target_phase(&self, key: &str) -> Option<NetPhase> {
        self.targets.lock().get(key).map(|ts| ts.phase)
    }

    /// Target counts by phase: `[probe, discover, active, exhausted]`.
    pub fn phase_counts(&self) -> [usize; 4] {
        let mut c = [0usize; 4];
        for ts in self.targets.lock().values() {
            let i = match ts.phase {
                NetPhase::Probe => 0,
                NetPhase::Discover => 1,
                NetPhase::Active => 2,
                NetPhase::Exhausted => 3,
            };
            c[i] += 1;
        }
        c
    }

    /// FNV-1a over every current grid `StrategyId` — a fast "did the grid
    /// change" marker stored in the profile file.
    pub fn grid_signature(&self) -> u64 {
        let mut h: u64 = 0xcbf2_9ce4_8422_2325;
        for s in self.generator.all() {
            for b in s.id().0.to_le_bytes() {
                h ^= b as u64;
                h = h.wrapping_mul(0x0000_0100_0000_01b3);
            }
        }
        h
    }

    /// Restore targets from a loaded profile. For each target: if every
    /// persisted `StrategyId` still exists in the live grid, the sweep state is
    /// fully restored (so an `Exhausted` target can revive under a grown grid);
    /// otherwise the ids were renumbered — drop `tried`/`scores`/`active`, keep
    /// only the learned server TTL. Returns `(restored, degraded)` counts.
    pub fn load_persisted(&self, file: &ProfileFile) -> (usize, usize) {
        let now = Instant::now();
        let live: HashSet<StrategyId> =
            self.generator.all().iter().map(|s| s.id()).collect();
        let (mut restored, mut degraded) = (0usize, 0usize);
        let mut map = self.targets.lock();

        for pt in &file.targets {
            let ids_ok = pt.tried.iter().all(|id| live.contains(id))
                && pt.scores.iter().all(|s| live.contains(&s.strategy.id()))
                && pt.active.map_or(true, |id| live.contains(&id));

            let mut ts = TargetState::new(pt.key.clone(), now);
            ts.from_disk = true;
            ts.server_initial_ttl = pt.server_initial_ttl;
            ts.injector_hops = pt.injector_hops;

            if ids_ok {
                ts.phase = pt.phase;
                ts.tried = pt.tried.clone();
                ts.active = pt.active;
                ts.consecutive_failure = pt.consecutive_failure;
                ts.grid_size_at_exhaustion = pt.grid_size_at_exhaustion;
                for sc in &pt.scores {
                    ts.scores.insert(
                        sc.strategy.id(),
                        ScoredStrategy {
                            strategy: sc.strategy.clone(),
                            trials: sc.trials,
                            successes: sc.successes,
                            // Not persisted — a reloaded sweep restarts the
                            // "in a row" count for every candidate.
                            consecutive_success: 0,
                            last_success: None,
                            quality: sc.quality.clone(),
                        },
                    );
                }
                restored += 1;
            } else {
                degraded += 1;
            }
            map.insert(pt.key.clone(), ts);
        }
        (restored, degraded)
    }

    /// Snapshot the current target map into a persistable [`ProfileFile`].
    ///
    /// Only targets that are expensive to re-derive are written — see
    /// [`persist_worthy`]. `Probe` and not-blocked passthrough targets are
    /// skipped: they carry no learned strategy and are re-established for free
    /// on the next connection, so persisting them would only bloat the profile
    /// file (and the reloaded target map) with hosts that need no bypass.
    pub fn export(&self, net_key: &str) -> ProfileFile {
        let sig = self.grid_signature();
        let targets = self
            .targets
            .lock()
            .values()
            .filter(|ts| persist_worthy(ts))
            .map(|ts| PersistedTarget {
                key: ts.key.clone(),
                phase: ts.phase,
                tried: ts.tried.clone(),
                scores: ts
                    .scores
                    .values()
                    .map(|s| PersistedScore {
                        strategy: s.strategy.clone(),
                        trials: s.trials,
                        successes: s.successes,
                        quality: s.quality.clone(),
                    })
                    .collect(),
                active: ts.active,
                consecutive_failure: ts.consecutive_failure,
                server_initial_ttl: ts.server_initial_ttl,
                injector_hops: ts.injector_hops,
                grid_size_at_exhaustion: ts.grid_size_at_exhaustion,
            })
            .collect();
        ProfileFile::new(sig, net_key, targets)
    }

    /// Pick the next trial for `target` (creating its state on first contact).
    /// `server_initial_ttl` (from the SYN-ACK, 64/128/255) gates overlap-family
    /// candidates; recorded once per target.
    ///
    /// A fresh `Discover` target is seeded from what already works on this
    /// network: the promoted strategy of an `Active` sibling under the same
    /// registered domain first, then the session's most common `active`
    /// strategy, then — weakest — strategies other networks of this ISP settled
    /// on ([`SeedTier::IspPool`], only present with `--isp`). Seeds are tried
    /// before the grid sweep; a bad one costs a single trial. With nothing to
    /// learn from the seed list is empty and behaviour is identical to a plain
    /// grid sweep.
    pub fn assign(&self, target: &str, server_initial_ttl: Option<u8>) -> Assignment {
        let now = Instant::now();
        let mut map = self.targets.lock();

        let mut priority = build_seeds(&map, target);
        if let Some(pool) = self.isp_pool.get() {
            for (id, tier) in pool.seeds() {
                if !priority.iter().any(|(pid, _)| *pid == id) {
                    priority.push((id, tier)); // appended after the same-network tiers
                }
            }
        }

        let ts = map
            .entry(target.to_owned())
            .or_insert_with(|| TargetState::new(target.to_owned(), now));
        if ts.server_initial_ttl.is_none() {
            ts.server_initial_ttl = server_initial_ttl;
        }
        let a = self
            .scheduler
            .assign_seeded(ts, &self.generator, &priority, now);
        if let Some(tier) = a.seed_tier {
            tracing::debug!(
                target: "bosphorus::discovery",
                server = %target, ?tier,
                strategy = a.strategy.as_ref().map(|s| s.describe()),
                "seeded candidate offered (out of grid order)"
            );
        }
        match &a.event {
            Some(DiscoveryEvent::Exhausted { tried }) => tracing::warn!(
                target: "bosphorus::discovery",
                server = %target, tried, phase = ?ts.phase,
                "grid EXHAUSTED on assign — no strategy bypassed this target"
            ),
            Some(DiscoveryEvent::Revived { new_total, untried }) => tracing::info!(
                target: "bosphorus::discovery",
                server = %target, new_total, untried,
                "exhausted target revived — live grid grew past the swept size"
            ),
            Some(DiscoveryEvent::ProbeSkipped { via }) => tracing::info!(
                target: "bosphorus::discovery",
                server = %target, ?via,
                strategy = a.strategy.as_ref().map(|s| s.describe()),
                "probe skipped — high-confidence sibling seed applied on first contact"
            ),
            _ => {}
        }
        a
    }

    /// Feed back a flow's verdict with no timing info. Returns the event + the
    /// target's new phase. See [`record_timed`](Self::record_timed).
    pub fn record(
        &self,
        target: &str,
        id: Option<StrategyId>,
        outcome: FlowOutcome,
    ) -> Option<(DiscoveryEvent, NetPhase)> {
        self.record_timed(target, id, outcome, VerdictTiming::NONE)
    }

    /// Feed back a flow's verdict plus its [`VerdictTiming`]. The timing is
    /// folded into the candidate's [`StrategyQuality`](crate::profile::StrategyQuality);
    /// it is recorded only — promotion is unchanged.
    pub fn record_timed(
        &self,
        target: &str,
        id: Option<StrategyId>,
        outcome: FlowOutcome,
        timing: VerdictTiming,
    ) -> Option<(DiscoveryEvent, NetPhase)> {
        let now = Instant::now();
        let mut map = self.targets.lock();
        let ts = map.get_mut(target)?;
        let ev = self
            .scheduler
            .record_timed(ts, &self.generator, id, outcome, timing, now);
        Some((ev, ts.phase))
    }

    /// Drop stale / low-value targets. Returns how many were removed. Called
    /// from [`crate::engine::Engine::tick`] (throttled). `now` is the tick
    /// clock. A no-op in a forced-strategy run (the target map stays empty).
    pub fn evict(&self, now: Instant) -> usize {
        let t = &self.scheduler.tuning;
        let mut map = self.targets.lock();
        let before = map.len();

        map.retain(|_, ts| !evictable(ts, now, t));

        if map.len() > t.max_targets {
            let overflow = map.len() - t.max_targets;
            let mut rows: Vec<(String, u8, Instant)> = map
                .iter()
                .map(|(k, ts)| (k.clone(), value_rank(ts), last_activity(ts)))
                .collect();
            // Worst first: lowest value rank, then oldest activity.
            rows.sort_by(|a, b| a.1.cmp(&b.1).then(a.2.cmp(&b.2)));
            for (k, _, _) in rows.into_iter().take(overflow) {
                map.remove(&k);
            }
        }
        before - map.len()
    }

    pub fn summary(&self) -> Vec<TargetSummary> {
        let total = self.generator.len();
        let now = Instant::now();
        self.targets
            .lock()
            .values()
            .map(|ts| TargetSummary {
                key: ts.key.clone(),
                phase: ts.phase,
                tried: ts.tried.len(),
                total,
                in_flight: ts.in_flight.len(),
                last_trial_age: ts.last_assigned_at.map(|t| now.saturating_duration_since(t)),
                from_disk: ts.from_disk,
                active: ts
                    .active
                    .and_then(|sid| ts.scores.get(&sid))
                    .map(|s| s.strategy.describe()),
                active_is_passthrough: ts.phase == NetPhase::Active && ts.active.is_none(),
                best: ts
                    .best()
                    .map(|s| (s.strategy.describe(), s.successes, s.trials)),
            })
            .collect()
    }

    /// Targets still being worked (`Probe` / `Discover`) — the bottleneck set,
    /// for the engine's periodic progress digest.
    pub fn working_targets(&self) -> Vec<TargetSummary> {
        self.summary()
            .into_iter()
            .filter(|t| matches!(t.phase, NetPhase::Probe | NetPhase::Discover))
            .collect()
    }
}

/// Most recent activity of any kind on a target (assignment or verdict).
fn last_activity(ts: &TargetState) -> Instant {
    ts.last_assigned_at.unwrap_or(ts.created_at).max(ts.updated_at)
}

/// Crude registered domain (eTLD+1) — no Public Suffix List. Keeps the last two
/// labels, or three when the second-to-last is a common second-level under a
/// two-letter ccTLD (`bbc.co.uk`). Good enough as a *seeding* signal (a wrong
/// grouping costs one trial); never used for a hard target merge.
fn registered_domain(host: &str) -> &str {
    let host = host.trim_end_matches('.');
    let labels: Vec<&str> = host.split('.').collect();
    if labels.len() <= 2 {
        return host;
    }
    const SLD: &[&str] = &["co", "com", "net", "org", "gov", "edu", "ac"];
    let last = labels[labels.len() - 1];
    let penult = labels[labels.len() - 2];
    let take = if last.len() == 2 && SLD.contains(&penult) { 3 } else { 2 };
    let start = labels.len() - take;
    let byte_off: usize = labels[..start].iter().map(|l| l.len() + 1).sum();
    &host[byte_off..]
}

/// Order two seed candidates by `StrategyQuality`: retransmit-free-looking
/// first, then lowest observed latency. Used to break ties in the seed list.
fn better_seed(a: &StrategyQuality, b: &StrategyQuality) -> std::cmp::Ordering {
    use std::cmp::Ordering;
    b.looks_fast().cmp(&a.looks_fast()).then_with(|| match (a.min_latency, b.min_latency) {
        (Some(x), Some(y)) => x.cmp(&y),
        (Some(_), None) => Ordering::Less,
        (None, Some(_)) => Ordering::Greater,
        (None, None) => Ordering::Equal,
    })
}

/// Build the seed list for a `Discover` target from what already works on this
/// network. `map` is the whole session target map (locked by the caller);
/// `target` is excluded. Layered, most-confident first:
///
/// 1. `DomainSibling` — the promoted strategy of every `Active` target sharing
///    `target`'s registered domain, quality-ordered.
/// 2. `HouseStrategy` — the up-to-3 most common `active` strategies across every
///    `Active` target in the session.
///
/// Ids are deduped across layers (first tier wins). Empty when there is nothing
/// `Active` to learn from.
fn build_seeds(
    map: &HashMap<String, TargetState>,
    target: &str,
) -> Vec<(StrategyId, SeedTier)> {
    let reg = registered_domain(target);
    let mut out: Vec<(StrategyId, SeedTier)> = Vec::new();
    let mut seen: HashSet<StrategyId> = HashSet::new();

    let quality_of = |ts: &TargetState, id: StrategyId| -> StrategyQuality {
        ts.scores.get(&id).map(|s| s.quality.clone()).unwrap_or_default()
    };

    // --- 1. domain-sibling promoted strategies ---
    let mut sib: Vec<(StrategyId, StrategyQuality)> = Vec::new();
    for (k, ts) in map {
        if k == target || ts.phase != NetPhase::Active {
            continue;
        }
        let Some(id) = ts.active else { continue };
        if registered_domain(k) == reg {
            sib.push((id, quality_of(ts, id)));
        }
    }
    sib.sort_by(|a, b| better_seed(&a.1, &b.1));
    for (id, _) in sib {
        if seen.insert(id) {
            out.push((id, SeedTier::DomainSibling));
        }
    }

    // --- 2. session "house strategy": most common `active` id ---
    let mut freq: HashMap<StrategyId, (u32, StrategyQuality)> = HashMap::new();
    for (k, ts) in map {
        if k == target || ts.phase != NetPhase::Active {
            continue;
        }
        let Some(id) = ts.active else { continue };
        let e = freq.entry(id).or_insert_with(|| (0, quality_of(ts, id)));
        e.0 += 1;
    }
    let mut house: Vec<(StrategyId, (u32, StrategyQuality))> = freq.into_iter().collect();
    house.sort_by(|a, b| b.1 .0.cmp(&a.1 .0).then_with(|| better_seed(&a.1 .1, &b.1 .1)));
    for (id, _) in house.into_iter().take(3) {
        if seen.insert(id) {
            out.push((id, SeedTier::HouseStrategy));
        }
    }

    out
}

/// Lower = less worth keeping under the hard cap.
fn value_rank(ts: &TargetState) -> u8 {
    match ts.phase {
        NetPhase::Probe => 0,
        // Passthrough: not blocked, nothing learned — re-probed for free.
        NetPhase::Active if ts.active.is_none() => 1,
        NetPhase::Discover => 2,
        NetPhase::Exhausted => 3,
        // A working strategy is the most expensive thing to re-learn.
        NetPhase::Active => 4,
    }
}

/// Which targets [`Discovery::export`] persists to disk. Only state that is
/// expensive to re-derive is kept:
///
/// * `Discover` — a grid sweep is in progress; losing it restarts from Probe.
/// * `Active` with a promoted strategy — the working bypass for this host.
/// * `Exhausted` — so 166 candidates are not re-swept on the next launch.
///
/// A `Probe` target has learned nothing, and an `Active` passthrough target
/// (`active.is_none()`) is simply "not blocked here" — both are re-established
/// for free from the next connection, so persisting them only bloats the
/// profile file and the reloaded target map.
///
/// This is never a delete: a target that stops being persist-worthy just drops
/// out of the next snapshot, and an older on-disk profile that still lists such
/// a target self-heals on the following `export`. Each network's file is only
/// ever created or overwritten in place with that same network's newer state.
fn persist_worthy(ts: &TargetState) -> bool {
    match ts.phase {
        NetPhase::Probe => false,
        NetPhase::Active => ts.active.is_some(),
        NetPhase::Discover | NetPhase::Exhausted => true,
    }
}

fn evictable(ts: &TargetState, now: Instant, t: &crate::config::DiscoveryTuning) -> bool {
    let idle = now.saturating_duration_since(last_activity(ts));
    match ts.phase {
        NetPhase::Probe => idle >= t.target_idle_evict,
        NetPhase::Active if ts.active.is_none() => idle >= t.target_idle_evict,
        _ => idle >= t.target_max_idle,
    }
}

#[derive(Debug, Clone)]
pub struct TargetSummary {
    pub key: String,
    pub phase: NetPhase,
    pub tried: usize,
    pub total: usize,
    /// `Explore` trials handed out for this target and not yet resolved.
    pub in_flight: usize,
    /// Time since the last assignment of any kind (`None` = never assigned).
    pub last_trial_age: Option<Duration>,
    /// Restored from a persisted profile this session (vs. learned live).
    pub from_disk: bool,
    pub active: Option<String>,
    pub active_is_passthrough: bool,
    pub best: Option<(String, u32, u32)>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::DiscoveryTuning;
    use crate::strategy::generator::{DesyncKind, GridAxes};
    use crate::strategy::model::{SendOrder, SplitAnchor};

    /// `n` single-split candidates: `frag@<off>`, wrong-seq.
    fn tiny_gen(offsets: &[u16]) -> DefaultGenerator {
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

    // --- M8: persistence ---

    #[test]
    fn export_then_load_preserves_sweep_progress() {
        let a = Discovery::new(&EvasionConfig::default());
        let t = "updates.discord.com";
        a.assign(t, Some(128));
        a.record(t, None, FlowOutcome::DpiReset); // -> Discover
        for _ in 0..3 {
            let x = a.assign(t, Some(128));
            a.record(t, x.id, FlowOutcome::DpiReset);
        }
        let file = a.export("k");
        assert_eq!(file.grid_signature, a.grid_signature());

        let b = Discovery::new(&EvasionConfig::default());
        let (restored, degraded) = b.load_persisted(&file);
        assert_eq!((restored, degraded), (1, 0));
        let s = b.summary();
        let ts = s.iter().find(|x| x.key == t).unwrap();
        assert_eq!(ts.tried, 3, "sweep progress carried over");
        assert_eq!(ts.phase, NetPhase::Discover);
        assert!(ts.from_disk);
        // server TTL carried too -> overlap gating still applies for this target.
    }

    /// B1: `export` persists only the targets that are expensive to re-derive.
    /// A `Probe` target (no verdict yet) and an `Active` passthrough target
    /// (not blocked) are dropped from the snapshot; `Discover`, `Exhausted`,
    /// and `Active`-with-a-strategy targets are kept.
    #[test]
    fn export_skips_probe_and_passthrough_targets() {
        let d = Discovery::new(&EvasionConfig::default());

        // not blocked -> Active passthrough (active = None).
        d.assign("clean.example", None);
        d.record("clean.example", None, FlowOutcome::Success);

        // probe only, no verdict -> still Probe.
        d.assign("pending.example", None);

        // blocked, mid-sweep -> Discover.
        d.assign("blocked.example", None);
        d.record("blocked.example", None, FlowOutcome::DpiReset);

        // blocked, a candidate promoted -> Active with a real strategy.
        let w = "working.example";
        d.assign(w, None);
        d.record(w, None, FlowOutcome::DpiReset); // -> Discover
        let a = d.assign(w, None);
        d.record(w, a.id, FlowOutcome::Success);
        d.record(w, a.id, FlowOutcome::Success); // promote_after_success = 2

        let file = d.export("k");
        let mut keys: Vec<&str> = file.targets.iter().map(|t| t.key.as_str()).collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            vec!["blocked.example", "working.example"],
            "Probe and not-blocked passthrough targets are not persisted"
        );

        let working = file.targets.iter().find(|t| t.key == w).unwrap();
        assert_eq!(working.phase, NetPhase::Active);
        assert!(working.active.is_some(), "the promoted strategy is persisted");

        // Round-trips cleanly: reload restores exactly the two kept targets.
        let d2 = Discovery::new(&EvasionConfig::default());
        let (restored, degraded) = d2.load_persisted(&file);
        assert_eq!((restored, degraded), (2, 0));
    }

    /// D-plumbing: verdict timing (latency + retx) reaches the promoted
    /// candidate's `StrategyQuality`, and survives export -> load. Promotion
    /// itself is unchanged — this only checks the data is recorded.
    #[test]
    fn verdict_timing_reaches_strategy_quality_and_round_trips() {
        let a = Discovery::new(&EvasionConfig::default());
        let t = "updates.discord.com";
        a.assign(t, Some(128));
        a.record(t, None, FlowOutcome::DpiReset); // -> Discover

        let x = a.assign(t, Some(128));
        let fast = VerdictTiming { latency: Some(Duration::from_millis(180)), retx: 0, injector_hops: None };
        let faster = VerdictTiming { latency: Some(Duration::from_millis(150)), retx: 0, injector_hops: None };
        a.record_timed(t, x.id, FlowOutcome::Success, fast);
        a.record_timed(t, x.id, FlowOutcome::Success, faster); // 2nd success -> promoted

        {
            let m = a.targets.lock();
            let ts = m.get(t).unwrap();
            assert_eq!(ts.phase, NetPhase::Active);
            let q = &ts.scores.get(&ts.active.unwrap()).unwrap().quality;
            assert_eq!(q.retx_free_successes, 2);
            assert_eq!(q.slow_successes, 0);
            assert_eq!(q.min_latency, Some(Duration::from_millis(150)));
            assert!(q.looks_fast());
        }

        // Persist -> reload: the quality counters come back.
        let file = a.export("k");
        let b = Discovery::new(&EvasionConfig::default());
        assert_eq!(b.load_persisted(&file), (1, 0));
        let m = b.targets.lock();
        let ts = m.get(t).unwrap();
        let q = &ts.scores.get(&ts.active.unwrap()).unwrap().quality;
        assert_eq!(q.retx_free_successes, 2);
        assert_eq!(q.min_latency, Some(Duration::from_millis(150)));
    }

    /// A success that only landed after a ClientHello retransmit is recorded as
    /// a *slow* success — the RTO-paying case the latency feature targets.
    #[test]
    fn retransmit_success_is_recorded_as_slow() {
        let a = Discovery::new(&EvasionConfig::default());
        let t = "slow.example";
        a.assign(t, None);
        a.record(t, None, FlowOutcome::DpiReset); // -> Discover
        let x = a.assign(t, None);
        a.record_timed(
            t,
            x.id,
            FlowOutcome::Success,
            VerdictTiming { latency: Some(Duration::from_millis(1300)), retx: 1, injector_hops: None },
        );
        let m = a.targets.lock();
        let q = &m.get(t).unwrap().scores.get(&x.id.unwrap()).unwrap().quality;
        assert_eq!(q.slow_successes, 1);
        assert_eq!(q.retx_free_successes, 0);
        assert!(!q.looks_fast());
    }

    /// End-to-end proof of the TTL-discovery feature: a `DpiReset`'s measured
    /// injector distance is stored on the target and handed back on every
    /// later `assign` — the actual value `engine::act_on_client_hello` would
    /// feed into `TransformCtx::discovered_ttl` for the next trial.
    #[test]
    fn injector_hops_measured_from_a_dpi_reset_feeds_later_assignments() {
        let a = Discovery::new(&EvasionConfig::default());
        let t = "injected.example";

        let probe = a.assign(t, None);
        assert_eq!(probe.discovered_ttl, None, "nothing measured yet");

        a.record_timed(
            t,
            probe.id,
            FlowOutcome::DpiReset,
            VerdictTiming { latency: None, retx: 0, injector_hops: Some(4) },
        );

        let next = a.assign(t, None);
        assert_eq!(next.discovered_ttl, Some(4));

        // Set once: a later, different measurement on the same target must
        // not overwrite the first (mirrors server_initial_ttl's contract).
        a.record_timed(
            t,
            next.id,
            FlowOutcome::DpiReset,
            VerdictTiming { latency: None, retx: 0, injector_hops: Some(9) },
        );
        assert_eq!(a.assign(t, None).discovered_ttl, Some(4), "first measurement wins");
    }

    // --- Phase 2: sibling / house-strategy seeding ---

    #[test]
    fn registered_domain_crude_etld_plus_one() {
        assert_eq!(registered_domain("gateway-us-east1-c.discord.gg"), "discord.gg");
        assert_eq!(registered_domain("cdn.discordapp.com"), "discordapp.com");
        assert_eq!(registered_domain("updates.discord.com"), "discord.com");
        assert_eq!(registered_domain("discord.com"), "discord.com");
        assert_eq!(registered_domain("a.b.c.example.com"), "example.com");
        assert_eq!(registered_domain("bbc.co.uk"), "bbc.co.uk");
        assert_eq!(registered_domain("www.bbc.co.uk"), "bbc.co.uk");
        assert_eq!(registered_domain("localhost"), "localhost");
        assert_eq!(registered_domain("trailing.dot.com."), "dot.com");
    }

    /// REGRESSION (explicitly requested): with nothing `Active` to learn from,
    /// the seed list is empty and the `Discover` sweep is byte-identical to a
    /// plain grid walk.
    #[test]
    fn no_active_siblings_means_empty_seeds_and_identical_sweep() {
        use crate::strategy::DefaultGenerator;
        let g = DefaultGenerator::new(&EvasionConfig::default());
        let disc = Discovery::new(&EvasionConfig::default());

        let t = "lonely.example";
        disc.assign(t, None);
        disc.record(t, None, FlowOutcome::DpiReset); // -> Discover

        for i in 0..6 {
            let a = disc.assign(t, None);
            assert_eq!(a.id, Some(g.all()[i].id()), "candidate {i} follows grid order");
            assert_eq!(a.seed_tier, None, "no seed offered with nothing Active");
            disc.record(t, a.id, FlowOutcome::DpiReset);
        }
    }

    #[test]
    fn active_passthrough_sibling_is_not_a_seed_source() {
        let disc = Discovery::new(&EvasionConfig::default());
        // clean.example -> Active passthrough (active = None) -> carries no strategy.
        disc.assign("clean.example", None);
        disc.record("clean.example", None, FlowOutcome::Success);
        assert_eq!(disc.target_phase("clean.example"), Some(NetPhase::Active));

        let t = "blocked.example";
        disc.assign(t, None);
        disc.record(t, None, FlowOutcome::DpiReset);
        let a = disc.assign(t, None);
        assert_eq!(a.seed_tier, None, "an Active-passthrough sibling has no strategy to seed");
    }

    #[test]
    fn domain_sibling_strategy_is_seeded_before_the_grid() {
        use crate::strategy::DefaultGenerator;
        let g = DefaultGenerator::new(&EvasionConfig::default());
        let (id0, id1) = (g.all()[0].id(), g.all()[1].id());
        let disc = Discovery::new(&EvasionConfig::default());

        // Sibling updates.discord.com: block, fail grid[0], promote grid[1].
        let sib = "updates.discord.com";
        disc.assign(sib, None);
        disc.record(sib, None, FlowOutcome::DpiReset); // -> Discover
        let a0 = disc.assign(sib, None);
        assert_eq!(a0.id, Some(id0));
        disc.record(sib, a0.id, FlowOutcome::DpiReset); // grid[0] fails
        let a1 = disc.assign(sib, None);
        assert_eq!(a1.id, Some(id1));
        disc.record(sib, a1.id, FlowOutcome::Success);
        disc.record(sib, a1.id, FlowOutcome::Success); // grid tier: 2 successes -> promote
        assert_eq!(disc.target_phase(sib), Some(NetPhase::Active));

        // Fresh same-registered-domain target: Phase 2 (b) - the sibling's
        // strategy is offered on the FIRST contact (naked Probe skipped),
        // not grid[0].
        let fresh = "status.discord.com";
        let a = disc.assign(fresh, None);
        assert_eq!(a.id, Some(id1), "domain-sibling strategy seeded ahead of the grid");
        assert_eq!(a.seed_tier, Some(SeedTier::DomainSibling));
        assert_eq!(disc.target_phase(fresh), Some(NetPhase::Discover), "no naked Probe");

        // #4: a domain-sibling seed promotes on its FIRST success.
        let (ev, phase) = disc.record(fresh, Some(id1), FlowOutcome::Success).unwrap();
        assert!(
            matches!(
                ev,
                DiscoveryEvent::Promoted { via_seed: Some(SeedTier::DomainSibling), after: 1, .. }
            ),
            "got {ev:?}"
        );
        assert_eq!(phase, NetPhase::Active);
    }

    #[test]
    fn house_strategy_seeds_when_there_is_no_domain_sibling() {
        use crate::strategy::DefaultGenerator;
        let g = DefaultGenerator::new(&EvasionConfig::default());
        let (id0, id1) = (g.all()[0].id(), g.all()[1].id());
        let disc = Discovery::new(&EvasionConfig::default());

        // a.example: force-promote grid[1].
        disc.assign("a.example", None);
        disc.record("a.example", None, FlowOutcome::DpiReset);
        let x0 = disc.assign("a.example", None);
        assert_eq!(x0.id, Some(id0));
        disc.record("a.example", x0.id, FlowOutcome::DpiReset);
        let x1 = disc.assign("a.example", None);
        assert_eq!(x1.id, Some(id1));
        disc.record("a.example", x1.id, FlowOutcome::Success);
        disc.record("a.example", x1.id, FlowOutcome::Success);
        assert_eq!(disc.target_phase("a.example"), Some(NetPhase::Active));

        // b.example (unrelated domain): now seeded id1 as the house strategy on
        // first contact (Probe skipped); HouseStrategy tier promotes on the
        // first success.
        let xb = disc.assign("b.example", None);
        assert_eq!(xb.id, Some(id1), "seeded from a.example's house strategy");
        assert_eq!(xb.seed_tier, Some(SeedTier::HouseStrategy));
        disc.record("b.example", Some(id1), FlowOutcome::Success);
        assert_eq!(disc.target_phase("b.example"), Some(NetPhase::Active));

        // c.example: no domain sibling, house strategy = id1 (2/2 Active).
        let a = disc.assign("c.example", None);
        assert_eq!(a.id, Some(id1));
        assert_eq!(a.seed_tier, Some(SeedTier::HouseStrategy));
    }

    #[test]
    fn a_failed_seed_costs_one_trial_then_the_grid_resumes() {
        use crate::strategy::DefaultGenerator;
        let g = DefaultGenerator::new(&EvasionConfig::default());
        let (id0, id1) = (g.all()[0].id(), g.all()[1].id());
        let disc = Discovery::new(&EvasionConfig::default());

        // sibling gateway.discord.gg -> promoted to grid[1].
        let sib = "gateway.discord.gg";
        disc.assign(sib, None);
        disc.record(sib, None, FlowOutcome::DpiReset);
        let a0 = disc.assign(sib, None);
        disc.record(sib, a0.id, FlowOutcome::DpiReset);
        let a1 = disc.assign(sib, None);
        disc.record(sib, a1.id, FlowOutcome::Success);
        disc.record(sib, a1.id, FlowOutcome::Success);

        // fresh same-domain target: seed id1 offered on first contact (Probe
        // skipped), then FAILS.
        let t = "media.discord.gg";
        let s = disc.assign(t, None);
        assert_eq!(s.id, Some(id1));
        assert_eq!(s.seed_tier, Some(SeedTier::DomainSibling));
        disc.record(t, Some(id1), FlowOutcome::DpiReset); // seed ruled out

        // next assignment falls through to the grid, not the (now-tried) seed —
        // the wrong-seed cost is exactly one trial.
        let nxt = disc.assign(t, None);
        assert_eq!(nxt.id, Some(id0), "grid sweep resumes at index 0");
        assert_eq!(nxt.seed_tier, None);
    }

    #[test]
    fn stale_strategy_ids_degrade_to_ttl_only() {
        let file = ProfileFile::new(
            0, // deliberately wrong signature
            "k",
            vec![PersistedTarget {
                key: "x.example".into(),
                phase: NetPhase::Discover,
                tried: vec![StrategyId(0xdead)], // id not in any real grid
                scores: vec![],
                active: None,
                consecutive_failure: 2,
                server_initial_ttl: Some(64),
                injector_hops: Some(5),
                grid_size_at_exhaustion: None,
            }],
        );
        let d = Discovery::new(&EvasionConfig::default());
        let (restored, degraded) = d.load_persisted(&file);
        assert_eq!((restored, degraded), (0, 1));
        let s = d.summary();
        let ts = s.iter().find(|x| x.key == "x.example").unwrap();
        assert_eq!(ts.tried, 0, "stale tried list dropped");
        assert_eq!(ts.phase, NetPhase::Probe, "reset to Probe");
        assert!(ts.from_disk);
        // The learned TTLs survive the degrade — both are set unconditionally
        // in load_persisted, before the ids_ok check.
        let m = d.targets.lock();
        let restored_ts = m.get("x.example").unwrap();
        assert_eq!(restored_ts.server_initial_ttl, Some(64));
        assert_eq!(restored_ts.injector_hops, Some(5));
    }

    /// The headline M8 proof: a target that Exhausted a 2-candidate grid,
    /// persisted, and reloaded under a 3-candidate grid must **revive** into
    /// Discover on the next assignment — `tried` preserved, only the new
    /// candidate offered.
    #[test]
    fn revival_after_reload_under_a_grown_grid() {
        let tuning = DiscoveryTuning::default();
        let t = "updates.discord.com";

        // Session 1: exhaust the 2-candidate grid.
        let s1 = Discovery::with_generator(tiny_gen(&[2, 3]), tuning.clone());
        s1.assign(t, None);
        s1.record(t, None, FlowOutcome::DpiReset); // -> Discover
        loop {
            let a = s1.assign(t, None);
            match a.id {
                Some(id) => {
                    s1.record(t, Some(id), FlowOutcome::DpiReset);
                }
                None => break,
            }
        }
        let file = s1.export("k");
        {
            let m = s1.targets.lock();
            let ts = m.get(t).unwrap();
            assert_eq!(ts.phase, NetPhase::Exhausted);
            assert_eq!(ts.grid_size_at_exhaustion, Some(2));
        }

        // Session 2: reload under a 3-candidate grid (ids of 2 & 3 unchanged).
        let s2 = Discovery::with_generator(tiny_gen(&[2, 3, 4]), tuning);
        let (restored, degraded) = s2.load_persisted(&file);
        assert_eq!((restored, degraded), (1, 0), "ids still valid -> full restore");

        // First assignment revives it.
        let a = s2.assign(t, None);
        {
            let m = s2.targets.lock();
            let ts = m.get(t).unwrap();
            assert_eq!(ts.phase, NetPhase::Discover, "revived");
            assert_eq!(ts.tried.len(), 2, "old sweep NOT re-run");
        }
        let fresh = a.id.expect("a new candidate handed out");
        assert!(
            !file.targets[0].tried.contains(&fresh),
            "only the not-yet-tried candidate is offered"
        );
    }

    #[test]
    fn evict_drops_stale_passthrough_but_keeps_exhausted_then_ages_it_out() {
        let disc = Discovery::new(&EvasionConfig::default());

        // A clean target -> Active passthrough (low value).
        disc.assign("clean.example", None);
        disc.record("clean.example", None, FlowOutcome::Success);

        // A blocked target -> exhaust the grid (high value: keep longer).
        let t = "blocked.example";
        disc.assign(t, None);
        disc.record(t, None, FlowOutcome::DpiReset);
        loop {
            let a = disc.assign(t, None);
            match a.id {
                Some(id) => {
                    disc.record(t, Some(id), FlowOutcome::DpiReset);
                }
                None => break,
            }
        }
        assert_eq!(disc.target_count(), 2);

        let now = Instant::now();
        // 1 h on: nothing stale.
        assert_eq!(disc.evict(now + Duration::from_secs(3600)), 0);
        assert_eq!(disc.target_count(), 2);

        // 25 h on: the passthrough target is gone, the exhausted one stays.
        assert_eq!(disc.evict(now + Duration::from_secs(25 * 3600)), 1);
        let s = disc.summary();
        assert_eq!(s.len(), 1);
        assert_eq!(s[0].key, t);
        assert_eq!(s[0].phase, NetPhase::Exhausted);

        // 8 days on: even the exhausted target ages out (target_max_idle = 7 d).
        assert_eq!(disc.evict(now + Duration::from_secs(8 * 24 * 3600)), 1);
        assert_eq!(disc.target_count(), 0);
    }

    #[test]
    fn evict_enforces_the_hard_cap_worst_first() {
        let cfg = EvasionConfig {
            discovery: crate::config::DiscoveryTuning { max_targets: 3, ..Default::default() },
            ..Default::default()
        };
        let disc = Discovery::new(&cfg);
        for i in 0..5 {
            let k = format!("t{i}.example");
            disc.assign(&k, None);
            disc.record(&k, None, FlowOutcome::Success); // all fresh passthrough
        }
        assert_eq!(disc.target_count(), 5);

        // No idle eviction (all fresh); the hard cap forces the 2 worst out.
        let dropped = disc.evict(Instant::now());
        assert_eq!(dropped, 2);
        assert_eq!(disc.target_count(), 3);
    }

    #[test]
    fn summary_reports_in_flight_and_last_trial_age() {
        let disc = Discovery::new(&EvasionConfig::default());
        let t = "blocked.example";
        disc.assign(t, None);
        disc.record(t, None, FlowOutcome::DpiReset); // -> Discover

        // Two concurrent explores, no verdicts yet.
        let a = disc.assign(t, None);
        let b = disc.assign(t, None);
        assert!(a.id.is_some() && b.id.is_some());
        assert_ne!(a.id, b.id, "concurrent explores of one target differ");

        let s = disc.summary();
        let ts = s.iter().find(|x| x.key == t).unwrap();
        assert_eq!(ts.in_flight, 2);
        assert!(ts.last_trial_age.is_some());

        // working_targets() surfaces it (still in Discover).
        assert!(disc.working_targets().iter().any(|x| x.key == t));
    }

    #[test]
    fn end_to_end_blocked_then_exhausted_is_visible_in_summary() {
        let disc = Discovery::new(&EvasionConfig::default());
        let t = "updates.discord.com";

        // Probe -> fail -> Blocked.
        let a = disc.assign(t, None);
        assert!(a.strategy.is_none());
        let (ev, phase) = disc.record(t, None, FlowOutcome::DpiReset).unwrap();
        assert_eq!(ev, DiscoveryEvent::Blocked);
        assert_eq!(phase, NetPhase::Discover);

        // Fail every candidate.
        let grid = disc.grid_len();
        for _ in 0..grid {
            let a = disc.assign(t, None);
            match a.id {
                Some(id) => {
                    let _ = disc.record(t, Some(id), FlowOutcome::DpiReset);
                }
                None => break, // exhausted
            }
        }

        let s = disc.summary();
        let ts = s.iter().find(|s| s.key == t).unwrap();
        assert_eq!(ts.phase, NetPhase::Exhausted);
        assert_eq!(ts.tried, grid);
        assert!(ts.active.is_none());
        assert!(ts.best.is_none(), "no strategy ever succeeded");
    }

    /// M7a safety fix: with the default config (overlap OFF) no target — not
    /// even a permissive unix (TTL 64) server — is ever assigned an
    /// overlap-family strategy. This is the "no site breaks" smoke at the
    /// discovery layer.
    #[test]
    fn default_config_never_assigns_an_overlap_strategy() {
        use crate::strategy::generator::is_overlap_family;
        let disc = Discovery::new(&EvasionConfig::default());
        let t = "unix.example";

        disc.assign(t, Some(64)); // permissive server, no gating would apply
        disc.record(t, None, FlowOutcome::DpiReset); // -> Discover

        let mut saw_any = false;
        loop {
            let a = disc.assign(t, Some(64));
            match a.strategy {
                Some(strat) => {
                    saw_any = true;
                    assert!(
                        !is_overlap_family(&strat),
                        "default config must never hand out an overlap strategy"
                    );
                    let _ = disc.record(t, a.id, FlowOutcome::DpiReset);
                }
                None => break,
            }
        }
        assert!(saw_any, "the grid was actually swept");
        assert_eq!(
            disc.grid_len(),
            166,
            "default grid: 142 single-split + 12 multi-part + 6 tls_pad + 6 aggressive, no overlap"
        );
    }

    #[test]
    fn windows_server_never_gets_an_overlap_candidate() {
        use crate::strategy::generator::is_overlap_family;
        // Overlap opted in — otherwise there is nothing to gate.
        let cfg = EvasionConfig { enable_overlap_disorder: true, ..Default::default() };
        let disc = Discovery::new(&cfg);
        let t = "win.example";

        // server_initial_ttl = 128 (Windows) -> Probe fails -> Discover.
        disc.assign(t, Some(128));
        disc.record(t, None, FlowOutcome::DpiReset);

        // Sweep the whole grid; collect every assigned strategy.
        let mut saw_overlap = false;
        let mut saw_any = false;
        loop {
            let a = disc.assign(t, Some(128));
            match a.strategy {
                Some(strat) => {
                    saw_any = true;
                    if is_overlap_family(&strat) {
                        saw_overlap = true;
                    }
                    let _ = disc.record(t, a.id, FlowOutcome::DpiReset);
                }
                None => break,
            }
        }
        assert!(saw_any, "at least the non-overlap grid was swept");
        assert!(!saw_overlap, "Windows server must never be assigned an overlap-family strategy");

        // The same target on a unix server (TTL 64) *would* see overlap candidates.
        let disc2 = Discovery::new(&cfg);
        disc2.assign("unix.example", Some(64));
        disc2.record("unix.example", None, FlowOutcome::DpiReset);
        let mut saw_overlap_unix = false;
        loop {
            let a = disc2.assign("unix.example", Some(64));
            match a.strategy {
                Some(strat) => {
                    if is_overlap_family(&strat) {
                        saw_overlap_unix = true;
                    }
                    let _ = disc2.record("unix.example", a.id, FlowOutcome::DpiReset);
                }
                None => break,
            }
        }
        assert!(saw_overlap_unix, "unix server sweeps overlap candidates too");
    }

    // ---- C: ISP seed pool ------------------------------------------------- #

    #[test]
    fn isp_pool_seeds_come_after_the_probe_and_at_the_default_threshold() {
        use crate::strategy::DefaultGenerator;
        let g = DefaultGenerator::new(&EvasionConfig::default());
        let id5 = g.all()[5].id();
        let disc = Discovery::new(&EvasionConfig::default());

        // grid[5] proven on two networks of "acme".
        let mut pool = crate::profile::IspPool::new("acme");
        let mut sc = ScoredStrategy::new(g.all()[5].clone());
        sc.trials = 4;
        sc.successes = 3;
        pool.merge_session("n1", &[(id5, sc.clone())], 1);
        pool.merge_session("n2", &[(id5, sc.clone())], 2);
        disc.set_isp_pool(std::sync::Arc::new(pool));

        // Fresh target, nothing Active on this network: the ISP-pool candidate is
        // the only seed, and it must NOT skip the naked Probe.
        let a = disc.assign("fresh.example", None);
        assert!(a.id.is_none() && a.event.is_none(), "naked Probe still runs");
        assert_eq!(disc.target_phase("fresh.example"), Some(NetPhase::Probe));

        // Probe fails -> Discover -> ISP-pool strategy offered ahead of grid[0].
        disc.record("fresh.example", None, FlowOutcome::DpiReset);
        let b = disc.assign("fresh.example", None);
        assert_eq!(b.id, Some(id5));
        assert_eq!(b.seed_tier, Some(SeedTier::IspPool));

        // One success is not enough — IspPool keeps the default threshold (2),
        // unlike DomainSibling / HouseStrategy.
        let (ev, _) = disc.record("fresh.example", Some(id5), FlowOutcome::Success).unwrap();
        assert!(matches!(ev, DiscoveryEvent::Noted), "got {ev:?}");
        assert_eq!(disc.target_phase("fresh.example"), Some(NetPhase::Discover));
    }

    #[test]
    fn an_empty_isp_pool_changes_nothing() {
        let a = Discovery::new(&EvasionConfig::default());
        a.set_isp_pool(std::sync::Arc::new(crate::profile::IspPool::new("acme")));
        let b = Discovery::new(&EvasionConfig::default());

        for d in [&a, &b] {
            let first = d.assign("t.example", None);
            assert!(first.id.is_none() && first.event.is_none());
            d.record("t.example", None, FlowOutcome::DpiReset);
        }
        let (pa, pb) = (a.assign("t.example", None), b.assign("t.example", None));
        assert_eq!(pa.id, pb.id, "first Discover candidate identical");
        assert_eq!(pa.seed_tier, None);
        assert_eq!(pb.seed_tier, None);
    }

    #[test]
    fn promoted_for_isp_returns_active_with_strategy_targets_only() {
        use crate::strategy::DefaultGenerator;
        let g = DefaultGenerator::new(&EvasionConfig::default());
        let (id0, id1) = (g.all()[0].id(), g.all()[1].id());
        let disc = Discovery::new(&EvasionConfig::default());

        // t1: block, fail grid[0], promote grid[1].
        disc.assign("t1", None);
        disc.record("t1", None, FlowOutcome::DpiReset);
        let a0 = disc.assign("t1", None);
        assert_eq!(a0.id, Some(id0));
        disc.record("t1", a0.id, FlowOutcome::DpiReset);
        let a1 = disc.assign("t1", None);
        disc.record("t1", a1.id, FlowOutcome::Success);
        disc.record("t1", a1.id, FlowOutcome::Success);
        // t2: not blocked -> Active passthrough (no strategy).
        disc.assign("t2", None);
        disc.record("t2", None, FlowOutcome::Success);

        let promoted = disc.promoted_for_isp();
        assert_eq!(promoted.len(), 1, "only the Active-with-strategy target");
        assert_eq!(promoted[0].0, id1);
        assert!(promoted[0].1.successes >= 2);
    }
}
