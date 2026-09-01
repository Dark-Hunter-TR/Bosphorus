//! Automatic multi-strategy discovery: for each target, probe whether it is
//! blocked, then sweep the candidate grid until one strategy works, then lock
//! it in. In-memory only in M6 (M8 persists per network fingerprint).

mod scheduler;
mod verdict;

pub use scheduler::{Assignment, DiscoveryEvent, Scheduler};
pub use verdict::{is_failure, is_success, score_delta};

use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

use parking_lot::Mutex;

use crate::config::EvasionConfig;
use crate::conntrack::FlowOutcome;
use crate::profile::persist::{PersistedScore, PersistedTarget, ProfileFile};
use crate::profile::{NetPhase, ScoredStrategy, TargetState};
use crate::strategy::{DefaultGenerator, StrategyId};

pub struct Discovery {
    generator: DefaultGenerator,
    scheduler: Scheduler,
    targets: Mutex<HashMap<String, TargetState>>,
}

impl Discovery {
    pub fn new(cfg: &EvasionConfig) -> Self {
        Self {
            generator: DefaultGenerator::new(cfg),
            scheduler: Scheduler { tuning: cfg.discovery.clone() },
            targets: Mutex::new(HashMap::new()),
        }
    }

    #[cfg(test)]
    pub(crate) fn with_generator(
        generator: DefaultGenerator,
        tuning: crate::config::DiscoveryTuning,
    ) -> Self {
        Self { generator, scheduler: Scheduler { tuning }, targets: Mutex::new(HashMap::new()) }
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

            if ids_ok {
                ts.phase = pt.phase;
                ts.tried = pt.tried.clone();
                ts.active = pt.active;
                ts.consecutive_success = pt.consecutive_success;
                ts.consecutive_failure = pt.consecutive_failure;
                ts.grid_size_at_exhaustion = pt.grid_size_at_exhaustion;
                for sc in &pt.scores {
                    ts.scores.insert(
                        sc.strategy.id(),
                        ScoredStrategy {
                            strategy: sc.strategy.clone(),
                            trials: sc.trials,
                            successes: sc.successes,
                            last_success: None,
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
    pub fn export(&self, net_key: &str) -> ProfileFile {
        let sig = self.grid_signature();
        let targets = self
            .targets
            .lock()
            .values()
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
                    })
                    .collect(),
                active: ts.active,
                consecutive_success: ts.consecutive_success,
                consecutive_failure: ts.consecutive_failure,
                server_initial_ttl: ts.server_initial_ttl,
                grid_size_at_exhaustion: ts.grid_size_at_exhaustion,
            })
            .collect();
        ProfileFile::new(sig, net_key, targets)
    }

    /// Pick the next trial for `target` (creating its state on first contact).
    /// `server_initial_ttl` (from the SYN-ACK, 64/128/255) gates overlap-family
    /// candidates; recorded once per target.
    pub fn assign(&self, target: &str, server_initial_ttl: Option<u8>) -> Assignment {
        let now = Instant::now();
        let mut map = self.targets.lock();
        let ts = map
            .entry(target.to_owned())
            .or_insert_with(|| TargetState::new(target.to_owned(), now));
        if ts.server_initial_ttl.is_none() {
            ts.server_initial_ttl = server_initial_ttl;
        }
        let a = self.scheduler.assign(ts, &self.generator, now);
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
            _ => {}
        }
        a
    }

    /// Feed back a flow's verdict. Returns the event + the target's new phase.
    pub fn record(
        &self,
        target: &str,
        id: Option<StrategyId>,
        outcome: FlowOutcome,
    ) -> Option<(DiscoveryEvent, NetPhase)> {
        let now = Instant::now();
        let mut map = self.targets.lock();
        let ts = map.get_mut(target)?;
        let ev = self.scheduler.record(ts, &self.generator, id, outcome, now);
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
                consecutive_success: 0,
                consecutive_failure: 2,
                server_initial_ttl: Some(64),
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
        // Only the learned TTL survives (checked indirectly: no panic, target kept).
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
}
