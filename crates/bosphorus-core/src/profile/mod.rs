//! Per-target discovery state. M6: in-memory only. M8 adds serde + a disk store
//! keyed by network fingerprint.

mod score;
pub mod persist;

pub use score::ScoredStrategy;

use std::collections::HashMap;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::strategy::StrategyId;

/// Where a target is in the discovery lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NetPhase {
    /// First contact: try passthrough to learn whether the target is blocked.
    Probe,
    /// Blocked; sweeping the candidate grid.
    Discover,
    /// A working strategy (or "passthrough is fine") is locked in.
    Active,
    /// Every grid candidate was tried and none worked.
    Exhausted,
}

/// Which role a trial played.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrialKind {
    /// Passthrough control (Probe / Active-with-no-strategy).
    Control,
    /// A grid candidate being evaluated.
    Explore,
    /// The promoted active strategy.
    Exploit,
}

/// Recorded on a flow so the verdict can be attributed back to the trial.
#[derive(Debug, Clone, Copy)]
pub struct TrialRecord {
    /// `None` = passthrough control.
    pub id: Option<StrategyId>,
    pub kind: TrialKind,
}

/// An `Explore` trial handed out for a target but whose verdict has not come
/// back yet. Tracked so two concurrent connections to the same blocked target
/// sweep *different* candidates instead of both re-trying the same one. Expired
/// after [`crate::config::DiscoveryTuning::in_flight_ttl`] so a flow that is
/// lost or idle-swept before a verdict cannot permanently shrink the sweep.
#[derive(Debug, Clone, Copy)]
pub struct InFlight {
    pub id: StrategyId,
    pub since: Instant,
}

#[derive(Debug)]
pub struct TargetState {
    pub key: String,
    pub phase: NetPhase,
    /// Grid candidates already ruled out for this target.
    pub tried: Vec<StrategyId>,
    pub scores: HashMap<StrategyId, ScoredStrategy>,
    /// In `Active`: the promoted strategy, or `None` = "no strategy needed".
    pub active: Option<StrategyId>,
    pub consecutive_success: u8,
    pub consecutive_failure: u8,
    /// Guessed server initial TTL (64 unix / 128 Windows / 255). Set once from
    /// the first SYN-ACK observed for this target; used to gate overlap-family
    /// candidates (a first-received-wins server would keep the junk overlap).
    pub server_initial_ttl: Option<u8>,
    pub created_at: Instant,
    pub updated_at: Instant,

    // --- M7d: parallel sweep + grid-growth revival ---
    /// `Explore` trials assigned but not yet resolved. Deduplicates concurrent
    /// sweeps of the same target. Populated only in [`NetPhase::Discover`].
    pub in_flight: Vec<InFlight>,
    /// Instant of the last assignment of any kind (for the progress digest).
    pub last_assigned_at: Option<Instant>,
    /// `grid.len()` captured when this target entered [`NetPhase::Exhausted`]
    /// (`None` whenever the target is not exhausted). If the live grid exceeds
    /// this, the next `assign` revives the target into `Discover` with `tried`
    /// preserved. Persisted (M8): a profile saved under a 142-grid and reloaded
    /// under a 154-grid revives on the first assignment.
    pub grid_size_at_exhaustion: Option<usize>,
    /// True if this target was restored from a persisted profile this session
    /// (for the summary table's `disk` / `new` mark). Not persisted.
    pub from_disk: bool,
}

impl TargetState {
    pub fn new(key: String, now: Instant) -> Self {
        Self {
            key,
            phase: NetPhase::Probe,
            tried: Vec::new(),
            scores: HashMap::new(),
            active: None,
            consecutive_success: 0,
            consecutive_failure: 0,
            server_initial_ttl: None,
            created_at: now,
            updated_at: now,
            in_flight: Vec::new(),
            last_assigned_at: None,
            grid_size_at_exhaustion: None,
            from_disk: false,
        }
    }

    /// Candidate ids to exclude from selection: already ruled out (`tried`) plus
    /// currently handed out and unresolved (`in_flight`).
    pub fn skip_ids(&self) -> Vec<StrategyId> {
        let mut v = self.tried.clone();
        v.extend(self.in_flight.iter().map(|f| f.id));
        v
    }

    /// Drop `in_flight` entries older than `ttl`.
    pub fn expire_in_flight(&mut self, now: Instant, ttl: Duration) {
        self.in_flight
            .retain(|f| now.saturating_duration_since(f.since) < ttl);
    }

    /// Note that `id` (if any) was just handed out at `now`. Adds an `in_flight`
    /// entry only for an `Explore` trial (i.e. while in `Discover`) that is not
    /// already tracked.
    pub fn mark_assigned(&mut self, id: Option<StrategyId>, now: Instant) {
        self.last_assigned_at = Some(now);
        if self.phase != NetPhase::Discover {
            return;
        }
        if let Some(id) = id {
            if !self.in_flight.iter().any(|f| f.id == id) {
                self.in_flight.push(InFlight { id, since: now });
            }
        }
    }

    /// Remove `id` from `in_flight` (its verdict arrived).
    pub fn clear_in_flight(&mut self, id: StrategyId) {
        self.in_flight.retain(|f| f.id != id);
    }

    /// Release memory a terminal-phase target no longer needs. A full sweep to
    /// `Exhausted` otherwise pins ~`grid_len` [`ScoredStrategy`] entries (each
    /// an inlined [`crate::strategy::Strategy`]) plus a `tried` list that grew
    /// its capacity geometrically. After this the target keeps only the
    /// promoted `active` score (none, for `Exhausted`); revival / re-sweep
    /// re-populates on demand.
    ///
    /// Call on `Promoted` and `Exhausted` transitions. `tried` is preserved
    /// (its ids still drive revival under a grown grid); only its spare
    /// capacity is trimmed.
    pub fn compact(&mut self) {
        let keep = self.active;
        self.scores.retain(|id, _| Some(*id) == keep);
        self.scores.shrink_to_fit();
        self.tried.shrink_to_fit();
        self.in_flight.shrink_to_fit();
    }

    /// Highest success-ratio strategy that has at least one success.
    pub fn best(&self) -> Option<&ScoredStrategy> {
        self.scores
            .values()
            .filter(|s| s.successes > 0)
            .max_by(|a, b| {
                a.ratio()
                    .partial_cmp(&b.ratio())
                    .unwrap_or(std::cmp::Ordering::Equal)
                    .then(a.successes.cmp(&b.successes))
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(n: u64) -> StrategyId {
        StrategyId(n)
    }

    #[test]
    fn skip_ids_is_tried_union_in_flight() {
        let now = Instant::now();
        let mut ts = TargetState::new("t".into(), now);
        ts.phase = NetPhase::Discover;
        ts.tried = vec![id(1), id(2)];
        ts.mark_assigned(Some(id(9)), now);

        let mut got = ts.skip_ids();
        got.sort_by_key(|x| x.0);
        assert_eq!(got, vec![id(1), id(2), id(9)]);
    }

    #[test]
    fn mark_assigned_only_tracks_discover_explores() {
        let now = Instant::now();
        let mut ts = TargetState::new("t".into(), now);

        // Probe phase: no in_flight, but last_assigned_at is set.
        ts.mark_assigned(None, now);
        assert!(ts.in_flight.is_empty());
        assert_eq!(ts.last_assigned_at, Some(now));

        // Discover phase: an id is tracked once.
        ts.phase = NetPhase::Discover;
        ts.mark_assigned(Some(id(5)), now);
        ts.mark_assigned(Some(id(5)), now);
        assert_eq!(ts.in_flight.len(), 1);

        // Active phase: not tracked (Exploit re-uses one id repeatedly).
        ts.phase = NetPhase::Active;
        ts.mark_assigned(Some(id(7)), now);
        assert_eq!(ts.in_flight.len(), 1);
    }

    #[test]
    fn expire_in_flight_drops_stale_entries() {
        let t0 = Instant::now();
        let mut ts = TargetState::new("t".into(), t0);
        ts.phase = NetPhase::Discover;
        ts.mark_assigned(Some(id(1)), t0);
        let later = t0 + Duration::from_secs(20);
        ts.mark_assigned(Some(id(2)), later);

        ts.expire_in_flight(later, Duration::from_secs(15));
        let live: Vec<_> = ts.in_flight.iter().map(|f| f.id).collect();
        assert_eq!(live, vec![id(2)], "the 20s-old entry is gone, the fresh one stays");
    }

    #[test]
    fn clear_in_flight_removes_one() {
        let now = Instant::now();
        let mut ts = TargetState::new("t".into(), now);
        ts.phase = NetPhase::Discover;
        ts.mark_assigned(Some(id(1)), now);
        ts.mark_assigned(Some(id(2)), now);
        ts.clear_in_flight(id(1));
        assert_eq!(ts.in_flight.iter().map(|f| f.id).collect::<Vec<_>>(), vec![id(2)]);
    }
}
