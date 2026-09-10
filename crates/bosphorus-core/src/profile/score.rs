use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::strategy::Strategy;

use super::VerdictTiming;

/// Latency / retransmit quality of one strategy. Shared shape: a per-target
/// [`ScoredStrategy`] holds one, and (later) the per-ISP seed pool aggregates
/// the same fields so "fast" and "merely works" are distinguishable everywhere.
///
/// The primary "fast" signal is [`retx_free_successes`](Self::retx_free_successes)
/// vs [`slow_successes`](Self::slow_successes): a handshake that completed with
/// zero ClientHello retransmits paid no RTO penalty, and that is
/// round-trip-time-independent (unlike a raw latency threshold). `latency_ewma`
/// / `min_latency` are kept for later calibration and tie-breaking.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct StrategyQuality {
    /// Fastest ClientHello -> verdict time ever seen for a success.
    pub min_latency: Option<Duration>,
    /// Exponentially-weighted moving average (a = 1/4) of success latency.
    pub latency_ewma: Option<Duration>,
    /// Successes with zero observed ClientHello retransmits.
    pub retx_free_successes: u32,
    /// Successes that only completed after >= 1 ClientHello retransmit (an RTO).
    pub slow_successes: u32,
}

impl StrategyQuality {
    /// Fold one successful verdict's timing in. No-op fields when `latency` is
    /// unknown; the retx-free / slow counter still moves.
    pub fn record_success(&mut self, latency: Option<Duration>, retx: u8) {
        if retx == 0 {
            self.retx_free_successes = self.retx_free_successes.saturating_add(1);
        } else {
            self.slow_successes = self.slow_successes.saturating_add(1);
        }
        if let Some(l) = latency {
            self.min_latency = Some(self.min_latency.map_or(l, |m| m.min(l)));
            self.latency_ewma = Some(match self.latency_ewma {
                None => l,
                Some(prev) => {
                    let blended = (prev.as_nanos() * 3 + l.as_nanos()) / 4;
                    Duration::from_nanos(blended.min(u64::MAX as u128) as u64)
                }
            });
        }
    }

    /// Solid evidence this strategy completes the handshake without an RTO.
    /// Not yet wired into promotion — that behaviour change waits on the
    /// real-world latency measurement.
    pub fn looks_fast(&self) -> bool {
        self.retx_free_successes >= 2 && self.slow_successes == 0
    }

    /// Fold `other`'s samples in — used to aggregate one strategy's quality
    /// across the networks that feed the ISP seed pool. Counters sum; latency
    /// fields take the better (lower) of the two. EWMA is not associative across
    /// merges, so `latency_ewma` is only kept for rough tie-breaking here.
    pub fn merge(&mut self, other: &Self) {
        self.retx_free_successes = self.retx_free_successes.saturating_add(other.retx_free_successes);
        self.slow_successes = self.slow_successes.saturating_add(other.slow_successes);
        self.min_latency = match (self.min_latency, other.min_latency) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        };
        self.latency_ewma = match (self.latency_ewma, other.latency_ewma) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        };
    }
}

/// Trial/success bookkeeping for one strategy against one target.
#[derive(Debug, Clone)]
pub struct ScoredStrategy {
    pub strategy: Strategy,
    pub trials: u32,
    pub successes: u32,
    /// Successes in a row for *this* candidate, reset by its own failure. The
    /// promotion gate reads this — it is deliberately per-candidate: under the
    /// parallel sweep two different candidates each succeeding once must not add
    /// up to a promotion (a target-level tally did exactly that). Not persisted:
    /// "in a row" is a within-session notion, so a reloaded sweep restarts it.
    pub consecutive_success: u8,
    pub last_success: Option<Instant>,
    /// Latency / retransmit quality (populated from verdict timing).
    pub quality: StrategyQuality,
}

impl ScoredStrategy {
    pub fn new(strategy: Strategy) -> Self {
        Self {
            strategy,
            trials: 0,
            successes: 0,
            consecutive_success: 0,
            last_success: None,
            quality: StrategyQuality::default(),
        }
    }
    pub fn note(&mut self, ok: bool, now: Instant, timing: VerdictTiming) {
        self.trials += 1;
        if ok {
            self.successes += 1;
            self.consecutive_success = self.consecutive_success.saturating_add(1);
            self.last_success = Some(now);
            self.quality.record_success(timing.latency, timing.retx);
        } else {
            self.consecutive_success = 0;
        }
    }
    pub fn failures(&self) -> u32 {
        self.trials - self.successes
    }
    pub fn ratio(&self) -> f32 {
        if self.trials == 0 {
            0.0
        } else {
            self.successes as f32 / self.trials as f32
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retx_free_vs_slow_successes_are_counted_separately() {
        let mut q = StrategyQuality::default();
        q.record_success(Some(Duration::from_millis(120)), 0);
        q.record_success(Some(Duration::from_millis(140)), 0);
        q.record_success(Some(Duration::from_millis(1300)), 1); // paid an RTO
        assert_eq!(q.retx_free_successes, 2);
        assert_eq!(q.slow_successes, 1);
        assert_eq!(q.min_latency, Some(Duration::from_millis(120)));
        // EWMA moved toward the samples, dominated by the first.
        let ewma = q.latency_ewma.unwrap();
        assert!(ewma > Duration::from_millis(120) && ewma < Duration::from_millis(500), "{ewma:?}");
    }

    #[test]
    fn looks_fast_needs_two_clean_successes_and_no_slow_ones() {
        let mut q = StrategyQuality::default();
        assert!(!q.looks_fast());
        q.record_success(None, 0);
        assert!(!q.looks_fast(), "one is not enough");
        q.record_success(None, 0);
        assert!(q.looks_fast());
        q.record_success(None, 2); // an RTO success taints it
        assert!(!q.looks_fast());
    }

    #[test]
    fn note_only_touches_quality_on_success() {
        let mut s = ScoredStrategy::new(Strategy::m4_fixed());
        let t = Instant::now();
        s.note(
            false,
            t,
            VerdictTiming { latency: Some(Duration::from_millis(50)), retx: 0, injector_hops: None },
        );
        assert_eq!(s.trials, 1);
        assert_eq!(s.successes, 0);
        assert_eq!(s.quality, StrategyQuality::default(), "failed trial leaves quality untouched");

        s.note(
            true,
            t,
            VerdictTiming { latency: Some(Duration::from_millis(80)), retx: 0, injector_hops: None },
        );
        assert_eq!(s.successes, 1);
        assert_eq!(s.quality.retx_free_successes, 1);
        assert_eq!(s.quality.min_latency, Some(Duration::from_millis(80)));
    }

    #[test]
    fn consecutive_success_counts_this_candidates_streak_and_a_failure_resets_it() {
        let mut s = ScoredStrategy::new(Strategy::m4_fixed());
        let t = Instant::now();
        assert_eq!(s.consecutive_success, 0);
        s.note(true, t, VerdictTiming::NONE);
        s.note(true, t, VerdictTiming::NONE);
        assert_eq!(s.consecutive_success, 2);
        s.note(false, t, VerdictTiming::NONE);
        assert_eq!(s.consecutive_success, 0, "own failure clears the streak");
        s.note(true, t, VerdictTiming::NONE);
        assert_eq!(s.consecutive_success, 1);
        // Total successes keep accumulating independently of the streak.
        assert_eq!(s.successes, 3);
    }
}
