use std::time::Instant;

use crate::strategy::Strategy;

/// Trial/success bookkeeping for one strategy against one target.
#[derive(Debug, Clone)]
pub struct ScoredStrategy {
    pub strategy: Strategy,
    pub trials: u32,
    pub successes: u32,
    pub last_success: Option<Instant>,
}

impl ScoredStrategy {
    pub fn new(strategy: Strategy) -> Self {
        Self { strategy, trials: 0, successes: 0, last_success: None }
    }
    pub fn note(&mut self, ok: bool, now: Instant) {
        self.trials += 1;
        if ok {
            self.successes += 1;
            self.last_success = Some(now);
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
