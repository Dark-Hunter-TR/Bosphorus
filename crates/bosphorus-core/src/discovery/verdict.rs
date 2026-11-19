use crate::conntrack::FlowOutcome;

/// Re-export: verdict scoring input lives in `profile` (where `ScoredStrategy`
/// consumes it) but reads naturally as `discovery::VerdictTiming`.
pub use crate::profile::VerdictTiming;

pub fn is_success(o: FlowOutcome) -> bool {
    matches!(o, FlowOutcome::Success)
}

pub fn is_failure(o: FlowOutcome) -> bool {
    matches!(
        o,
        FlowOutcome::DpiReset
            | FlowOutcome::LateReset
            | FlowOutcome::Blackhole
            | FlowOutcome::TlsError
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mapping() {
        assert!(is_success(FlowOutcome::Success));
        for o in [
            FlowOutcome::DpiReset,
            FlowOutcome::LateReset,
            FlowOutcome::Blackhole,
            FlowOutcome::TlsError,
        ] {
            assert!(is_failure(o));
        }
        assert!(!is_success(FlowOutcome::Inconclusive));
        assert!(!is_failure(FlowOutcome::Inconclusive));
    }
}
