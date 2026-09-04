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

/// +1 success, -1 failure, 0 for `Inconclusive`.
pub fn score_delta(o: FlowOutcome) -> i32 {
    match o {
        FlowOutcome::Success => 1,
        FlowOutcome::Inconclusive => 0,
        _ => -1,
    }
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
            assert_eq!(score_delta(o), -1);
        }
        assert!(!is_success(FlowOutcome::Inconclusive));
        assert!(!is_failure(FlowOutcome::Inconclusive));
        assert_eq!(score_delta(FlowOutcome::Success), 1);
        assert_eq!(score_delta(FlowOutcome::Inconclusive), 0);
    }
}
