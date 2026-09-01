use crate::strategy::model::TtlPolicy;

/// Resolve a fake-packet TTL from the policy and (for `AutoHeuristic`) the
/// hop count learned from the SYN-ACK.
///
/// M4: only `UserFixed` and `AutoHeuristic`. `TtlPolicy::Discovered` (reading a
/// value the M7 TTL search found) is not a variant yet.
pub fn resolve_ttl(policy: &TtlPolicy, hops_to_server: Option<u8>) -> Option<u8> {
    match *policy {
        TtlPolicy::UserFixed(v) => Some(v),
        TtlPolicy::AutoHeuristic { delta, min, max } => {
            let hops = hops_to_server?;
            Some(hops.saturating_sub(delta).clamp(min, max))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_fixed_ignores_hops() {
        assert_eq!(resolve_ttl(&TtlPolicy::UserFixed(5), None), Some(5));
        assert_eq!(resolve_ttl(&TtlPolicy::UserFixed(9), Some(20)), Some(9));
    }

    #[test]
    fn auto_heuristic_needs_hops_and_clamps() {
        let p = TtlPolicy::AutoHeuristic { delta: 4, min: 3, max: 10 };
        assert_eq!(resolve_ttl(&p, None), None);
        assert_eq!(resolve_ttl(&p, Some(11)), Some(7)); // 11 - 4
        assert_eq!(resolve_ttl(&p, Some(5)), Some(3)); // 1 -> clamp up to min
        assert_eq!(resolve_ttl(&p, Some(30)), Some(10)); // 26 -> clamp down to max
        assert_eq!(resolve_ttl(&p, Some(2)), Some(3)); // saturating_sub -> 0 -> min
    }
}
