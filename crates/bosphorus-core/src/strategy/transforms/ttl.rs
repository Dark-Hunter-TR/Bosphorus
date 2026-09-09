use crate::strategy::model::TtlPolicy;

/// Resolve a fake-packet TTL from the policy and (for `AutoHeuristic`) the
/// hop count learned from the SYN-ACK.
pub fn resolve_ttl(policy: &TtlPolicy, hops_to_server: Option<u8>) -> Option<u8> {
    match *policy {
        TtlPolicy::UserFixed(v) => Some(v),
        // Floor at 1: a fake packet needs at least one hop of travel to reach
        // an injector sitting right at the client's own gateway (0 hops
        // measured); TTL 0 would die before leaving the host, wasting the trial.
        TtlPolicy::Discovered(v) => Some(v.max(1)),
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

    #[test]
    fn discovered_ignores_hops_and_skips_the_heuristic_clamp() {
        // Unlike AutoHeuristic, a measured value is used exactly as given —
        // no delta subtraction, no min/max clamp, no dependence on hops.
        assert_eq!(resolve_ttl(&TtlPolicy::Discovered(2), None), Some(2));
        assert_eq!(resolve_ttl(&TtlPolicy::Discovered(2), Some(30)), Some(2));
    }

    #[test]
    fn discovered_floors_at_one() {
        // An injector measured as "0 hops away" (right at the client's own
        // gateway) must still get a fake packet that can leave the host.
        assert_eq!(resolve_ttl(&TtlPolicy::Discovered(0), None), Some(1));
    }
}
