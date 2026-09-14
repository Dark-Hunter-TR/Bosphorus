//! Destinations caught interfering, tracked by IP rather than by name.
//!
//! Discovery reasons about *targets* (SNI), because that is what a strategy is
//! learned against. A QUIC datagram carries no readable name, so the only thing
//! the two paths share is the destination address — which is why this set is
//! keyed by IP and kept separate from the profile.
//!
//! Entries are deliberately **never persisted**. A hostname's address set turns
//! over constantly behind a CDN, so a saved IP is as likely to belong to someone
//! else tomorrow as to the host it was learned from; re-learning costs one TCP
//! connection. They also expire on their own, so a network that stops censoring
//! stops being treated as censoring without anyone restarting anything.

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

use parking_lot::Mutex;

/// How long an observation keeps a destination marked.
pub const DEFAULT_TTL: Duration = Duration::from_secs(15 * 60);

/// Ceiling on tracked destinations. Reaching it evicts the oldest observation,
/// which is the one most likely to have expired anyway.
pub const DEFAULT_CAPACITY: usize = 2048;

/// Destination addresses where conntrack saw the censor act.
pub struct CensoredIps {
    seen: Mutex<HashMap<IpAddr, Instant>>,
    ttl: Duration,
    capacity: usize,
}

impl Default for CensoredIps {
    fn default() -> Self {
        Self::new(DEFAULT_TTL, DEFAULT_CAPACITY)
    }
}

impl CensoredIps {
    pub fn new(ttl: Duration, capacity: usize) -> Self {
        Self { seen: Mutex::new(HashMap::new()), ttl, capacity: capacity.max(1) }
    }

    /// Record interference against `ip`, refreshing it if already known.
    pub fn note(&self, ip: IpAddr, now: Instant) {
        let mut seen = self.seen.lock();
        seen.insert(ip, now);
        if seen.len() > self.capacity {
            let ttl = self.ttl;
            seen.retain(|_, at| now.saturating_duration_since(*at) < ttl);
        }
        while seen.len() > self.capacity {
            let Some(oldest) = seen.iter().min_by_key(|(_, at)| **at).map(|(ip, _)| *ip) else {
                break;
            };
            seen.remove(&oldest);
        }
    }

    /// Whether `ip` has interfered recently enough to still count.
    pub fn contains(&self, ip: &IpAddr, now: Instant) -> bool {
        let seen = self.seen.lock();
        seen.get(ip)
            .is_some_and(|at| now.saturating_duration_since(*at) < self.ttl)
    }

    /// Drop expired entries. Called from the engine's maintenance tick so a
    /// long-lived process doesn't hold addresses it will never consult again.
    pub fn sweep(&self, now: Instant) {
        let ttl = self.ttl;
        self.seen
            .lock()
            .retain(|_, at| now.saturating_duration_since(*at) < ttl);
    }

    /// Live (non-expired entries included) count, for digests and tests.
    pub fn len(&self) -> usize {
        self.seen.lock().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn ip(last: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(203, 0, 113, last))
    }

    #[test]
    fn a_noted_destination_counts_until_its_ttl_runs_out() {
        let c = CensoredIps::new(Duration::from_secs(60), 16);
        let t0 = Instant::now();
        c.note(ip(1), t0);

        assert!(c.contains(&ip(1), t0));
        assert!(c.contains(&ip(1), t0 + Duration::from_secs(59)));
        assert!(!c.contains(&ip(1), t0 + Duration::from_secs(60)));
        assert!(!c.contains(&ip(2), t0), "unrelated destination untouched");
    }

    #[test]
    fn noting_again_extends_the_entry() {
        let c = CensoredIps::new(Duration::from_secs(60), 16);
        let t0 = Instant::now();
        c.note(ip(1), t0);
        c.note(ip(1), t0 + Duration::from_secs(50));

        assert!(c.contains(&ip(1), t0 + Duration::from_secs(100)));
        assert_eq!(c.len(), 1, "refresh must not duplicate the entry");
    }

    #[test]
    fn sweeping_drops_only_what_expired() {
        let c = CensoredIps::new(Duration::from_secs(60), 16);
        let t0 = Instant::now();
        c.note(ip(1), t0);
        c.note(ip(2), t0 + Duration::from_secs(30));

        c.sweep(t0 + Duration::from_secs(70));
        assert_eq!(c.len(), 1);
        assert!(c.contains(&ip(2), t0 + Duration::from_secs(70)));
    }

    #[test]
    fn capacity_is_enforced_oldest_first() {
        let c = CensoredIps::new(Duration::from_secs(600), 3);
        let t0 = Instant::now();
        for i in 0..3 {
            c.note(ip(i), t0 + Duration::from_secs(i as u64));
        }
        assert_eq!(c.len(), 3);

        c.note(ip(9), t0 + Duration::from_secs(10));
        assert_eq!(c.len(), 3, "capacity held");
        assert!(!c.contains(&ip(0), t0 + Duration::from_secs(10)), "oldest evicted");
        assert!(c.contains(&ip(2), t0 + Duration::from_secs(10)));
        assert!(c.contains(&ip(9), t0 + Duration::from_secs(10)));
    }

    #[test]
    fn expired_entries_are_reclaimed_before_live_ones_when_full() {
        let c = CensoredIps::new(Duration::from_secs(60), 2);
        let t0 = Instant::now();
        c.note(ip(1), t0);
        c.note(ip(2), t0 + Duration::from_secs(59));

        // ip(1) is expired by now, so it — not ip(2) — makes room.
        c.note(ip(3), t0 + Duration::from_secs(61));
        assert!(c.contains(&ip(2), t0 + Duration::from_secs(61)));
        assert!(c.contains(&ip(3), t0 + Duration::from_secs(61)));
        assert!(!c.contains(&ip(1), t0 + Duration::from_secs(61)));
    }

    #[test]
    fn a_zero_capacity_request_still_holds_one_entry() {
        let c = CensoredIps::new(Duration::from_secs(60), 0);
        let t0 = Instant::now();
        c.note(ip(1), t0);
        assert!(c.contains(&ip(1), t0));
    }
}
