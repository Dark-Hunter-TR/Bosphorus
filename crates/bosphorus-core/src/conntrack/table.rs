use std::collections::HashMap;
use std::time::{Duration, Instant};

use parking_lot::Mutex;

use crate::config::ConntrackTuning;

use crate::profile::TrialRecord;

use super::events::{resolve_timeout, FlowOutcome};
use super::flow::{FlowKey, FlowState};

/// A flow whose verdict was decided by a timeout in [`FlowTable::resolve_timeouts`].
pub struct ResolvedFlow {
    pub key: FlowKey,
    pub server_name: Option<String>,
    pub outcome: FlowOutcome,
    pub target_key: Option<String>,
    pub trial: Option<TrialRecord>,
    /// ClientHello -> verdict wall time (`None` if no ClientHello was seen).
    pub latency: Option<Duration>,
    /// ClientHello retransmits observed before the verdict.
    pub retx: u8,
}

const SHARDS: usize = 16;
/// Don't bother shrinking a shard below this capacity — churn isn't worth it.
const MIN_SHARD_CAP: usize = 32;

/// Sharded flow table. One `Mutex` per shard keeps per-packet lock contention
/// low without an async runtime.
pub struct FlowTable {
    shards: Vec<Mutex<HashMap<FlowKey, FlowState>>>,
    idle: Duration,
}

impl FlowTable {
    pub fn new(idle: Duration) -> Self {
        Self {
            shards: (0..SHARDS).map(|_| Mutex::new(HashMap::new())).collect(),
            idle,
        }
    }

    fn shard(&self, key: &FlowKey) -> &Mutex<HashMap<FlowKey, FlowState>> {
        // Cheap spread over the tuple; FlowKey isn't Hash-into-usize directly.
        let mut h = 0u64;
        for b in key_bytes(key) {
            h = h.wrapping_mul(0x100000001b3).wrapping_add(b as u64);
        }
        &self.shards[(h as usize) % SHARDS]
    }

    /// Get-or-create the flow, bump `last_seen`, run `f` against it.
    pub fn with_mut<R>(&self, key: FlowKey, now: Instant, f: impl FnOnce(&mut FlowState) -> R) -> R {
        let mut g = self.shard(&key).lock();
        let st = g.entry(key).or_insert_with(|| FlowState::new(now));
        st.last_seen = now;
        f(st)
    }

    /// Read-only peek at an existing flow.
    pub fn peek<R>(&self, key: &FlowKey, f: impl FnOnce(&FlowState) -> R) -> Option<R> {
        self.shard(key).lock().get(key).map(f)
    }

    pub fn remove(&self, key: &FlowKey) -> Option<FlowState> {
        self.shard(key).lock().remove(key)
    }

    pub fn len(&self) -> usize {
        self.shards.iter().map(|s| s.lock().len()).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// `(live entries, summed bucket capacity across all shards)` — for the
    /// `bosphorus::mem` digest. A capacity that dwarfs the entry count is the
    /// "`retain` never gives memory back" high-water mark.
    pub fn stats(&self) -> (usize, usize) {
        let mut len = 0;
        let mut cap = 0;
        for s in &self.shards {
            let g = s.lock();
            len += g.len();
            cap += g.capacity();
        }
        (len, cap)
    }

    /// Drop every flow and release the bucket allocations. Called on a live
    /// network rebind — a flow carried over from the old network points its
    /// `target_key` into a discovery map that no longer exists.
    pub fn clear(&self) {
        for shard in &self.shards {
            let mut g = shard.lock();
            g.clear();
            g.shrink_to(MIN_SHARD_CAP);
        }
    }

    /// Drop flows whose last packet is older than `idle`. Returns how many.
    pub fn sweep(&self, now: Instant) -> usize {
        let mut removed = 0;
        for shard in &self.shards {
            let mut g = shard.lock();
            let before = g.len();
            g.retain(|_, st| now.duration_since(st.last_seen) < self.idle);
            let live = g.len();
            removed += before - live;
            // `retain` never shrinks the bucket allocation, so a traffic burst
            // would pin its high-water capacity for the life of the process.
            // Reclaim it once the live set is well below that mark.
            if g.capacity() > 4 * live.max(MIN_SHARD_CAP) {
                g.shrink_to(live * 2);
            }
        }
        removed
    }

    /// Resolve flows that have gone quiet. Marks `st.outcome` and returns the
    /// newly-decided flows for the caller to log / feed to discovery.
    pub fn resolve_timeouts(&self, tuning: &ConntrackTuning, now: Instant) -> Vec<ResolvedFlow> {
        let mut out = Vec::new();
        for shard in &self.shards {
            let mut g = shard.lock();
            for (key, st) in g.iter_mut() {
                if let Some(o) = resolve_timeout(st, tuning, now) {
                    st.outcome = Some(o);
                    out.push(ResolvedFlow {
                        key: *key,
                        server_name: st.server_name.clone(),
                        outcome: o,
                        target_key: st.target_key.clone(),
                        trial: st.trial,
                        latency: st
                            .client_hello_at
                            .map(|t| now.saturating_duration_since(t)),
                        retx: st.client_hello_retx,
                    });
                }
            }
        }
        out
    }
}

fn key_bytes(k: &FlowKey) -> impl Iterator<Item = u8> + '_ {
    let cip = ip_octets(k.client_ip);
    let sip = ip_octets(k.server_ip);
    cip.into_iter()
        .chain(sip)
        .chain(k.client_port.to_be_bytes())
        .chain(k.server_port.to_be_bytes())
}

fn ip_octets(ip: std::net::IpAddr) -> Vec<u8> {
    match ip {
        std::net::IpAddr::V4(a) => a.octets().to_vec(),
        std::net::IpAddr::V6(a) => a.octets().to_vec(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn key(port: u16) -> FlowKey {
        FlowKey {
            client_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            client_port: port,
            server_ip: IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
            server_port: 443,
        }
    }

    #[test]
    fn sweep_drops_only_idle_flows() {
        let t = FlowTable::new(Duration::from_secs(30));
        let start = Instant::now();

        t.with_mut(key(1111), start, |st| st.client_hello_seen = true);
        t.with_mut(key(2222), start, |_| {});
        assert_eq!(t.len(), 2);

        // 40s later, touch only flow 2222.
        let later = start + Duration::from_secs(40);
        t.with_mut(key(2222), later, |_| {});

        let removed = t.sweep(later);
        assert_eq!(removed, 1, "only the untouched flow should age out");
        assert_eq!(t.len(), 1);
        assert!(t.peek(&key(2222), |_| ()).is_some());
        assert!(t.peek(&key(1111), |_| ()).is_none());
    }

    #[test]
    fn sweep_reclaims_bucket_capacity_after_a_burst() {
        let t = FlowTable::new(Duration::from_secs(30));
        let start = Instant::now();

        // Burst: 5000 flows across the shards.
        for p in 0..5000u32 {
            t.with_mut(key(1024 + p as u16 % 60000), start, |_| {});
        }
        let (_, cap_peak) = t.stats();
        assert!(cap_peak > 2000, "capacity grew with the burst (cap={cap_peak})");

        // All age out; the next sweep must give the allocation back.
        let removed = t.sweep(start + Duration::from_secs(60));
        assert!(removed > 0);
        let (len_after, cap_after) = t.stats();
        assert_eq!(len_after, 0);
        assert!(
            cap_after * 4 < cap_peak,
            "swept table released most of its capacity (peak={cap_peak}, after={cap_after})"
        );
    }

    #[test]
    fn flowtable_clear_empties_and_releases() {
        let t = FlowTable::new(Duration::from_secs(30));
        let start = Instant::now();
        for p in 0..5000u32 {
            t.with_mut(key(1024 + p as u16 % 60000), start, |_| {});
        }
        let (len_before, cap_before) = t.stats();
        assert!(len_before > 0 && cap_before > 2000);

        t.clear();

        let (len_after, cap_after) = t.stats();
        assert_eq!(len_after, 0, "clear() drops every flow");
        assert!(
            cap_after * 4 < cap_before,
            "clear() releases the bucket capacity (before={cap_before}, after={cap_after})"
        );
        // Still usable afterwards.
        t.with_mut(key(7777), start, |st| st.client_hello_seen = true);
        assert_eq!(t.len(), 1);
    }

    #[test]
    fn sweep_noop_when_all_fresh() {
        let t = FlowTable::new(Duration::from_secs(30));
        let now = Instant::now();
        t.with_mut(key(1), now, |_| {});
        t.with_mut(key(2), now, |_| {});
        assert_eq!(t.sweep(now + Duration::from_secs(5)), 0);
        assert_eq!(t.len(), 2);
    }

    #[test]
    fn resolve_timeouts_marks_and_reports_once() {
        let t = FlowTable::new(Duration::from_secs(60));
        let tuning = ConntrackTuning::default();
        let start = Instant::now();
        t.with_mut(key(9), start, |st| {
            st.client_hello_seen = true;
            st.client_hello_at = Some(start);
        });

        let later = start + tuning.verdict_timeout + Duration::from_millis(1);
        let first = t.resolve_timeouts(&tuning, later);
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].outcome, FlowOutcome::Blackhole);
        // Second call: already resolved, nothing new.
        assert!(t.resolve_timeouts(&tuning, later).is_empty());
    }
}
