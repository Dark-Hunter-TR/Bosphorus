//! Cross-network **ISP seed pool** (feature C). Opt-in, via the CLI's
//! `--isp <name>` label.
//!
//! DERIVED, never authoritative: it aggregates the *promoted* strategies from
//! every NetKey the user tagged with one ISP name, and — on a fresh network of
//! that ISP — offers them to the grid sweep ahead of the untried grid. It is a
//! [`SeedTier::IspPool`] source, the weakest tier: a cross-network prior, not
//! same-network proof, so it only reorders `Discover` and never skips the Probe.
//! Deleting the file just means a cold start (no learned state is lost — the
//! NetKey profiles remain the authority).

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::profile::persist::{atomic_write, sanitize};
use crate::profile::{ScoredStrategy, SeedTier, StrategyQuality};
use crate::strategy::{Strategy, StrategyId};

/// On-disk format version for the ISP pool file. Independent of the discovery
/// profile's `PROFILE_VERSION`.
pub const ISP_POOL_VERSION: u32 = 1;

/// Only seed from a strategy proven on at least this many distinct networks of
/// the ISP — one network is just this session's house strategy re-labelled.
const MIN_NETWORKS: usize = 2;
/// ...and only if its aggregate `successes / trials` clears this.
const MIN_SUCCESS_RATIO: f32 = 0.6;
/// Cap on per-network contributions kept per strategy (newest `last_seen` wins).
const MAX_CONTRIBUTIONS: usize = 20;

/// One network's evidence for one strategy: the summed trial/success counts of
/// every target on that network that promoted this strategy.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Contribution {
    pub net_key: String,
    pub trials: u64,
    pub successes: u64,
    pub targets_promoted: u32,
    #[serde(default)]
    pub quality: StrategyQuality,
    /// Unix seconds of the last session that refreshed this contribution.
    pub last_seen: u64,
}

/// One strategy's pooled evidence across networks of the ISP.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IspPoolEntry {
    pub strategy: Strategy,
    pub contributions: Vec<Contribution>,
}

impl IspPoolEntry {
    fn networks(&self) -> usize {
        self.contributions.len()
    }
    fn totals(&self) -> (u64, u64, StrategyQuality) {
        let mut q = StrategyQuality::default();
        let (mut t, mut s) = (0u64, 0u64);
        for c in &self.contributions {
            t += c.trials;
            s += c.successes;
            q.merge(&c.quality);
        }
        (t, s, q)
    }
    /// Clears the `MIN_NETWORKS` + `MIN_SUCCESS_RATIO` gate.
    fn is_seed_worthy(&self) -> bool {
        if self.networks() < MIN_NETWORKS {
            return false;
        }
        let (trials, successes, _) = self.totals();
        trials > 0 && (successes as f32 / trials as f32) >= MIN_SUCCESS_RATIO
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IspPool {
    pub version: u32,
    /// The `--isp` label this pool belongs to (echoed for debugging).
    pub isp: String,
    pub entries: Vec<IspPoolEntry>,
}

impl IspPool {
    pub fn new(isp: &str) -> Self {
        Self { version: ISP_POOL_VERSION, isp: isp.to_owned(), entries: Vec::new() }
    }

    /// `<dir>/isp/<sanitized-isp>.json`.
    pub fn path(dir: &Path, isp: &str) -> PathBuf {
        dir.join("isp").join(format!("{}.json", sanitize(isp)))
    }

    /// Read the pool for `isp`. `None` if it does not exist, cannot be parsed, or
    /// is a version we do not understand (all treated as "start cold").
    pub fn load(dir: &Path, isp: &str) -> Option<Self> {
        let bytes = std::fs::read(Self::path(dir, isp)).ok()?;
        match serde_json::from_slice::<IspPool>(&bytes) {
            Ok(p) if p.version == ISP_POOL_VERSION => Some(p),
            _ => None,
        }
    }

    /// Atomic write (per-process staging file + last-writer-wins rename — see
    /// [`atomic_write`]). Returns the JSON byte count.
    pub fn save(&self, dir: &Path) -> std::io::Result<usize> {
        let json = serde_json::to_vec_pretty(self).map_err(std::io::Error::other)?;
        atomic_write(&Self::path(dir, &self.isp), &json)?;
        Ok(json.len())
    }

    /// Fold this session's promoted strategies into the pool as `net_key`'s
    /// contribution. Idempotent per network: re-running on the same NetKey
    /// *replaces* its contribution rather than adding a second one, so
    /// `networks` never inflates. `promoted` is `(id, its score)` for every
    /// `Active`-with-strategy target — see [`Discovery::promoted_for_isp`].
    ///
    /// [`Discovery::promoted_for_isp`]: crate::discovery::Discovery::promoted_for_isp
    pub fn merge_session(
        &mut self,
        net_key: &str,
        promoted: &[(StrategyId, ScoredStrategy)],
        now_unix: u64,
    ) {
        // Group this session's promotions by strategy id.
        let mut by_id: HashMap<StrategyId, (Strategy, u64, u64, u32, StrategyQuality)> =
            HashMap::new();
        for (id, sc) in promoted {
            let e = by_id.entry(*id).or_insert_with(|| {
                (sc.strategy.clone(), 0, 0, 0, StrategyQuality::default())
            });
            e.1 += sc.trials as u64;
            e.2 += sc.successes as u64;
            e.3 += 1;
            e.4.merge(&sc.quality);
        }

        for (id, (strategy, trials, successes, targets, quality)) in by_id {
            let contrib = Contribution {
                net_key: net_key.to_owned(),
                trials,
                successes,
                targets_promoted: targets,
                quality,
                last_seen: now_unix,
            };
            let entry = match self.entries.iter_mut().find(|e| e.strategy.id() == id) {
                Some(e) => e,
                None => {
                    self.entries.push(IspPoolEntry { strategy, contributions: Vec::new() });
                    self.entries.last_mut().unwrap()
                }
            };
            // Replace this network's prior contribution, if any.
            entry.contributions.retain(|c| c.net_key != net_key);
            entry.contributions.push(contrib);
            if entry.contributions.len() > MAX_CONTRIBUTIONS {
                entry.contributions.sort_by_key(|c| std::cmp::Reverse(c.last_seen));
                entry.contributions.truncate(MAX_CONTRIBUTIONS);
            }
        }
    }

    /// The seed list this pool contributes to a fresh `Discover` target: every
    /// entry that clears the corroboration gate, most-proven first
    /// (`networks` desc, then retransmit-free-looking, then lowest latency).
    /// All tagged [`SeedTier::IspPool`].
    pub fn seeds(&self) -> Vec<(StrategyId, SeedTier)> {
        let mut ranked: Vec<(&IspPoolEntry, usize, StrategyQuality)> = self
            .entries
            .iter()
            .filter(|e| e.is_seed_worthy())
            .map(|e| {
                let (_, _, q) = e.totals();
                (e, e.networks(), q)
            })
            .collect();
        ranked.sort_by(|a, b| {
            b.1.cmp(&a.1)
                .then_with(|| b.2.looks_fast().cmp(&a.2.looks_fast()))
                .then_with(|| match (a.2.min_latency, b.2.min_latency) {
                    (Some(x), Some(y)) => x.cmp(&y),
                    (Some(_), None) => std::cmp::Ordering::Less,
                    (None, Some(_)) => std::cmp::Ordering::Greater,
                    (None, None) => std::cmp::Ordering::Equal,
                })
        });
        ranked.into_iter().map(|(e, ..)| (e.strategy.id(), SeedTier::IspPool)).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::strategy::DefaultGenerator;
    use crate::config::EvasionConfig;

    fn gen() -> DefaultGenerator {
        DefaultGenerator::new(&EvasionConfig::default())
    }
    fn score(strategy: Strategy, trials: u32, successes: u32) -> ScoredStrategy {
        let mut s = ScoredStrategy::new(strategy);
        s.trials = trials;
        s.successes = successes;
        s
    }

    #[test]
    fn merge_is_idempotent_for_one_network() {
        let g = gen();
        let s0 = g.all()[0].clone();
        let mut pool = IspPool::new("acme");
        pool.merge_session("netA", &[(s0.id(), score(s0.clone(), 3, 2))], 100);
        pool.merge_session("netA", &[(s0.id(), score(s0.clone(), 9, 8))], 200);
        assert_eq!(pool.entries.len(), 1);
        assert_eq!(pool.entries[0].contributions.len(), 1, "same network -> one contribution");
        // The later run's counts replaced the earlier ones.
        let (t, s, _) = pool.entries[0].totals();
        assert_eq!((t, s), (9, 8));
    }

    #[test]
    fn seeds_need_two_networks_and_a_passing_ratio() {
        let g = gen();
        let (a, b, c) = (g.all()[0].clone(), g.all()[1].clone(), g.all()[2].clone());
        let mut pool = IspPool::new("acme");

        // a: only one network -> excluded no matter how good.
        pool.merge_session("net1", &[(a.id(), score(a.clone(), 10, 10))], 1);
        // b: two networks but ratio 4/10 = 0.4 -> excluded.
        pool.merge_session("net1", &[(b.id(), score(b.clone(), 5, 2))], 1);
        pool.merge_session("net2", &[(b.id(), score(b.clone(), 5, 2))], 1);
        // c: two networks, ratio 7/10 = 0.7 -> included.
        pool.merge_session("net1", &[(c.id(), score(c.clone(), 5, 4))], 1);
        pool.merge_session("net2", &[(c.id(), score(c.clone(), 5, 3))], 1);

        let seeds = pool.seeds();
        assert_eq!(seeds, vec![(c.id(), SeedTier::IspPool)]);
    }

    #[test]
    fn seeds_are_ordered_by_network_count_desc() {
        let g = gen();
        let (a, b) = (g.all()[0].clone(), g.all()[1].clone());
        let mut pool = IspPool::new("acme");
        // b on 3 networks, a on 2 — both pass the ratio gate.
        for n in ["n1", "n2"] {
            pool.merge_session(n, &[(a.id(), score(a.clone(), 4, 3))], 1);
        }
        for n in ["n1", "n2", "n3"] {
            pool.merge_session(n, &[(b.id(), score(b.clone(), 4, 3))], 1);
        }
        assert_eq!(
            pool.seeds(),
            vec![(b.id(), SeedTier::IspPool), (a.id(), SeedTier::IspPool)],
            "more networks first"
        );
    }

    #[test]
    fn contributions_are_capped_to_the_newest() {
        let g = gen();
        let a = g.all()[0].clone();
        let mut pool = IspPool::new("acme");
        for i in 0..(MAX_CONTRIBUTIONS as u64 + 5) {
            pool.merge_session(&format!("net{i}"), &[(a.id(), score(a.clone(), 2, 2))], i);
        }
        assert_eq!(pool.entries[0].contributions.len(), MAX_CONTRIBUTIONS);
        let oldest = pool.entries[0].contributions.iter().map(|c| c.last_seen).min().unwrap();
        assert_eq!(oldest, 5, "the 5 oldest contributions were dropped");
    }

    #[test]
    fn save_load_round_trips_and_leaves_no_temp() {
        let g = gen();
        let a = g.all()[0].clone();
        let dir = tempfile::tempdir().unwrap();
        let mut pool = IspPool::new("Acme ISP / Fibre");
        pool.merge_session("n1", &[(a.id(), score(a.clone(), 4, 3))], 1);
        pool.merge_session("n2", &[(a.id(), score(a.clone(), 4, 3))], 2);
        pool.save(dir.path()).unwrap();

        let back = IspPool::load(dir.path(), "Acme ISP / Fibre").unwrap();
        assert_eq!(back.version, ISP_POOL_VERSION);
        assert_eq!(back.seeds(), vec![(a.id(), SeedTier::IspPool)]);
        let isp_dir = dir.path().join("isp");
        let tmps: Vec<_> = std::fs::read_dir(&isp_dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().ends_with(".tmp"))
            .collect();
        assert!(tmps.is_empty(), "left a temp file: {tmps:?}");
    }

    #[test]
    fn load_rejects_an_unknown_version() {
        let dir = tempfile::tempdir().unwrap();
        let p = IspPool::path(dir.path(), "acme");
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(&p, br#"{"version":999,"isp":"acme","entries":[]}"#).unwrap();
        assert!(IspPool::load(dir.path(), "acme").is_none());
    }

    #[test]
    fn isp_pool_tier_is_weak_default_threshold_and_never_skips_the_probe() {
        assert_eq!(SeedTier::IspPool.promote_threshold(2), 2, "no 1-success shortcut");
        assert!(!SeedTier::IspPool.is_high_confidence(), "must not trigger Probe-skip");
    }
}
