//! Minimal JSON persistence for discovery profiles (M8).
//!
//! One file per network fingerprint (`<dir>/<net_key>.json`). Holds the
//! per-target sweep state so multiple short sessions accumulate toward the full
//! grid instead of restarting from `Probe` every process launch.
//!
//! Compatibility: on load, every persisted `StrategyId` is checked against the
//! live grid. If they are all still present the target is fully restored (and
//! [`grid_size_at_exhaustion`](crate::profile::TargetState::grid_size_at_exhaustion)
//! lets an `Exhausted` target revive under a grown grid). If any id is gone
//! (the grid was renumbered), the per-strategy data is dropped and only the
//! learned server TTL is kept.

use std::io;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::profile::NetPhase;
use crate::strategy::{Strategy, StrategyId};

/// On-disk format version. Bump on an incompatible schema change.
pub const PROFILE_VERSION: u32 = 1;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PersistedScore {
    pub strategy: Strategy,
    pub trials: u32,
    pub successes: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PersistedTarget {
    pub key: String,
    pub phase: NetPhase,
    pub tried: Vec<StrategyId>,
    pub scores: Vec<PersistedScore>,
    pub active: Option<StrategyId>,
    pub consecutive_success: u8,
    pub consecutive_failure: u8,
    pub server_initial_ttl: Option<u8>,
    pub grid_size_at_exhaustion: Option<usize>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProfileFile {
    pub version: u32,
    /// FNV-1a over every current grid `StrategyId` (informational — the actual
    /// keep/drop decision is a per-id subset check).
    pub grid_signature: u64,
    /// The NetKey this file is stored under (echoed for debugging).
    pub net_key: String,
    pub targets: Vec<PersistedTarget>,
}

impl ProfileFile {
    pub fn new(grid_signature: u64, net_key: &str, targets: Vec<PersistedTarget>) -> Self {
        Self { version: PROFILE_VERSION, grid_signature, net_key: net_key.to_owned(), targets }
    }
}

fn sanitize(net_key: &str) -> String {
    net_key
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '_' })
        .collect()
}

pub fn profile_path(dir: &Path, net_key: &str) -> PathBuf {
    dir.join(format!("{}.json", sanitize(net_key)))
}

/// Read `<dir>/<net_key>.json`. `None` if it does not exist or cannot be
/// parsed (a corrupt file is treated as "start fresh").
pub fn load(dir: &Path, net_key: &str) -> Option<ProfileFile> {
    let bytes = std::fs::read(profile_path(dir, net_key)).ok()?;
    match serde_json::from_slice::<ProfileFile>(&bytes) {
        Ok(f) if f.version == PROFILE_VERSION => Some(f),
        _ => None,
    }
}

/// Atomic write: temp file then rename. Returns the number of JSON bytes
/// written (fed to the `bosphorus::mem` digest as a proxy for discovery-state
/// size).
pub fn save(dir: &Path, net_key: &str, file: &ProfileFile) -> io::Result<usize> {
    std::fs::create_dir_all(dir)?;
    let path = profile_path(dir, net_key);
    let tmp = path.with_extension("json.tmp");
    let json = serde_json::to_vec_pretty(file).map_err(io::Error::other)?;
    let n = json.len();
    std::fs::write(&tmp, json)?;
    std::fs::rename(&tmp, &path)?;
    Ok(n)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::strategy::Strategy;

    fn sample() -> ProfileFile {
        ProfileFile::new(
            0xdead_beef,
            "gw=192.168.1.1;net=192.168.1.0/24;dns=lan",
            vec![PersistedTarget {
                key: "updates.discord.com".into(),
                phase: NetPhase::Discover,
                tried: vec![Strategy::m4_fixed().id()],
                scores: vec![PersistedScore {
                    strategy: Strategy::m4_fixed(),
                    trials: 3,
                    successes: 0,
                }],
                active: None,
                consecutive_success: 0,
                consecutive_failure: 1,
                server_initial_ttl: Some(128),
                grid_size_at_exhaustion: None,
            }],
        )
    }

    #[test]
    fn json_round_trips() {
        let f = sample();
        let j = serde_json::to_string(&f).unwrap();
        let back: ProfileFile = serde_json::from_str(&j).unwrap();
        assert_eq!(back.version, PROFILE_VERSION);
        assert_eq!(back.targets.len(), 1);
        assert_eq!(back.targets[0].key, "updates.discord.com");
        assert_eq!(back.targets[0].tried, f.targets[0].tried);
    }

    #[test]
    fn save_then_load_reproduces_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let key = "abc123";
        assert!(load(dir.path(), key).is_none());

        save(dir.path(), key, &sample()).unwrap();
        let back = load(dir.path(), key).unwrap();
        assert_eq!(back.targets[0].server_initial_ttl, Some(128));
        assert_eq!(back.grid_signature, 0xdead_beef);
        // No stray temp file left behind.
        assert!(!profile_path(dir.path(), key).with_extension("json.tmp").exists());
    }

    #[test]
    fn corrupt_file_loads_as_none() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(profile_path(dir.path(), "k"), b"{ not json").unwrap();
        assert!(load(dir.path(), "k").is_none());
    }
}
