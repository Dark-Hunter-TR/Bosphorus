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

use crate::profile::{NetPhase, StrategyQuality};
use crate::strategy::{Strategy, StrategyId};

/// On-disk format version. Bump on an incompatible schema change.
///
/// Still `1` after adding [`PersistedScore::quality`]: the new field is
/// `#[serde(default)]`, so a v1 file written before that change loads fine and
/// the quality counters simply start from zero. Also still `1` after dropping
/// `PersistedTarget::consecutive_success`: deserialization ignores unknown keys,
/// so an older file that still carries it loads without complaint (the value is
/// discarded — the success streak is now per-candidate and not persisted).
pub const PROFILE_VERSION: u32 = 1;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PersistedScore {
    pub strategy: Strategy,
    pub trials: u32,
    pub successes: u32,
    /// Latency / retransmit quality. Absent in profiles written before it
    /// existed — defaults to empty.
    #[serde(default)]
    pub quality: StrategyQuality,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PersistedTarget {
    pub key: String,
    pub phase: NetPhase,
    pub tried: Vec<StrategyId>,
    pub scores: Vec<PersistedScore>,
    pub active: Option<StrategyId>,
    pub consecutive_failure: u8,
    pub server_initial_ttl: Option<u8>,
    /// Absent in profiles written before this existed — defaults to `None`.
    #[serde(default)]
    pub injector_hops: Option<u8>,
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

pub(crate) fn sanitize(net_key: &str) -> String {
    net_key
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '_' })
        .collect()
}

pub fn profile_path(dir: &Path, net_key: &str) -> PathBuf {
    dir.join(format!("{}.json", sanitize(net_key)))
}

/// Write `bytes` to `path` atomically: a per-process staging file
/// (`<path>.<pid>.tmp`) then a last-writer-wins rename. Two processes sharing one
/// store never touch the same temp; the target is never left torn. Shared by the
/// discovery profile and the ISP seed pool.
pub(crate) fn atomic_write(path: &Path, bytes: &[u8]) -> io::Result<()> {
    atomic_write_with_tag(path, bytes, &std::process::id().to_string())
}

fn atomic_write_with_tag(path: &Path, bytes: &[u8], tag: &str) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("json");
    let tmp = path.with_extension(format!("{ext}.{tag}.tmp"));
    std::fs::write(&tmp, bytes)?;
    if let Err(e) = std::fs::rename(&tmp, path) {
        let _ = std::fs::remove_file(&tmp); // don't leak our staging file on a lost race
        return Err(e);
    }
    Ok(())
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

/// Atomic write (see [`atomic_write`]): a per-process staging file then a
/// last-writer-wins rename. Two processes pointed at the same store — the
/// service and an interactive `--engine` sharing `%ProgramData%` — never write
/// the same temp and never leave the target torn, but one can overwrite the
/// other's incremental learning. The profile is a cache, not a ledger — the next
/// session re-learns — so this is acceptable; callers just should not run both
/// against one store for long stretches. Returns the JSON byte count.
pub fn save(dir: &Path, net_key: &str, file: &ProfileFile) -> io::Result<usize> {
    let json = serde_json::to_vec_pretty(file).map_err(io::Error::other)?;
    atomic_write(&profile_path(dir, net_key), &json)?;
    Ok(json.len())
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
                    quality: StrategyQuality::default(),
                }],
                active: None,
                consecutive_failure: 1,
                server_initial_ttl: Some(128),
                injector_hops: Some(4),
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
        assert_eq!(back.targets[0].injector_hops, Some(4));
        assert_eq!(back.grid_signature, 0xdead_beef);
        // No stray temp file left behind.
        assert!(!tmp_files(dir.path()).iter().any(|_| true), "left a .tmp file");
    }

    #[test]
    fn missing_injector_hops_field_defaults_to_none() {
        // A target JSON written before `injector_hops` existed, e.g. from an
        // older build. #[serde(default)] must let it load, not just skip it.
        let json = r#"{
            "key": "example.com",
            "phase": "Discover",
            "tried": [],
            "scores": [],
            "active": null,
            "consecutive_failure": 0,
            "server_initial_ttl": null,
            "grid_size_at_exhaustion": null
        }"#;
        let pt: PersistedTarget = serde_json::from_str(json).expect("old-format target still loads");
        assert_eq!(pt.injector_hops, None);
    }

    #[test]
    fn corrupt_file_loads_as_none() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(profile_path(dir.path(), "k"), b"{ not json").unwrap();
        assert!(load(dir.path(), "k").is_none());
    }

    fn tmp_files(dir: &Path) -> Vec<String> {
        std::fs::read_dir(dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.ends_with(".tmp"))
            .collect()
    }

    #[test]
    fn a_second_writers_save_does_not_disturb_the_first_writers_staged_temp() {
        // Two processes share one store. Writer P1 has staged its temp but not
        // yet renamed; writer P2 runs a full save meanwhile. Per-process temp
        // names mean P2 cannot touch P1's staging file, and P2's own write lands
        // as a valid store.
        let dir = tempfile::tempdir().unwrap();
        let key = "net";
        let path = profile_path(dir.path(), key);
        let p1_tmp = path.with_extension("json.p1.tmp");
        std::fs::write(&p1_tmp, b"P1-STAGED-BYTES").unwrap();

        let json = serde_json::to_vec_pretty(&sample()).unwrap();
        atomic_write_with_tag(&path, &json, "p2").unwrap();

        assert_eq!(std::fs::read(&p1_tmp).unwrap(), b"P1-STAGED-BYTES", "P1's temp was clobbered");
        assert!(load(dir.path(), key).is_some(), "P2's save produced a valid store");
        // P2 cleaned up after itself; only P1's staging file remains.
        assert_eq!(tmp_files(dir.path()), vec!["net.json.p1.tmp".to_string()]);
    }

    #[test]
    fn back_to_back_saves_to_one_store_leave_a_valid_file_last_writer_wins() {
        let dir = tempfile::tempdir().unwrap();
        let key = "net";
        let path = profile_path(dir.path(), key);
        let mut a = sample();
        a.targets[0].key = "a.example".into();
        let mut b = sample();
        b.targets[0].key = "b.example".into();

        atomic_write_with_tag(&path, &serde_json::to_vec_pretty(&a).unwrap(), "1111").unwrap();
        atomic_write_with_tag(&path, &serde_json::to_vec_pretty(&b).unwrap(), "2222").unwrap();

        let back = load(dir.path(), key).unwrap();
        assert_eq!(back.targets.len(), 1);
        assert_eq!(back.targets[0].key, "b.example", "last writer wins");
        assert!(tmp_files(dir.path()).is_empty(), "no temp litter");
    }
}
