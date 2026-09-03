//! `bosphorus service status` — no elevation required.

use std::ffi::OsStr;
use std::time::SystemTime;

use windows_service::service::ServiceAccess;
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

pub fn run() -> anyhow::Result<()> {
    match ServiceManager::local_computer(None::<&OsStr>, ServiceManagerAccess::CONNECT) {
        Ok(mgr) => match mgr.open_service(
            super::SERVICE_NAME,
            ServiceAccess::QUERY_STATUS | ServiceAccess::QUERY_CONFIG,
        ) {
            Ok(svc) => {
                let st = svc.query_status().map_err(super::map_scm_err)?;
                println!("{}", crate::i18n::svc_state_line(&format!("{:?}", st.current_state)));
            }
            Err(_) => println!("{}", crate::i18n::t(crate::i18n::Msg::SvcNotInstalled)),
        },
        Err(e) => return Err(super::map_scm_err(e)),
    }

    if let Some((name, age)) = newest_profile() {
        println!("{}", crate::i18n::svc_last_write(&name, age));
    }
    println!("Get-WinEvent -ProviderName Bosphorus   # full service log");
    Ok(())
}

fn newest_profile() -> Option<(String, u64)> {
    newest_profile_in(&super::profiles_dir())
}

/// Newest `*.json` in `dir` as `(file name, age in seconds)`. `None` if the
/// directory is missing / unreadable or holds no JSON file.
fn newest_profile_in(dir: &std::path::Path) -> Option<(String, u64)> {
    let mut best: Option<(String, SystemTime)> = None;
    for entry in std::fs::read_dir(dir).ok()?.flatten() {
        if entry.path().extension().and_then(OsStr::to_str) != Some("json") {
            continue;
        }
        let Ok(mtime) = entry.metadata().and_then(|m| m.modified()) else { continue };
        let name = entry.file_name().to_string_lossy().into_owned();
        if best.as_ref().map_or(true, |(_, t)| mtime > *t) {
            best = Some((name, mtime));
        }
    }
    let (name, mtime) = best?;
    let age = SystemTime::now().duration_since(mtime).unwrap_or_default().as_secs();
    Some((name, age))
}

#[cfg(test)]
mod tests {
    use super::newest_profile_in;
    use std::time::Duration;

    fn scratch(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("bosphorus-status-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        d
    }

    #[test]
    fn none_when_dir_missing_or_empty_or_only_non_json() {
        let d = scratch("empty");
        assert!(newest_profile_in(&d).is_none(), "missing dir");

        std::fs::create_dir_all(&d).unwrap();
        assert!(newest_profile_in(&d).is_none(), "empty dir");

        std::fs::write(d.join("notes.txt"), b"x").unwrap();
        assert!(newest_profile_in(&d).is_none(), "no .json present");

        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn picks_the_most_recently_written_json_and_ignores_others() {
        let d = scratch("newest");
        std::fs::create_dir_all(&d).unwrap();

        std::fs::write(d.join("aaaa.json"), b"{}").unwrap();
        std::thread::sleep(Duration::from_millis(25));
        std::fs::write(d.join("bbbb.json"), b"{}").unwrap();
        std::fs::write(d.join("ignore.txt"), b"x").unwrap();

        let (name, age) = newest_profile_in(&d).expect("a json profile is found");
        assert_eq!(name, "bbbb.json", "newest by mtime wins");
        assert!(age < 60, "age looks sane: {age}s");

        let _ = std::fs::remove_dir_all(&d);
    }
}
