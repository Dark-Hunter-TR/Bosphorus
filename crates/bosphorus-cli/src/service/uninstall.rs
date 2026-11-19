//! `bosphorus service uninstall [--purge]`.

use std::ffi::OsStr;
use std::path::Path;
use std::time::{Duration, Instant};

use windows_service::service::{ServiceAccess, ServiceState};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

pub fn run(args: &[String]) -> anyhow::Result<()> {
    crate::i18n::set(crate::resolve_lang(args));
    let res = do_uninstall(args.iter().any(|a| a == "--purge"));

    // Elevated re-spawn from the interactive launcher: its console is hidden,
    // so also surface the outcome in a MessageBox.
    if args
        .iter()
        .any(|a| a == crate::launcher::FROM_LAUNCHER_FLAG)
    {
        crate::launcher::show_uninstall_result(&res);
    }
    res
}

fn do_uninstall(purge: bool) -> anyhow::Result<()> {
    let mgr = ServiceManager::local_computer(None::<&OsStr>, ServiceManagerAccess::CONNECT)
        .map_err(super::map_scm_err)?;
    let svc = mgr
        .open_service(
            super::SERVICE_NAME,
            ServiceAccess::QUERY_STATUS | ServiceAccess::STOP | ServiceAccess::DELETE,
        )
        .map_err(super::map_scm_err)?;

    // Best-effort stop, then wait up to ~15s for it to actually stop.
    if svc
        .query_status()
        .map(|s| s.current_state)
        .unwrap_or(ServiceState::Stopped)
        != ServiceState::Stopped
    {
        let _ = svc.stop();
        let deadline = Instant::now() + Duration::from_secs(15);
        while Instant::now() < deadline {
            if svc
                .query_status()
                .map(|s| s.current_state)
                .unwrap_or(ServiceState::Stopped)
                == ServiceState::Stopped
            {
                break;
            }
            std::thread::sleep(Duration::from_millis(300));
        }
    }

    svc.delete().map_err(super::map_scm_err)?;
    println!("{}", crate::i18n::svc_deleted(super::SERVICE_NAME));

    if purge {
        purge_data_dir()?;
    }
    Ok(())
}

fn purge_data_dir() -> anyhow::Result<()> {
    let dir = super::data_dir();
    ensure_safe_purge_target(&dir)?;
    match std::fs::remove_dir_all(&dir) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(anyhow::anyhow!("failed to purge {}: {e}", dir.display())),
    }
    println!("purged {}", dir.display());
    Ok(())
}

fn ensure_safe_purge_target(dir: &Path) -> anyhow::Result<()> {
    let name_ok = dir
        .file_name()
        .and_then(|n| n.to_str())
        .is_some_and(|n| n.eq_ignore_ascii_case(super::SERVICE_NAME));
    let has_parent = dir.parent().is_some_and(|p| !p.as_os_str().is_empty());
    if name_ok && has_parent {
        Ok(())
    } else {
        anyhow::bail!(
            "refusing to purge unexpected data directory: {}",
            dir.display()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::ensure_safe_purge_target;
    use std::path::Path;

    #[test]
    fn accepts_expected_bosphorus_data_dir() {
        ensure_safe_purge_target(Path::new(r"C:\ProgramData\Bosphorus")).unwrap();
        ensure_safe_purge_target(Path::new(r"C:\CustomBase\Bosphorus")).unwrap();
        ensure_safe_purge_target(Path::new("/var/lib/Bosphorus")).unwrap();
        ensure_safe_purge_target(Path::new(r"C:\ProgramData\bosPhorus")).unwrap();
    }

    #[test]
    fn rejects_unexpected_or_unsafe_targets() {
        for bad in [
            r"C:\ProgramData",
            r"C:\ProgramData\NotBosphorus",
            r"C:\",
            "Bosphorus",
            "",
        ] {
            assert!(
                ensure_safe_purge_target(Path::new(bad)).is_err(),
                "should reject: {bad}"
            );
        }
    }
}
