//! `bosphorus service uninstall [--purge]`.

use std::ffi::OsStr;
use std::time::{Duration, Instant};

use windows_service::service::{ServiceAccess, ServiceState};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

pub fn run(args: &[String]) -> anyhow::Result<()> {
    let purge = args.iter().any(|a| a == "--purge");

    let mgr = ServiceManager::local_computer(None::<&OsStr>, ServiceManagerAccess::CONNECT)
        .map_err(super::map_scm_err)?;
    let svc = mgr
        .open_service(
            super::SERVICE_NAME,
            ServiceAccess::QUERY_STATUS | ServiceAccess::STOP | ServiceAccess::DELETE,
        )
        .map_err(super::map_scm_err)?;

    // Best-effort stop, then wait up to ~15s for it to actually stop.
    if svc.query_status().map(|s| s.current_state).unwrap_or(ServiceState::Stopped)
        != ServiceState::Stopped
    {
        let _ = svc.stop();
        let deadline = Instant::now() + Duration::from_secs(15);
        while Instant::now() < deadline {
            if svc.query_status().map(|s| s.current_state).unwrap_or(ServiceState::Stopped)
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
        let _ = std::fs::remove_dir_all(super::data_dir());
        println!("purged {}", super::data_dir().display());
    }
    Ok(())
}
