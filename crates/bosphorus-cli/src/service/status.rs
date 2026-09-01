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
    let mut best: Option<(String, SystemTime)> = None;
    for entry in std::fs::read_dir(super::profiles_dir()).ok()?.flatten() {
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
    let age = SystemTime::now().duration_since(mtime).ok()?.as_secs();
    Some((name, age))
}
