//! `bosphorus service <install|uninstall|run|status>` — Windows Service host.

use std::path::PathBuf;

mod install;
mod runner;
mod status;
mod uninstall;

pub const SERVICE_NAME: &str = "Bosphorus";
pub const SERVICE_DISPLAY: &str = "Bosphorus DPI Bypass";

/// `%ProgramData%\Bosphorus` — writable by SYSTEM, readable by everyone. The
/// service must not use `%LOCALAPPDATA%` (that resolves under
/// `C:\Windows\System32\config\systemprofile` for the SYSTEM account).
pub fn data_dir() -> PathBuf {
    std::env::var_os("ProgramData")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"))
        .join("Bosphorus")
}
pub fn profiles_dir() -> PathBuf {
    data_dir().join("profiles")
}
pub fn logs_dir() -> PathBuf {
    data_dir().join("logs")
}

/// `args` is `std::env::args().skip(1)` — so `args[0] == "service"`.
pub fn dispatch(args: &[String]) -> anyhow::Result<()> {
    match args.get(1).map(String::as_str) {
        Some("install") => install::run(args),
        Some("uninstall") => uninstall::run(args),
        Some("run") => runner::run(),
        Some("status") => status::run(),
        other => {
            eprintln!("{}", crate::i18n::t(crate::i18n::Msg::SvcUsage));
            if other.is_some() {
                std::process::exit(2);
            }
            Ok(())
        }
    }
}

/// Translate a `windows_service` error, surfacing the "not elevated" case.
pub(crate) fn map_scm_err(e: windows_service::Error) -> anyhow::Error {
    if let windows_service::Error::Winapi(io) = &e {
        if io.raw_os_error() == Some(5) {
            return anyhow::anyhow!("{}", crate::i18n::t(crate::i18n::Msg::NeedAdmin));
        }
    }
    anyhow::anyhow!("SCM: {e}")
}
