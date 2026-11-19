//! `bosphorus service <install|uninstall|run|status>` — Windows Service host.

use std::path::PathBuf;

pub(crate) mod install;
mod runner;
pub(crate) mod status;
pub(crate) mod uninstall;

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

/// True if the `Bosphorus` service is registered with the SCM. No elevation
/// needed — a plain `CONNECT` + `QUERY_STATUS` open, same as `service status`.
/// Used by the double-click launcher to decide install vs. "already there".
pub fn is_installed() -> bool {
    use std::ffi::OsStr;
    use windows_service::service::ServiceAccess;
    use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
    ServiceManager::local_computer(None::<&OsStr>, ServiceManagerAccess::CONNECT)
        .and_then(|m| m.open_service(SERVICE_NAME, ServiceAccess::QUERY_STATUS))
        .is_ok()
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

/// Best-effort/strict helper to restrict a service data directory to SYSTEM and
/// Administrators on Windows (B5). No-op on other platforms.
pub(crate) fn harden_service_dir(path: &std::path::Path) -> std::io::Result<()> {
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        use windows::core::PCWSTR;
        use windows::Win32::Foundation::{LocalFree, BOOL, HLOCAL};
        use windows::Win32::Security::Authorization::{
            ConvertStringSecurityDescriptorToSecurityDescriptorW, SetNamedSecurityInfoW,
            SE_FILE_OBJECT,
        };
        use windows::Win32::Security::{
            GetSecurityDescriptorDacl, ACL, DACL_SECURITY_INFORMATION,
            PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
        };

        // Protected DACL: Administrators and SYSTEM full control, inherited by children.
        let sddl: Vec<u16> = "D:P(A;OICI;FA;;;BA)(A;OICI;FA;;;SY)\0"
            .encode_utf16()
            .collect();
        let mut sd = PSECURITY_DESCRIPTOR::default();
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                PCWSTR(sddl.as_ptr()),
                1, // SDDL_REVISION_1
                &mut sd,
                None,
            )
            .ok()
            .map_err(|e| std::io::Error::from_raw_os_error(e.code().0))?;

            let mut present = BOOL(0);
            let mut defaulted = BOOL(0);
            let mut dacl: *mut ACL = std::ptr::null_mut();
            if !GetSecurityDescriptorDacl(sd, &mut present, &mut dacl, &mut defaulted).as_bool() {
                let err = std::io::Error::last_os_error();
                let _ = LocalFree(HLOCAL(sd.0));
                return Err(err);
            }
            if !present.as_bool() || dacl.is_null() {
                let _ = LocalFree(HLOCAL(sd.0));
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "security descriptor has no DACL",
                ));
            }

            let path_w: Vec<u16> = path
                .as_os_str()
                .encode_wide()
                .chain(std::iter::once(0))
                .collect();
            let status = SetNamedSecurityInfoW(
                PCWSTR(path_w.as_ptr()),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                None,
                None,
                Some(dacl),
                None,
            );
            let _ = LocalFree(HLOCAL(sd.0));
            if status.0 != 0 {
                return Err(std::io::Error::from_raw_os_error(status.0 as i32));
            }
        }
        Ok(())
    }
    #[cfg(not(windows))]
    {
        let _ = path;
        Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn data_dirs_are_nested_under_bosphorus() {
        let d = data_dir();
        assert!(d.ends_with("Bosphorus"), "data_dir = {d:?}");
        assert_eq!(profiles_dir(), d.join("profiles"));
        assert_eq!(logs_dir(), d.join("logs"));
    }

    #[test]
    fn dispatch_without_a_subcommand_prints_usage_and_returns_ok() {
        // `args[0] == "service"`, nothing after it -> usage, no SCM call, Ok.
        assert!(dispatch(&["service".to_string()]).is_ok());
    }
}
