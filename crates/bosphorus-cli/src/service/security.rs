//! Best-effort hardening for service data/profile/log directories on Windows.
//!
//! G14/B5: `%ProgramData%\Bosphorus` and its sensitive subdirs must not be
//! world-readable/writable with default inherited ACLs. We apply a protected DACL
//! granting full control only to LocalSystem (SY) and Built-in Administrators
//! (BA) so local non-admin users cannot read or tamper with profiles/logs.

use std::path::Path;

/// Harden `dir` when it is (or lives under) the default service data tree.
/// No-op for non-default/custom paths and on non-Windows targets.
pub fn harden_default_service_dir(dir: &Path) {
    if !is_default_service_path(dir) {
        return;
    }
    if let Err(e) = harden_dir(dir) {
        tracing::warn!(path = %dir.display(), error = %e, "failed to harden service data directory ACL");
    }
}

/// Like [`harden_default_service_dir`] but returns the error so callers that
/// run in a security-sensitive setup path (install) can fail closed.
pub fn try_harden_default_service_dir(dir: &Path) -> std::io::Result<()> {
    if !is_default_service_path(dir) {
        return Ok(());
    }
    harden_dir(dir)
}

/// Harden the default `%ProgramData%\Bosphorus` root and its known subdirs.
/// Best-effort; intended for runtime/startup paths.
pub fn harden_default_data_tree() {
    for dir in [super::data_dir(), super::profiles_dir(), super::logs_dir()] {
        let _ = std::fs::create_dir_all(&dir);
        harden_default_service_dir(&dir);
    }
}

fn is_default_service_path(path: &Path) -> bool {
    let data = super::data_dir();
    path == data
        || path == super::profiles_dir()
        || path == super::logs_dir()
        || path.starts_with(&data)
}

#[cfg(windows)]
fn harden_dir(dir: &Path) -> std::io::Result<()> {
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{BOOL, HLOCAL};
    use windows::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SetNamedSecurityInfoW, SE_FILE_OBJECT,
    };
    use windows::Win32::Security::{
        GetSecurityDescriptorDacl, ACL, DACL_SECURITY_INFORMATION,
        PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
    };
    use windows::Win32::System::Memory::LocalFree;

    // Protected DACL: no inheritance from parent; grant Full Control to
    // LocalSystem and Built-in Administrators. (OI)(CI) lets child files/dirs
    // inherit this ACE so newly written profiles/logs/temp files are covered.
    const SDDL: &str = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)\0";

    let wide: Vec<u16> = SDDL.encode_utf16().collect();
    let mut sd = PSECURITY_DESCRIPTOR::default();
    // SAFETY: `wide` is NUL-terminated UTF-16 SDDL_REVISION_1; `sd` receives a
    // LocalAlloc'd descriptor that must be freed with LocalFree.
    unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            PCWSTR::from_raw(wide.as_ptr()),
            1u32, // SDDL_REVISION_1
            &mut sd,
            None,
        )
        .ok()
        .map_err(|e| std::io::Error::from_raw_os_error(e.code().0))?;
    }

    let result = (|| unsafe {
        let mut present: i32 = 0;
        let mut dacl: *mut ACL = std::ptr::null_mut();
        let mut defaulted: i32 = 0;
        GetSecurityDescriptorDacl(sd, &mut present, &mut dacl, &mut defaulted)
            .ok()
            .map_err(|e| std::io::Error::from_raw_os_error(e.code().0))?;
        if present == 0 || dacl.is_null() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "SDDL conversion produced no DACL",
            ));
        }

        let path_w: Vec<u16> = std::os::windows::ffi::OsStrExt::encode_wide(dir.as_os_str())
            .chain(std::iter::once(0))
            .collect();
        SetNamedSecurityInfoW(
            PCWSTR::from_raw(path_w.as_ptr()),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            None,
            None,
            Some(dacl),
            None,
        )
        .ok()
        .map_err(|e| std::io::Error::from_raw_os_error(e.code().0))
    })();

    // SAFETY: `sd` was allocated by ConvertStringSecurityDescriptorToSecurityDescriptorW.
    unsafe {
        let _ = LocalFree(HLOCAL(sd.0 as _));
    }
    result
}

#[cfg(not(windows))]
fn harden_dir(_dir: &Path) -> std::io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn non_default_paths_are_not_considered_service_paths() {
        // Unrelated/custom dirs must never be treated as the service data tree.
        assert!(!is_default_service_path(Path::new(
            r"C:\Users\someone\profiles"
        )));
        assert!(!is_default_service_path(Path::new("/tmp/custom-profiles")));
    }

    #[test]
    fn default_service_paths_are_recognized() {
        let data = crate::service::data_dir();
        assert!(is_default_service_path(&data));
        assert!(is_default_service_path(&crate::service::profiles_dir()));
        assert!(is_default_service_path(&crate::service::logs_dir()));
        assert!(is_default_service_path(&data.join("profiles")));
        assert!(is_default_service_path(&data.join("logs")));
        assert!(is_default_service_path(&data.join("some").join("nested")));
    }

    #[test]
    fn harden_dir_is_best_effort_noop_off_windows() {
        // On non-Windows hosts this must not fail; on Windows it may succeed or
        // fail depending on privileges, but must not panic.
        let _ = harden_dir(&std::env::temp_dir());
    }

    #[test]
    fn try_harden_skips_custom_paths() {
        // A custom path outside the service tree is left untouched (and must not
        // error just because we lack privilege to change its ACL).
        let custom = std::env::temp_dir().join("bosphorus-g14-custom-path");
        assert!(try_harden_default_service_dir(&custom).is_ok());
    }
}
