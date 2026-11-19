//! `bosphorus service install [--lang en|tr] [--enable-overlap] [--quic P]
//!    [--profile-dir <p>] [--install-dir <p>] [--start auto|demand] [--force]`

use std::ffi::{CString, OsStr, OsString};
use std::path::PathBuf;
use std::time::Duration;

use bosphorus_core::config::QuicPolicy;

use windows_service::service::{
    ServiceAccess, ServiceAction, ServiceActionType, ServiceErrorControl, ServiceFailureActions,
    ServiceFailureResetPeriod, ServiceInfo, ServiceStartType, ServiceType,
};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

use bosphorus_divert::{DivertError, Layer, OpenFlags, WinDivertHandle};

pub struct Opts {
    pub lang: crate::i18n::Lang,
    pub enable_overlap: bool,
    pub quic: QuicPolicy,
    pub profile_dir: Option<PathBuf>,
    pub install_dir: Option<PathBuf>,
    pub start_demand: bool,
    pub force: bool,
}

pub fn run(args: &[String]) -> anyhow::Result<()> {
    let opts = Opts {
        lang: crate::resolve_lang(args),
        enable_overlap: args.iter().any(|a| a == "--enable-overlap"),
        quic: crate::parse_quic(args)?,
        profile_dir: value_after(args, "--profile-dir").map(PathBuf::from),
        install_dir: value_after(args, "--install-dir").map(PathBuf::from),
        start_demand: value_after(args, "--start")
            .map(|s| s.eq_ignore_ascii_case("demand"))
            .unwrap_or(false),
        force: args.iter().any(|a| a == "--force"),
    };
    crate::i18n::set(opts.lang);

    // Elevated re-spawn from the double-click launcher: its console is hidden,
    // so also surface the outcome in a MessageBox.
    let from_launcher = args
        .iter()
        .any(|a| a == crate::launcher::FROM_LAUNCHER_FLAG);
    let res = install(&opts);
    if from_launcher {
        crate::launcher::show_install_result(&res);
    }
    res
}

/// Shared with the interactive launcher (4b). Console output only — the
/// launcher adds the MessageBox itself from the returned `Result`.
pub fn install(opts: &Opts) -> anyhow::Result<()> {
    println!("{}", crate::i18n::t(crate::i18n::Msg::DiscoveryWarning));
    println!();

    if let Some(profile_dir) = &opts.profile_dir {
        validate_service_profile_dir(profile_dir)?;
    }

    let exe = resolve_exe(opts)?;
    preflight_windivert(opts.force)?;

    let profile_dir = opts.profile_dir.clone().unwrap_or_else(super::profiles_dir);
    std::fs::create_dir_all(&profile_dir)?;
    std::fs::create_dir_all(super::logs_dir())?;

    let mgr = ServiceManager::local_computer(
        None::<&OsStr>,
        ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE,
    )
    .map_err(super::map_scm_err)?;

    let launch_arguments = build_launch_arguments(opts);

    let info = ServiceInfo {
        name: OsString::from(super::SERVICE_NAME),
        display_name: OsString::from(super::SERVICE_DISPLAY),
        service_type: ServiceType::OWN_PROCESS,
        start_type: if opts.start_demand {
            ServiceStartType::OnDemand
        } else {
            ServiceStartType::AutoStart
        },
        error_control: ServiceErrorControl::Normal,
        executable_path: exe,
        launch_arguments,
        dependencies: vec![],
        account_name: None, // LocalSystem
        account_password: None,
    };

    let svc = mgr
        .create_service(
            &info,
            ServiceAccess::CHANGE_CONFIG
                | ServiceAccess::START
                | ServiceAccess::QUERY_STATUS
                | ServiceAccess::DELETE,
        )
        .map_err(super::map_scm_err)?;

    let _ = svc.set_description(super::SERVICE_DISPLAY);
    // Plain AutoStart, not delayed: Windows holds a delayed-auto-start
    // service back ~1-2 minutes after boot to avoid competing with more
    // critical services, but a DPI bypass should be intercepting before the
    // user's other apps start making blocked connections, not after.
    let _ = svc.update_failure_actions(ServiceFailureActions {
        reset_period: ServiceFailureResetPeriod::After(Duration::from_secs(86_400)),
        reboot_msg: None,
        command: None,
        actions: Some(vec![
            ServiceAction {
                action_type: ServiceActionType::Restart,
                delay: Duration::from_secs(5),
            },
            ServiceAction {
                action_type: ServiceActionType::Restart,
                delay: Duration::from_secs(30),
            },
            ServiceAction {
                action_type: ServiceActionType::None,
                delay: Duration::ZERO,
            },
        ]),
    });
    let _ = svc.set_failure_actions_on_non_crash_failures(true);

    if let Err(e) = svc.start::<&OsStr>(&[]) {
        let start_err = super::map_scm_err(e);
        // B6: a failed start leaves a registered but broken service; roll it back.
        if let Err(del_err) = svc.delete() {
            return Err(anyhow::anyhow!(
                "{start_err}; also failed to roll back service registration: {}",
                super::map_scm_err(del_err)
            ));
        }
        return Err(anyhow::anyhow!(
            "{start_err} (service registration rolled back)"
        ));
    }

    println!("{}", crate::i18n::svc_created(super::SERVICE_NAME));
    println!("{}", crate::i18n::install_verification());
    Ok(())
}

/// The `service run` argv the SCM launches the service with. Kept separate
/// from [`install`] so it can be unit-tested without touching the SCM.
///
/// Callers that persist these arguments for the elevated service must ensure any
/// explicit `--profile-dir` has been accepted by [`validate_service_profile_dir`]
/// (G13: do not persist arbitrary service data paths).
fn build_launch_arguments(opts: &Opts) -> Vec<OsString> {
    let mut v: Vec<OsString> = vec![
        "service".into(),
        "run".into(),
        "--lang".into(),
        lang_code(opts.lang).into(),
    ];
    if opts.enable_overlap {
        v.push("--enable-overlap".into());
    }
    // Always written out, not just when non-default: the stored argv is what
    // the service runs for years, and it should not silently change meaning if
    // a later build moves the default.
    v.push("--quic".into());
    v.push(opts.quic.as_str().into());
    if let Some(p) = &opts.profile_dir {
        v.push("--profile-dir".into());
        v.push(p.clone().into_os_string());
    }
    v
}

fn lang_code(l: crate::i18n::Lang) -> &'static str {
    match l {
        crate::i18n::Lang::En => "en",
        crate::i18n::Lang::Tr => "tr",
    }
}

fn value_after<'a>(args: &'a [String], key: &str) -> Option<&'a str> {
    args.iter()
        .position(|a| a == key)
        .and_then(|i| args.get(i + 1))
        .map(String::as_str)
}

/// Absolute path to register as the service binary. `--install-dir` copies the
/// exe + the two WinDivert files there and points at the copy.
///
/// G1: a LocalSystem service must not run from a user-writable/transient
/// location. When no install dir is given, the current exe must already reside
/// in a trusted install location; when an install dir is given, that destination
/// must be a trusted install location (never a transient/user-profile/temp path).
/// G2: the relevant install/service-binary directory must be owned by a trusted
/// privileged principal (verified on Windows before copy/register).
/// G19: WinDivert collateral (`WinDivert.dll`, `WinDivert64.sys`) must pass
/// provenance/integrity verification before being copied or used (preflight runs after
/// resolution in the install flow). Missing/unverifiable/mismatching collateral fails closed.
fn resolve_exe(opts: &Opts) -> anyhow::Result<PathBuf> {
    let current = std::env::current_exe()?;
    let Some(dst_dir) = &opts.install_dir else {
        validate_service_install_target(&current, false)?;
        let install_dir = current
            .parent()
            .unwrap_or_else(|| std::path::Path::new("."));
        validate_service_install_ancestor_trust_chain(install_dir, false)?;
        // No copy: the service/preflight will use collateral colocated with the current exe.
        verify_windivert_collateral_in_dir(
            install_dir,
            "service install/preflight from the current executable directory (no --install-dir)",
        )?;
        return Ok(current);
    };

    validate_service_install_target(dst_dir, true)?;
    std::fs::create_dir_all(dst_dir)?;
    validate_service_install_ancestor_trust_chain(dst_dir, true)?;
    let src_dir = current
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."));
    // Verify source collateral before copying to the trusted install destination and before
    // preflight/use in this process (G19, fail closed; `--force` does not bypass integrity).
    verify_windivert_collateral_in_dir(
        src_dir,
        "copying WinDivert collateral from the current executable directory to --install-dir",
    )?;
    let exe_dst = dst_dir.join("bosphorus.exe");
    std::fs::copy(&current, &exe_dst)?;
    for expected in WINDIVERT_COLLATERAL_FILES {
        let src = src_dir.join(expected.file_name);
        let dst = dst_dir.join(expected.file_name);
        std::fs::copy(&src, &dst).map_err(|e| {
            anyhow::anyhow!(
                "failed to copy verified WinDivert collateral {} to {}: {e}",
                src.display(),
                dst.display()
            )
        })?;
    }
    Ok(exe_dst)
}

/// Validate that `path` is an acceptable LocalSystem service binary/install target (G1).
///
/// Policy (lexical): reject obviously transient or user-writable locations and require
/// the path to reside under a trusted system program location (`Program Files` /
/// `Program Files (x86)`). G2 verifies the relevant install directory owner on
/// Windows, and G3 verifies trust of the relevant ancestor-chain directories
/// (owner/reparse checks on Windows, fail-closed when unverifiable).
///
/// `explicit_install_dir` controls the actionable error guidance.
fn validate_service_install_target(
    path: &std::path::Path,
    explicit_install_dir: bool,
) -> anyhow::Result<()> {
    let raw = path.to_string_lossy();
    if raw.trim().is_empty() {
        anyhow::bail!("install path is empty; use --install-dir with a safe path such as C:\\Program Files\\Bosphorus");
    }

    if let Some(reason) = unsafe_install_target_reason(path) {
        if explicit_install_dir {
            anyhow::bail!(
                "refusing to install the LocalSystem service into an unsafe location ({}): {}\n\
                 choose a safe --install-dir under a protected program location, e.g. C:\\Program Files\\Bosphorus",
                reason,
                path.display()
            );
        }
        anyhow::bail!(
            "refusing to install the LocalSystem service from an unsafe location ({}): {}\n\
             move the executable into a protected program location or re-run with \
             --install-dir \"C:\\Program Files\\Bosphorus\"",
            reason,
            path.display()
        );
    }

    if !is_trusted_service_program_location(path) {
        if explicit_install_dir {
            anyhow::bail!(
                "refusing to install the LocalSystem service into a non-trusted location: {}\n\
                 --install-dir must point to a protected program location such as \
                 C:\\Program Files\\Bosphorus (G2/G3 verify directory and ancestor trust on Windows)",
                path.display()
            );
        }
        anyhow::bail!(
            "refusing to install the LocalSystem service from a non-trusted location: {}\n\
             the current executable is not in a protected program location. Move it under \
             C:\\Program Files\\Bosphorus or re-run with --install-dir \"C:\\Program Files\\Bosphorus\"",
            path.display()
        );
    }

    Ok(())
}

/// Directories in the install path that must be trusted for a LocalSystem service
/// binary/install directory (G3): the directory itself and every ancestor up to
/// the filesystem root/prefix, in nearest-to-root-last order is not required, but
/// we return them from leaf to root as produced by [`std::path::Path::ancestors`].
fn relevant_install_ancestor_dirs(path: &std::path::Path) -> Vec<PathBuf> {
    path.ancestors().map(PathBuf::from).collect()
}

/// Verify trust of the relevant install/service-binary directory ancestor chain (G3).
///
/// Policy: every directory from `install_dir` up to its filesystem root must be
/// verifiably trusted. On Windows, each ancestor is rejected if it is a reparse
/// point (symlink/junction/mount point, which can redirect path resolution outside
/// the intended trusted location) or if its owner SID is not a trusted privileged
/// principal (SYSTEM, Administrators, TrustedInstaller), reusing G2 owner-trust
/// primitives. Any unverifiable ancestor or API failure fails closed with an
/// actionable error identifying the affected ancestor.
///
/// Rationale (MCP/MS Learn): Windows service binaries run with high privilege;
/// writable/untrusted or redirected path components can enable tampering/hijacking.
/// `GetNamedSecurityInfoW`/security descriptors are queried per path component on
/// Windows; reparse-point detection uses `symlink_metadata` file attributes.
/// On non-Windows this check cannot be enforced with Windows security APIs, so it
/// fails closed (Windows runtime behavior is SUSPECTED/unverified here).
fn validate_service_install_ancestor_trust_chain(
    install_dir: &std::path::Path,
    explicit_install_dir: bool,
) -> anyhow::Result<()> {
    #[cfg(windows)]
    {
        for ancestor in relevant_install_ancestor_dirs(install_dir) {
            if ancestor.as_os_str().is_empty() {
                continue;
            }
            validate_install_ancestor_entry(&ancestor, install_dir, explicit_install_dir)?;
        }
        Ok(())
    }
    #[cfg(not(windows))]
    {
        let _ = install_dir;
        let _ = explicit_install_dir;
        anyhow::bail!(
            "cannot verify install directory ancestor trust chain on this platform (G3 requires Windows security APIs and reparse-point checks); \
             refusing to install a LocalSystem service without ancestor trust verification"
        )
    }
}

#[cfg(windows)]
fn validate_install_ancestor_entry(
    ancestor: &std::path::Path,
    install_dir: &std::path::Path,
    explicit_install_dir: bool,
) -> anyhow::Result<()> {
    if is_reparse_point(ancestor).map_err(|e| {
        ancestor_verification_error(
            ancestor,
            install_dir,
            explicit_install_dir,
            &format!("cannot determine reparse-point status: {e}"),
        )
    })? {
        anyhow::bail!(ancestor_untrusted_message(
            ancestor,
            install_dir,
            explicit_install_dir,
            "directory is a reparse point (symlink/junction/mount point), which is not trusted for a LocalSystem service install path (G3)"
        ));
    }

    let owner_sid = query_directory_owner_sid(ancestor).map_err(|e| {
        ancestor_verification_error(
            ancestor,
            install_dir,
            explicit_install_dir,
            &format!("cannot verify owner: {e}"),
        )
    })?;
    if !is_trusted_install_owner_sid(&owner_sid) {
        anyhow::bail!(ancestor_untrusted_message(
            ancestor,
            install_dir,
            explicit_install_dir,
            &format!(
                "directory owner SID {owner_sid} is not trusted (trusted: NT AUTHORITY\\SYSTEM S-1-5-18, \
                 BUILTIN\\Administrators S-1-5-32-544, NT SERVICE\\TrustedInstaller \
                 S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)"
            )
        ));
    }

    Ok(())
}

#[cfg(windows)]
fn is_reparse_point(path: &std::path::Path) -> std::io::Result<bool> {
    use std::os::windows::fs::MetadataExt;

    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
    let md = std::fs::symlink_metadata(path)?;
    Ok(md.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0)
}

#[cfg(windows)]
fn ancestor_verification_error(
    ancestor: &std::path::Path,
    install_dir: &std::path::Path,
    explicit_install_dir: bool,
    detail: &str,
) -> anyhow::Error {
    if explicit_install_dir {
        anyhow::anyhow!(
            "cannot verify trust of install path ancestor {} for --install-dir {}: {}\n\
             refusing to install the LocalSystem service without ancestor trust verification (G3). \
             Ensure every ancestor is a real directory under a protected program location \
             (e.g. C:\\Program Files\\Bosphorus) with a trusted owner",
            ancestor.display(),
            install_dir.display(),
            detail
        )
    } else {
        anyhow::anyhow!(
            "cannot verify trust of install path ancestor {} for {}: {}\n\
             refusing to install the LocalSystem service from this location without ancestor trust verification (G3). \
             Move the executable under C:\\Program Files\\Bosphorus or use --install-dir",
            ancestor.display(),
            install_dir.display(),
            detail
        )
    }
}

#[cfg(windows)]
fn ancestor_untrusted_message(
    ancestor: &std::path::Path,
    install_dir: &std::path::Path,
    explicit_install_dir: bool,
    reason: &str,
) -> String {
    if explicit_install_dir {
        format!(
            "refusing to install the LocalSystem service into --install-dir {} because ancestor {} is untrusted: {}\n\
             Every ancestor of the install directory must be a trusted, non-reparse directory owned by \
             SYSTEM, Administrators, or TrustedInstaller (G3). Choose a protected --install-dir such as \
             C:\\Program Files\\Bosphorus",
            install_dir.display(),
            ancestor.display(),
            reason
        )
    } else {
        format!(
            "refusing to install the LocalSystem service from {} because ancestor {} is untrusted: {}\n\
             Every ancestor of the install directory must be a trusted, non-reparse directory owned by \
             SYSTEM, Administrators, or TrustedInstaller (G3). Move the executable under \
             C:\\Program Files\\Bosphorus or use --install-dir",
            install_dir.display(),
            ancestor.display(),
            reason
        )
    }
}

/// Well-known SIDs accepted as trusted owners for a LocalSystem service install directory (G2).
///
/// Policy rationale (MS Learn / Windows security model):
/// - `S-1-5-18` (NT AUTHORITY\SYSTEM / LocalSystem): built-in OS account.
/// - `S-1-5-32-544` (BUILTIN\Administrators): local administrators alias.
/// - `S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464`
///   (NT SERVICE\TrustedInstaller): Windows Modules Installer / TrustedInstaller service SID,
///   common owner of protected program locations.
/// Any other owner is treated as untrusted for a LocalSystem service binary directory.
fn is_trusted_install_owner_sid(owner_sid: &str) -> bool {
    owner_sid.eq_ignore_ascii_case("S-1-5-18")
        || owner_sid.eq_ignore_ascii_case("S-1-5-32-544")
        || owner_sid
            .eq_ignore_ascii_case("S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464")
}

/// Verify the relevant install/service-binary directory is owned by a trusted privileged
/// principal (G2). Fails closed with actionable errors if the owner is untrusted or cannot
/// be determined.
///
/// On Windows this queries the directory owner via `GetNamedSecurityInfoW`
/// (`OWNER_SECURITY_INFORMATION`, `SE_FILE_OBJECT`) and compares the owner SID against the
/// trusted set above. On non-Windows platforms the owner cannot be verified, so this
/// returns an explicit error (Windows runtime behavior is SUSPECTED/unverified here).
fn validate_service_install_directory_owner(
    install_dir: &std::path::Path,
    explicit_install_dir: bool,
) -> anyhow::Result<()> {
    #[cfg(windows)]
    {
        let owner_sid = query_directory_owner_sid(install_dir).map_err(|e| {
            owner_verification_error(install_dir, explicit_install_dir, &format!("{e}"))
        })?;
        if !is_trusted_install_owner_sid(&owner_sid) {
            anyhow::bail!(untrusted_owner_message(
                install_dir,
                explicit_install_dir,
                &owner_sid
            ));
        }
        Ok(())
    }
    #[cfg(not(windows))]
    {
        let _ = install_dir;
        let _ = explicit_install_dir;
        anyhow::bail!(
            "cannot verify install directory owner on this platform (G2 requires Windows security APIs); \
             refusing to install a LocalSystem service without owner verification"
        )
    }
}

#[cfg(windows)]
fn owner_verification_error(
    install_dir: &std::path::Path,
    explicit_install_dir: bool,
    detail: &str,
) -> anyhow::Error {
    if explicit_install_dir {
        anyhow::anyhow!(
            "cannot verify install directory owner for {}: {}\n\
             refusing to install the LocalSystem service into --install-dir without owner verification (G2). \
             Ensure the directory exists under a protected program location (e.g. C:\\Program Files\\Bosphorus) \
             and is owned by SYSTEM, Administrators, or TrustedInstaller",
            install_dir.display(),
            detail
        )
    } else {
        anyhow::anyhow!(
            "cannot verify install directory owner for {}: {}\n\
             refusing to install the LocalSystem service from this location without owner verification (G2). \
             Move the executable under C:\\Program Files\\Bosphorus or use --install-dir",
            install_dir.display(),
            detail
        )
    }
}

#[cfg(windows)]
fn untrusted_owner_message(
    install_dir: &std::path::Path,
    explicit_install_dir: bool,
    owner_sid: &str,
) -> String {
    if explicit_install_dir {
        format!(
            "refusing to install the LocalSystem service into an untrusted install directory: {}\n\
             directory owner SID {owner_sid} is not trusted for a LocalSystem service binary (G2). \
             Trusted owners: NT AUTHORITY\\SYSTEM (S-1-5-18), BUILTIN\\Administrators (S-1-5-32-544), \
             NT SERVICE\\TrustedInstaller (S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464). \
             Choose a protected --install-dir such as C:\\Program Files\\Bosphorus with a trusted owner",
            install_dir.display()
        )
    } else {
        format!(
            "refusing to install the LocalSystem service from an untrusted install directory: {}\n\
             directory owner SID {owner_sid} is not trusted for a LocalSystem service binary (G2). \
             Trusted owners: NT AUTHORITY\\SYSTEM (S-1-5-18), BUILTIN\\Administrators (S-1-5-32-544), \
             NT SERVICE\\TrustedInstaller (S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464). \
             Move the executable under C:\\Program Files\\Bosphorus or use --install-dir",
            install_dir.display()
        )
    }
}

#[cfg(windows)]
fn query_directory_owner_sid(path: &std::path::Path) -> anyhow::Result<String> {
    use std::os::windows::ffi::OsStrExt;

    use windows::core::{PCWSTR, PWSTR};
    use windows::Win32::Foundation::{LocalFree, HLOCAL, WIN32_ERROR};
    use windows::Win32::Security::Authorization::{
        ConvertSidToStringSidW, GetNamedSecurityInfoW, SE_FILE_OBJECT,
    };
    use windows::Win32::Security::{OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID};

    let wide: Vec<u16> = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    let mut owner_sid = PSID::default();
    let mut sd = PSECURITY_DESCRIPTOR::default();
    // SAFETY: `wide` is a NUL-terminated UTF-16 path; output pointers receive
    // views into or ownership of `sd` as documented by GetNamedSecurityInfoW.
    let status = unsafe {
        GetNamedSecurityInfoW(
            PCWSTR(wide.as_ptr()),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION,
            Some(&mut owner_sid),
            None,
            None,
            None,
            Some(&mut sd),
        )
    };
    if status != WIN32_ERROR(0) {
        anyhow::bail!(
            "GetNamedSecurityInfoW failed with WIN32_ERROR({})",
            status.0
        );
    }
    if sd.is_invalid() {
        anyhow::bail!("GetNamedSecurityInfoW returned no security descriptor");
    }

    struct LocalAllocGuard(HLOCAL);
    impl Drop for LocalAllocGuard {
        fn drop(&mut self) {
            if !self.0.is_invalid() {
                // SAFETY: handle was allocated by a Windows security API and is
                // freed exactly once here; contained pointers become invalid.
                unsafe {
                    let _ = LocalFree(self.0);
                }
            }
        }
    }
    let _sd_guard = LocalAllocGuard(HLOCAL(sd.0));

    if owner_sid.is_invalid() {
        anyhow::bail!("security descriptor does not contain an owner SID");
    }

    let mut sid_str = PWSTR::null();
    // SAFETY: `owner_sid` is valid while `_sd_guard` is alive; `sid_str`
    // receives a LocalAlloc-allocated string on success.
    unsafe { ConvertSidToStringSidW(owner_sid, &mut sid_str) }
        .ok()
        .map_err(|e| anyhow::anyhow!("ConvertSidToStringSidW failed: {e}"))?;
    let _sid_guard = LocalAllocGuard(HLOCAL(sid_str.as_ptr() as _));

    // SAFETY: `sid_str` is a valid NUL-terminated UTF-16 string allocated by
    // ConvertSidToStringSidW and guarded by `_sid_guard`.
    let sid = unsafe { sid_str.to_string() }
        .map_err(|e| anyhow::anyhow!("owner SID is not valid UTF-16: {e}"))?;
    Ok(sid)
}

fn unsafe_install_target_reason(path: &std::path::Path) -> Option<&'static str> {
    let norm = normalized_policy_path(path);
    // Order matters: report the most specific/common reason first.
    const MARKERS: &[(&str, &str)] = &[
        ("\\downloads\\", "user Downloads directory"),
        ("\\desktop\\", "user Desktop directory"),
        ("\\appdata\\", "user AppData directory"),
        ("\\temp\\", "temporary directory"),
        ("\\tmp\\", "temporary directory"),
        ("\\temporary", "temporary directory"),
        ("\\users\\", "user profile directory"),
        ("\\recycle", "recycle bin"),
        ("\\target\\debug", "build output directory"),
        ("\\target\\release", "build output directory"),
        ("\\target\\", "build output directory"),
        ("/downloads/", "user Downloads directory"),
        ("/desktop/", "user Desktop directory"),
        ("/appdata/", "user AppData directory"),
        ("/tmp/", "temporary directory"),
        ("/var/tmp/", "temporary directory"),
        ("/users/", "user profile directory"),
        ("/home/", "user home directory"),
        ("/target/debug", "build output directory"),
        ("/target/release", "build output directory"),
        ("/target/", "build output directory"),
    ];
    for (needle, reason) in MARKERS {
        if contains_policy_segment(&norm, needle) {
            return Some(*reason);
        }
    }
    None
}

/// True if `path` is under a trusted system program location for service binaries.
/// This is a lexical G1 check (no ACL/owner verification; see G2/G3).
fn is_trusted_service_program_location(path: &std::path::Path) -> bool {
    let norm = normalized_policy_path(path);
    const ROOTS: &[&str] = &["\\program files\\", "\\program files (x86)\\"];
    for root in ROOTS {
        if contains_policy_segment(&norm, root) {
            return true;
        }
    }
    // Also accept the root itself (path ends with the trusted directory name).
    const ROOT_SUFFIXES: &[&str] = &["\\program files", "\\program files (x86)"];
    for suffix in ROOT_SUFFIXES {
        if norm.ends_with(suffix) {
            return true;
        }
    }
    false
}

/// Validate that an explicit `--profile-dir` is safe to persist and use as a
/// LocalSystem service data path (G13).
///
/// The service reads/writes discovery profiles (and is colocated with service data
/// under the default ProgramData location). Persisting an arbitrary attacker-chosen
/// path can direct service reads/writes to unsafe locations (tampering/leakage).
/// Policy (lexical, fail closed): require an absolute local drive path, reject
/// UNC/device/relative/empty paths, reject paths under obviously unsafe or
/// user-writable/transient locations, and require the path to reside under a
/// protected service data/program location (ProgramData or Program Files /
/// Program Files (x86)). The default service profile directory is preserved.
/// Windows ACL/owner/reparse behavior of the chosen directory contents is out of
/// scope for this lexical check and is SUSPECTED/unverified on non-Windows hosts.
fn validate_service_profile_dir(path: &std::path::Path) -> anyhow::Result<()> {
    let raw = path.to_string_lossy();
    if raw.trim().is_empty() {
        anyhow::bail!(
            "refusing to use an empty --profile-dir for the LocalSystem service; \
             choose a protected data path such as {}",
            super::profiles_dir().display()
        );
    }

    if !is_absolute_local_service_path(path) {
        anyhow::bail!(
            "refusing to use a non-absolute or non-local --profile-dir for the LocalSystem service: {}\n\
             --profile-dir must be an absolute local drive path (for example under C:\\ProgramData\\Bosphorus\\profiles). \
             UNC/device/relative paths are not accepted for persisted service data paths",
            path.display()
        );
    }

    if let Some(reason) = unsafe_install_target_reason(path) {
        anyhow::bail!(
            "refusing to use an unsafe --profile-dir for the LocalSystem service ({}): {}\n\
             choose a protected service data path such as {}",
            reason,
            path.display(),
            super::profiles_dir().display()
        );
    }

    if !is_allowed_service_data_location(path) {
        anyhow::bail!(
            "refusing to use --profile-dir outside protected service locations: {}\n\
             explicit profile directories must reside under ProgramData or a protected program location \
             (Program Files / Program Files (x86)), for example {}",
            path.display(),
            super::profiles_dir().display()
        );
    }

    Ok(())
}

/// True for an absolute local drive path suitable for a persisted service path.
/// Rejects relative paths and UNC/device/verbatim paths (`\\...\`), which are
/// risky or ambiguous for LocalSystem service arguments. Accepts Windows drive-
/// absolute forms (`C:\...`) even when checked on non-Windows hosts so policy
/// tests remain runnable on Linux (Windows runtime path semantics SUSPECTED).
fn is_absolute_local_service_path(path: &std::path::Path) -> bool {
    let s = path.to_string_lossy();
    if s.starts_with("\\\\") {
        return false;
    }
    if path.is_absolute() {
        return !s.starts_with("\\\\");
    }
    let b = s.as_bytes();
    b.len() >= 3 && b[0].is_ascii_alphabetic() && b[1] == b':' && (b[2] == b'\\' || b[2] == b'/')
}

/// True if `path` is under a protected location appropriate for persisted service
/// data/profile paths (G13 lexical policy): ProgramData or a trusted program
/// location.
fn is_allowed_service_data_location(path: &std::path::Path) -> bool {
    is_program_data_location(path) || is_trusted_service_program_location(path)
}

/// Lexical check for paths under a `ProgramData` directory component.
fn is_program_data_location(path: &std::path::Path) -> bool {
    contains_policy_segment(&normalized_policy_path(path), "\\programdata\\")
}

/// Lowercased path string with separators normalized for lexical policy checks.
/// A trailing separator is appended so segment markers like `\temp\` match terminal dirs.
fn normalized_policy_path(path: &std::path::Path) -> String {
    let mut s = path
        .to_string_lossy()
        .replace('/', "\\")
        .to_ascii_lowercase();
    if !s.ends_with('\\') {
        s.push('\\');
    }
    s
}

fn contains_policy_segment(norm_with_trailing_sep: &str, needle: &str) -> bool {
    // `norm_with_trailing_sep` always ends with '\' (or includes normalized '/'). Most
    // needles are written with separators; direct containment is sufficient for our
    // marker set after normalization.
    norm_with_trailing_sep.contains(needle)
}

/// Expected WinDivert collateral shipped with this release (WinDivert 2.2.2-A, x64).
///
/// G19: installation must only copy/use collateral whose provenance and integrity are
/// verified. Policy is fail-closed: missing, unreadable, unverifiable, or mismatching
/// collateral is rejected with an actionable error (never silently accepted).
///
/// Provenance/integrity mechanism (defensible, Linux-testable): pinned SHA-256 hashes and
/// exact file sizes for the exact x64 files this installer copies/uses
/// (`WinDivert.dll`, `WinDivert64.sys`). These match the bundled
/// `assets/WinDivert-2.2.2-A/x64/` artifacts in this repository (verified locally) and are
/// corroborated by public provenance references for WinDivert 2.2.2 x64 collateral (e.g.
/// SagerNet/sing-box pins `WinDivert64.sys` SHA-256 8da085... for 2.2.2; Manalyzer reports the
/// same driver hash for the 2.2.2 x64 driver). This provides explicit integrity verification
/// against a known-good release artifact set.
///
/// Windows Authenticode/signature verification (WinVerifyTrust / WINTRUST_FILE_INFO or catalog
/// verification for `.sys`) is recommended by Windows guidance, but WinTrust APIs are
/// Windows-runtime only and cannot be executed/validated on this Linux dev machine; any such
/// runtime signature check is therefore SUSPECTED/unverified here. The pinned-hash gate is the
/// enforced, cross-platform-verifiable control for this change.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ExpectedCollateral {
    file_name: &'static str,
    sha256_hex: &'static str,
    size_bytes: u64,
}

const WINDIVERT_COLLATERAL_FILES: &[ExpectedCollateral] = &[
    ExpectedCollateral {
        file_name: "WinDivert.dll",
        sha256_hex: "c1e060ee19444a259b2162f8af0f3fe8c4428a1c6f694dce20de194ac8d7d9a2",
        size_bytes: 47616,
    },
    ExpectedCollateral {
        file_name: "WinDivert64.sys",
        sha256_hex: "8da085332782708d8767bcace5327a6ec7283c17cfb85e40b03cd2323a90ddc2",
        size_bytes: 94144,
    },
];

/// Compute SHA-256 digest of `data` and return it as a lowercase hex string.
///
/// Small, self-contained implementation (FIPS 180-4) used so provenance verification does not
/// depend on external hashing crates and remains testable on Linux.
fn sha256_hex(data: &[u8]) -> String {
    let digest = sha256_digest(data);
    let mut s = String::with_capacity(64);
    for b in digest {
        use std::fmt::Write as _;
        let _ = write!(s, "{b:02x}");
    }
    s
}

fn sha256_digest(data: &[u8]) -> [u8; 32] {
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];

    let mut msg = data.to_vec();
    let bit_len = (data.len() as u64) * 8;
    msg.push(0x80);
    while (msg.len() % 64) != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());

    for chunk in msg.chunks(64) {
        let mut w = [0u32; 64];
        for (i, c) in chunk.chunks(4).enumerate().take(16) {
            w[i] = u32::from_be_bytes([c[0], c[1], c[2], c[3]]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }

        let mut a = h[0];
        let mut b = h[1];
        let mut c = h[2];
        let mut d = h[3];
        let mut e = h[4];
        let mut f = h[5];
        let mut g = h[6];
        let mut hh = h[7];
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }

    let mut out = [0u8; 32];
    for (i, v) in h.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&v.to_be_bytes());
    }
    out
}

/// Verify WinDivert collateral files in `dir` against pinned provenance/integrity expectations (G19).
///
/// `purpose` is included in errors to make remediation actionable (e.g. copy source vs
/// install/service location). Fails closed on any missing, unreadable, non-regular, or
/// mismatching file; does not silently accept unverified collateral.
fn verify_windivert_collateral_in_dir(dir: &std::path::Path, purpose: &str) -> anyhow::Result<()> {
    verify_windivert_collateral_in_dir_with_expected(dir, purpose, WINDIVERT_COLLATERAL_FILES)
}

fn verify_windivert_collateral_in_dir_with_expected(
    dir: &std::path::Path,
    purpose: &str,
    expected_files: &[ExpectedCollateral],
) -> anyhow::Result<()> {
    for expected in expected_files {
        let path = dir.join(expected.file_name);
        let md = std::fs::symlink_metadata(&path).map_err(|e| {
            anyhow::anyhow!(
                "G19: cannot verify WinDivert collateral for {purpose}: required file {} is missing or not accessible: {}\n\
                 expected a verified WinDivert 2.2.2-A x64 {} (sha256 {}) next to the executable/install source. \
                 Place the authentic unmodified file in {} or reinstall Bosphorus from a trusted release package.",
                path.display(),
                e,
                expected.file_name,
                expected.sha256_hex,
                dir.display()
            )
        })?;
        if !md.file_type().is_file() {
            anyhow::bail!(
                "G19: refusing unverified WinDivert collateral for {purpose}: {} is not a regular file\n\
                 expected a verified WinDivert 2.2.2-A x64 {} (sha256 {}). Replace it with the authentic unmodified file.",
                path.display(),
                expected.file_name,
                expected.sha256_hex
            );
        }
        if md.len() != expected.size_bytes {
            anyhow::bail!(
                "G19: refusing unverified WinDivert collateral for {purpose}: {} has unexpected size {} bytes (expected {} bytes)\n\
                 expected WinDivert 2.2.2-A x64 {} (sha256 {}). The file does not match the pinned provenance and will not be copied/used.",
                path.display(),
                md.len(),
                expected.size_bytes,
                expected.file_name,
                expected.sha256_hex
            );
        }
        let bytes = std::fs::read(&path).map_err(|e| {
            anyhow::anyhow!(
                "G19: cannot verify WinDivert collateral for {purpose}: failed to read {}: {}\n\
                 integrity/provenance verification could not be completed; refusing to copy/use unverified collateral.",
                path.display(),
                e
            )
        })?;
        let actual = sha256_hex(&bytes);
        if !actual.eq_ignore_ascii_case(expected.sha256_hex) {
            anyhow::bail!(
                "G19: refusing unverified WinDivert collateral for {purpose}: {} has SHA-256 {} but expected {}\n\
                 the file does not match the pinned WinDivert 2.2.2-A x64 provenance for {} and will not be copied/used. \
                 Replace it with the authentic unmodified file from a trusted Bosphorus/WinDivert 2.2.2-A source.",
                path.display(),
                actual,
                expected.sha256_hex,
                expected.file_name
            );
        }
    }
    Ok(())
}

/// Try to load the WinDivert driver right here. If it fails now, the SYSTEM
/// service would fail the same way at boot with no visible error.
fn preflight_windivert(force: bool) -> anyhow::Result<()> {
    // A filter that matches ~nothing — exercises driver load without touching
    // real traffic.
    let filter = CString::new("tcp.DstPort == 65535 and tcp.SrcPort == 65534").unwrap();
    match WinDivertHandle::open(&filter, Layer::Network, 0, OpenFlags::new()) {
        Ok(h) => {
            drop(h);
            Ok(())
        }
        Err(DivertError::Open(e)) if force => {
            eprintln!("{}", crate::i18n::preflight_warn_forced(&e.to_string()));
            Ok(())
        }
        Err(DivertError::Open(e)) => {
            anyhow::bail!("{}", crate::i18n::preflight_fail(&e.to_string()))
        }
        Err(e) if force => {
            eprintln!("pre-flight: {e} (--force)");
            Ok(())
        }
        Err(e) => anyhow::bail!("pre-flight WinDivertOpen: {e}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::i18n::Lang;

    fn opts(lang: Lang, enable_overlap: bool, profile_dir: Option<PathBuf>) -> Opts {
        Opts {
            lang,
            enable_overlap,
            quic: QuicPolicy::default(),
            profile_dir,
            install_dir: None,
            start_demand: false,
            force: false,
        }
    }

    fn as_strings(v: &[OsString]) -> Vec<String> {
        v.iter().map(|o| o.to_string_lossy().into_owned()).collect()
    }

    #[test]
    fn launch_arguments_minimal_is_just_service_run_lang_and_quic() {
        let v = build_launch_arguments(&opts(Lang::En, false, None));
        assert_eq!(
            as_strings(&v),
            ["service", "run", "--lang", "en", "--quic", "blocked"]
        );
    }

    #[test]
    fn launch_arguments_carry_overlap_and_profile_dir_in_order() {
        let v = build_launch_arguments(&opts(Lang::Tr, true, Some(PathBuf::from(r"C:\pd"))));
        assert_eq!(
            as_strings(&v),
            [
                "service",
                "run",
                "--lang",
                "tr",
                "--enable-overlap",
                "--quic",
                "blocked",
                "--profile-dir",
                r"C:\pd"
            ]
        );
    }

    #[test]
    fn launch_arguments_omit_profile_dir_key_when_none() {
        let v = build_launch_arguments(&opts(Lang::En, true, None));
        assert!(!v.iter().any(|o| o == "--profile-dir"));
        assert_eq!(
            as_strings(&v),
            [
                "service",
                "run",
                "--lang",
                "en",
                "--enable-overlap",
                "--quic",
                "blocked"
            ]
        );
    }

    #[test]
    fn the_quic_policy_is_pinned_into_the_stored_arguments() {
        // Spelled out even at the default, so a later change of default can't
        // silently repurpose an already-installed service.
        for p in [QuicPolicy::Off, QuicPolicy::Blocked, QuicPolicy::All] {
            let mut o = opts(Lang::En, false, None);
            o.quic = p;
            let v = as_strings(&build_launch_arguments(&o));
            let i = v
                .iter()
                .position(|a| a == "--quic")
                .expect("--quic present");
            assert_eq!(v[i + 1], p.as_str());
        }
    }

    #[test]
    fn lang_code_maps_both_languages() {
        assert_eq!(lang_code(Lang::En), "en");
        assert_eq!(lang_code(Lang::Tr), "tr");
    }

    #[test]
    fn value_after_reads_the_following_token_only() {
        let s = [
            "--profile-dir".to_string(),
            "p".to_string(),
            "--force".to_string(),
        ];
        assert_eq!(value_after(&s, "--profile-dir"), Some("p"));
        assert_eq!(value_after(&s, "--force"), None); // flag, nothing after
        assert_eq!(value_after(&s, "--missing"), None);
    }

    // --- G1: install target safety (lexical) ---------------------------------

    #[test]
    fn rejects_user_writable_or_transient_install_targets() {
        for p in [
            r"C:\Users\alice\Downloads",
            r"C:\Users\alice\Desktop\Bosphorus",
            r"C:\Users\alice\AppData\Local\Temp\Bosphorus",
            r"C:\Users\alice\AppData\Roaming\Bosphorus",
            r"C:\Temp\Bosphorus",
            r"C:\Windows\Temp\Bosphorus",
            r"C:\build\target\release",
            r"D:\work\target\debug\bosphorus",
            r"C:\Users\alice\bosphorus",
            "/tmp/bosphorus",
            "/home/alice/Downloads/bosphorus",
        ] {
            let path = PathBuf::from(p);
            assert!(
                unsafe_install_target_reason(&path).is_some(),
                "expected unsafe: {p}"
            );
            assert!(
                validate_service_install_target(&path, true).is_err(),
                "explicit install-dir must reject unsafe path: {p}"
            );
            assert!(
                validate_service_install_target(&path, false).is_err(),
                "implicit current-exe location must reject unsafe path: {p}"
            );
        }
    }

    #[test]
    fn accepts_trusted_program_files_install_targets() {
        for p in [
            r"C:\Program Files\Bosphorus",
            r"C:\Program Files (x86)\Bosphorus",
            r"D:\Program Files\Bosphorus",
            r"c:\program files\Custom Folder\Bosphorus",
            r"C:\Program Files",
        ] {
            let path = PathBuf::from(p);
            assert!(
                unsafe_install_target_reason(&path).is_none(),
                "expected not-unsafe: {p}"
            );
            assert!(
                is_trusted_service_program_location(&path),
                "expected trusted: {p}"
            );
            validate_service_install_target(&path, true)
                .unwrap_or_else(|e| panic!("explicit install-dir should accept {p}: {e}"));
            validate_service_install_target(&path, false)
                .unwrap_or_else(|e| panic!("implicit trusted location should accept {p}: {e}"));
        }
    }

    #[test]
    fn rejects_non_trusted_locations_even_if_not_obviously_transient() {
        // Without ancestor-chain trust verification (G3), arbitrary locations outside
        // protected program locations are not accepted as safe LocalSystem service
        // binary targets (G2 owner verification applies only to accepted/lexically-trusted dirs).
        for p in [
            r"C:\Tools\Bosphorus",
            r"D:\Bosphorus",
            r"C:\Bosphorus",
            r"C:\Opt\Bosphorus",
        ] {
            let path = PathBuf::from(p);
            assert!(
                unsafe_install_target_reason(&path).is_none(),
                "not in unsafe marker set: {p}"
            );
            assert!(
                !is_trusted_service_program_location(&path),
                "expected non-trusted: {p}"
            );
            let err = validate_service_install_target(&path, true).unwrap_err();
            let msg = err.to_string();
            assert!(
                msg.contains("--install-dir"),
                "actionable guidance expected for {p}: {msg}"
            );
        }
    }

    #[test]
    fn implicit_unsafe_location_error_mentions_install_dir_guidance() {
        let err = validate_service_install_target(
            &PathBuf::from(r"C:\Users\alice\Downloads\bosphorus.exe"),
            false,
        )
        .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("--install-dir"), "missing guidance: {msg}");
        assert!(
            msg.contains("unsafe location"),
            "missing reason context: {msg}"
        );
    }

    // --- G2: install directory owner trust -----------------------------------

    #[test]
    fn trusted_install_owner_sids_are_accepted_case_insensitively() {
        for sid in [
            "S-1-5-18",
            "s-1-5-18",
            "S-1-5-32-544",
            "s-1-5-32-544",
            "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464",
            "s-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464",
        ] {
            assert!(is_trusted_install_owner_sid(sid), "expected trusted: {sid}");
        }
    }

    #[test]
    fn untrusted_install_owner_sids_are_rejected() {
        for sid in [
            "S-1-5-21-1000-1000-1000-1001", // ordinary user
            "S-1-5-32-545",                 // Users group (not a trusted owner principal)
            "S-1-1-0",                      // Everyone
            "",
        ] {
            assert!(
                !is_trusted_install_owner_sid(sid),
                "expected untrusted: {sid}"
            );
        }
    }

    #[cfg(not(windows))]
    #[test]
    fn non_windows_owner_verification_fails_closed() {
        let err = validate_service_install_directory_owner(
            &PathBuf::from(r"C:\Program Files\Bosphorus"),
            true,
        )
        .unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("cannot verify install directory owner"),
            "missing fail-closed reason: {msg}"
        );
        assert!(msg.contains("G2"), "missing G2 context: {msg}");
    }

    // --- G3: install ancestor-chain trust ------------------------------------

    #[test]
    fn ancestor_chain_includes_leaf_and_progresses_to_root() {
        let path = PathBuf::from("/opt/bosphorus/bin");
        let chain = relevant_install_ancestor_dirs(&path);
        assert_eq!(
            chain,
            vec![
                PathBuf::from("/opt/bosphorus/bin"),
                PathBuf::from("/opt/bosphorus"),
                PathBuf::from("/opt"),
                PathBuf::from("/"),
            ]
        );
    }

    #[test]
    fn ancestor_chain_for_root_is_just_root() {
        let path = PathBuf::from("/");
        let chain = relevant_install_ancestor_dirs(&path);
        assert_eq!(chain, vec![PathBuf::from("/")]);
    }

    #[cfg(not(windows))]
    #[test]
    fn non_windows_ancestor_trust_verification_fails_closed() {
        let err = validate_service_install_ancestor_trust_chain(
            &PathBuf::from(r"C:\Program Files\Bosphorus"),
            true,
        )
        .unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("cannot verify install directory ancestor trust chain"),
            "missing fail-closed reason: {msg}"
        );
        assert!(msg.contains("G3"), "missing G3 context: {msg}");
        assert!(
            msg.contains("reparse-point"),
            "missing reparse-point context: {msg}"
        );
    }

    #[cfg(not(windows))]
    #[test]
    fn non_windows_ancestor_trust_verification_fails_closed_for_implicit_location() {
        let err = validate_service_install_ancestor_trust_chain(
            &PathBuf::from(r"C:\Program Files\Bosphorus"),
            false,
        )
        .unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("cannot verify install directory ancestor trust chain"),
            "missing fail-closed reason: {msg}"
        );
        assert!(msg.contains("G3"), "missing G3 context: {msg}");
    }

    // --- G13: service profile-dir validation ---------------------------------

    #[test]
    fn accepts_explicit_profile_dir_under_protected_service_data_locations() {
        for p in [
            r"C:\ProgramData\Bosphorus\profiles",
            r"C:\ProgramData\Bosphorus\profiles\custom",
            r"c:\programdata\CustomBosphorus",
            r"C:\Program Files\Bosphorus\profiles",
            r"C:\Program Files (x86)\Bosphorus\data",
        ] {
            let path = PathBuf::from(p);
            validate_service_profile_dir(&path)
                .unwrap_or_else(|e| panic!("expected accepted profile dir {p}: {e}"));
        }
    }

    #[test]
    fn rejects_unsafe_or_user_writable_profile_dirs() {
        for p in [
            r"C:\Users\alice\Downloads\profiles",
            r"C:\Users\alice\Desktop\profiles",
            r"C:\Users\alice\AppData\Local\Temp\profiles",
            r"C:\Temp\profiles",
            r"C:\Windows\Temp\profiles",
            r"C:\build\target\release\profiles",
            r"D:\work\target\debug\profiles",
            r"C:\Users\alice\profiles",
            "/tmp/profiles",
            "/home/alice/profiles",
        ] {
            let err = validate_service_profile_dir(&PathBuf::from(p)).unwrap_err();
            let msg = err.to_string();
            assert!(
                msg.contains("--profile-dir"),
                "expected actionable --profile-dir guidance for {p}: {msg}"
            );
        }
    }

    #[test]
    fn rejects_profile_dirs_outside_protected_locations_even_if_not_obviously_transient() {
        for p in [
            r"C:\Tools\profiles",
            r"D:\Bosphorus\profiles",
            r"C:\Bosphorus\profiles",
            r"C:\Opt\profiles",
            r"D:\Data\profiles",
        ] {
            let path = PathBuf::from(p);
            assert!(
                unsafe_install_target_reason(&path).is_none(),
                "not in unsafe marker set: {p}"
            );
            let err = validate_service_profile_dir(&path).unwrap_err();
            let msg = err.to_string();
            assert!(
                msg.contains("outside protected service locations"),
                "expected protected-location rejection for {p}: {msg}"
            );
        }
    }

    #[test]
    fn rejects_non_absolute_non_local_or_empty_profile_dirs() {
        for p in [
            "",
            "profiles",
            r"relative\profiles",
            r".\profiles",
            r"..\profiles",
            r"\\server\share\profiles",
            r"\\?\C:\ProgramData\Bosphorus\profiles",
        ] {
            let err = validate_service_profile_dir(&PathBuf::from(p)).unwrap_err();
            let msg = err.to_string();
            assert!(
                msg.contains("--profile-dir") || msg.contains("empty"),
                "expected actionable rejection for profile dir '{p}': {msg}"
            );
        }
    }

    #[test]
    fn profile_dir_policy_helpers_distinguish_local_drive_and_program_data() {
        assert!(is_absolute_local_service_path(&PathBuf::from(
            r"C:\ProgramData\Bosphorus\profiles"
        )));
        assert!(!is_absolute_local_service_path(&PathBuf::from(
            r"\\server\share\profiles"
        )));
        assert!(!is_absolute_local_service_path(&PathBuf::from(
            r"relative\profiles"
        )));
        assert!(is_program_data_location(&PathBuf::from(
            r"C:\ProgramData\Bosphorus\profiles"
        )));
        assert!(is_program_data_location(&PathBuf::from(r"c:\programdata")));
        assert!(!is_program_data_location(&PathBuf::from(
            r"C:\Program Files\Bosphorus"
        )));
        assert!(is_allowed_service_data_location(&PathBuf::from(
            r"C:\ProgramData\Bosphorus\profiles"
        )));
        assert!(is_allowed_service_data_location(&PathBuf::from(
            r"C:\Program Files\Bosphorus\profiles"
        )));
        assert!(!is_allowed_service_data_location(&PathBuf::from(
            r"C:\Tools\profiles"
        )));
    }

    // --- G19: WinDivert collateral provenance/integrity ----------------------

    fn g19_temp_dir(name: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let dir = std::env::temp_dir().join(format!(
            "bosphorus-g19-{}-{nanos}-{name}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).expect("create temp dir");
        dir
    }

    #[test]
    fn sha256_hex_matches_known_vectors() {
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn pinned_windivert_collateral_expectations_match_bundled_release_artifacts() {
        assert_eq!(WINDIVERT_COLLATERAL_FILES.len(), 2);
        assert_eq!(WINDIVERT_COLLATERAL_FILES[0].file_name, "WinDivert.dll");
        assert_eq!(
            WINDIVERT_COLLATERAL_FILES[0].sha256_hex,
            "c1e060ee19444a259b2162f8af0f3fe8c4428a1c6f694dce20de194ac8d7d9a2"
        );
        assert_eq!(WINDIVERT_COLLATERAL_FILES[0].size_bytes, 47616);
        assert_eq!(WINDIVERT_COLLATERAL_FILES[1].file_name, "WinDivert64.sys");
        assert_eq!(
            WINDIVERT_COLLATERAL_FILES[1].sha256_hex,
            "8da085332782708d8767bcace5327a6ec7283c17cfb85e40b03cd2323a90ddc2"
        );
        assert_eq!(WINDIVERT_COLLATERAL_FILES[1].size_bytes, 94144);
    }

    #[test]
    fn collateral_verification_accepts_files_matching_pinned_hash_and_size() {
        let dir = g19_temp_dir("accept");
        let dll = b"verified-dll-content";
        let sys = b"verified-sys-content";
        std::fs::write(dir.join("WinDivert.dll"), dll).unwrap();
        std::fs::write(dir.join("WinDivert64.sys"), sys).unwrap();
        let dll_hash: &'static str = Box::leak(sha256_hex(dll).into_boxed_str());
        let sys_hash: &'static str = Box::leak(sha256_hex(sys).into_boxed_str());
        let expected = [
            ExpectedCollateral {
                file_name: "WinDivert.dll",
                sha256_hex: dll_hash,
                size_bytes: dll.len() as u64,
            },
            ExpectedCollateral {
                file_name: "WinDivert64.sys",
                sha256_hex: sys_hash,
                size_bytes: sys.len() as u64,
            },
        ];
        verify_windivert_collateral_in_dir_with_expected(&dir, "test install source", &expected)
            .expect("matching collateral must be accepted");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn collateral_verification_rejects_missing_file_fail_closed() {
        let dir = g19_temp_dir("missing");
        let dll = b"verified-dll-content";
        std::fs::write(dir.join("WinDivert.dll"), dll).unwrap();
        let dll_hash: &'static str = Box::leak(sha256_hex(dll).into_boxed_str());
        let expected = [
            ExpectedCollateral {
                file_name: "WinDivert.dll",
                sha256_hex: dll_hash,
                size_bytes: dll.len() as u64,
            },
            ExpectedCollateral {
                file_name: "WinDivert64.sys",
                sha256_hex: "00",
                size_bytes: 1,
            },
        ];
        let err = verify_windivert_collateral_in_dir_with_expected(
            &dir,
            "test install source",
            &expected,
        )
        .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("G19"), "missing G19 context: {msg}");
        assert!(
            msg.contains("WinDivert64.sys"),
            "must identify missing file: {msg}"
        );
        assert!(
            msg.contains("missing or not accessible"),
            "must fail closed on missing file: {msg}"
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn collateral_verification_rejects_size_mismatch_fail_closed() {
        let dir = g19_temp_dir("size");
        let dll = b"verified-dll-content";
        let sys = b"verified-sys-content";
        std::fs::write(dir.join("WinDivert.dll"), dll).unwrap();
        std::fs::write(dir.join("WinDivert64.sys"), sys).unwrap();
        let dll_hash: &'static str = Box::leak(sha256_hex(dll).into_boxed_str());
        let sys_hash: &'static str = Box::leak(sha256_hex(sys).into_boxed_str());
        let expected = [
            ExpectedCollateral {
                file_name: "WinDivert.dll",
                sha256_hex: dll_hash,
                size_bytes: dll.len() as u64,
            },
            ExpectedCollateral {
                file_name: "WinDivert64.sys",
                sha256_hex: sys_hash,
                size_bytes: (sys.len() as u64) + 1,
            },
        ];
        let err = verify_windivert_collateral_in_dir_with_expected(
            &dir,
            "test install source",
            &expected,
        )
        .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("G19"), "missing G19 context: {msg}");
        assert!(
            msg.contains("unexpected size"),
            "must report size mismatch: {msg}"
        );
        assert!(
            msg.contains("WinDivert64.sys"),
            "must identify mismatching file: {msg}"
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn collateral_verification_rejects_hash_mismatch_fail_closed() {
        let dir = g19_temp_dir("hash");
        let dll = b"verified-dll-content";
        let sys = b"tampered-sys-content";
        std::fs::write(dir.join("WinDivert.dll"), dll).unwrap();
        std::fs::write(dir.join("WinDivert64.sys"), sys).unwrap();
        let dll_hash: &'static str = Box::leak(sha256_hex(dll).into_boxed_str());
        let wrong_hash: &'static str =
            Box::leak(sha256_hex(b"different-expected-content").into_boxed_str());
        let expected = [
            ExpectedCollateral {
                file_name: "WinDivert.dll",
                sha256_hex: dll_hash,
                size_bytes: dll.len() as u64,
            },
            ExpectedCollateral {
                file_name: "WinDivert64.sys",
                sha256_hex: wrong_hash,
                size_bytes: sys.len() as u64,
            },
        ];
        let err = verify_windivert_collateral_in_dir_with_expected(
            &dir,
            "test install source",
            &expected,
        )
        .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("G19"), "missing G19 context: {msg}");
        assert!(msg.contains("SHA-256"), "must report hash mismatch: {msg}");
        assert!(
            msg.contains("will not be copied/used"),
            "must fail closed: {msg}"
        );
        let _ = std::fs::remove_dir_all(dir);
    }
}
