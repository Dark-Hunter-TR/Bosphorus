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
            ServiceAccess::CHANGE_CONFIG | ServiceAccess::START | ServiceAccess::QUERY_STATUS,
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

    svc.start::<&OsStr>(&[]).map_err(super::map_scm_err)?;

    println!("{}", crate::i18n::svc_created(super::SERVICE_NAME));
    println!("{}", crate::i18n::install_verification());
    Ok(())
}

/// The `service run` argv the SCM launches the service with. Kept separate
/// from [`install`] so it can be unit-tested without touching the SCM.
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
fn resolve_exe(opts: &Opts) -> anyhow::Result<PathBuf> {
    let current = std::env::current_exe()?;
    let Some(dst_dir) = &opts.install_dir else {
        validate_service_install_target(&current, false)?;
        let install_dir = current
            .parent()
            .unwrap_or_else(|| std::path::Path::new("."));
        validate_service_install_ancestor_trust_chain(install_dir, false)?;
        return Ok(current);
    };

    validate_service_install_target(dst_dir, true)?;
    std::fs::create_dir_all(dst_dir)?;
    validate_service_install_ancestor_trust_chain(dst_dir, true)?;
    let src_dir = current
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."));
    let exe_dst = dst_dir.join("bosphorus.exe");
    std::fs::copy(&current, &exe_dst)?;
    for f in ["WinDivert.dll", "WinDivert64.sys"] {
        let s = src_dir.join(f);
        if s.exists() {
            std::fs::copy(&s, dst_dir.join(f))?;
        } else {
            eprintln!(
                "warning: {} not found next to the exe; copy it into {} manually",
                f,
                dst_dir.display()
            );
        }
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
}
