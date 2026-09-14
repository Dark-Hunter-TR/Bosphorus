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
        start_demand: value_after(args, "--start").map(|s| s.eq_ignore_ascii_case("demand"))
            .unwrap_or(false),
        force: args.iter().any(|a| a == "--force"),
    };
    crate::i18n::set(opts.lang);

    // Elevated re-spawn from the double-click launcher: its console is hidden,
    // so also surface the outcome in a MessageBox.
    let from_launcher = args.iter().any(|a| a == crate::launcher::FROM_LAUNCHER_FLAG);
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
            ServiceAction { action_type: ServiceActionType::Restart, delay: Duration::from_secs(5) },
            ServiceAction { action_type: ServiceActionType::Restart, delay: Duration::from_secs(30) },
            ServiceAction { action_type: ServiceActionType::None, delay: Duration::ZERO },
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
    args.iter().position(|a| a == key).and_then(|i| args.get(i + 1)).map(String::as_str)
}

/// Absolute path to register as the service binary. `--install-dir` copies the
/// exe + the two WinDivert files there and points at the copy.
fn resolve_exe(opts: &Opts) -> anyhow::Result<PathBuf> {
    let current = std::env::current_exe()?;
    let Some(dst_dir) = &opts.install_dir else {
        warn_if_transient(&current);
        return Ok(current);
    };
    std::fs::create_dir_all(dst_dir)?;
    let src_dir = current.parent().unwrap_or_else(|| std::path::Path::new("."));
    let exe_dst = dst_dir.join("bosphorus.exe");
    std::fs::copy(&current, &exe_dst)?;
    for f in ["WinDivert.dll", "WinDivert64.sys"] {
        let s = src_dir.join(f);
        if s.exists() {
            std::fs::copy(&s, dst_dir.join(f))?;
        } else {
            eprintln!("warning: {} not found next to the exe; copy it into {} manually", f, dst_dir.display());
        }
    }
    Ok(exe_dst)
}

fn warn_if_transient(p: &std::path::Path) {
    let s = p.to_string_lossy().to_ascii_lowercase();
    if ["\\temp\\", "\\downloads\\", "\\target\\", "\\appdata\\local\\temp"].iter().any(|m| s.contains(m)) {
        eprintln!(
            "warning: the exe lives at a transient-looking path:\n  {}\n\
             move it somewhere stable (e.g. C:\\Program Files\\Bosphorus\\) or use --install-dir,\n\
             otherwise the service (and the WinDivert driver it registers) break if the file moves.",
            p.display()
        );
    }
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
        Err(DivertError::Open(e)) => anyhow::bail!("{}", crate::i18n::preflight_fail(&e.to_string())),
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
        assert_eq!(as_strings(&v), ["service", "run", "--lang", "en", "--quic", "blocked"]);
    }

    #[test]
    fn launch_arguments_carry_overlap_and_profile_dir_in_order() {
        let v = build_launch_arguments(&opts(Lang::Tr, true, Some(PathBuf::from(r"C:\pd"))));
        assert_eq!(
            as_strings(&v),
            [
                "service", "run", "--lang", "tr", "--enable-overlap", "--quic", "blocked",
                "--profile-dir", r"C:\pd"
            ]
        );
    }

    #[test]
    fn launch_arguments_omit_profile_dir_key_when_none() {
        let v = build_launch_arguments(&opts(Lang::En, true, None));
        assert!(!v.iter().any(|o| o == "--profile-dir"));
        assert_eq!(
            as_strings(&v),
            ["service", "run", "--lang", "en", "--enable-overlap", "--quic", "blocked"]
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
            let i = v.iter().position(|a| a == "--quic").expect("--quic present");
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
        let s = ["--profile-dir".to_string(), "p".to_string(), "--force".to_string()];
        assert_eq!(value_after(&s, "--profile-dir"), Some("p"));
        assert_eq!(value_after(&s, "--force"), None); // flag, nothing after
        assert_eq!(value_after(&s, "--missing"), None);
    }
}
