//! `bosphorus service install [--lang en|tr] [--enable-overlap]
//!    [--profile-dir <p>] [--install-dir <p>] [--start auto|demand] [--force]`

use std::ffi::{CString, OsStr, OsString};
use std::path::PathBuf;
use std::time::Duration;

use windows_service::service::{
    ServiceAccess, ServiceAction, ServiceActionType, ServiceErrorControl, ServiceFailureActions,
    ServiceFailureResetPeriod, ServiceInfo, ServiceStartType, ServiceType,
};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

use bosphorus_divert::{DivertError, Layer, OpenFlags, WinDivertHandle};

pub struct Opts {
    pub lang: crate::i18n::Lang,
    pub enable_overlap: bool,
    pub profile_dir: Option<PathBuf>,
    pub install_dir: Option<PathBuf>,
    pub start_demand: bool,
    pub force: bool,
}

pub fn run(args: &[String]) -> anyhow::Result<()> {
    let opts = Opts {
        lang: crate::resolve_lang(args),
        enable_overlap: args.iter().any(|a| a == "--enable-overlap"),
        profile_dir: value_after(args, "--profile-dir").map(PathBuf::from),
        install_dir: value_after(args, "--install-dir").map(PathBuf::from),
        start_demand: value_after(args, "--start").map(|s| s.eq_ignore_ascii_case("demand"))
            .unwrap_or(false),
        force: args.iter().any(|a| a == "--force"),
    };
    crate::i18n::set(opts.lang);
    install(&opts)
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

    let mut launch_arguments: Vec<OsString> = vec![
        "service".into(),
        "run".into(),
        "--lang".into(),
        lang_code(opts.lang).into(),
    ];
    if opts.enable_overlap {
        launch_arguments.push("--enable-overlap".into());
    }
    if let Some(p) = &opts.profile_dir {
        launch_arguments.push("--profile-dir".into());
        launch_arguments.push(p.clone().into_os_string());
    }

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
    if !opts.start_demand {
        let _ = svc.set_delayed_auto_start(true);
    }
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
