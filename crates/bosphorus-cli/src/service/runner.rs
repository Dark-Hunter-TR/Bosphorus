//! `bosphorus service run` — the SCM entry point. Not for interactive use.

use std::ffi::OsString;
use std::path::PathBuf;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use bosphorus_core::{filter, Engine, EvasionConfig, NetKeyFn, ProfilePaths, StopFlag};
use bosphorus_divert::{compile_filter, Layer, OpenFlags, WinDivertHandle};
use windows_service::service::{
    ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::{define_windows_service, service_dispatcher};

use crate::divert_backend::{WinDivertSink, WinDivertSource};
use crate::eventlog;

define_windows_service!(ffi_service_main, service_main);

pub fn run() -> anyhow::Result<()> {
    match service_dispatcher::start(super::SERVICE_NAME, ffi_service_main) {
        Ok(()) => Ok(()),
        Err(windows_service::Error::Winapi(e)) if e.raw_os_error() == Some(1063) => {
            eprintln!("{}", crate::i18n::t(crate::i18n::Msg::SvcRunNotFromConsole));
            std::process::exit(1);
        }
        Err(e) => Err(anyhow::anyhow!("service_dispatcher: {e}")),
    }
}

fn service_main(arguments: Vec<OsString>) {
    if let Err(e) = run_service(arguments) {
        eventlog::error(eventlog::ID_OPEN_FAILED, &format!("service exited with error: {e}"));
    }
}

fn run_service(arguments: Vec<OsString>) -> anyhow::Result<()> {
    let (lang, enable_overlap, profile_dir) = parse_args(&arguments);
    crate::i18n::set(lang);
    let _guard = crate::logging::init(crate::logging::LogSink::ServiceFile { dir: super::logs_dir() });

    // Leave a breadcrumb in the Event Log before the process dies on a panic
    // (an unwind past the SCM FFI boundary aborts).
    std::panic::set_hook(Box::new(|info| {
        eventlog::error(eventlog::ID_PANIC, &format!("panic: {info}"));
    }));

    let stop = Arc::new(StopFlag::new());
    let hslot: Arc<OnceLock<Arc<WinDivertHandle>>> = Arc::new(OnceLock::new());

    let status_handle = {
        let stop = Arc::clone(&stop);
        let hslot = Arc::clone(&hslot);
        service_control_handler::register(super::SERVICE_NAME, move |control| match control {
            ServiceControl::Stop | ServiceControl::Shutdown => {
                stop.stop();
                if let Some(h) = hslot.get() {
                    let _ = h.shutdown_both();
                }
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        })?
    };

    let set_state = |state: ServiceState, accept: ServiceControlAccept, wait: Duration| {
        let _ = status_handle.set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: state,
            controls_accepted: accept,
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: wait,
            process_id: None,
        });
    };
    set_state(ServiceState::StartPending, ServiceControlAccept::empty(), Duration::from_secs(10));

    let profile_dir = profile_dir.unwrap_or_else(super::profiles_dir);
    let _ = std::fs::create_dir_all(&profile_dir);
    let (human, key) = crate::netkey::compute();

    let mut cfg = EvasionConfig { enable_overlap_disorder: enable_overlap, ..Default::default() };
    cfg.profile = Some(ProfilePaths { dir: profile_dir, net_key: key });

    let filters = filter::build(&cfg).map_err(|e| anyhow::anyhow!("filter build: {e}"))?;
    compile_filter(&filters.main, Layer::Network)
        .map_err(|e| anyhow::anyhow!("filter rejected at pos {}: {}", e.pos, e.msg))?;

    let handle = match WinDivertHandle::open(filters.main.as_c_str(), Layer::Network, 0, OpenFlags::new())
    {
        Ok(h) => Arc::new(h),
        Err(e) => {
            eventlog::error(
                eventlog::ID_OPEN_FAILED,
                &format!("WinDivertOpen failed: {e} — HVCI / Smart App Control? see the install notes"),
            );
            set_state(ServiceState::Stopped, ServiceControlAccept::empty(), Duration::default());
            anyhow::bail!("WinDivertOpen: {e}");
        }
    };
    let _ = hslot.set(Arc::clone(&handle));

    let provider: NetKeyFn = Arc::new(crate::netkey::compute);
    let engine = Arc::new(Engine::with_live_netkey(cfg, provider));
    eventlog::info(eventlog::ID_STARTED, &format!("service started — capture active (net {human})"));

    {
        let engine = Arc::clone(&engine);
        let stop = Arc::clone(&stop);
        std::thread::spawn(move || {
            while !stop.is_stopped() {
                engine.tick(Instant::now());
                std::thread::sleep(Duration::from_millis(500));
            }
        });
    }

    let _netwatch = crate::netwatch::NetWatch::start({
        let engine = Arc::clone(&engine);
        move || engine.mark_netkey_dirty()
    })
    .ok();

    set_state(
        ServiceState::Running,
        ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
        Duration::default(),
    );

    let mut src = WinDivertSource { h: Arc::clone(&handle) };
    let mut sink = WinDivertSink { h: Arc::clone(&handle) };
    let run = engine.run_main(&mut src, &mut sink, &stop);

    drop(_netwatch);
    engine.persist_now();
    if let Err(e) = run {
        eventlog::warn(eventlog::ID_STOPPED, &format!("capture loop ended with: {e}"));
    }

    eventlog::info(eventlog::ID_STOPPED, "service stopped");
    set_state(ServiceState::Stopped, ServiceControlAccept::empty(), Duration::default());
    Ok(())
}

fn parse_args(args: &[OsString]) -> (crate::i18n::Lang, bool, Option<PathBuf>) {
    let s: Vec<String> = args.iter().map(|a| a.to_string_lossy().into_owned()).collect();
    let lang = pos_value(&s, "--lang")
        .and_then(crate::i18n::parse)
        .unwrap_or(crate::i18n::Lang::En);
    let enable_overlap = s.iter().any(|a| a == "--enable-overlap");
    let profile_dir = pos_value(&s, "--profile-dir").map(PathBuf::from);
    (lang, enable_overlap, profile_dir)
}

fn pos_value<'a>(args: &'a [String], key: &str) -> Option<&'a str> {
    args.iter().position(|a| a == key).and_then(|i| args.get(i + 1)).map(String::as_str)
}
