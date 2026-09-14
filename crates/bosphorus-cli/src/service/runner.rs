//! `bosphorus service run` — the SCM entry point. Not for interactive use.

use std::ffi::OsString;
use std::path::PathBuf;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use bosphorus_core::config::QuicPolicy;
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
    let ServiceArgs { lang, enable_overlap, quic, profile_dir } = parse_args(&arguments);
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

    let mut cfg = EvasionConfig { enable_overlap_disorder: enable_overlap, quic, ..Default::default() };
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

    // `--quic all` only. A failure here is not fatal: the TCP bypass is the
    // service's actual job, and it should not refuse to run because the
    // secondary blanket-block handle could not be opened.
    let _quic_block = match crate::engine_cmd::open_quic_block(&filters) {
        Ok(h) => h,
        Err(e) => {
            eventlog::error(eventlog::ID_OPEN_FAILED, &format!("{e}; continuing without it"));
            None
        }
    };

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

/// What the SCM passes us — the argv `service install` stored.
pub struct ServiceArgs {
    pub lang: crate::i18n::Lang,
    pub enable_overlap: bool,
    pub quic: QuicPolicy,
    pub profile_dir: Option<PathBuf>,
}

fn parse_args(args: &[OsString]) -> ServiceArgs {
    let s: Vec<String> = args.iter().map(|a| a.to_string_lossy().into_owned()).collect();
    let lang = pos_value(&s, "--lang")
        .and_then(crate::i18n::parse)
        .unwrap_or(crate::i18n::Lang::En);
    // Unlike the interactive CLI, a bad value here must not stop the service
    // from starting: this argv was written by our own installer, so a bad one
    // is our bug, and refusing to start would take the user's whole bypass down
    // over a spelling. The Event Log keeps the breadcrumb.
    let quic = match pos_value(&s, "--quic") {
        Some(v) => v.parse().unwrap_or_else(|e| {
            eventlog::error(
                eventlog::ID_BAD_ARGUMENT,
                &format!("{e}; falling back to {}", QuicPolicy::default().as_str()),
            );
            QuicPolicy::default()
        }),
        None => QuicPolicy::default(),
    };
    ServiceArgs {
        lang,
        enable_overlap: s.iter().any(|a| a == "--enable-overlap"),
        quic,
        profile_dir: pos_value(&s, "--profile-dir").map(PathBuf::from),
    }
}

fn pos_value<'a>(args: &'a [String], key: &str) -> Option<&'a str> {
    args.iter().position(|a| a == key).and_then(|i| args.get(i + 1)).map(String::as_str)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::i18n::Lang;

    fn argv(v: &[&str]) -> Vec<OsString> {
        v.iter().map(OsString::from).collect()
    }

    #[test]
    fn parse_args_defaults_to_en_no_overlap_no_dir() {
        let a = parse_args(&argv(&["service", "run"]));
        assert_eq!(a.lang, Lang::En);
        assert!(!a.enable_overlap);
        assert!(a.profile_dir.is_none());
        assert_eq!(a.quic, QuicPolicy::default());
    }

    #[test]
    fn parse_args_reads_lang_overlap_quic_and_profile_dir() {
        let a = parse_args(&argv(&[
            "service",
            "run",
            "--lang",
            "tr",
            "--enable-overlap",
            "--quic",
            "all",
            "--profile-dir",
            r"C:\pd",
        ]));
        assert_eq!(a.lang, Lang::Tr);
        assert!(a.enable_overlap);
        assert_eq!(a.quic, QuicPolicy::All);
        assert_eq!(a.profile_dir, Some(PathBuf::from(r"C:\pd")));
    }

    #[test]
    fn parse_args_unknown_lang_falls_back_to_en() {
        assert_eq!(parse_args(&argv(&["service", "run", "--lang", "xx"])).lang, Lang::En);
    }

    #[test]
    fn an_unreadable_quic_policy_keeps_the_service_starting() {
        // Refusing to start would take the whole bypass down over a bad token
        // in argv we wrote ourselves.
        let a = parse_args(&argv(&["service", "run", "--quic", "sometimes"]));
        assert_eq!(a.quic, QuicPolicy::default());
    }

    #[test]
    fn pos_value_returns_following_token_or_none() {
        let s = vec!["--a".to_string(), "1".to_string(), "--b".to_string()];
        assert_eq!(pos_value(&s, "--a"), Some("1"));
        assert_eq!(pos_value(&s, "--b"), None); // last token, nothing after
        assert_eq!(pos_value(&s, "--c"), None); // absent
    }
}
