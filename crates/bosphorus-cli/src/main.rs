//! Bosphorus CLI.
//!
//!   --selftest                       WinDivert verification harness (V1-V4)
//!   --passthru [--secs N]            raw capture/log/reinject demo
//!   --check-filters                  build + syntax-check the filter strings
//!   --engine [--secs N] [--strategy S] [--enable-overlap] [--quic P] [--profile-dir DIR] [--isp NAME]   run the core engine
//!
//! `--enable-overlap` opts auto-discovery into the `OverlapDisorder` candidates
//! (OFF by default — overlap can break a handshake on a first-received-wins
//! server). `--strategy overlap:<seqovl>/<anchor>` works regardless.
//!
//! `--quic off|blocked|all` decides what happens to HTTP/3; `blocked` (the
//! default) refuses it only towards destinations a censor was caught
//! interfering with, so those sites fall back to TCP where a strategy exists.
//!
//! `--strategy` grammar:
//!   list | grid:<i> | overlap:<seqovl>/<anchor> | <frag>[/<desync>]
//!     <frag>   = <anchor>[,<anchor>...] | none   (a list => multi-part split)
//!     <anchor> = <u16> | sni | sni-mid | tls
//!     <desync> = wrongseq (default) | wrongsum | ttl:<u8> | none

mod divert_backend;
mod engine_cmd;
mod eventlog;
mod i18n;
mod launcher;
mod logging;
mod mem_bench;
mod netkey;
mod netwatch;
mod passthru;
mod selftest;
mod selftest_m7;
mod observe;
mod service;

use engine_cmd::StrategyArg;

/// This crate's own version — each crate in the workspace carries its own, so
/// this is the number a release is named after and the one a user sees.
/// Printed by `--version`/`-V` and echoed at the top of `usage()` so a bug
/// report always carries it.
pub(crate) const VERSION: &str = env!("CARGO_PKG_VERSION");

/// The engine's version, which moves independently of this binary's. Reported
/// alongside it so a bug report distinguishes a CLI-only build from one that
/// carries new discovery behaviour.
pub(crate) const CORE_VERSION: &str = bosphorus_core::VERSION;

pub(crate) fn usage() {
    eprintln!("bosphorus {VERSION}\n");
    eprintln!("USAGE:");
    eprintln!("    bosphorus --selftest");
    eprintln!("    bosphorus --selftest-m7          overlap/disorder feasibility (V-A/V-B/V-C)");
    eprintln!("    bosphorus --passthru [--secs N]");
    eprintln!("    bosphorus --check-filters");
    eprintln!("    bosphorus --engine [--secs N] [--strategy S] [--enable-overlap] [--quic P] [--profile-dir DIR] [--isp NAME]");
    eprintln!("    bosphorus --discovery-demo       no-elevation proof of the discovery loop");
    eprintln!("    bosphorus --mem-bench [N]        no-elevation RAM footprint probe (N synthetic targets)");
    eprintln!("    bosphorus --observe [--secs N]   analysis: log ALL TCP+UDP (no mutation)");
    eprintln!();
    eprintln!("  --strategy list           print the default discovery grid");
    eprintln!("  --strategy grid:<i>       run grid entry i");
    eprintln!("  --strategy <frag>[/<d>]   frag = <anchor>[,<anchor>...]|none  (list = multi-part)");
    eprintln!("                            anchor = <u16>|sni|sni-mid|tls");
    eprintln!("                            d    = wrongseq|wrongsum|ttl:<u8>|none  (default wrongseq)");
    eprintln!("  --strategy overlap:<sq>/<anchor>   forced OverlapDisorder (disorder + seqovl)");
    eprintln!("  --enable-overlap         opt auto-discovery into OverlapDisorder (default OFF)");
    eprintln!("  --quic off|blocked|all   HTTP/3 handling (default: blocked). blocked refuses QUIC");
    eprintln!("                           only towards destinations caught being censored, so those");
    eprintln!("                           sites fall back to TCP where a strategy exists; all refuses");
    eprintln!("                           every QUIC connection; off leaves HTTP/3 alone");
    eprintln!("  --profile-dir DIR        read/write discovery profiles here instead of");
    eprintln!("                           %LOCALAPPDATA%\\Bosphorus\\profiles (e.g. the service's");
    eprintln!("                           %ProgramData%\\Bosphorus\\profiles store)");
    eprintln!("  --isp NAME               opt into the cross-network ISP seed pool: seed a fresh");
    eprintln!("                           network's sweep from what other networks you tagged NAME");
    eprintln!("                           settled on (discovery mode only; derived, safe to delete)");
    eprintln!("  --lang en|tr             message language (default: English, or Turkish if the");
    eprintln!("                           Windows UI language is Turkish; BOSPHORUS_LANG also works)");
    eprintln!("  --version, -V            print the version and exit");
}

fn value_after<'a>(args: &'a [String], key: &str) -> Option<&'a str> {
    args.iter()
        .position(|a| a == key)
        .and_then(|i| args.get(i + 1))
        .map(String::as_str)
}

/// Resolve `--quic off|blocked|all`, defaulting to the selective policy. A
/// misspelling is an error rather than a silent fallback: quietly running a
/// different QUIC policy than asked for is exactly the kind of surprise that
/// looks like the engine misbehaving.
fn parse_quic(args: &[String]) -> anyhow::Result<bosphorus_core::config::QuicPolicy> {
    match value_after(args, "--quic") {
        Some(v) => v.parse().map_err(|e| anyhow::anyhow!("{e}")),
        None => Ok(bosphorus_core::config::QuicPolicy::default()),
    }
}

/// Resolve the UI language: `--lang` > `BOSPHORUS_LANG` > Windows UI language
/// (Turkish -> Tr) > English.
fn resolve_lang(args: &[String]) -> i18n::Lang {
    if let Some(l) = value_after(args, "--lang").and_then(i18n::parse) {
        return l;
    }
    if let Some(l) = std::env::var("BOSPHORUS_LANG").ok().as_deref().and_then(i18n::parse) {
        return l;
    }
    if windows_ui_is_turkish() {
        return i18n::Lang::Tr;
    }
    i18n::Lang::En
}

/// `PRIMARYLANGID(GetUserDefaultUILanguage()) == LANG_TURKISH`.
fn windows_ui_is_turkish() -> bool {
    use windows::Win32::Globalization::GetUserDefaultUILanguage;
    const LANG_TURKISH: u16 = 0x1F;
    // SAFETY: no arguments, no out-params; returns a plain LANGID.
    let langid = unsafe { GetUserDefaultUILanguage() };
    (langid & 0x3FF) == LANG_TURKISH
}

/// Report `result`, then exit — holding the window open first if this process
/// owns its console alone.
///
/// `--engine` and `--selftest` are the two commands the launcher's `elevate()`
/// spawns as a *visible* new window (`ShellExecuteW "runas"`, not hidden). A
/// plain `return`ed `Err` there used to fall through to `main`'s default
/// `Result` reporting and exit immediately — on a driver-load failure (HVCI,
/// Smart App Control, no Administrator) the freshly opened window closed
/// before anyone could read why. Only called where the console is known to be
/// either a normal shell (this is a no-op past the `is_double_click` check —
/// exact same exit code, no pause) or one of those two visible re-spawns:
/// never call it from the hidden `service install/uninstall --from-launcher`
/// path, which reports through a MessageBox and has no one to press Enter.
fn finish(result: anyhow::Result<()>) -> ! {
    let code = match &result {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("Error: {e}");
            1
        }
    };
    if launcher::is_double_click() {
        println!("\n{}", i18n::t(i18n::Msg::TuiPressKey));
        let mut s = String::new();
        let _ = std::io::stdin().read_line(&mut s);
    }
    std::process::exit(code);
}

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.iter().any(|a| a == "--version" || a == "-V") {
        println!("bosphorus {VERSION} (core {CORE_VERSION})");
        return Ok(());
    }
    i18n::set(resolve_lang(&args));
    let secs = value_after(&args, "--secs").and_then(|s| s.parse::<u64>().ok());
    let enable_overlap = args.iter().any(|a| a == "--enable-overlap");
    let profile_dir = value_after(&args, "--profile-dir").map(std::path::PathBuf::from);
    let isp = value_after(&args, "--isp").map(str::to_owned);
    let quic = parse_quic(&args)?;

    match args.first().map(String::as_str) {
        Some("service") => service::dispatch(&args),
        Some("--selftest") => finish(selftest::run_all()),
        Some("--selftest-m7") => selftest_m7::run(),
        Some("--passthru") => passthru::run(secs),
        Some("--check-filters") => engine_cmd::check_filters(),
        Some("--discovery-demo") => engine_cmd::discovery_demo(args.iter().any(|a| a == "--fresh")),
        Some("--mem-bench") => {
            let n = value_after(&args, "--mem-bench").and_then(|s| s.parse().ok()).unwrap_or(2000);
            mem_bench::run(n)
        }
        Some("--observe") => observe::run(secs.unwrap_or(60)),
        Some("--engine") => {
            let opts = |strategy| engine_cmd::EngineOpts {
                secs,
                strategy,
                enable_overlap,
                profile_dir: profile_dir.clone(),
                isp: isp.clone(),
                quic,
            };
            match value_after(&args, "--strategy") {
                None => finish(engine_cmd::run_engine(opts(None))),
                Some(spec) => match engine_cmd::parse_strategy(spec, enable_overlap)? {
                    StrategyArg::List => {
                        engine_cmd::list_grid(enable_overlap);
                        Ok(())
                    }
                    StrategyArg::One(s) => finish(engine_cmd::run_engine(opts(Some(s)))),
                },
            }
        }
        None => launcher::run(),
        _ => {
            usage();
            std::process::exit(2);
        }
    }
}
