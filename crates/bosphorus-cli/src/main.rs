//! Bosphorus CLI.
//!
//! M5 build:
//!   --selftest                       WinDivert verification harness (V1-V4)
//!   --passthru [--secs N]            raw capture/log/reinject demo
//!   --check-filters                  build + syntax-check the filter strings
//!   --engine [--secs N] [--strategy S] [--enable-overlap]   run the core engine
//!
//! `--enable-overlap` opts auto-discovery into the `OverlapDisorder` candidates
//! (OFF by default — overlap can break a handshake on a first-received-wins
//! server). `--strategy overlap:<seqovl>/<anchor>` works regardless.
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

fn usage() {
    eprintln!("bosphorus (M5)\n");
    eprintln!("USAGE:");
    eprintln!("    bosphorus --selftest");
    eprintln!("    bosphorus --selftest-m7          overlap/disorder feasibility (V-A/V-B/V-C)");
    eprintln!("    bosphorus --passthru [--secs N]");
    eprintln!("    bosphorus --check-filters");
    eprintln!("    bosphorus --engine [--secs N] [--strategy S] [--enable-overlap]");
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
    eprintln!("  --lang en|tr             message language (default: English, or Turkish if the");
    eprintln!("                           Windows UI language is Turkish; BOSPHORUS_LANG also works)");
}

fn value_after<'a>(args: &'a [String], key: &str) -> Option<&'a str> {
    args.iter()
        .position(|a| a == key)
        .and_then(|i| args.get(i + 1))
        .map(String::as_str)
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

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    i18n::set(resolve_lang(&args));
    let secs = value_after(&args, "--secs").and_then(|s| s.parse::<u64>().ok());
    let enable_overlap = args.iter().any(|a| a == "--enable-overlap");

    match args.first().map(String::as_str) {
        Some("service") => service::dispatch(&args),
        Some("--selftest") => selftest::run_all(),
        Some("--selftest-m7") => selftest_m7::run(),
        Some("--passthru") => passthru::run(secs),
        Some("--check-filters") => engine_cmd::check_filters(),
        Some("--discovery-demo") => engine_cmd::discovery_demo(args.iter().any(|a| a == "--fresh")),
        Some("--mem-bench") => {
            let n = value_after(&args, "--mem-bench").and_then(|s| s.parse().ok()).unwrap_or(2000);
            mem_bench::run(n)
        }
        Some("--observe") => observe::run(secs.unwrap_or(60)),
        Some("--engine") => match value_after(&args, "--strategy") {
            None => engine_cmd::run_engine(secs, None, enable_overlap),
            Some(spec) => match engine_cmd::parse_strategy(spec, enable_overlap)? {
                StrategyArg::List => {
                    engine_cmd::list_grid(enable_overlap);
                    Ok(())
                }
                StrategyArg::One(s) => engine_cmd::run_engine(secs, Some(s), enable_overlap),
            },
        },
        _ => {
            usage();
            std::process::exit(2);
        }
    }
}
