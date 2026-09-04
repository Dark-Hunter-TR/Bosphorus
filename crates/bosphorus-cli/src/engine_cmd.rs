//! M2 CLI entry points:
//!   `--check-filters`  build + compile-check filter strings (no elevation)
//!   `--engine [--secs N]`  run the core engine passthrough over WinDivert

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use bosphorus_core::strategy::{
    DefaultGenerator, DesyncMethod, FakePayload, FakeSpec, FragmentSpec, OverlapFill, SendOrder,
    SplitAnchor, Strategy, TtlPolicy, ACK_DELTA, SEQ_DELTA,
};
use bosphorus_core::{filter, Engine, EvasionConfig, NetKeyFn, ProfilePaths, StopFlag};
use bosphorus_divert::{compile_filter, DivertError, Layer, OpenFlags, Param, WinDivertHandle};

use crate::divert_backend::{WinDivertSink, WinDivertSource};

/// Result of parsing `--strategy`.
pub enum StrategyArg {
    /// Print the grid and exit.
    List,
    /// Run this strategy instead of the M4 baseline.
    One(Strategy),
}

/// `--strategy` grammar:
///   list                       print the default grid, one per line
///   grid:<i>                    the i-th strategy of the default grid
///   overlap:<seqovl>/<anchor>   forced OverlapDisorder (disorder + seqovl)
///   <frag>[/<desync>]          e.g. `sni`, `6`, `tls,sni`, `sni-mid/ttl:6`, `2/wrongsum`
///     <frag>   = <anchor>[,<anchor>...] | none   (a list => multi-part split)
///     <anchor> = <u16> | sni | sni-mid | tls
///     <desync> = wrongseq (default) | wrongsum | ttl:<u8> | none
///
/// A trailing `+pad:<n>` (e.g. `2/wrongseq+pad:512`) forces `Strategy::tls_pad`
/// (RFC 7685 padding, M7c) on top of whichever form it's appended to — except
/// `list`, where it is silently ignored.
pub fn parse_strategy(s: &str, enable_overlap: bool) -> anyhow::Result<StrategyArg> {
    let (s, tls_pad) = match s.rsplit_once("+pad:") {
        Some((rest, n)) => {
            let n: u16 = n.parse().map_err(|_| anyhow::anyhow!("bad pad length '{n}'"))?;
            (rest, Some(n))
        }
        None => (s, None),
    };
    let with_pad = |mut st: Strategy| {
        st.tls_pad = tls_pad;
        st
    };

    if s == "list" {
        return Ok(StrategyArg::List);
    }
    if let Some(i) = s.strip_prefix("grid:") {
        let i: usize = i.parse().map_err(|_| anyhow::anyhow!("bad grid index '{s}'"))?;
        let g = DefaultGenerator::new(&cfg_for(enable_overlap));
        let st = g
            .all()
            .get(i)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("grid index {i} out of range (0..{})", g.len()))?;
        return Ok(StrategyArg::One(with_pad(st)));
    }
    // overlap:<seqovl>/<anchor>  (disorder + seqovl, no separate fake)
    if let Some(rest) = s.strip_prefix("overlap:") {
        let (sq, anc) = rest
            .split_once('/')
            .ok_or_else(|| anyhow::anyhow!("overlap needs 'overlap:<seqovl>/<anchor>'"))?;
        let seqovl: u16 = sq.parse().map_err(|_| anyhow::anyhow!("bad seqovl '{sq}'"))?;
        let a = parse_anchor(anc)?;
        return Ok(StrategyArg::One(with_pad(Strategy {
            fake: Some(fake_spec(
                DesyncMethod::OverlapDisorder { seqovl, fill: OverlapFill::Zeros },
                None,
            )),
            fragment: Some(FragmentSpec::one(a, true)),
            order: SendOrder::FakeThenReal,
            tls_pad: None,
        })));
    }

    let (frag_s, desync_s) = s.split_once('/').unwrap_or((s, "wrongseq"));

    // `frag` is one anchor, or a comma-joined list -> multi-part split.
    let fragment = match frag_s {
        "none" => None,
        other => {
            let anchors = other
                .split(',')
                .map(parse_anchor)
                .collect::<anyhow::Result<Vec<_>>>()?;
            Some(FragmentSpec { anchors, reverse: false })
        }
    };

    let fake = match desync_s {
        "none" => None,
        "wrongseq" => Some(fake_spec(
            DesyncMethod::WrongSeq { seq_delta: SEQ_DELTA, ack_delta: ACK_DELTA },
            None,
        )),
        "wrongsum" => Some(fake_spec(DesyncMethod::WrongChecksum, None)),
        t if t.starts_with("ttl:") => {
            let n: u8 = t[4..].parse().map_err(|_| anyhow::anyhow!("bad ttl in '{t}'"))?;
            Some(fake_spec(DesyncMethod::TtlLimited, Some(TtlPolicy::UserFixed(n))))
        }
        other => anyhow::bail!("unknown desync '{other}'"),
    };

    if fake.is_none() && fragment.is_none() && tls_pad.is_none() {
        anyhow::bail!("strategy 'none/none' does nothing");
    }
    Ok(StrategyArg::One(with_pad(Strategy {
        fake,
        fragment,
        order: SendOrder::FakeThenReal,
        tls_pad: None,
    })))
}

/// The one place `--engine` chooses between auto-discovery and a forced
/// strategy. `None` => discovery with live NetKey re-keying (a network switch
/// rebinds the session, no restart); `Some` => forced, network-independent.
pub fn build_engine(cfg: EvasionConfig, strategy: Option<Strategy>) -> Engine {
    match strategy {
        None => {
            let provider: NetKeyFn = Arc::new(crate::netkey::compute);
            Engine::with_live_netkey(cfg, provider)
        }
        Some(s) => Engine::new_with_strategy(cfg, s),
    }
}

/// Base config for `--engine`. `enable_overlap` (CLI `--enable-overlap`) is the
/// only opt-in for `OverlapDisorder` candidates in auto-discovery; it is OFF by
/// default because overlap can break a real handshake against a
/// first-received-wins server. `--strategy overlap:...` is unaffected by it.
fn cfg_for(enable_overlap: bool) -> EvasionConfig {
    EvasionConfig { enable_overlap_disorder: enable_overlap, ..Default::default() }
}

/// Where discovery profiles live. `override_dir` (from `--profile-dir`) wins when
/// given — e.g. to point an interactive run at the service's
/// `%ProgramData%\Bosphorus\profiles` store. Otherwise
/// `%LOCALAPPDATA%\Bosphorus\profiles` (falling back to the temp dir).
fn profile_dir(override_dir: Option<PathBuf>) -> PathBuf {
    if let Some(d) = override_dir {
        return d;
    }
    std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir)
        .join("Bosphorus")
        .join("profiles")
}

fn parse_anchor(s: &str) -> anyhow::Result<SplitAnchor> {
    Ok(match s {
        "sni" => SplitAnchor::SniStart,
        "sni-mid" => SplitAnchor::SniMiddle,
        "tls" => SplitAnchor::TlsRecordStart,
        n => SplitAnchor::AbsoluteOffset(
            n.parse()
                .map_err(|_| anyhow::anyhow!("bad anchor '{n}' (want u16 | sni | sni-mid | tls)"))?,
        ),
    })
}
fn fake_spec(desync: DesyncMethod, ttl: Option<TtlPolicy>) -> FakeSpec {
    FakeSpec { desync, ttl, payload: FakePayload::StaticClientHello, repeats: 1 }
}

pub fn list_grid(enable_overlap: bool) {
    let g = DefaultGenerator::new(&cfg_for(enable_overlap));
    println!(
        "default grid — {} strategies{}:",
        g.len(),
        if enable_overlap { " (overlap opted in)" } else { "" }
    );
    for (i, s) in g.all().iter().enumerate() {
        println!("  [{i:>3}] {}", s.describe());
    }
}

/// No-elevation proof that `--engine` (no `--strategy`) drives the discovery
/// loop and that persistence carries sweep progress between processes.
///
/// First run bootstraps `demo.blocked.test` (Probe -> Blocked -> D3 parallel
/// sweep) and persists. Each later run *loads* that state and advances the
/// sweep by one, so `tried` accumulates across invocations. `--fresh` deletes
/// the demo profile first.
pub fn discovery_demo(fresh: bool) -> anyhow::Result<()> {
    init_tracing_with_default("bosphorus::discovery=info,bosphorus::strategy=info,bosphorus::conntrack=info");

    let dir = std::env::temp_dir().join("bosphorus-discovery-demo");
    let path = bosphorus_core::profile::persist::profile_path(&dir, "demo");
    if fresh {
        let _ = std::fs::remove_file(&path);
        println!("(--fresh) deleted {}", path.display());
    }

    let cfg = EvasionConfig {
        profile: Some(ProfilePaths { dir: dir.clone(), net_key: "demo".into() }),
        ..Default::default()
    };
    let engine = bosphorus_core::Engine::new(cfg);
    anyhow::ensure!(engine.is_discovery(), "Engine::new must be discovery mode");

    let restored = engine.discovery_summary().into_iter().find(|t| t.key == "demo.blocked.test");
    println!("profile: {}", path.display());
    println!("grid: {} strategies", engine.grid_len());

    match &restored {
        Some(t) => {
            println!(
                "RESTORED demo.blocked.test from disk: phase={:?} tried={}/{}\n",
                t.phase, t.tried, t.total
            );
            // Advance the sweep by exactly one failed candidate.
            let before = t.tried;
            let mut ch = demo_client_hello("demo.blocked.test", 50100 + before as u16);
            let mut out = bosphorus_core::SendBatch::new();
            let d = engine.process(&mut ch, &mut out_meta(), &mut out);
            println!("[A] ClientHello -> {d:?}  parts={}  (bir aday daha uygulandi)", out.len());
            let mut rst = demo_rst(50100 + before as u16);
            engine.process(&mut rst, &mut in_meta(), &mut bosphorus_core::SendBatch::new());
            let after = engine
                .discovery_summary()
                .into_iter()
                .find(|t| t.key == "demo.blocked.test")
                .map(|t| t.tried)
                .unwrap_or(before);
            println!("[B] inbound RST -> tried {before} -> {after}\n");
            anyhow::ensure!(after == before + 1, "persisted sweep must advance by one");
        }
        None => {
            println!("demo.blocked.test not on disk — bootstrapping\n");

            let mut ch1 = demo_client_hello("demo.blocked.test", 50001);
            let mut out = bosphorus_core::SendBatch::new();
            let d1 = engine.process(&mut ch1, &mut out_meta(), &mut out);
            println!("[1] ClientHello       -> {d1:?}   (beklenen: ForwardOriginal, Probe)");

            let mut rst = demo_rst(50001);
            engine.process(&mut rst, &mut in_meta(), &mut bosphorus_core::SendBatch::new());
            println!("[2] inbound RST       -> discovery: Blocked bekleniyor");

            // Two concurrent ClientHellos, no verdict between -> D3 parallel sweep.
            let mut ch2 = demo_client_hello("demo.blocked.test", 50002);
            let mut out_a = bosphorus_core::SendBatch::new();
            let d3a = engine.process(&mut ch2, &mut out_meta(), &mut out_a);
            let mut ch3 = demo_client_hello("demo.blocked.test", 50003);
            let mut out_b = bosphorus_core::SendBatch::new();
            let d3b = engine.process(&mut ch3, &mut out_meta(), &mut out_b);

            let bytes_a: Vec<Vec<u8>> = out_a.items.iter().map(|i| i.bytes.clone()).collect();
            let bytes_b: Vec<Vec<u8>> = out_b.items.iter().map(|i| i.bytes.clone()).collect();
            let in_flight = engine
                .discovery_summary()
                .iter()
                .find(|t| t.key == "demo.blocked.test")
                .map(|t| t.in_flight)
                .unwrap_or(0);
            println!("[3a] ClientHello :50002 -> {d3a:?}  parts={}", out_a.len());
            println!("[3b] ClientHello :50003 -> {d3b:?}  parts={}", out_b.len());
            println!(
                "     in_flight={in_flight}  distinct_candidates={}   <-- D3: FARKLI aday",
                bytes_a != bytes_b
            );
            anyhow::ensure!(in_flight == 2, "M7d: two unresolved explores must be tracked");
            anyhow::ensure!(bytes_a != bytes_b, "M7d: concurrent connections must sweep different candidates");

            let mut rst2 = demo_rst(50002);
            engine.process(&mut rst2, &mut in_meta(), &mut bosphorus_core::SendBatch::new());
            println!("[4]  inbound RST :50002 -> discovery: NextCandidate\n");
        }
    }

    engine.persist_now();
    println!("--- discovery ozeti (kaydedildi -> {}) ---", path.display());
    for t in engine.discovery_summary() {
        let src = if t.from_disk { "disk" } else { "new " };
        println!(
            "  [{src}] {} : phase={:?} tried={}/{} in_flight={}",
            t.key, t.phase, t.tried, t.total, t.in_flight
        );
    }
    println!("\ntekrar calistir: ayni tried'dan devam edecek  (sifirla: --discovery-demo --fresh)");
    Ok(())
}

fn out_meta() -> bosphorus_core::CaptureMeta {
    bosphorus_core::CaptureMeta { outbound: true, ..Default::default() }
}
fn in_meta() -> bosphorus_core::CaptureMeta {
    bosphorus_core::CaptureMeta { outbound: false, ..Default::default() }
}

fn init_tracing_with_default(default: &str) {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(default));
    let _ = tracing_subscriber::fmt().with_env_filter(filter).with_target(true).try_init();
}

/// Minimal IPv4/TCP ClientHello 10.0.0.9:<sport> -> 93.184.216.34:443 with SNI.
fn demo_client_hello(host: &str, sport: u16) -> Vec<u8> {
    let h = host.as_bytes();
    let mut ext = Vec::new();
    ext.extend_from_slice(&((3 + h.len()) as u16).to_be_bytes());
    ext.push(0);
    ext.extend_from_slice(&(h.len() as u16).to_be_bytes());
    ext.extend_from_slice(h);
    let mut exts = Vec::new();
    exts.extend_from_slice(&0u16.to_be_bytes());
    exts.extend_from_slice(&(ext.len() as u16).to_be_bytes());
    exts.extend_from_slice(&ext);
    let mut hb = Vec::new();
    hb.extend_from_slice(&[0x03, 0x03]);
    hb.extend_from_slice(&[0x11; 32]);
    hb.push(0);
    hb.extend_from_slice(&2u16.to_be_bytes());
    hb.extend_from_slice(&[0x13, 0x01]);
    hb.push(1);
    hb.push(0);
    hb.extend_from_slice(&(exts.len() as u16).to_be_bytes());
    hb.extend_from_slice(&exts);
    let mut hs = vec![0x01];
    let l = hb.len() as u32;
    hs.extend_from_slice(&[(l >> 16) as u8, (l >> 8) as u8, l as u8]);
    hs.extend_from_slice(&hb);
    let mut tls = vec![0x16, 0x03, 0x01];
    tls.extend_from_slice(&(hs.len() as u16).to_be_bytes());
    tls.extend_from_slice(&hs);
    let mut p = vec![0x45, 0, 0, 0, 0, 0, 0x40, 0, 64, 6, 0, 0, 10, 0, 0, 9, 93, 184, 216, 34];
    p.extend_from_slice(&sport.to_be_bytes());
    p.extend_from_slice(&[0x01, 0xbb]);
    p.extend_from_slice(&1000u32.to_be_bytes());
    p.extend_from_slice(&[0, 0, 0, 0, 0x50, 0x18, 0xff, 0xff, 0, 0, 0, 0]);
    p.extend_from_slice(&tls);
    let total = p.len() as u16;
    p[2..4].copy_from_slice(&total.to_be_bytes());
    p
}

fn demo_rst(sport: u16) -> Vec<u8> {
    let mut p = vec![0x45, 0, 0, 0, 0, 0, 0x40, 0, 64, 6, 0, 0, 93, 184, 216, 34, 10, 0, 0, 9];
    p.extend_from_slice(&[0x01, 0xbb]);
    p.extend_from_slice(&sport.to_be_bytes());
    p.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0x50, 0x04, 0xff, 0xff, 0, 0, 0, 0]);
    let total = p.len() as u16;
    p[2..4].copy_from_slice(&total.to_be_bytes());
    p
}

pub fn check_filters() -> anyhow::Result<()> {
    let mut any_err = false;

    for (label, cfg) in [
        ("default", EvasionConfig::default()),
        (
            "dns-upstream=9.9.9.9",
            EvasionConfig {
                dns_upstream: Some("9.9.9.9".parse().unwrap()),
                ..Default::default()
            },
        ),
    ] {
        let f = filter::build(&cfg).map_err(|e| anyhow::anyhow!("build ({label}): {e}"))?;
        println!("[{label}] main:");
        println!("  {}", f.main.to_string_lossy());
        match compile_filter(&f.main, Layer::Network) {
            Ok(()) => println!("  -> WinDivertHelperCompileFilter: OK"),
            Err(e) => {
                any_err = true;
                println!("  -> REJECTED at pos {}: {}", e.pos, e.msg);
            }
        }
        if let Some(q) = &f.quic_drop {
            match compile_filter(q, Layer::Network) {
                Ok(()) => println!("  quic-drop -> OK"),
                Err(e) => {
                    any_err = true;
                    println!("  quic-drop -> REJECTED at pos {}: {}", e.pos, e.msg);
                }
            }
        }
        println!();
    }

    if any_err {
        anyhow::bail!("one or more filters rejected by WinDivert");
    }
    println!("all filters accepted.");
    Ok(())
}

fn init_tracing() {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(true)
        .try_init();
}

pub fn run_engine(
    secs: Option<u64>,
    strategy: Option<Strategy>,
    enable_overlap: bool,
    profile_dir_override: Option<PathBuf>,
) -> anyhow::Result<()> {
    init_tracing();
    let mut cfg = cfg_for(enable_overlap);

    // Persistence: discovery runs only (forced `--strategy` runs stay in-memory).
    let net_human = if strategy.is_none() {
        let (human, key) = crate::netkey::compute();
        cfg.profile = Some(ProfilePaths { dir: profile_dir(profile_dir_override), net_key: key });
        Some(human)
    } else {
        None
    };

    let filters =
        filter::build(&cfg).map_err(|e| anyhow::anyhow!("{}", crate::i18n::err_filter_build(&e.to_string())))?;

    // Fail fast on a bad filter — user-mode, before touching the driver.
    compile_filter(&filters.main, Layer::Network)
        .map_err(|e| anyhow::anyhow!("{}", crate::i18n::err_filter_rejected(e.pos, &e.msg)))?;
    println!("{}", crate::i18n::t(crate::i18n::Msg::FilterCompiledOk));

    // Build the engine now (before touching the driver) so `--engine` without
    // `--strategy` genuinely runs auto-discovery and the mode is visible even
    // on a non-elevated smoke run.
    let engine = build_engine(cfg, strategy);
    if engine.is_discovery() {
        println!("{}", crate::i18n::engine_mode_auto(engine.grid_len()));
        if let (Some(p), Some(human)) = (engine.config().profile.as_ref(), &net_human) {
            let path = bosphorus_core::profile::persist::profile_path(&p.dir, &p.net_key);
            let loaded = engine.discovery_summary().iter().filter(|t| t.from_disk).count();
            println!("{}", crate::i18n::profile_line(&path.display().to_string()));
            println!("{}", crate::i18n::net_line(human, loaded));
        }
        if enable_overlap {
            println!("{}", crate::i18n::t(crate::i18n::Msg::OverlapEnabledWarning));
        }
        // The auto-discovery warning — shown once, discovery mode only.
        println!();
        println!("{}", crate::i18n::t(crate::i18n::Msg::DiscoveryWarning));
    } else {
        println!("{}", crate::i18n::t(crate::i18n::Msg::EngineModeForced));
    }
    match secs {
        Some(n) => println!("{}", crate::i18n::run_timed(n)),
        None => println!("{}", crate::i18n::t(crate::i18n::Msg::RunStopCtrlC)),
    }
    println!();

    let h = match WinDivertHandle::open(filters.main.as_c_str(), Layer::Network, 0, OpenFlags::new()) {
        Ok(h) => h,
        Err(DivertError::Open(e)) => {
            let hint = match e.0 {
                5 => crate::i18n::t(crate::i18n::Msg::HintElevated),
                2 => crate::i18n::t(crate::i18n::Msg::HintDriverColocated),
                _ => "",
            };
            anyhow::bail!("{}", crate::i18n::err_windivert_open(&e.to_string(), hint));
        }
        Err(e) => anyhow::bail!("{}", crate::i18n::err_windivert_open(&e.to_string(), "")),
    };
    // D2: raise the driver's kernel queue above the 4096-packet / 2000-ms
    // defaults (same values GoodbyeDPI uses) so a bulk transfer isn't throttled
    // by the queue filling faster than our recv loop drains it.
    let _ = h.set_param(Param::QueueLength, 16_384);
    let _ = h.set_param(Param::QueueTime, 8_000);

    let (maj, min) = h.version().unwrap_or((0, 0));
    println!("WinDivert {maj}.{min}");

    let h = Arc::new(h);
    let stop = Arc::new(StopFlag::new());

    {
        let h = Arc::clone(&h);
        let stop = Arc::clone(&stop);
        let _ = ctrlc::set_handler(move || {
            stop.stop();
            let _ = h.shutdown_both();
        });
    }
    if let Some(n) = secs {
        let h = Arc::clone(&h);
        let stop = Arc::clone(&stop);
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_secs(n));
            stop.stop();
            let _ = h.shutdown_both();
        });
    }

    let mut src = WinDivertSource { h: Arc::clone(&h) };
    let mut sink = WinDivertSink { h: Arc::clone(&h) };
    let engine = Arc::new(engine);

    // Tick thread: sweep idle flows + resolve verdict timeouts (~2 Hz).
    {
        let engine = Arc::clone(&engine);
        let stop = Arc::clone(&stop);
        std::thread::spawn(move || {
            while !stop.is_stopped() {
                engine.tick(std::time::Instant::now());
                std::thread::sleep(Duration::from_millis(500));
            }
        });
    }

    // Live network-change watch (interactive parity with the service): a route
    // or unicast-address change arms a debounced NetKey re-check on the tick
    // thread. Held for the run; dropped before `persist_now` so no callback can
    // fire during shutdown. Discovery mode only — a forced strategy is
    // network-independent.
    let _netwatch = if engine.is_discovery() {
        match crate::netwatch::NetWatch::start({
            let engine = Arc::clone(&engine);
            move || engine.mark_netkey_dirty()
        }) {
            Ok(w) => {
                tracing::info!(
                    target: "bosphorus::net",
                    "route-change watch active — network switches are auto-detected"
                );
                Some(w)
            }
            Err(e) => {
                tracing::warn!(
                    target: "bosphorus::net", error = %e,
                    "route-change watch unavailable; network switches won't be auto-detected"
                );
                None
            }
        }
    } else {
        None
    };

    let run = engine.run_main(&mut src, &mut sink, &stop);
    drop(_netwatch); // stop callbacks before the final flush
    engine.persist_now(); // flush the discovery profile even on a run error
    let stats = run?;

    println!();
    println!(
        "{}",
        crate::i18n::engine_finished(
            stats.packets,
            stats.bytes / 1024,
            stats.dropped,
            stats.batches,
        )
    );

    let summary = engine.discovery_summary();
    if !summary.is_empty() {
        use crate::i18n;
        println!();
        println!("{}", i18n::summary_title(engine.grid_len()));
        let mut rows: Vec<_> = summary.iter().collect();
        rows.sort_by(|a, b| a.key.cmp(&b.key));
        for t in rows {
            let phase = format!("{:?}", t.phase);
            let src = if t.from_disk {
                i18n::t(i18n::Msg::OriginDisk)
            } else {
                i18n::t(i18n::Msg::OriginNew)
            };
            match (&t.phase, t.active_is_passthrough, &t.active, &t.best) {
                (bosphorus_core::NetPhase::Exhausted, ..) => {
                    println!(
                        "  !! [{src}] {:<32} {:<10} — {}",
                        t.key,
                        phase,
                        i18n::summary_exhausted(t.tried, t.total)
                    );
                }
                (bosphorus_core::NetPhase::Active, true, ..) => {
                    println!(
                        "  ok [{src}] {:<32} {:<10} — {}",
                        t.key,
                        phase,
                        i18n::t(i18n::Msg::NotBlockedPassthrough)
                    );
                }
                (bosphorus_core::NetPhase::Active, false, Some(a), _) => {
                    println!("  OK [{src}] {:<32} {:<10} — {}", t.key, phase, i18n::summary_active(a));
                }
                _ => {
                    let best = t
                        .best
                        .as_ref()
                        .map(|(d, s, tr)| i18n::best_so_far(d, *s, *tr))
                        .unwrap_or_else(|| i18n::t(i18n::Msg::NoSuccessYet).to_string());
                    let age = t
                        .last_trial_age
                        .map(|d| i18n::secs_ago(d.as_secs()))
                        .unwrap_or_else(|| "-".into());
                    println!(
                        "  .. [{src}] {:<32} {:<10} — {}",
                        t.key,
                        phase,
                        i18n::summary_progress(t.tried, t.total, t.in_flight, &age, &best)
                    );
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn engine_with_no_strategy_is_discovery() {
        let e = build_engine(cfg_for(false), None);
        assert!(e.is_discovery(), "--engine (no --strategy) must run auto-discovery");
        // Default (overlap OFF) => 142 split + 12 multi + 6 tls_pad + 6 aggressive fake.
        assert_eq!(e.grid_len(), 166, "grid: {}", e.grid_len());
    }

    #[test]
    fn enable_overlap_widens_the_discovery_grid() {
        let e = build_engine(cfg_for(true), None);
        assert!(e.is_discovery());
        assert_eq!(e.grid_len(), 174, "142 split + 12 multi + 6 tls_pad + 6 aggressive + 8 overlap");
    }

    #[test]
    fn engine_with_strategy_is_forced() {
        let e = build_engine(EvasionConfig::default(), Some(Strategy::m4_fixed()));
        assert!(!e.is_discovery(), "--engine --strategy ... must force that strategy");
    }

    #[test]
    fn parse_strategy_forms() {
        assert!(matches!(parse_strategy("list", false).unwrap(), StrategyArg::List));
        assert!(matches!(parse_strategy("sni", false).unwrap(), StrategyArg::One(_)));
        assert!(matches!(parse_strategy("6/wrongsum", false).unwrap(), StrategyArg::One(_)));
        assert!(matches!(parse_strategy("grid:0", false).unwrap(), StrategyArg::One(_)));
        assert!(matches!(
            parse_strategy("overlap:16/sni", false).unwrap(),
            StrategyArg::One(_)
        ));
        // multi-part: comma-joined anchors
        match parse_strategy("tls,sni", false).unwrap() {
            StrategyArg::One(s) => {
                assert_eq!(s.fragment.as_ref().unwrap().anchors.len(), 2);
            }
            _ => panic!("expected One"),
        }
        assert!(parse_strategy("bogus/x", false).is_err());
        assert!(parse_strategy("none/none", false).is_err());
        // grid:166 (first overlap entry) only exists once overlap is opted in.
        assert!(parse_strategy("grid:166", false).is_err());
        assert!(matches!(parse_strategy("grid:166", true).unwrap(), StrategyArg::One(_)));

        // M7c: +pad:<n> forces tls_pad, on any form.
        match parse_strategy("2/wrongseq+pad:512", false).unwrap() {
            StrategyArg::One(s) => assert_eq!(s.tls_pad, Some(512)),
            _ => panic!("expected One"),
        }
        match parse_strategy("grid:0+pad:9", false).unwrap() {
            StrategyArg::One(s) => assert_eq!(s.tls_pad, Some(9)),
            _ => panic!("expected One"),
        }
        assert!(parse_strategy("2/wrongseq+pad:bogus", false).is_err());
    }
}
