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
use bosphorus_core::config::QuicPolicy;
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

/// Which profile store an interactive `--engine` run resolved to, and why.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProfileDirSource {
    /// An explicit `--profile-dir` — always wins.
    Flag,
    /// The Windows service is installed and has already learned this network,
    /// so its `%ProgramData%` store is read/written and the two run modes share
    /// one per-network memory ("service = authority").
    ServiceAuthority,
    /// The per-user `%LOCALAPPDATA%\Bosphorus\profiles` default.
    PerUser,
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// The per-user default: `%LOCALAPPDATA%\Bosphorus\profiles` (temp-dir fallback).
fn user_profile_dir() -> PathBuf {
    std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir)
        .join("Bosphorus")
        .join("profiles")
}

/// Pure decision core (unit-tested). `svc_installed` / `svc_file_exists` are the
/// two facts [`resolve_profile_dir`] gathers from the environment.
///
/// 1. an explicit `--profile-dir` is unconditional — it never loses.
/// 2. else, if the service is installed *and* it already has a profile for this
///    exact network, use its store (so an interactive run sees, and feeds back
///    into, what the long-running service learned).
/// 3. else, the per-user default (unchanged behaviour when no service).
fn pick_profile_dir(
    override_dir: Option<PathBuf>,
    svc_installed: bool,
    svc_file_exists: bool,
    svc_dir: PathBuf,
    user_dir: PathBuf,
) -> (PathBuf, ProfileDirSource) {
    if let Some(d) = override_dir {
        return (d, ProfileDirSource::Flag);
    }
    if svc_installed && svc_file_exists {
        return (svc_dir, ProfileDirSource::ServiceAuthority);
    }
    (user_dir, ProfileDirSource::PerUser)
}

/// Resolve the discovery-profile directory for `net_key`, gathering the service
/// facts (`is_installed` is a plain SCM `QUERY_STATUS` — no elevation).
fn resolve_profile_dir(
    override_dir: Option<PathBuf>,
    net_key: &str,
) -> (PathBuf, ProfileDirSource) {
    let svc_dir = crate::service::profiles_dir();
    let svc_file_exists = svc_dir.join(format!("{net_key}.json")).is_file();
    pick_profile_dir(
        override_dir,
        crate::service::is_installed(),
        svc_file_exists,
        svc_dir,
        user_profile_dir(),
    )
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
        // Every shipped filter string gets checked, not just the ones today's
        // defaults happen to build.
        ("quic=off", EvasionConfig { quic: QuicPolicy::Off, ..Default::default() }),
        ("quic=all", EvasionConfig { quic: QuicPolicy::All, ..Default::default() }),
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

/// Open the blanket QUIC-block handle, if this run's policy asked for one.
///
/// `WINDIVERT_FLAG_DROP` means the driver discards every match without queueing
/// it, so nothing is ever received from this handle — keeping it alive *is* the
/// block. Shared by `--engine` and the service.
pub fn open_quic_block(filters: &filter::Filters) -> anyhow::Result<Option<WinDivertHandle>> {
    let Some(f) = filters.quic_drop.as_ref() else {
        return Ok(None);
    };
    let h = WinDivertHandle::open(f.as_c_str(), Layer::Network, 0, OpenFlags::new().drop())
        .map_err(|e| anyhow::anyhow!("{}", crate::i18n::err_quic_block_open(&e.to_string())))?;
    Ok(Some(h))
}

/// The one-line summary of what this run does about HTTP/3.
pub fn quic_policy_line(policy: QuicPolicy) -> &'static str {
    crate::i18n::t(match policy {
        QuicPolicy::Off => crate::i18n::Msg::QuicOff,
        QuicPolicy::Blocked => crate::i18n::Msg::QuicBlockSelective,
        QuicPolicy::All => crate::i18n::Msg::QuicBlockAll,
    })
}

/// Everything `--engine` accepts. A struct rather than positional arguments
/// because the flags are mostly `bool`/`Option` and a call site reads as
/// `(None, None, false, None, None)` otherwise.
#[derive(Debug, Default)]
pub struct EngineOpts {
    /// Stop automatically after this many seconds (`--secs`).
    pub secs: Option<u64>,
    /// Force one strategy instead of running discovery (`--strategy`).
    pub strategy: Option<Strategy>,
    /// Admit `OverlapDisorder` candidates (`--enable-overlap`).
    pub enable_overlap: bool,
    /// Override where profiles are read and written (`--profile-dir`).
    pub profile_dir: Option<PathBuf>,
    /// Opt into the cross-network seed pool under this tag (`--isp`).
    pub isp: Option<String>,
    /// How to treat HTTP/3 (`--quic`).
    pub quic: QuicPolicy,
}

pub fn run_engine(opts: EngineOpts) -> anyhow::Result<()> {
    let EngineOpts { secs, strategy, enable_overlap, profile_dir: profile_dir_override, isp, quic } =
        opts;
    init_tracing();
    let mut cfg = cfg_for(enable_overlap);
    cfg.quic = quic;

    // Persistence: discovery runs only (forced `--strategy` runs stay in-memory).
    let mut profile_src = None;
    // (resolved profile dir, net_key) — kept for the ISP pool file below.
    let mut store_ctx: Option<(PathBuf, String)> = None;
    let net_human = if strategy.is_none() {
        let (human, key) = crate::netkey::compute();
        let (dir, src) = resolve_profile_dir(profile_dir_override, &key);
        profile_src = Some(src);
        store_ctx = Some((dir.clone(), key.clone()));
        cfg.profile = Some(ProfilePaths { dir, net_key: key });
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
            if let Some(src) = profile_src {
                println!(
                    "  profile store: {}",
                    match src {
                        ProfileDirSource::Flag => "--profile-dir (explicit)",
                        ProfileDirSource::ServiceAuthority =>
                            "service %ProgramData% (authoritative)",
                        ProfileDirSource::PerUser => "per-user %LOCALAPPDATA%",
                    }
                );
            }
            // Feature C: cross-network ISP seed pool (opt-in via --isp).
            if let (Some(name), Some((dir, _))) = (&isp, &store_ctx) {
                let pool = bosphorus_core::IspPool::load(dir, name)
                    .unwrap_or_else(|| bosphorus_core::IspPool::new(name));
                let n = pool.seeds().len();
                println!(
                    "  isp pool: \"{name}\" — {n} seedable strateg{}",
                    if n == 1 { "y" } else { "ies" }
                );
                engine.set_isp_pool(std::sync::Arc::new(pool));
            }
        }
        println!("  {}", quic_policy_line(quic));
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

    // `QuicPolicy::All` only: a second handle whose matches the driver discards
    // outright, so the blanket block costs nothing per packet. Held for the run;
    // the selective policy needs no handle because its packets arrive on `h`.
    let _quic_block = open_quic_block(&filters)?;

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

    // Feature C: fold this session's promotions into the ISP seed pool.
    if let (Some(name), Some((dir, net_key))) = (&isp, &store_ctx) {
        let promoted = engine.with_discovery(|d| d.promoted_for_isp());
        let mut pool = bosphorus_core::IspPool::load(dir, name)
            .unwrap_or_else(|| bosphorus_core::IspPool::new(name));
        pool.merge_session(net_key, &promoted, now_unix());
        match pool.save(dir) {
            Ok(bytes) => println!(
                "  isp pool: merged {} promoted strateg{} ({bytes} B)",
                promoted.len(),
                if promoted.len() == 1 { "y" } else { "ies" }
            ),
            Err(e) => tracing::warn!(target: "bosphorus::discovery", error = %e, "isp pool save failed"),
        }
    }
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

    fn svc() -> PathBuf {
        PathBuf::from(r"C:\ProgramData\Bosphorus\profiles")
    }
    fn usr() -> PathBuf {
        PathBuf::from(r"C:\Users\me\AppData\Local\Bosphorus\profiles")
    }

    #[test]
    fn profile_dir_explicit_flag_always_wins() {
        let flag = PathBuf::from(r"D:\custom\profiles");
        for (inst, exists) in [(true, true), (true, false), (false, true), (false, false)] {
            assert_eq!(
                pick_profile_dir(Some(flag.clone()), inst, exists, svc(), usr()),
                (flag.clone(), ProfileDirSource::Flag),
                "flag must win for (installed={inst}, file={exists})"
            );
        }
    }

    #[test]
    fn profile_dir_service_installed_with_this_network_uses_the_service_store() {
        assert_eq!(
            pick_profile_dir(None, true, true, svc(), usr()),
            (svc(), ProfileDirSource::ServiceAuthority)
        );
    }

    #[test]
    fn profile_dir_service_installed_but_no_profile_for_this_network_uses_per_user() {
        assert_eq!(
            pick_profile_dir(None, true, false, svc(), usr()),
            (usr(), ProfileDirSource::PerUser)
        );
    }

    #[test]
    fn profile_dir_no_service_uses_per_user_even_if_a_file_is_there() {
        assert_eq!(
            pick_profile_dir(None, false, true, svc(), usr()),
            (usr(), ProfileDirSource::PerUser)
        );
    }

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
