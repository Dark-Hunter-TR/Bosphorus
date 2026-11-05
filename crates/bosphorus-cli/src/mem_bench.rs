//! `--mem-bench <N>`: no-elevation RAM probe.
//!
//! Synthesizes `N` discovery targets through a real [`Engine`] — most driven to
//! a clean `Active` passthrough, ~1-in-7 driven all the way to grid
//! `Exhausted` — then prints the `bosphorus::mem` digest plus this process's
//! working set, before and after a far-future maintenance tick (idle sweep +,
//! once it exists, target eviction).
//!
//! Run the same command on the pre-change and post-change binary and diff the
//! two blocks; that is the before/after comparison for the eviction step.

use std::time::{Duration, Instant};

use bosphorus_core::{CaptureMeta, Decision, Engine, EvasionConfig, NetPhase, ProfilePaths, SendBatch};

pub fn run(n: usize) -> anyhow::Result<()> {
    // Console logs are plain text (no ANSI escapes); see `logging::console_layer`.
    crate::logging::init_console("bosphorus::mem=debug");

    let dir = std::env::temp_dir().join("bosphorus-mem-bench");
    let _ = std::fs::remove_dir_all(&dir);
    let cfg = EvasionConfig {
        profile: Some(ProfilePaths { dir: dir.clone(), net_key: "membench".into() }),
        ..Default::default()
    };
    let engine = Engine::new(cfg);
    println!("mem-bench N={n}  grid={} strategies", engine.grid_len());
    println!("profile: {}", dir.display());

    // Every flow needs a unique client port — a stale flow at a reused port is
    // treated as a ClientHello retransmit and passes straight through, so the
    // sweep would never progress. Monotonic counter over the ephemeral range.
    let mut next_port = 1025u16;
    let mut port = || {
        let p = next_port;
        next_port = if next_port >= 60_000 { 1025 } else { next_port + 1 };
        p
    };

    let blocked_every = 7usize; // ~14% of targets end up Exhausted
    for i in 0..n {
        let host = format!("t{i:05}.membench.test");
        let p0 = port();

        // ClientHello -> Probe control (no mutation).
        drive(&engine, client_hello(&host, p0), true);

        if i % blocked_every == 0 {
            // Blocked: inbound RST -> Discover, then fail candidates until the
            // grid is Exhausted for this target (each ClientHello+RST rules one
            // out; a few candidates are unbuildable for this minimal SNI and
            // are skipped by discovery itself).
            drive(&engine, rst(p0), false);
            for _ in 0u16..600 {
                let p2 = port();
                drive(&engine, client_hello(&host, p2), true);
                drive(&engine, rst(p2), false);
                if target_phase(&engine, &host) == Some(NetPhase::Exhausted) {
                    break;
                }
            }
        } else {
            // Clean: inbound ServerHello -> Success -> Active passthrough.
            drive(&engine, server_hello(p0), false);
        }
    }

    engine.persist_now();
    report(&engine, "after fill");

    // Far-future tick: forces the idle flow sweep and target eviction.
    let future = Instant::now() + Duration::from_secs(48 * 3600);
    for _ in 0..3 {
        engine.tick(future);
    }
    engine.persist_now();
    report(&engine, "after tick(now + 48h)");

    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

fn drive(engine: &Engine, pkt: Vec<u8>, outbound: bool) -> Decision {
    let mut p = pkt;
    let mut meta = CaptureMeta { outbound, ..Default::default() };
    let mut out = SendBatch::new();
    engine.process(&mut p, &mut meta, &mut out)
}

fn target_phase(engine: &Engine, host: &str) -> Option<NetPhase> {
    engine.target_phase(host)
}

fn report(engine: &Engine, label: &str) {
    let summary = engine.discovery_summary();
    let mut c = [0usize; 4];
    for t in &summary {
        let i = match t.phase {
            NetPhase::Probe => 0,
            NetPhase::Discover => 1,
            NetPhase::Active => 2,
            NetPhase::Exhausted => 3,
        };
        c[i] += 1;
    }
    let (flows, flow_cap) = engine.flows().stats();
    let (ws, priv_kib) = working_set_kib();
    println!("--- {label} ---");
    println!(
        "  targets={:<6} probe={} discover={} active={} exhausted={}",
        summary.len(),
        c[0],
        c[1],
        c[2],
        c[3]
    );
    println!("  flows={flows}  flow_cap={flow_cap}");
    println!("  working_set={ws} KiB   private={priv_kib} KiB");
}

/// This process's working set and private (pagefile) bytes, in KiB.
fn working_set_kib() -> (u64, u64) {
    use windows::Win32::System::ProcessStatus::{GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS};
    use windows::Win32::System::Threading::GetCurrentProcess;

    let mut counters = PROCESS_MEMORY_COUNTERS::default();
    let cb = std::mem::size_of::<PROCESS_MEMORY_COUNTERS>() as u32;
    // SAFETY: `counters` is a valid, correctly-sized out-param; the pseudo
    // handle from `GetCurrentProcess` needs no close.
    let ok = unsafe { GetProcessMemoryInfo(GetCurrentProcess(), &mut counters, cb) };
    if ok.as_bool() {
        (
            counters.WorkingSetSize as u64 / 1024,
            counters.PagefileUsage as u64 / 1024,
        )
    } else {
        (0, 0)
    }
}

// --- synthetic packets (IPv4/TCP, 10.0.0.9 <-> 93.184.216.34:443) ---------

fn client_hello(host: &str, sport: u16) -> Vec<u8> {
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

fn inbound(sport: u16, flags: u8, payload: &[u8]) -> Vec<u8> {
    let mut p = vec![0x45, 0, 0, 0, 0, 0, 0x40, 0, 64, 6, 0, 0, 93, 184, 216, 34, 10, 0, 0, 9];
    p.extend_from_slice(&[0x01, 0xbb]);
    p.extend_from_slice(&sport.to_be_bytes());
    p.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0x50, flags, 0xff, 0xff, 0, 0, 0, 0]);
    p.extend_from_slice(payload);
    let total = p.len() as u16;
    p[2..4].copy_from_slice(&total.to_be_bytes());
    p
}

fn rst(sport: u16) -> Vec<u8> {
    inbound(sport, 0x04, &[])
}

fn server_hello(sport: u16) -> Vec<u8> {
    inbound(sport, 0x18, &[0x16, 0x03, 0x03, 0x00, 0x05, 0x02])
}
