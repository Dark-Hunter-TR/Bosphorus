//! `--observe` — analysis-only traffic profiler. NOT part of the engine or M7.
//!
//! SNIFF-mode capture of ALL TCP + UDP on ALL ports (both directions). Never
//! reinjects, never mutates — pure observation. Groups flows by SNI (or server
//! IP) + port + protocol and prints a profile table with a rough per-target
//! outcome (OK / DpiReset / Blackhole).
//!
//! Purpose: see what the Discord desktop app actually does — QUIC/UDP? other
//! TCP ports? a specific blocked SNI/IP set?

use std::collections::HashMap;
use std::ffi::CString;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bosphorus_divert::{DivertError, Layer, OpenFlags, WinDivertHandle};

const BUF: usize = 65_535;

pub fn run(secs: u64) -> anyhow::Result<()> {
    println!("=== Bosphorus --observe — traffic profiler (analysis only, no mutation) ===\n");
    println!("SNIFF modu: TUM TCP+UDP, tum portlar. Hicbir paket degistirilmez / yeniden");
    println!("enjekte edilmez. {secs}s boyunca Discord masaustu uygulamasini acip GIRIS");
    println!("DENEYIN (varsa cikis yapip yeniden giris). Sonra tablo yazdirilir.\n");

    let h = match WinDivertHandle::open(
        CString::new("tcp or udp").unwrap().as_c_str(),
        Layer::Network,
        0,
        OpenFlags::new().sniff(),
    ) {
        Ok(h) => h,
        Err(DivertError::Open(e)) if e.0 == 5 => {
            anyhow::bail!("WinDivertOpen: ERROR_ACCESS_DENIED — elevated (Yonetici) calistirin");
        }
        Err(e) => anyhow::bail!("WinDivertOpen basarisiz: {e}"),
    };

    let h = Arc::new(h);
    let hc = Arc::clone(&h);
    let worker = std::thread::spawn(move || capture(&hc));
    std::thread::sleep(Duration::from_secs(secs));
    let _ = h.shutdown_both();
    let state = worker.join().map_err(|_| anyhow::anyhow!("capture worker panicked"))?;

    print_report(&state);
    Ok(())
}

// ---------------------------------------------------------------------------

type FlowKey = (bool, IpAddr, u16, IpAddr, u16); // (is_udp, client_ip, client_port, server_ip, server_port)

#[derive(Default)]
struct FlowSt {
    sni: Option<String>,
    outbound_syn: bool,
    synack_in: bool,
    client_hello: bool,
    quic_initial: bool,
    quic_version: Option<u32>,
    inbound_data: bool,
    inbound_rst: bool,
    ch_at: Option<Instant>,
    rst_dt_ms: Option<u128>,
}

struct State {
    flows: HashMap<FlowKey, FlowSt>,
    bytes_out: u64,
    bytes_in: u64,
    total_pkts: u64,
}

fn capture(h: &WinDivertHandle) -> State {
    let mut buf = vec![0u8; BUF];
    let mut st = State { flows: HashMap::new(), bytes_out: 0, bytes_in: 0, total_pkts: 0 };
    loop {
        match h.recv(&mut buf) {
            Ok(r) => {
                st.total_pkts += 1;
                observe(&mut st, r.data, r.addr.outbound());
            }
            Err(DivertError::ShutDown) => break,
            Err(e) => {
                eprintln!("recv hata: {e}");
                break;
            }
        }
    }
    st
}

struct L4 {
    is_udp: bool,
    payload_off: usize,
    src_ip: IpAddr,
    dst_ip: IpAddr,
    src_port: u16,
    dst_port: u16,
    syn: bool,
    ack: bool,
    rst: bool,
}

fn parse(pkt: &[u8]) -> Option<L4> {
    let (ihl, proto, src_ip, dst_ip) = match *pkt.first()? >> 4 {
        4 => {
            if pkt.len() < 20 {
                return None;
            }
            let n = (pkt[0] & 0x0f) as usize * 4;
            if !(20..=pkt.len()).contains(&n) {
                return None;
            }
            (
                n,
                pkt[9],
                IpAddr::V4(Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15])),
                IpAddr::V4(Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19])),
            )
        }
        6 => {
            if pkt.len() < 40 {
                return None;
            }
            let mut s = [0u8; 16];
            let mut d = [0u8; 16];
            s.copy_from_slice(&pkt[8..24]);
            d.copy_from_slice(&pkt[24..40]);
            (40usize, pkt[6], IpAddr::V6(Ipv6Addr::from(s)), IpAddr::V6(Ipv6Addr::from(d)))
        }
        _ => return None,
    };
    let t = pkt.get(ihl..)?;
    match proto {
        6 => {
            if t.len() < 20 {
                return None;
            }
            let doff = (t[12] >> 4) as usize * 4;
            if !(20..=t.len()).contains(&doff) {
                return None;
            }
            let f = t[13];
            Some(L4 {
                is_udp: false,
                payload_off: ihl + doff,
                src_ip,
                dst_ip,
                src_port: u16::from_be_bytes([t[0], t[1]]),
                dst_port: u16::from_be_bytes([t[2], t[3]]),
                syn: f & 0x02 != 0,
                ack: f & 0x10 != 0,
                rst: f & 0x04 != 0,
            })
        }
        17 => {
            if t.len() < 8 {
                return None;
            }
            Some(L4 {
                is_udp: true,
                payload_off: ihl + 8,
                src_ip,
                dst_ip,
                src_port: u16::from_be_bytes([t[0], t[1]]),
                dst_port: u16::from_be_bytes([t[2], t[3]]),
                syn: false,
                ack: false,
                rst: false,
            })
        }
        _ => None,
    }
}

/// Best-effort SNI from a TLS ClientHello (works on a truncated first segment).
fn tls_sni(p: &[u8]) -> Option<String> {
    if p.len() < 9 || p[0] != 0x16 || p[1] != 0x03 || p[5] != 0x01 {
        return None;
    }
    let rec = u16::from_be_bytes([p[3], p[4]]) as usize;
    let end = (5 + rec).min(p.len());
    let hs = p.get(5..end)?;
    let mut i = 4 + 2 + 32usize; // hs hdr + client_version + random
    i += *hs.get(i)? as usize + 1; // session id
    i = i.checked_add(u16::from_be_bytes([*hs.get(i)?, *hs.get(i + 1)?]) as usize + 2)?; // cipher suites
    i += *hs.get(i)? as usize + 1; // compression methods
    i += 2; // extensions length
    while i + 4 <= hs.len() {
        let ext_ty = u16::from_be_bytes([hs[i], hs[i + 1]]);
        let ext_len = u16::from_be_bytes([hs[i + 2], hs[i + 3]]) as usize;
        let body = hs.get(i + 4..i + 4 + ext_len)?;
        if ext_ty == 0 {
            let nl = u16::from_be_bytes([*body.get(3)?, *body.get(4)?]) as usize;
            return std::str::from_utf8(body.get(5..5 + nl)?)
                .ok()
                .map(|s| s.to_ascii_lowercase());
        }
        i += 4 + ext_len;
    }
    None
}

fn is_clienthello(p: &[u8]) -> bool {
    p.len() >= 6 && p[0] == 0x16 && p[1] == 0x03 && p[5] == 0x01
}

/// QUIC long-header Initial? Returns `Some(version)`.
fn quic_initial(p: &[u8]) -> Option<u32> {
    if p.len() < 5 || p[0] & 0xc0 != 0xc0 || p[0] & 0x30 != 0x00 {
        return None;
    }
    Some(u32::from_be_bytes([p[1], p[2], p[3], p[4]]))
}

fn observe(st: &mut State, pkt: &[u8], outbound: bool) {
    let Some(l4) = parse(pkt) else { return };
    if outbound {
        st.bytes_out += pkt.len() as u64;
    } else {
        st.bytes_in += pkt.len() as u64;
    }
    let payload = pkt.get(l4.payload_off..).unwrap_or(&[]);
    let now = Instant::now();

    let (cip, cport, sip, sport) = if outbound {
        (l4.src_ip, l4.src_port, l4.dst_ip, l4.dst_port)
    } else {
        (l4.dst_ip, l4.dst_port, l4.src_ip, l4.src_port)
    };
    let f = st.flows.entry((l4.is_udp, cip, cport, sip, sport)).or_default();

    if l4.is_udp {
        if outbound {
            if let Some(v) = quic_initial(payload) {
                f.quic_initial = true;
                f.quic_version = Some(v);
                f.ch_at.get_or_insert(now);
            }
        } else if !payload.is_empty() {
            f.inbound_data = true;
        }
        return;
    }

    if outbound {
        if l4.syn && !l4.ack {
            f.outbound_syn = true;
        }
        if is_clienthello(payload) {
            f.client_hello = true;
            f.ch_at.get_or_insert(now);
            if f.sni.is_none() {
                f.sni = tls_sni(payload);
            }
        }
    } else {
        if l4.syn && l4.ack {
            f.synack_in = true;
        }
        if l4.rst {
            f.inbound_rst = true;
            if let Some(t) = f.ch_at {
                f.rst_dt_ms.get_or_insert(t.elapsed().as_millis());
            }
        }
        if !payload.is_empty() {
            f.inbound_data = true;
        }
    }
}

// ---------------------------------------------------------------------------

#[derive(Default)]
struct Row {
    conns: usize,
    tls_ch: usize,
    quic_init: usize,
    rst_in: usize,
    ok: usize,        // saw inbound data
    blackhole: usize, // CH/QUIC out, nothing back
    rst_dts: Vec<u128>,
    quic_versions: Vec<u32>,
}

fn print_report(st: &State) {
    let mut rows: HashMap<(String, u16, &'static str), Row> = HashMap::new();
    for ((is_udp, _cip, _cport, sip, sport), f) in &st.flows {
        let proto = if *is_udp { "udp" } else { "tcp" };
        let name = f.sni.clone().unwrap_or_else(|| sip.to_string());
        let r = rows.entry((name, *sport, proto)).or_default();
        r.conns += 1;
        if f.client_hello {
            r.tls_ch += 1;
        }
        if f.quic_initial {
            r.quic_init += 1;
        }
        if f.inbound_rst {
            r.rst_in += 1;
        }
        if let Some(d) = f.rst_dt_ms {
            r.rst_dts.push(d);
        }
        if f.inbound_data {
            r.ok += 1;
        } else if f.client_hello || f.quic_initial {
            r.blackhole += 1;
        }
        if let Some(v) = f.quic_version {
            if !r.quic_versions.contains(&v) {
                r.quic_versions.push(v);
            }
        }
    }

    println!("\n================ --observe SONUC (bu blogu bana yapistir) ================");
    println!("toplam paket: {}", st.total_pkts);
    println!("toplam bayt : OUT {} KB / IN {} KB", st.bytes_out / 1024, st.bytes_in / 1024);
    println!("akis sayisi : {}", st.flows.len());
    println!();
    println!(
        "{:<38} {:>5} {:>4} {:>5} {:>4} {:>5} {:>6}  {:<9} detay",
        "hedef (SNI veya server IP)", "port", "prt", "baglt", "CH", "QUIC", "RST-in", "gozlem"
    );
    println!("{}", "-".repeat(100));

    let mut sorted: Vec<_> = rows.into_iter().collect();
    sorted.sort_by(|a, b| {
        (b.1.tls_ch + b.1.quic_init + b.1.conns).cmp(&(a.1.tls_ch + a.1.quic_init + a.1.conns))
    });

    for ((name, port, proto), r) in sorted {
        let verdict = if r.rst_in > 0 && r.ok == 0 {
            "DpiReset"
        } else if r.blackhole > 0 && r.ok == 0 {
            "Blackhole"
        } else if r.ok > 0 && r.blackhole == 0 && r.rst_in == 0 {
            "OK"
        } else if r.ok > 0 {
            "mixed"
        } else {
            "?"
        };
        let mut detay = String::new();
        if !r.quic_versions.is_empty() {
            detay.push_str(&format!(
                "quicv={} ",
                r.quic_versions.iter().map(|v| format!("0x{v:08x}")).collect::<Vec<_>>().join(",")
            ));
        }
        if !r.rst_dts.is_empty() {
            let avg = r.rst_dts.iter().sum::<u128>() / r.rst_dts.len() as u128;
            detay.push_str(&format!("rst~{avg}ms "));
        }
        println!(
            "{:<38} {:>5} {:>4} {:>5} {:>4} {:>5} {:>6}  {:<9} {}",
            trunc(&name, 38),
            port,
            proto,
            r.conns,
            r.tls_ch,
            r.quic_init,
            r.rst_in,
            verdict,
            detay.trim()
        );
    }
    println!("{}", "=".repeat(100));
    println!("\nNot: CH = TLS ClientHello sayisi | QUIC = QUIC Initial paket sayisi");
    println!("RST-in = sunucudan/DPI'dan gelen RST | verdict kaba: DpiReset / Blackhole / OK / mixed");
}

fn trunc(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        let cut: String = s.chars().take(n - 1).collect();
        format!("{cut}~")
    }
}
