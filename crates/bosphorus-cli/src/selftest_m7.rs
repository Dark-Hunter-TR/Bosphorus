//! M7a selftest — OverlapDisorder feasibility on this machine.
//!
//!   V-A  inject one outbound overlap-style segment (seq - 32); report what
//!        went on the wire (ip_id / checksum — confirm with pktmon)
//!   V-B  drop one ClientHello, inject [seg_A(low seq, 32B junk), seg_B],
//!        watch inbound on that flow for a reaction (RST / ServerHello / ACK)
//!   V-C  drop one ClientHello, measure Windows' retransmit timing (RTO)
//!
//! Elevated only. V-B / V-C drop a single ClientHello — that one connection may
//! briefly stall; others are untouched.

use std::ffi::CString;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bosphorus_divert::{calc_checksums, ChecksumFlags, DivertError, Layer, OpenFlags, WinDivertHandle};

const BUF: usize = 65_535;
const WINDOW_SECS: u64 = 20;

pub fn run() -> anyhow::Result<()> {
    println!("=== Bosphorus M7a selftest — overlap / disorder feasibility ===\n");
    println!("Yonetici gerekir. Test sirasinda bir tarayicida YENI HTTPS baglantilari acin.\n");

    let va = t_overlap_segment_egress();
    let vb = t_two_overlapping_segments();
    let vc = t_windows_retransmit_behavior();

    println!("\n================ M7a SONUC OZETI (bu blogu bana yapistir) ================");
    println!("{va}");
    println!("{vb}");
    println!("{vc}");
    println!("========================================================================\n");
    println!("V-A kablo dogrulamasi (opsiyonel, ayni elevated pencerede):");
    println!("  pktmon start --capture --pkt-size 0 -f bosphorus_m7.etl");
    println!("  .\\target\\debug\\bosphorus.exe --selftest-m7");
    println!("  pktmon stop && pktmon etl2pcap bosphorus_m7.etl -o bosphorus_m7.pcapng");
    println!("  -> Wireshark'ta overlap segmentinin ip_id / TCP checksum durumuna bakin.");
    Ok(())
}

// --- minimal helpers ---

struct L4 {
    ip_hdr_len: usize,
    payload_off: usize,
    is_v6: bool,
    src_port: u16,
    dst_port: u16,
    rst: bool,
}

fn parse(pkt: &[u8]) -> Option<L4> {
    let (ihl, proto, is_v6) = match *pkt.first()? >> 4 {
        4 => {
            if pkt.len() < 20 {
                return None;
            }
            let n = (pkt[0] & 0x0f) as usize * 4;
            if !(20..=pkt.len()).contains(&n) {
                return None;
            }
            (n, pkt[9], false)
        }
        6 => {
            if pkt.len() < 40 {
                return None;
            }
            (40usize, pkt[6], true)
        }
        _ => return None,
    };
    if proto != 6 {
        return None;
    }
    let t = pkt.get(ihl..)?;
    if t.len() < 20 {
        return None;
    }
    let doff = (t[12] >> 4) as usize * 4;
    if !(20..=t.len()).contains(&doff) {
        return None;
    }
    Some(L4 {
        ip_hdr_len: ihl,
        payload_off: ihl + doff,
        is_v6,
        src_port: u16::from_be_bytes([t[0], t[1]]),
        dst_port: u16::from_be_bytes([t[2], t[3]]),
        rst: t[13] & 0x04 != 0,
    })
}

fn ips_v4(pkt: &[u8]) -> (u32, u32) {
    (
        u32::from_be_bytes([pkt[12], pkt[13], pkt[14], pkt[15]]),
        u32::from_be_bytes([pkt[16], pkt[17], pkt[18], pkt[19]]),
    )
}
fn tcp_seq(pkt: &[u8], l4: &L4) -> u32 {
    let o = l4.ip_hdr_len + 4;
    u32::from_be_bytes([pkt[o], pkt[o + 1], pkt[o + 2], pkt[o + 3]])
}
fn set_tcp_seq(pkt: &mut [u8], l4: &L4, v: u32) {
    let o = l4.ip_hdr_len + 4;
    pkt[o..o + 4].copy_from_slice(&v.to_be_bytes());
}
fn fix_ip_len(pkt: &mut [u8]) {
    let t = pkt.len() as u16;
    pkt[2..4].copy_from_slice(&t.to_be_bytes());
}
fn ip_id_v4(pkt: &[u8]) -> u16 {
    u16::from_be_bytes([pkt[4], pkt[5]])
}
fn tcp_cksum(pkt: &[u8], l4: &L4) -> u16 {
    let o = l4.ip_hdr_len + 16;
    u16::from_be_bytes([pkt[o], pkt[o + 1]])
}
fn looks_tls(p: &[u8]) -> bool {
    p.len() >= 2 && p[0] == 0x16 && p[1] == 0x03
}

fn open(filter: &str, flags: OpenFlags) -> anyhow::Result<WinDivertHandle> {
    let c = CString::new(filter).expect("static filter has no NUL");
    match WinDivertHandle::open(c.as_c_str(), Layer::Network, 0, flags) {
        Ok(h) => Ok(h),
        Err(DivertError::Open(e)) if e.0 == 5 => {
            Err(anyhow::anyhow!("WinDivertOpen: ERROR_ACCESS_DENIED — elevated calistirin"))
        }
        Err(e) => Err(anyhow::anyhow!("WinDivertOpen basarisiz: {e}")),
    }
}

fn window<T, F>(handle: WinDivertHandle, secs: u64, worker: F) -> anyhow::Result<T>
where
    T: Send + 'static,
    F: FnOnce(&WinDivertHandle) -> T + Send + 'static,
{
    let h = Arc::new(handle);
    let hc = Arc::clone(&h);
    let jh = std::thread::spawn(move || worker(&hc));
    std::thread::sleep(Duration::from_secs(secs));
    let _ = h.shutdown_both();
    jh.join().map_err(|_| anyhow::anyhow!("worker panicked"))
}

// --- V-A ---

fn t_overlap_segment_egress() -> String {
    println!("--- V-A: overlap segmenti (seq-32, 40B) enjeksiyonu ---");
    let h = match open(
        "outbound and tcp and tcp.DstPort == 443 and tcp.PayloadLength > 0",
        OpenFlags::new(),
    ) {
        Ok(h) => h,
        Err(e) => {
            let s = format!("V-A: FAIL — {e}");
            println!("{s}\n");
            return s;
        }
    };
    let res = window(h, WINDOW_SECS, |h| {
        let mut buf = vec![0u8; BUF];
        let mut report = String::from("V-A: uygun (16 03 ..) outbound paket gorulmedi");
        loop {
            match h.recv(&mut buf) {
                Ok(r) => {
                    let _ = h.send(r.data, &r.addr); // orijinali koru
                    let Some(l4) = parse(r.data) else { continue };
                    if l4.is_v6 || r.data.len() <= l4.payload_off {
                        continue;
                    }
                    let p = &r.data[l4.payload_off..];
                    if !looks_tls(p) {
                        continue;
                    }
                    let orig_seq = tcp_seq(r.data, &l4);
                    let take = 40.min(p.len());
                    let mut dup = r.data[..l4.payload_off].to_vec();
                    dup.extend_from_slice(&p[..take]);
                    fix_ip_len(&mut dup);
                    let mut addr = r.addr;
                    set_tcp_seq(&mut dup, &l4, orig_seq.wrapping_sub(32));
                    if calc_checksums(&mut dup, Some(&mut addr), ChecksumFlags::new()).is_err() {
                        report = "V-A: calc_checksums hata".into();
                    } else if let Err(e) = h.send(&dup, &addr) {
                        report = format!("V-A: send(overlap) hata: {e}");
                    } else {
                        let l4d = parse(&dup).unwrap();
                        report = format!(
                            "V-A: enjekte edildi — seq={} (orig {orig_seq}) ip_id=0x{:04x} len={} tcp_cksum=0x{:04x}",
                            tcp_seq(&dup, &l4d),
                            ip_id_v4(&dup),
                            dup.len(),
                            tcp_cksum(&dup, &l4d),
                        );
                    }
                    let _ = h.shutdown_both();
                    break;
                }
                Err(DivertError::ShutDown) => break,
                Err(e) => {
                    eprintln!("  V-A recv hata: {e}");
                    break;
                }
            }
        }
        report
    });
    let s = res.unwrap_or_else(|e| format!("V-A: FAIL — {e}"));
    println!("{s}\n");
    s
}

// --- V-B ---

fn t_two_overlapping_segments() -> String {
    println!("--- V-B: iki overlapping segment; inbound reaksiyon ---");
    let filter = "(outbound and tcp and tcp.DstPort == 443 and tcp.PayloadLength > 0) \
                  or (inbound and tcp and tcp.SrcPort == 443)";
    let h = match open(filter, OpenFlags::new()) {
        Ok(h) => h,
        Err(e) => {
            let s = format!("V-B: FAIL — {e}");
            println!("{s}\n");
            return s;
        }
    };
    let res = window(h, WINDOW_SECS, |h| {
        let mut buf = vec![0u8; BUF];
        let mut flow: Option<(u32, u32, u16)> = None; // (client_ip, server_ip, client_port)
        let mut injected_at: Option<Instant> = None;
        let mut report = String::from("V-B: uygun outbound ClientHello gorulmedi");
        loop {
            match h.recv(&mut buf) {
                Ok(r) => {
                    let Some(l4) = parse(r.data) else {
                        let _ = h.send(r.data, &r.addr);
                        continue;
                    };
                    if l4.is_v6 {
                        let _ = h.send(r.data, &r.addr);
                        continue;
                    }
                    let (sip, dip) = ips_v4(r.data);

                    if r.addr.outbound() && l4.dst_port == 443 && injected_at.is_none() {
                        let p = &r.data[l4.payload_off..];
                        if looks_tls(p) && p.len() > 20 {
                            let orig_seq = tcp_seq(r.data, &l4);
                            let split = 48usize.min(p.len() / 2).max(4);
                            let hdr = r.data[..l4.payload_off].to_vec();

                            let mut a = hdr.clone();
                            a.extend_from_slice(&[0xEE; 32]);
                            a.extend_from_slice(&p[split..]);
                            fix_ip_len(&mut a);
                            let mut aa = r.addr;
                            set_tcp_seq(&mut a, &l4, orig_seq.wrapping_add((split - 32) as u32));
                            let _ = calc_checksums(&mut a, Some(&mut aa), ChecksumFlags::new());

                            let mut b = hdr;
                            b.extend_from_slice(&p[..split]);
                            fix_ip_len(&mut b);
                            let mut ab = r.addr;
                            let _ = calc_checksums(&mut b, Some(&mut ab), ChecksumFlags::new());

                            let _ = h.send(&a, &aa);
                            let _ = h.send(&b, &ab);
                            flow = Some((sip, dip, l4.src_port));
                            injected_at = Some(Instant::now());
                            continue; // orijinali DROP
                        }
                    }

                    if !r.addr.outbound() && l4.src_port == 443 {
                        if let Some((cip, sip_f, cport)) = flow {
                            if dip == cip && sip == sip_f && l4.dst_port == cport {
                                let dt = injected_at.map(|t| t.elapsed().as_millis()).unwrap_or(0);
                                let p = r.data.get(l4.payload_off..).unwrap_or(&[]);
                                if l4.rst {
                                    report = format!("V-B: {dt}ms sonra inbound RST (ip.ttl={})", r.data[8]);
                                    let _ = h.send(r.data, &r.addr);
                                    let _ = h.shutdown_both();
                                    break;
                                } else if looks_tls(p) {
                                    report = format!("V-B: {dt}ms sonra inbound ServerHello — handshake ILERLIYOR");
                                    let _ = h.send(r.data, &r.addr);
                                    let _ = h.shutdown_both();
                                    break;
                                } else {
                                    report = format!("V-B: {dt}ms — yalnizca ACK (RST/ServerHello yok)");
                                }
                            }
                        }
                    }
                    let _ = h.send(r.data, &r.addr);
                }
                Err(DivertError::ShutDown) => break,
                Err(e) => {
                    eprintln!("  V-B recv hata: {e}");
                    break;
                }
            }
        }
        report
    });
    let s = res.unwrap_or_else(|e| format!("V-B: FAIL — {e}"));
    println!("{s}\n");
    s
}

// --- V-C ---

fn t_windows_retransmit_behavior() -> String {
    println!("--- V-C: ClientHello DROP sonrasi Windows retransmit (RTO) ---");
    let h = match open(
        "outbound and tcp and tcp.DstPort == 443 and tcp.PayloadLength > 0",
        OpenFlags::new(),
    ) {
        Ok(h) => h,
        Err(e) => {
            let s = format!("V-C: FAIL — {e}");
            println!("{s}\n");
            return s;
        }
    };
    let res = window(h, 12, |h| {
        let mut buf = vec![0u8; BUF];
        let mut tracked: Option<(u16, u32, Vec<u8>, Instant)> = None;
        let mut times: Vec<u128> = Vec::new();
        let mut identical = true;
        loop {
            match h.recv(&mut buf) {
                Ok(r) => {
                    let Some(l4) = parse(r.data) else {
                        let _ = h.send(r.data, &r.addr);
                        continue;
                    };
                    if l4.is_v6 || r.data.len() <= l4.payload_off {
                        let _ = h.send(r.data, &r.addr);
                        continue;
                    }
                    let p = &r.data[l4.payload_off..];
                    let seq = tcp_seq(r.data, &l4);
                    match &tracked {
                        None if looks_tls(p) => {
                            tracked = Some((l4.src_port, seq, p.to_vec(), Instant::now()));
                            // DROP (send nothing)
                        }
                        None => {
                            let _ = h.send(r.data, &r.addr);
                        }
                        Some((sp, sq, orig_p, drop_at)) => {
                            if l4.src_port == *sp && seq == *sq {
                                times.push(drop_at.elapsed().as_millis());
                                if p != orig_p.as_slice() {
                                    identical = false;
                                }
                            }
                            let _ = h.send(r.data, &r.addr); // let the connection recover
                        }
                    }
                }
                Err(DivertError::ShutDown) => break,
                Err(e) => {
                    eprintln!("  V-C recv hata: {e}");
                    break;
                }
            }
        }
        match tracked {
            Some((sp, sq, ref op, _)) => format!(
                "V-C: sport={sp} seq={sq} payload={}B — retransmit={} timings_ms={:?} payload-ayni={}",
                op.len(),
                times.len(),
                times,
                identical
            ),
            None => "V-C: uygun outbound ClientHello gorulmedi".to_string(),
        }
    });
    let s = res.unwrap_or_else(|e| format!("V-C: FAIL — {e}"));
    println!("{s}\n");
    s
}
