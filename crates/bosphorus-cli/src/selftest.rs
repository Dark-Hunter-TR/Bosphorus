//! M0 verification harness.
//!
//!   V1  first inbound data segment of flows whose outbound SYN we saw *during*
//!       the window (genuinely new connections) — categorised by TLS ContentType
//!   V2  outbound 443 ClientHello segment sizes; is LSO/coalescing producing >MTU packets?
//!   V3  deliberately-corrupted TCP checksum: injected duplicate; wire survival needs pktmon
//!   V4  WinDivert driver loads + `get_param` version
//!
//! Requires an elevated process. V1/V2 open in SNIFF mode (observation only,
//! cannot disturb traffic). V3 opens in divert mode, reinjects every packet,
//! and injects exactly one corrupted duplicate.

use std::collections::{HashMap, HashSet};
use std::ffi::CString;
use std::sync::Arc;
use std::time::Duration;

use bosphorus_divert::{
    calc_checksums, ChecksumFlags, DivertError, Layer, OpenFlags, WinDivertHandle,
};

const WINDOW_SECS: u64 = 20;
const BUF: usize = 65_535;

pub fn run_all() -> anyhow::Result<()> {
    println!("=== Bosphorus M0 selftest — WinDivert verification harness ===");
    println!();
    println!("Yonetici (elevated) gerekir. Test pencereleri boyunca bir tarayicida");
    println!("YENI HTTPS baglantilari acin (yeni sekme + hard-refresh) ki V1 gercekten");
    println!("yeni acilan akislarin SYN'ini gorebilsin. Her pencere ~{WINDOW_SECS}s.");
    println!();

    let v4 = v4_driver_load();
    let v1 = v1_inbound_first_segment();
    let v2 = v2_outbound_clienthello_sizes();
    let v3 = v3_wrong_checksum();

    println!();
    println!("================ M0 SONUC OZETI (bu blogu bana yapistir) ================");
    println!("{v4}");
    println!("{v1}");
    println!("{v2}");
    println!("{v3}");
    println!("=======================================================================");
    Ok(())
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

fn open(filter: &str, flags: OpenFlags) -> anyhow::Result<WinDivertHandle> {
    let c = CString::new(filter).expect("static filter has no interior NUL");
    match WinDivertHandle::open(c.as_c_str(), Layer::Network, 0, flags) {
        Ok(h) => Ok(h),
        Err(DivertError::Open(e)) => {
            let hint = match e.0 {
                5 => "ERROR_ACCESS_DENIED — elevated (Yonetici) PowerShell'den calistirin",
                2 => "ERROR_FILE_NOT_FOUND — WinDivert64.sys, WinDivert.dll ile ayni klasorde degil",
                87 => "ERROR_INVALID_PARAMETER — filtre string'i reddedildi",
                577 => "ERROR_INVALID_IMAGE_HASH — surucu imzasi reddedildi (Secure Boot / imza)",
                1275 => "ERROR_DRIVER_BLOCKED — surucu politika ile engellendi",
                1058 => "ERROR_SERVICE_DISABLED — WinDivert servisi devre disi",
                _ => "bilinmeyen — WinDivert dokumanindaki hata koduna bakin",
            };
            Err(anyhow::anyhow!("WinDivertOpen basarisiz: {e} — {hint}"))
        }
        Err(e) => Err(anyhow::anyhow!("WinDivertOpen basarisiz: {e}")),
    }
}

/// Run `worker` on a thread for `secs`, then shut the handle down and join.
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
    jh.join().map_err(|_| anyhow::anyhow!("capture worker panicked"))
}

/// Minimal L3/L4 walk. IPv6 extension headers are not followed (fine for
/// TCP/UDP on :443 in practice); such packets are simply skipped.
struct L4 {
    proto: u8,
    ip_hdr_len: usize,
    payload_off: usize,
    is_v6: bool,
    src_port: u16,
    dst_port: u16,
    syn: bool,
    ack: bool,
}

fn parse(pkt: &[u8]) -> Option<L4> {
    let version = *pkt.first()? >> 4;
    let (ip_hdr_len, proto, is_v6) = match version {
        4 => {
            if pkt.len() < 20 {
                return None;
            }
            let ihl = (pkt[0] & 0x0f) as usize * 4;
            if !(20..=pkt.len()).contains(&ihl) {
                return None;
            }
            (ihl, pkt[9], false)
        }
        6 => {
            if pkt.len() < 40 {
                return None;
            }
            (40usize, pkt[6], true)
        }
        _ => return None,
    };
    let l4 = &pkt[ip_hdr_len..];
    let (l4_hdr_len, src_port, dst_port, syn, ack) = match proto {
        6 => {
            if l4.len() < 20 {
                return None;
            }
            let d = (l4[12] >> 4) as usize * 4;
            if !(20..=l4.len()).contains(&d) {
                return None;
            }
            let flags = l4[13];
            (
                d,
                u16::from_be_bytes([l4[0], l4[1]]),
                u16::from_be_bytes([l4[2], l4[3]]),
                flags & 0x02 != 0,
                flags & 0x10 != 0,
            )
        }
        17 => {
            if l4.len() < 8 {
                return None;
            }
            (
                8,
                u16::from_be_bytes([l4[0], l4[1]]),
                u16::from_be_bytes([l4[2], l4[3]]),
                false,
                false,
            )
        }
        _ => return None,
    };
    Some(L4 {
        proto,
        ip_hdr_len,
        payload_off: ip_hdr_len + l4_hdr_len,
        is_v6,
        src_port,
        dst_port,
        syn,
        ack,
    })
}

/// (src_ip, dst_ip) as u128 (v4 mapped into the low 32 bits).
fn ips(pkt: &[u8], is_v6: bool) -> (u128, u128) {
    if is_v6 {
        let mut s = [0u8; 16];
        let mut d = [0u8; 16];
        s.copy_from_slice(&pkt[8..24]);
        d.copy_from_slice(&pkt[24..40]);
        (u128::from_be_bytes(s), u128::from_be_bytes(d))
    } else {
        (
            u32::from_be_bytes([pkt[12], pkt[13], pkt[14], pkt[15]]) as u128,
            u32::from_be_bytes([pkt[16], pkt[17], pkt[18], pkt[19]]) as u128,
        )
    }
}

/// Canonical client-side 4-tuple: (client_ip, client_port, server_ip, server_port).
type FlowKey = (u128, u16, u128, u16);

#[derive(Clone, Copy, PartialEq, Eq)]
enum TlsCat {
    Handshake, // 16 03 0X
    AppData,   // 17 03 0X
    Alert,     // 15 03 0X
    Ccs,       // 14 03 0X
    NonTls,    // anything else
}

fn classify(p: &[u8]) -> TlsCat {
    match (p.first().copied(), p.get(1).copied(), p.get(2).copied()) {
        (Some(0x16), Some(0x03), Some(0x00..=0x04)) => TlsCat::Handshake,
        (Some(0x17), Some(0x03), Some(0x00..=0x04)) => TlsCat::AppData,
        (Some(0x15), Some(0x03), Some(0x00..=0x04)) => TlsCat::Alert,
        (Some(0x14), Some(0x03), Some(0x00..=0x04)) => TlsCat::Ccs,
        _ => TlsCat::NonTls,
    }
}

// ---------------------------------------------------------------------------
// V4 — driver load + version
// ---------------------------------------------------------------------------

fn v4_driver_load() -> String {
    println!("--- V4: WinDivert surucu yukleme + surum ---");
    let h = match open("false", OpenFlags::new()) {
        Ok(h) => h,
        Err(e) => {
            let s = format!("V4: FAIL — {e}");
            println!("{s}\n");
            return s;
        }
    };
    let ver = h.version();
    drop(h);
    match ver {
        Ok((maj, min)) => {
            let s =
                format!("V4: OK — WinDivert {maj}.{min} yuklendi, get_param calisti, temiz kapandi");
            println!("{s}\n");
            s
        }
        Err(e) => {
            let s = format!("V4: PARTIAL — acildi ama get_param hata: {e}");
            println!("{s}\n");
            s
        }
    }
}

// ---------------------------------------------------------------------------
// V1 — first inbound data segment of SYN-correlated NEW flows
// ---------------------------------------------------------------------------

fn v1_inbound_first_segment() -> String {
    println!(
        "--- V1: bu pencerede outbound SYN gorulen YENI akislarin ilk inbound veri segmenti ({WINDOW_SECS}s) ---"
    );
    // Pure SYN out to :443  OR  inbound :443 data.
    let filter = "(outbound and tcp and tcp.DstPort == 443 and tcp.Syn and !tcp.Ack) \
                  or (inbound and tcp and tcp.SrcPort == 443 and tcp.PayloadLength > 0)";
    let h = match open(filter, OpenFlags::new().sniff()) {
        Ok(h) => h,
        Err(e) => {
            let s = format!("V1: FAIL — {e}");
            println!("{s}\n");
            return s;
        }
    };

    let res = window(h, WINDOW_SECS, |h| {
        let mut buf = vec![0u8; BUF];
        let mut new_flows: HashSet<FlowKey> = HashSet::new(); // outbound SYN seen this window
        let mut recorded: HashSet<FlowKey> = HashSet::new(); // first inbound data already taken
        let mut cats: HashMap<u8, usize> = HashMap::new(); // TlsCat discriminant -> count
        let mut hs_samples: Vec<[u8; 4]> = Vec::new();
        let mut nontls_samples: Vec<[u8; 6]> = Vec::new();
        let mut inbound_data_seen_pretest = 0u64; // inbound data for flows with NO in-window SYN

        loop {
            match h.recv(&mut buf) {
                Ok(r) => {
                    let Some(l4) = parse(r.data) else { continue };
                    if l4.proto != 6 {
                        continue;
                    }
                    let (sip, dip) = ips(r.data, l4.is_v6);

                    if l4.syn && !l4.ack && l4.dst_port == 443 {
                        // outbound pure SYN: client = src
                        new_flows.insert((sip, l4.src_port, dip, l4.dst_port));
                        continue;
                    }

                    if l4.src_port == 443 && r.data.len() > l4.payload_off {
                        // inbound data: client = dst
                        let key: FlowKey = (dip, l4.dst_port, sip, l4.src_port);
                        if !new_flows.contains(&key) {
                            inbound_data_seen_pretest += 1;
                            continue;
                        }
                        if !recorded.insert(key) {
                            continue; // already took this flow's first segment
                        }
                        let p = &r.data[l4.payload_off..];
                        let cat = classify(p);
                        *cats.entry(cat as u8).or_insert(0) += 1;
                        match cat {
                            TlsCat::Handshake if hs_samples.len() < 12 => {
                                let mut b = [0u8; 4];
                                for (i, x) in p.iter().take(4).enumerate() {
                                    b[i] = *x;
                                }
                                hs_samples.push(b);
                            }
                            TlsCat::NonTls if nontls_samples.len() < 12 => {
                                let mut b = [0u8; 6];
                                for (i, x) in p.iter().take(6).enumerate() {
                                    b[i] = *x;
                                }
                                nontls_samples.push(b);
                            }
                            _ => {}
                        }
                    }
                }
                Err(DivertError::ShutDown) => break,
                Err(e) => {
                    eprintln!("  V1 recv hata: {e}");
                    break;
                }
            }
        }
        (
            new_flows.len(),
            recorded.len(),
            cats,
            hs_samples,
            nontls_samples,
            inbound_data_seen_pretest,
        )
    });

    let (n_syn, n_recorded, cats, hs, nontls, pretest) = match res {
        Ok(x) => x,
        Err(e) => {
            let s = format!("V1: FAIL — {e}");
            println!("{s}\n");
            return s;
        }
    };

    let get = |c: TlsCat| *cats.get(&(c as u8)).unwrap_or(&0);
    let (handshake, appdata, alert, ccs, nontls_n) = (
        get(TlsCat::Handshake),
        get(TlsCat::AppData),
        get(TlsCat::Alert),
        get(TlsCat::Ccs),
        get(TlsCat::NonTls),
    );

    println!("  bu pencerede outbound SYN gorulen yeni akis: {n_syn}");
    println!("  bunlardan ilk inbound veri segmenti yakalanan: {n_recorded}");
    println!("  (test oncesinde kurulmus akislarin inbound veri paketi, HARIC tutuldu: {pretest})");
    println!("  ilk inbound veri segmenti dagilimi (yalniz SYN-korelasyonlu yeni akislar):");
    println!("    TLS handshake (16 03 0X) : {handshake}");
    println!("    TLS app-data  (17 03 0X) : {appdata}");
    println!("    TLS alert     (15 03 0X) : {alert}");
    println!("    TLS CCS       (14 03 0X) : {ccs}");
    println!("    non-TLS / bilinmeyen     : {nontls_n}");
    for b in &hs {
        println!("      [handshake ornek] {:02x} {:02x} {:02x} {:02x}", b[0], b[1], b[2], b[3]);
    }
    for b in &nontls {
        println!(
            "      [non-TLS ornek]   {:02x} {:02x} {:02x} {:02x} {:02x} {:02x}",
            b[0], b[1], b[2], b[3], b[4], b[5]
        );
    }

    let s = if n_recorded == 0 {
        format!(
            "V1: NO NEW FLOWS — pencerede {n_syn} yeni SYN goruldu ama ilk inbound veri segmenti yakalanamadi; tarayicida yeni siteler acin ve tekrar deneyin"
        )
    } else {
        format!(
            "V1: yeni akis {n_recorded} ornek — ilk inbound veri segmenti: handshake={handshake} app-data={appdata} alert={alert} ccs={ccs} non-TLS={nontls_n} (test-oncesi akislarin veri paketi haric: {pretest})"
        )
    };
    println!("{s}\n");
    s
}

// ---------------------------------------------------------------------------
// V2 — outbound ClientHello sizes / LSO
// ---------------------------------------------------------------------------

fn v2_outbound_clienthello_sizes() -> String {
    println!("--- V2: outbound 443 ClientHello segment boyutlari / LSO var mi? ({WINDOW_SECS}s) ---");
    let filter = "outbound and tcp and tcp.DstPort == 443 and tcp.PayloadLength > 0";
    let h = match open(filter, OpenFlags::new().sniff()) {
        Ok(h) => h,
        Err(e) => {
            let s = format!("V2: FAIL — {e}");
            println!("{s}\n");
            return s;
        }
    };

    let res = window(h, WINDOW_SECS, |h| {
        let mut buf = vec![0u8; BUF];
        let mut ch_sizes: Vec<usize> = Vec::new(); // tcp payload len of records starting 16 03 0X
        let mut max_total: usize = 0; // largest full IP packet among all outbound 443 data
        let mut over_mtu: u64 = 0; // packets whose total len > 1600
        let mut total: u64 = 0;
        loop {
            match h.recv(&mut buf) {
                Ok(r) => {
                    let Some(l4) = parse(r.data) else { continue };
                    if l4.proto != 6 || r.data.len() < l4.payload_off {
                        continue;
                    }
                    total += 1;
                    max_total = max_total.max(r.data.len());
                    if r.data.len() > 1600 {
                        over_mtu += 1;
                    }
                    let p = &r.data[l4.payload_off..];
                    if p.len() >= 3 && p[0] == 0x16 && p[1] == 0x03 && (p[2] == 0x01 || p[2] == 0x03) {
                        ch_sizes.push(p.len());
                    }
                }
                Err(DivertError::ShutDown) => break,
                Err(e) => {
                    eprintln!("  V2 recv hata: {e}");
                    break;
                }
            }
        }
        (ch_sizes, max_total, over_mtu, total)
    });

    let (ch, max_total, over_mtu, total) = match res {
        Ok(x) => x,
        Err(e) => {
            let s = format!("V2: FAIL — {e}");
            println!("{s}\n");
            return s;
        }
    };
    if total == 0 {
        let s =
            "V2: NO DATA — outbound 443 verisi gorulmedi (tarayicida yeni siteler acin)".to_string();
        println!("{s}\n");
        return s;
    }
    let (mn, avg, mx) = if ch.is_empty() {
        (0, 0, 0)
    } else {
        (
            *ch.iter().min().unwrap(),
            ch.iter().sum::<usize>() / ch.len(),
            *ch.iter().max().unwrap(),
        )
    };
    let lso = if over_mtu > 0 || max_total > 1600 {
        "EVET (LSO/coalescing — fragment transform >MTU segment gorebilir)"
    } else {
        "hayir (segmentler MTU sinirinda)"
    };
    println!(
        "  ClientHello benzeri kayit: n={} (tcp payload B: min {mn} / avg {avg} / max {mx})",
        ch.len()
    );
    println!("  tum outbound-443-data icinde en buyuk IP paketi: {max_total} B");
    println!("  1600 B ustu paket: {over_mtu} / {total}");
    let s = format!(
        "V2: ClientHello n={} min/avg/max={mn}/{avg}/{mx} B; en buyuk outbound-443 paketi {max_total} B; LSO: {lso}",
        ch.len()
    );
    println!("{s}\n");
    s
}

// ---------------------------------------------------------------------------
// V3 — corrupted TCP checksum survival
// ---------------------------------------------------------------------------

fn v3_wrong_checksum() -> String {
    println!("--- V3: kasitli bozuk TCP checksum kablo uzerinde sag kaliyor mu? ---");
    println!("  Bir outbound TLS kaydi yakalanip bozuk-checksum'li KOPYASI enjekte edilir.");
    println!("  Gercek baglanti bozulmaz (orijinal her paket yeniden enjekte edilir).");
    let filter = "outbound and tcp and tcp.DstPort == 443 and tcp.PayloadLength > 0";
    let h = match open(filter, OpenFlags::new()) {
        Ok(h) => h,
        Err(e) => {
            let s = format!("V3: FAIL — {e}");
            println!("{s}\n");
            return s;
        }
    };

    let res = window(h, WINDOW_SECS, |h| {
        let mut buf = vec![0u8; BUF];
        let mut report =
            String::from("V3: pencere boyunca uygun (16 03 ..) outbound paket gorulmedi");
        loop {
            match h.recv(&mut buf) {
                Ok(r) => {
                    // Always reinject the real packet first.
                    let _ = h.send(r.data, &r.addr);

                    let Some(l4) = parse(r.data) else { continue };
                    if l4.proto != 6 || r.data.len() <= l4.payload_off {
                        continue;
                    }
                    let p = &r.data[l4.payload_off..];
                    if !(p.len() >= 2 && p[0] == 0x16 && p[1] == 0x03) {
                        continue;
                    }
                    let payload_len = p.len();

                    let mut dup = r.data.to_vec();
                    let mut addr = r.addr;
                    if calc_checksums(&mut dup, Some(&mut addr), ChecksumFlags::new()).is_err() {
                        report = "V3: calc_checksums hata".into();
                        let _ = h.shutdown_both();
                        break;
                    }
                    let ck_off = l4.ip_hdr_len + 16; // TCP checksum = bytes 16..18 of the TCP header
                    let good = u16::from_be_bytes([dup[ck_off], dup[ck_off + 1]]);
                    let bad = good.wrapping_sub(1);
                    dup[ck_off..ck_off + 2].copy_from_slice(&bad.to_be_bytes());
                    let seq = u32::from_be_bytes([
                        r.data[l4.ip_hdr_len + 4],
                        r.data[l4.ip_hdr_len + 5],
                        r.data[l4.ip_hdr_len + 6],
                        r.data[l4.ip_hdr_len + 7],
                    ]);

                    report = match h.send(&dup, &addr) {
                        Ok(_) => format!(
                            "V3: bozuk-checksum kopya enjekte edildi — seq={seq} tcp_payload={payload_len} B, good=0x{good:04x} bad=0x{bad:04x}; kablo dogrulamasi gerekli (asagidaki pktmon adimlari)"
                        ),
                        Err(e) => format!("V3: WinDivertSend(dup) hata: {e}"),
                    };
                    let _ = h.shutdown_both();
                    break;
                }
                Err(DivertError::ShutDown) => break,
                Err(e) => {
                    eprintln!("  V3 recv hata: {e}");
                    break;
                }
            }
        }
        report
    });

    let s = match res {
        Ok(s) => s,
        Err(e) => format!("V3: FAIL — {e}"),
    };
    println!("{s}");
    println!("  --- pktmon ile kablo dogrulamasi (ayni elevated pencerede) ---");
    println!("    pktmon start --capture --pkt-size 0 -f bosphorus_v3.etl");
    println!("    .\\target\\debug\\bosphorus.exe --selftest        (bu sirada tekrar calistirin)");
    println!("    pktmon stop");
    println!("    pktmon etl2pcap bosphorus_v3.etl -o bosphorus_v3.pcapng");
    println!("  bosphorus_v3.pcapng'yi Wireshark'ta acin: yukaridaki seq'e sahip segmentin");
    println!("  TCP checksum'i 'incorrect' mi (sag kaldi) yoksa duzeltilmis mi?");
    println!("  Alternatif kesin test: 'Disable-NetAdapterChecksumOffload -Name *' ile");
    println!("  yazilim-checksum'a gecip tekrar deneyin (test sonrasi Enable... ile geri alin).");
    println!();
    s
}
