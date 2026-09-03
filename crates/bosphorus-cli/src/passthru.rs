//! M1 exit-criterion demo: capture every :443 TCP packet (both directions),
//! log it, and reinject it **unchanged**. The internet must keep working.

use std::ffi::CString;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bosphorus_divert::{
    Address, DivertError, Layer, OpenFlags, Param, WinDivertHandle, RECV_BUF_HINT,
};

pub fn run(secs: Option<u64>) -> anyhow::Result<()> {
    let filter = "tcp and (tcp.SrcPort == 443 or tcp.DstPort == 443)";
    let c = CString::new(filter).expect("static filter has no NUL");

    let h = match WinDivertHandle::open(c.as_c_str(), Layer::Network, 0, OpenFlags::new()) {
        Ok(h) => h,
        Err(DivertError::Open(e)) => {
            anyhow::bail!(
                "WinDivertOpen basarisiz: {e} — elevated (Yonetici) PowerShell'den calistirin"
            )
        }
        Err(e) => anyhow::bail!("WinDivertOpen basarisiz: {e}"),
    };

    // D2: raise the driver's kernel queue above the 4096-packet / 2000-ms
    // defaults (same values GoodbyeDPI uses) so a bulk transfer isn't throttled
    // by the queue filling faster than our recv loop drains it.
    let _ = h.set_param(Param::QueueLength, 16_384);
    let _ = h.set_param(Param::QueueTime, 8_000);

    let (maj, min) = h.version().unwrap_or((0, 0));
    println!("passthru: WinDivert {maj}.{min}");
    println!("filtre  : {filter}");
    println!("tum eslesEN paketler DEGISTIRILMEDEN yeniden enjekte edilir.");
    match secs {
        Some(n) => println!("sure    : {n}s, sonra otomatik durur"),
        None => println!("sure    : Ctrl+C ile durdurun"),
    }
    println!();

    let h = Arc::new(h);
    let stop = Arc::new(AtomicBool::new(false));

    {
        let h = Arc::clone(&h);
        let stop = Arc::clone(&stop);
        let _ = ctrlc::set_handler(move || {
            stop.store(true, Ordering::SeqCst);
            let _ = h.shutdown_both();
        });
    }

    if let Some(n) = secs {
        let h = Arc::clone(&h);
        let stop = Arc::clone(&stop);
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_secs(n));
            stop.store(true, Ordering::SeqCst);
            let _ = h.shutdown_both();
        });
    }

    let mut buf = vec![0u8; RECV_BUF_HINT];
    let mut n_pkt: u64 = 0;
    let mut n_bytes: u64 = 0;
    let mut n_out: u64 = 0;
    let mut n_in: u64 = 0;
    let mut n_reinject_fail: u64 = 0;
    let start = Instant::now();

    loop {
        match h.recv(&mut buf) {
            Ok(r) => {
                n_pkt += 1;
                n_bytes += r.data.len() as u64;
                if r.addr.outbound() {
                    n_out += 1;
                } else {
                    n_in += 1;
                }
                if n_pkt <= 40 {
                    log_pkt(n_pkt, r.data, &r.addr);
                } else if n_pkt % 1000 == 0 {
                    println!(
                        "  ... {n_pkt} paket ({n_out} OUT / {n_in} IN) / {} KB / {} s (reinject hata: {n_reinject_fail})",
                        n_bytes / 1024,
                        start.elapsed().as_secs()
                    );
                }
                if let Err(e) = h.send(r.data, &r.addr) {
                    n_reinject_fail += 1;
                    if n_reinject_fail <= 5 {
                        eprintln!("  reinject hata (paket {n_pkt}): {e}");
                    }
                }
            }
            Err(DivertError::ShutDown) => break,
            Err(e) => {
                eprintln!("recv hata: {e}");
                break;
            }
        }
    }

    let _ = h.shutdown_both();
    println!();
    println!(
        "passthru bitti: {n_pkt} paket ({n_out} OUT / {n_in} IN), {} KB, {} s, reinject hata {n_reinject_fail}",
        n_bytes / 1024,
        start.elapsed().as_secs()
    );
    if n_pkt > 0 && n_reinject_fail == 0 {
        println!("EXIT KRITERI: tum paketler degistirilmeden yeniden enjekte edildi.");
    } else if n_pkt == 0 {
        println!("UYARI: hic paket yakalanmadi — 443 trafigi uretin (tarayici).");
    } else {
        println!("UYARI: {n_reinject_fail} paket yeniden enjekte edilemedi.");
    }
    Ok(())
}

fn log_pkt(n: u64, pkt: &[u8], addr: &Address) {
    let dir = if addr.outbound() { "OUT" } else { "IN " };
    let ver = if addr.ipv6() { "v6" } else { "v4" };
    match tcp_bits(pkt) {
        Some((sp, dp, flags, seq, plen)) => println!(
            "  [{n:>3}] {dir} {ver} {sp:>5} -> {dp:<5}  seq={seq:<10} ip_len={:<5} tcp_payload={plen:<5} {}",
            pkt.len(),
            tcp_flag_str(flags)
        ),
        None => println!("  [{n:>3}] {dir} {ver} ip_len={} (parse edilemedi)", pkt.len()),
    }
}

/// Minimal walk: returns (src_port, dst_port, tcp_flags_byte, seq, tcp_payload_len).
/// IPv6 extension headers are not followed.
fn tcp_bits(pkt: &[u8]) -> Option<(u16, u16, u8, u32, usize)> {
    let version = *pkt.first()? >> 4;
    let ihl = match version {
        4 => {
            if pkt.len() < 20 || pkt[9] != 6 {
                return None;
            }
            let n = (pkt[0] & 0x0f) as usize * 4;
            if !(20..=pkt.len()).contains(&n) {
                return None;
            }
            n
        }
        6 => {
            if pkt.len() < 40 || pkt[6] != 6 {
                return None;
            }
            40
        }
        _ => return None,
    };
    let t = pkt.get(ihl..)?;
    if t.len() < 20 {
        return None;
    }
    let data_off = (t[12] >> 4) as usize * 4;
    if !(20..=t.len()).contains(&data_off) {
        return None;
    }
    Some((
        u16::from_be_bytes([t[0], t[1]]),
        u16::from_be_bytes([t[2], t[3]]),
        t[13],
        u32::from_be_bytes([t[4], t[5], t[6], t[7]]),
        t.len() - data_off,
    ))
}

fn tcp_flag_str(f: u8) -> &'static str {
    let (syn, ack, fin, rst, psh) = (
        f & 0x02 != 0,
        f & 0x10 != 0,
        f & 0x01 != 0,
        f & 0x04 != 0,
        f & 0x08 != 0,
    );
    match (syn, ack, fin, rst, psh) {
        (true, true, _, _, _) => "SYN-ACK",
        (true, false, _, _, _) => "SYN",
        (_, _, _, true, _) => "RST",
        (_, _, true, _, _) => "FIN",
        (_, true, _, _, true) => "PSH-ACK",
        (_, true, _, _, _) => "ACK",
        _ => "-",
    }
}
