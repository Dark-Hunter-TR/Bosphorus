use std::ffi::CString;

use crate::config::EvasionConfig;
use crate::error::CoreError;
use crate::filter::templates as t;

/// The WinDivert filter strings for a run.
pub struct Filters {
    /// Main capture handle (divert mode): outbound 443 requests + inbound 443
    /// SYN-ACK / RST / first-data(`16`) for verdict feedback.
    pub main: CString,
    /// QUIC-drop handle (`WINDIVERT_FLAG_DROP`), when enabled.
    pub quic_drop: Option<CString>,
}

/// Build the filter strings from config. String assembly only — call
/// `bosphorus_divert::compile_filter` to check them against WinDivert.
pub fn build(cfg: &EvasionConfig) -> Result<Filters, CoreError> {
    let maxpayload = t::MAXPAYLOAD_FMT.replace("{n}", &cfg.max_payload_filter.to_string());

    // Inbound verdict clause: SYN-ACK (passive TTL, M7), RST (DpiReset), and the
    // first data segment of a TLS response — `Payload[0] == 0x16` confirmed in
    // M0/V1 as a reliable ServerHello marker (WinDivert does no reassembly).
    let inbound = format!(
        "(inbound and tcp.SrcPort == 443 and \
           ((tcp.Syn and tcp.Ack) or tcp.Rst or (tcp.PayloadLength > 0 and tcp.Payload[0] == 0x16)) \
           and ({v4src} or {v6src}))",
        v4src = t::NO_LOCALNETS_V4_SRC,
        v6src = t::NO_LOCALNETS_V6_SRC,
    );

    // Outbound clause: mirrors GoodbyeDPI's outbound half, 443 only.
    let outbound = format!(
        "(outbound and tcp.DstPort == 443 and tcp.Ack and ({v4dst} or {v6dst}))",
        v4dst = t::NO_LOCALNETS_V4_DST,
        v6dst = t::NO_LOCALNETS_V6_DST,
    );

    let mut main = format!(
        "(tcp and !impostor and !loopback {maxpayload} and ({inbound} or {outbound}))"
    );
    if cfg.dns_upstream.is_some() {
        // GoodbyeDPI appends the UDP clause after the whole `(tcp ...)` group.
        main.push_str(" or ");
        main.push_str(t::DNS_CLAUSE_PORT53);
    }

    let main = CString::new(main).map_err(|_| CoreError::Filter("main filter has interior NUL".into()))?;
    let quic_drop = if cfg.quic_drop_enabled() {
        Some(CString::new(t::QUIC_DROP).map_err(|_| CoreError::Filter("quic filter has interior NUL".into()))?)
    } else {
        None
    };

    Ok(Filters { main, quic_drop })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn count(s: &str, ch: char) -> usize {
        s.chars().filter(|c| *c == ch).count()
    }

    #[test]
    fn parens_balanced_default() {
        let f = build(&EvasionConfig::default()).unwrap();
        let s = f.main.to_str().unwrap();
        assert_eq!(count(s, '('), count(s, ')'), "main: {s}");
        assert!(f.quic_drop.is_some());
    }

    #[test]
    fn verbatim_fragments_present() {
        let s = build(&EvasionConfig::default()).unwrap().main.into_string().unwrap();
        assert!(s.contains(t::NO_LOCALNETS_V4_SRC));
        assert!(s.contains(t::NO_LOCALNETS_V6_DST));
        assert!(s.contains("tcp.Payload[0] == 0x16"));
        assert!(s.contains("tcp.PayloadLength < 1200")); // {n} substituted
        assert!(!s.contains(" or (udp")); // no DNS clause by default
    }

    #[test]
    fn dns_clause_added_only_with_upstream() {
        let cfg = EvasionConfig {
            dns_upstream: Some(IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9))),
            ..Default::default()
        };
        let s = build(&cfg).unwrap().main.into_string().unwrap();
        assert!(s.ends_with(t::DNS_CLAUSE_PORT53));
        assert_eq!(count(&s, '('), count(&s, ')'));
    }

    #[test]
    fn quic_drop_suppressed_when_disabled() {
        let cfg = EvasionConfig {
            quic_drop: Some(false),
            ..Default::default()
        };
        assert!(build(&cfg).unwrap().quic_drop.is_none());
    }
}
