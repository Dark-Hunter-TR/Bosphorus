//! Integration: every filter string `bosphorus-core` builds must be accepted by
//! WinDivert's own compiler (`WinDivertHelperCompileFilter`, user-mode).

use std::net::{IpAddr, Ipv4Addr};

use bosphorus_core::config::QuicPolicy;
use bosphorus_core::{filter, EvasionConfig};
use bosphorus_divert::{compile_filter, Layer};

#[test]
fn default_filters_compile() {
    let f = filter::build(&EvasionConfig::default()).expect("build");
    compile_filter(&f.main, Layer::Network).expect("main filter accepted");
}

/// Every policy's filter, including the selective QUIC clause the engine needs
/// captured and the blanket drop clause only `all` opens.
#[test]
fn every_quic_policy_produces_filters_windivert_accepts() {
    for policy in [QuicPolicy::Off, QuicPolicy::Blocked, QuicPolicy::All] {
        let cfg = EvasionConfig {
            quic: policy,
            ..Default::default()
        };
        let f = filter::build(&cfg).expect("build");
        compile_filter(&f.main, Layer::Network)
            .unwrap_or_else(|e| panic!("main filter for {policy:?} rejected: {e:?}"));
        if let Some(q) = &f.quic_drop {
            compile_filter(q, Layer::Network)
                .unwrap_or_else(|e| panic!("quic-drop filter for {policy:?} rejected: {e:?}"));
        }
    }
}

/// The selective clause has to reach the engine, so a missing piece here is a
/// silently disabled feature rather than a loud failure.
#[test]
fn the_selective_quic_clause_is_present_and_version_agnostic() {
    let f = filter::build(&EvasionConfig::default()).expect("build");
    let s = f.main.to_str().unwrap();
    assert!(s.contains("udp.DstPort == 443"), "no QUIC capture: {s}");
    assert!(s.contains("udp.PayloadLength >= 1200"));
    assert!(
        s.contains("udp.Payload[0] >= 0x80"),
        "must capture greased long headers: {s}"
    );
    assert!(
        !s.contains("udp.Payload[0] >= 0xC0"),
        "fixed-bit requirement would miss greased Initials: {s}"
    );
    assert!(
        !s.contains("udp.Payload32[1b]"),
        "pinning the version would miss QUIC v2 and the drafts"
    );
    assert!(
        f.quic_drop.is_none(),
        "selective mode must not also blanket-drop"
    );
}

#[test]
fn quic_all_drop_covers_all_configured_tls_ports_and_compiles() {
    let cfg = EvasionConfig {
        quic: QuicPolicy::All,
        ..Default::default()
    };
    let f = filter::build(&cfg).expect("build");
    let drop = f
        .quic_drop
        .as_ref()
        .expect("blanket drop handle")
        .to_str()
        .unwrap();
    for p in ["443", "2053", "2083", "2087", "2096", "8443"] {
        assert!(
            drop.contains(&format!("udp.DstPort == {p}")),
            "drop missing {p}: {drop}"
        );
    }
    compile_filter(f.quic_drop.as_ref().unwrap(), Layer::Network)
        .expect("blanket QUIC drop filter accepted by WinDivert");
}

#[test]
fn quic_scopes_follow_custom_tls_ports() {
    let ports = vec![443, 9443];
    for policy in [QuicPolicy::Blocked, QuicPolicy::All] {
        let cfg = EvasionConfig {
            quic: policy,
            tls_ports: ports.clone(),
            ..Default::default()
        };
        let f = filter::build(&cfg).expect("build");
        match policy {
            QuicPolicy::Blocked => {
                let s = f.main.to_str().unwrap();
                assert!(
                    s.contains("udp.DstPort == 9443"),
                    "selective missing custom port: {s}"
                );
                assert!(
                    !s.contains("udp.DstPort == 2083"),
                    "selective leaked default port: {s}"
                );
                compile_filter(&f.main, Layer::Network)
                    .expect("custom-port selective filter accepted by WinDivert");
            }
            QuicPolicy::All => {
                let drop = f.quic_drop.as_ref().unwrap().to_str().unwrap();
                assert!(
                    drop.contains("udp.DstPort == 9443"),
                    "blanket missing custom port: {drop}"
                );
                assert!(
                    !drop.contains("udp.DstPort == 2083"),
                    "blanket leaked default port: {drop}"
                );
                compile_filter(f.quic_drop.as_ref().unwrap(), Layer::Network)
                    .expect("custom-port blanket filter accepted by WinDivert");
            }
            QuicPolicy::Off => {}
        }
    }
}

#[test]
fn dns_upstream_is_rejected() {
    let cfg = EvasionConfig {
        dns_upstream: Some(IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9))),
        ..Default::default()
    };
    let err = match filter::build(&cfg) {
        Ok(_) => panic!("dns_upstream must be rejected"),
        Err(e) => e,
    };
    let msg = err.to_string();
    assert!(msg.contains("dns_upstream"), "msg: {msg}");
    assert!(msg.contains("not supported"), "msg: {msg}");
}

#[test]
fn custom_max_payload_compiles() {
    let cfg = EvasionConfig {
        max_payload_filter: 800,
        ..Default::default()
    };
    let f = filter::build(&cfg).expect("build");
    compile_filter(&f.main, Layer::Network).expect("main filter accepted");
}

#[test]
fn default_filter_carries_the_cloudflare_https_alt_ports_and_compiles() {
    let f = filter::build(&EvasionConfig::default()).expect("build");
    let s = f.main.to_str().unwrap();
    for p in ["443", "2053", "2083", "2087", "2096", "8443"] {
        assert!(
            s.contains(&format!("tcp.DstPort == {p}")),
            "outbound missing {p}"
        );
        assert!(
            s.contains(&format!("tcp.SrcPort == {p}")),
            "inbound missing {p}"
        );
    }
    compile_filter(&f.main, Layer::Network).expect("alt-port main filter accepted by WinDivert");
}

#[test]
fn a_wide_custom_tls_port_set_still_compiles() {
    let cfg = EvasionConfig {
        tls_ports: vec![443, 2053, 2083, 2087, 2096, 8443],
        ..Default::default()
    };
    let f = filter::build(&cfg).expect("build");
    compile_filter(&f.main, Layer::Network).expect("6-port main filter accepted by WinDivert");
}
