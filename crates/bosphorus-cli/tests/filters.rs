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
        let cfg = EvasionConfig { quic: policy, ..Default::default() };
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
        !s.contains("udp.Payload32[1b]"),
        "pinning the version would miss QUIC v2 and the drafts"
    );
    assert!(f.quic_drop.is_none(), "selective mode must not also blanket-drop");
}

#[test]
fn dns_enabled_filter_compiles() {
    let cfg = EvasionConfig {
        dns_upstream: Some(IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9))),
        ..Default::default()
    };
    let f = filter::build(&cfg).expect("build");
    compile_filter(&f.main, Layer::Network).expect("dns-enabled main filter accepted");
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
        assert!(s.contains(&format!("tcp.DstPort == {p}")), "outbound missing {p}");
        assert!(s.contains(&format!("tcp.SrcPort == {p}")), "inbound missing {p}");
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
