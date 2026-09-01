//! Integration: every filter string `bosphorus-core` builds must be accepted by
//! WinDivert's own compiler (`WinDivertHelperCompileFilter`, user-mode).

use std::net::{IpAddr, Ipv4Addr};

use bosphorus_core::{filter, EvasionConfig};
use bosphorus_divert::{compile_filter, Layer};

#[test]
fn default_filters_compile() {
    let f = filter::build(&EvasionConfig::default()).expect("build");
    compile_filter(&f.main, Layer::Network).expect("main filter accepted");
    compile_filter(f.quic_drop.as_ref().expect("quic present"), Layer::Network)
        .expect("quic-drop filter accepted");
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
