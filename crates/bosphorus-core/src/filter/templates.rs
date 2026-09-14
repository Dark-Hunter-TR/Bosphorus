//! WinDivert filter fragments copied **verbatim** from
//! `ValdikSS/GoodbyeDPI` `src/goodbyedpi.c` (`master`):
//!   * lines 33-61   — `DIVERT_NO_LOCALNETSv4/v6_{SRC,DST}`
//!   * lines 82-84   — `FILTER_PASSIVE_BLOCK_QUIC`
//!   * lines 203-204 — `add_filter_str` UDP form (DNS clause)
//!   * lines 242-245 — `maxpayloadsize_str`
//!
//! Do not paraphrase or "tidy" these — they must match GoodbyeDPI byte for byte
//! (C adjacent-string-literal concatenation already applied).

pub const NO_LOCALNETS_V4_DST: &str = "((ip.DstAddr < 127.0.0.1 or ip.DstAddr > 127.255.255.255) and (ip.DstAddr < 10.0.0.0 or ip.DstAddr > 10.255.255.255) and (ip.DstAddr < 192.168.0.0 or ip.DstAddr > 192.168.255.255) and (ip.DstAddr < 172.16.0.0 or ip.DstAddr > 172.31.255.255) and (ip.DstAddr < 169.254.0.0 or ip.DstAddr > 169.254.255.255))";

pub const NO_LOCALNETS_V4_SRC: &str = "((ip.SrcAddr < 127.0.0.1 or ip.SrcAddr > 127.255.255.255) and (ip.SrcAddr < 10.0.0.0 or ip.SrcAddr > 10.255.255.255) and (ip.SrcAddr < 192.168.0.0 or ip.SrcAddr > 192.168.255.255) and (ip.SrcAddr < 172.16.0.0 or ip.SrcAddr > 172.31.255.255) and (ip.SrcAddr < 169.254.0.0 or ip.SrcAddr > 169.254.255.255))";

pub const NO_LOCALNETS_V6_DST: &str = "((ipv6.DstAddr > ::1) and (ipv6.DstAddr < 2001::0 or ipv6.DstAddr > 2001:1::0) and (ipv6.DstAddr < fc00::0 or ipv6.DstAddr > fe00::0) and (ipv6.DstAddr < fe80::0 or ipv6.DstAddr > fec0::0) and (ipv6.DstAddr < ff00::0 or ipv6.DstAddr > ffff::0))";

pub const NO_LOCALNETS_V6_SRC: &str = "((ipv6.SrcAddr > ::1) and (ipv6.SrcAddr < 2001::0 or ipv6.SrcAddr > 2001:1::0) and (ipv6.SrcAddr < fc00::0 or ipv6.SrcAddr > fe00::0) and (ipv6.SrcAddr < fe80::0 or ipv6.SrcAddr > fec0::0) and (ipv6.SrcAddr < ff00::0 or ipv6.SrcAddr > ffff::0))";

/// `FILTER_PASSIVE_BLOCK_QUIC` (goodbyedpi.c:82-84) — verbatim. Used only for
/// [`QuicPolicy::All`](crate::config::QuicPolicy::All), where the handle drops
/// every match in the driver and the engine never sees the packets.
pub const QUIC_DROP: &str = "outbound and !impostor and !loopback and udp and udp.DstPort == 443 and udp.PayloadLength >= 1200 and udp.Payload[0] >= 0xC0 and udp.Payload32[1b] == 0x01";

/// Ours, not GoodbyeDPI's: the capture clause for
/// [`QuicPolicy::Blocked`](crate::config::QuicPolicy::Blocked), where the drop
/// decision is per destination and therefore has to be made in the engine.
///
/// It deliberately drops GoodbyeDPI's `udp.Payload32[1b] == 0x01` version pin —
/// that clause only matches QUIC v1, and both v2 (RFC 9369) and the draft
/// versions still in the wild open connections exactly the same way.
/// [`crate::packet::quic`] does the precise classification once a datagram is
/// in hand; this clause only has to be cheap and not miss anything.
///
/// `PayloadLength >= 1200` is what makes that safe: a client must pad any
/// datagram containing an Initial to at least 1200 bytes, so nothing that opens
/// a connection can slip past, while the short packets of an established
/// connection never reach the engine.
pub const QUIC_SELECTIVE_FMT: &str = "(outbound and !impostor and !loopback and udp and {dst_ports} and udp.PayloadLength >= 1200 and udp.Payload[0] >= 0xC0 and ({v4dst} or {v6dst}))";

/// `maxpayloadsize_str` (goodbyedpi.c:242-245) — verbatim, with GoodbyeDPI's
/// `%hu` replaced by the `{n}` placeholder. "GET " = 0x47455420,
/// "POST" = 0x504F5354 (big endian).
pub const MAXPAYLOAD_FMT: &str = "and (tcp.PayloadLength ? tcp.PayloadLength < {n} or tcp.Payload32[0] == 0x47455420 or tcp.Payload32[0] == 0x504F5354 or (tcp.Payload[0] == 0x16 and tcp.Payload[1] == 0x03 and tcp.Payload[2] <= 0x03): true)";

/// `add_filter_str` UDP form (goodbyedpi.c:203-204) with port 53 substituted
/// for `%d`, and the leading `" or "` dropped (the builder adds it).
pub const DNS_CLAUSE_PORT53: &str = "(udp and !impostor and !loopback and (udp.SrcPort == 53 or udp.DstPort == 53))";
