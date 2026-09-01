use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::ops::Range;

use crate::error::CoreError;

pub const IPPROTO_TCP: u8 = 6;
pub const IPPROTO_UDP: u8 = 17;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct TcpFlags {
    pub fin: bool,
    pub syn: bool,
    pub rst: bool,
    pub psh: bool,
    pub ack: bool,
    pub urg: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FiveTuple {
    pub src_ip: IpAddr,
    pub src_port: u16,
    pub dst_ip: IpAddr,
    pub dst_port: u16,
    pub protocol: u8,
}

/// Zero-copy view over one captured IP packet.
#[derive(Clone)]
pub struct PacketView<'a> {
    raw: &'a [u8],
    ipv6: bool,
    protocol: u8,
    ttl: u8,
    src_ip: IpAddr,
    dst_ip: IpAddr,
    l4_hdr: Range<usize>,
    payload: Range<usize>,
}

impl<'a> PacketView<'a> {
    pub fn parse(raw: &'a [u8]) -> Result<Self, CoreError> {
        let first = *raw.first().ok_or(CoreError::Parse("empty packet"))?;
        match first >> 4 {
            4 => Self::parse_v4(raw),
            6 => Self::parse_v6(raw),
            _ => Err(CoreError::Parse("unsupported IP version")),
        }
    }

    fn parse_v4(raw: &'a [u8]) -> Result<Self, CoreError> {
        if raw.len() < 20 {
            return Err(CoreError::Parse("truncated IPv4 header"));
        }
        let ihl = (raw[0] & 0x0f) as usize * 4;
        if !(20..=raw.len()).contains(&ihl) {
            return Err(CoreError::Parse("bad IPv4 IHL"));
        }
        let ttl = raw[8];
        let protocol = raw[9];
        let src_ip = IpAddr::V4(Ipv4Addr::new(raw[12], raw[13], raw[14], raw[15]));
        let dst_ip = IpAddr::V4(Ipv4Addr::new(raw[16], raw[17], raw[18], raw[19]));
        let (l4_hdr, payload) = parse_l4(raw, ihl, protocol)?;
        Ok(Self { raw, ipv6: false, protocol, ttl, src_ip, dst_ip, l4_hdr, payload })
    }

    fn parse_v6(raw: &'a [u8]) -> Result<Self, CoreError> {
        if raw.len() < 40 {
            return Err(CoreError::Parse("truncated IPv6 header"));
        }
        let ttl = raw[7]; // hop limit
        let mut next = raw[6];
        let mut off = 40usize;
        let mut src = [0u8; 16];
        let mut dst = [0u8; 16];
        src.copy_from_slice(&raw[8..24]);
        dst.copy_from_slice(&raw[24..40]);
        let src_ip = IpAddr::V6(Ipv6Addr::from(src));
        let dst_ip = IpAddr::V6(Ipv6Addr::from(dst));

        // Walk extension headers to the real upper-layer protocol.
        for _ in 0..8 {
            match next {
                // Hop-by-Hop(0), Routing(43), Dest-Opts(60): [next, ext_len, ...], (ext_len+1)*8 bytes
                0 | 43 | 60 => {
                    let hdr = raw.get(off..off + 2).ok_or(CoreError::Parse("truncated IPv6 ext header"))?;
                    let len = (hdr[1] as usize + 1) * 8;
                    next = hdr[0];
                    off = off.checked_add(len).ok_or(CoreError::Parse("IPv6 ext header overflow"))?;
                }
                // Fragment(44): fixed 8 bytes
                44 => {
                    let hdr = raw.get(off..off + 8).ok_or(CoreError::Parse("truncated IPv6 fragment header"))?;
                    next = hdr[0];
                    off += 8;
                }
                // Authentication Header(51): (payload_len+2)*4 bytes
                51 => {
                    let hdr = raw.get(off..off + 2).ok_or(CoreError::Parse("truncated AH"))?;
                    let len = (hdr[1] as usize + 2) * 4;
                    next = hdr[0];
                    off = off.checked_add(len).ok_or(CoreError::Parse("AH overflow"))?;
                }
                _ => break,
            }
            if off > raw.len() {
                return Err(CoreError::Parse("IPv6 ext headers exceed packet"));
            }
        }
        if matches!(next, 0 | 43 | 60 | 44 | 51) {
            return Err(CoreError::Parse("too many IPv6 extension headers"));
        }
        let (l4_hdr, payload) = parse_l4(raw, off, next)?;
        Ok(Self { raw, ipv6: true, protocol: next, ttl, src_ip, dst_ip, l4_hdr, payload })
    }

    pub fn raw(&self) -> &'a [u8] {
        self.raw
    }
    pub fn is_ipv6(&self) -> bool {
        self.ipv6
    }
    pub fn ip_version(&self) -> u8 {
        if self.ipv6 {
            6
        } else {
            4
        }
    }
    pub fn protocol(&self) -> u8 {
        self.protocol
    }
    /// IPv4 TTL or IPv6 hop limit.
    pub fn ttl(&self) -> u8 {
        self.ttl
    }
    pub fn src_ip(&self) -> IpAddr {
        self.src_ip
    }
    pub fn dst_ip(&self) -> IpAddr {
        self.dst_ip
    }
    pub fn is_tcp(&self) -> bool {
        self.protocol == IPPROTO_TCP
    }
    pub fn is_udp(&self) -> bool {
        self.protocol == IPPROTO_UDP
    }

    pub fn src_port(&self) -> Option<u16> {
        let h = self.raw.get(self.l4_hdr.start..self.l4_hdr.start + 2)?;
        Some(u16::from_be_bytes([h[0], h[1]]))
    }
    pub fn dst_port(&self) -> Option<u16> {
        let h = self.raw.get(self.l4_hdr.start + 2..self.l4_hdr.start + 4)?;
        Some(u16::from_be_bytes([h[0], h[1]]))
    }

    pub fn tcp_seq(&self) -> Option<u32> {
        if !self.is_tcp() {
            return None;
        }
        let b = self.raw.get(self.l4_hdr.start + 4..self.l4_hdr.start + 8)?;
        Some(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }
    pub fn tcp_ack(&self) -> Option<u32> {
        if !self.is_tcp() {
            return None;
        }
        let b = self.raw.get(self.l4_hdr.start + 8..self.l4_hdr.start + 12)?;
        Some(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }
    pub fn tcp_flags(&self) -> Option<TcpFlags> {
        if !self.is_tcp() {
            return None;
        }
        let f = *self.raw.get(self.l4_hdr.start + 13)?;
        Some(TcpFlags {
            fin: f & 0x01 != 0,
            syn: f & 0x02 != 0,
            rst: f & 0x04 != 0,
            psh: f & 0x08 != 0,
            ack: f & 0x10 != 0,
            urg: f & 0x20 != 0,
        })
    }

    pub fn payload_offset(&self) -> usize {
        self.payload.start
    }
    pub fn payload(&self) -> &'a [u8] {
        &self.raw[self.payload.clone()]
    }
    /// Byte range of the L4 header within the raw packet.
    pub fn l4_header_range(&self) -> Range<usize> {
        self.l4_hdr.clone()
    }

    pub fn five_tuple(&self) -> Option<FiveTuple> {
        Some(FiveTuple {
            src_ip: self.src_ip,
            src_port: self.src_port()?,
            dst_ip: self.dst_ip,
            dst_port: self.dst_port()?,
            protocol: self.protocol,
        })
    }
}

/// Returns `(l4_header_range, payload_range)` for TCP/UDP; for other protocols
/// the "header" is empty and everything is payload.
fn parse_l4(raw: &[u8], l4_start: usize, protocol: u8) -> Result<(Range<usize>, Range<usize>), CoreError> {
    let l4 = raw.get(l4_start..).ok_or(CoreError::Parse("L4 offset past packet"))?;
    match protocol {
        IPPROTO_TCP => {
            if l4.len() < 20 {
                return Err(CoreError::Parse("truncated TCP header"));
            }
            let data_off = (l4[12] >> 4) as usize * 4;
            if !(20..=l4.len()).contains(&data_off) {
                return Err(CoreError::Parse("bad TCP data offset"));
            }
            Ok((l4_start..l4_start + data_off, l4_start + data_off..raw.len()))
        }
        IPPROTO_UDP => {
            if l4.len() < 8 {
                return Err(CoreError::Parse("truncated UDP header"));
            }
            Ok((l4_start..l4_start + 8, l4_start + 8..raw.len()))
        }
        _ => Ok((l4_start..l4_start, l4_start..raw.len())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Real IPv4 / TCP packet carrying the start of a TLS 1.2 ClientHello to
    /// 93.184.216.34:443 (example.com). Hand-assembled from the wire format;
    /// IPv4 + TCP checksums are not meaningful here (parser ignores them).
    fn v4_tcp_clienthello() -> Vec<u8> {
        let mut p = Vec::new();
        // ---- IPv4 header (20 bytes) ----
        p.extend_from_slice(&[
            0x45, 0x00, // version=4, ihl=5, dscp/ecn=0
            0x00, 0x00, // total length (filled below)
            0x1c, 0x46, // id
            0x40, 0x00, // flags=DF, frag offset=0
            0x40, // ttl = 64
            0x06, // protocol = TCP
            0x00, 0x00, // header checksum (ignored)
            192, 168, 1, 23, // src 192.168.1.23
            93, 184, 216, 34, // dst 93.184.216.34
        ]);
        // ---- TCP header (20 bytes, no options) ----
        p.extend_from_slice(&[
            0xd8, 0xe2, // src port 55522
            0x01, 0xbb, // dst port 443
            0x11, 0x22, 0x33, 0x44, // seq
            0x55, 0x66, 0x77, 0x88, // ack
            0x50, // data offset = 5 (20 bytes), reserved=0
            0x18, // flags = PSH|ACK
            0xff, 0xff, // window
            0x00, 0x00, // checksum (ignored)
            0x00, 0x00, // urgent pointer
        ]);
        // ---- TLS payload: ClientHello record prefix ----
        p.extend_from_slice(&[
            0x16, 0x03, 0x01, // handshake, TLS 1.0 record version
            0x00, 0x2f, // record length (47)
            0x01, // handshake type = ClientHello
            0x00, 0x00, 0x2b, // handshake length
            0x03, 0x03, // client_version TLS 1.2
        ]);
        p.extend_from_slice(&[0xAA; 32]); // random
        p.push(0x00); // session_id length 0
        // fix IPv4 total length
        let total = p.len() as u16;
        p[2..4].copy_from_slice(&total.to_be_bytes());
        p
    }

    /// Real IPv6 / UDP DNS query for "example.com" A record to [2001:4860:4860::8888]:53.
    fn v6_udp_dns() -> Vec<u8> {
        let mut p = Vec::new();
        // ---- IPv6 base header (40 bytes) ----
        p.extend_from_slice(&[0x60, 0x00, 0x00, 0x00]); // version=6, tc=0, flow=0
        p.extend_from_slice(&[0x00, 0x00]); // payload length (filled below)
        p.push(17); // next header = UDP
        p.push(0x40); // hop limit = 64
        p.extend_from_slice(&[
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, // src 2001:db8::1
        ]);
        p.extend_from_slice(&[
            0x20, 0x01, 0x48, 0x60, 0x48, 0x60, 0, 0, 0, 0, 0, 0, 0, 0, 0x88, 0x88, // dst 2001:4860:4860::8888
        ]);
        // ---- UDP header (8 bytes) ----
        let udp_start = p.len();
        p.extend_from_slice(&[0xc0, 0x0a]); // src port 49162
        p.extend_from_slice(&[0x00, 0x35]); // dst port 53
        p.extend_from_slice(&[0x00, 0x00]); // length (filled below)
        p.extend_from_slice(&[0x00, 0x00]); // checksum (ignored)
        // ---- DNS query ----
        p.extend_from_slice(&[0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        for label in ["example", "com"] {
            p.push(label.len() as u8);
            p.extend_from_slice(label.as_bytes());
        }
        p.push(0x00); // root
        p.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // QTYPE=A, QCLASS=IN
        let udp_len = (p.len() - udp_start) as u16;
        p[udp_start + 4..udp_start + 6].copy_from_slice(&udp_len.to_be_bytes());
        let payload_len = (p.len() - 40) as u16;
        p[4..6].copy_from_slice(&payload_len.to_be_bytes());
        p
    }

    #[test]
    fn parses_v4_tcp() {
        let pkt = v4_tcp_clienthello();
        let v = PacketView::parse(&pkt).unwrap();
        assert_eq!(v.ip_version(), 4);
        assert!(!v.is_ipv6());
        assert!(v.is_tcp());
        assert_eq!(v.ttl(), 64);
        assert_eq!(v.src_ip(), "192.168.1.23".parse::<IpAddr>().unwrap());
        assert_eq!(v.dst_ip(), "93.184.216.34".parse::<IpAddr>().unwrap());
        assert_eq!(v.src_port(), Some(55522));
        assert_eq!(v.dst_port(), Some(443));
        assert_eq!(v.tcp_seq(), Some(0x11223344));
        assert_eq!(v.tcp_ack(), Some(0x55667788));
        let f = v.tcp_flags().unwrap();
        assert!(f.psh && f.ack && !f.syn && !f.rst);
        assert_eq!(v.payload_offset(), 40);
        assert_eq!(&v.payload()[..3], &[0x16, 0x03, 0x01]);
        let ft = v.five_tuple().unwrap();
        assert_eq!(ft.dst_port, 443);
        assert_eq!(ft.protocol, IPPROTO_TCP);
    }

    #[test]
    fn parses_v6_udp() {
        let pkt = v6_udp_dns();
        let v = PacketView::parse(&pkt).unwrap();
        assert_eq!(v.ip_version(), 6);
        assert!(v.is_ipv6() && v.is_udp());
        assert_eq!(v.ttl(), 64);
        assert_eq!(v.src_port(), Some(49162));
        assert_eq!(v.dst_port(), Some(53));
        assert_eq!(v.payload_offset(), 48);
        // DNS transaction id 0x1234
        assert_eq!(&v.payload()[..2], &[0x12, 0x34]);
    }

    #[test]
    fn v6_with_hop_by_hop_ext_header() {
        // IPv6 + Hop-by-Hop (8 bytes) + TCP.
        let mut p = Vec::new();
        p.extend_from_slice(&[0x60, 0, 0, 0, 0, 0]);
        p.push(0); // next header = Hop-by-Hop
        p.push(0x40);
        p.extend_from_slice(&[0u8; 16]);
        p.extend_from_slice(&[0u8; 16]);
        // Hop-by-Hop: next=TCP(6), ext_len=0 -> 8 bytes total
        p.extend_from_slice(&[6, 0, 1, 1, 1, 1, 1, 1]);
        // TCP header
        p.extend_from_slice(&[
            0x00, 0x50, 0x01, 0xbb, 0, 0, 0, 1, 0, 0, 0, 0, 0x50, 0x02, 0xff, 0xff, 0, 0, 0, 0,
        ]);
        p.extend_from_slice(b"hello");
        let v = PacketView::parse(&p).unwrap();
        assert!(v.is_ipv6() && v.is_tcp());
        assert_eq!(v.dst_port(), Some(443));
        assert_eq!(v.payload(), b"hello");
        assert_eq!(v.payload_offset(), 40 + 8 + 20);
    }

    #[test]
    fn rejects_garbage() {
        assert!(PacketView::parse(&[]).is_err());
        assert!(PacketView::parse(&[0x45, 0x00]).is_err()); // truncated v4
        assert!(PacketView::parse(&[0x40, 0, 0, 0]).is_err()); // truncated v6
        assert!(PacketView::parse(&[0x35, 0, 0, 0]).is_err()); // version 3
    }
}
