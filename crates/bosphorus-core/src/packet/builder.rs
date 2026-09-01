//! Owned, mutable copy of a packet for the transforms in M4+.
//!
//! M2 provides the byte-level edits (TTL, seq/ack, payload replace/truncate)
//! with IP length-field fixups. Checksums are **not** recomputed here — that is
//! the sink's job (`recalc_checksums`, added in M4), mirroring GoodbyeDPI's
//! `WinDivertHelperCalcChecksums` after mutation.

use crate::error::CoreError;
use crate::packet::view::PacketView;

pub struct PacketBuilder {
    buf: Vec<u8>,
    ipv6: bool,
    ip_hdr_len: usize,
    l4_hdr_start: usize,
    is_tcp: bool,
    payload_start: usize,
}

impl PacketBuilder {
    pub fn from_view(v: &PacketView<'_>) -> Self {
        let l4 = v.l4_header_range();
        Self {
            buf: v.raw().to_vec(),
            ipv6: v.is_ipv6(),
            ip_hdr_len: if v.is_ipv6() { 40 } else { (v.raw()[0] & 0x0f) as usize * 4 },
            l4_hdr_start: l4.start,
            is_tcp: v.is_tcp(),
            payload_start: v.payload_offset(),
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.buf
    }
    pub fn into_bytes(self) -> Vec<u8> {
        self.buf
    }

    /// IPv4 TTL / IPv6 hop limit.
    pub fn set_ttl(&mut self, ttl: u8) -> &mut Self {
        let off = if self.ipv6 { 7 } else { 8 };
        self.buf[off] = ttl;
        self
    }

    pub fn set_tcp_seq(&mut self, seq: u32) -> Result<&mut Self, CoreError> {
        self.write_tcp_u32(4, seq)
    }
    pub fn set_tcp_ack(&mut self, ack: u32) -> Result<&mut Self, CoreError> {
        self.write_tcp_u32(8, ack)
    }

    fn write_tcp_u32(&mut self, field_off: usize, val: u32) -> Result<&mut Self, CoreError> {
        if !self.is_tcp {
            return Err(CoreError::Parse("not a TCP packet"));
        }
        let at = self.l4_hdr_start + field_off;
        self.buf
            .get_mut(at..at + 4)
            .ok_or(CoreError::ShortPacket)?
            .copy_from_slice(&val.to_be_bytes());
        Ok(self)
    }

    /// Replace the L4 payload; fixes the IPv4 total-length / IPv6 payload-length
    /// field. TCP/UDP length-derived fields and all checksums are left stale.
    pub fn replace_payload(&mut self, new_payload: &[u8]) -> &mut Self {
        self.buf.truncate(self.payload_start);
        self.buf.extend_from_slice(new_payload);
        self.fix_ip_length();
        self
    }

    /// Keep only the first `keep` payload bytes (fragment part 0).
    pub fn truncate_payload(&mut self, keep: usize) -> &mut Self {
        let end = (self.payload_start + keep).min(self.buf.len());
        self.buf.truncate(end);
        self.fix_ip_length();
        self
    }

    /// Drop the first `start` payload bytes, keeping the rest (fragment part 1).
    /// The caller is responsible for bumping the TCP sequence number by `start`.
    pub fn slice_payload_from(&mut self, start: usize) -> &mut Self {
        let cut = (self.payload_start + start).min(self.buf.len());
        self.buf.drain(self.payload_start..cut);
        self.fix_ip_length();
        self
    }

    fn fix_ip_length(&mut self) {
        if self.ipv6 {
            let payload_len = (self.buf.len() - 40) as u16;
            self.buf[4..6].copy_from_slice(&payload_len.to_be_bytes());
        } else {
            let total = self.buf.len() as u16;
            self.buf[2..4].copy_from_slice(&total.to_be_bytes());
        }
        let _ = self.ip_hdr_len; // reserved for option-aware edits later
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4_tcp(payload: &[u8]) -> Vec<u8> {
        let mut p = vec![
            0x45, 0x00, 0x00, 0x00, 0, 0, 0x40, 0x00, 0x40, 0x06, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2,
        ];
        p.extend_from_slice(&[
            0x30, 0x39, 0x01, 0xbb, 0, 0, 0, 100, 0, 0, 0, 0, 0x50, 0x18, 0xff, 0xff, 0, 0, 0, 0,
        ]);
        p.extend_from_slice(payload);
        let total = p.len() as u16;
        p[2..4].copy_from_slice(&total.to_be_bytes());
        p
    }

    #[test]
    fn ttl_and_seq_edits() {
        let pkt = v4_tcp(b"abcdefgh");
        let v = PacketView::parse(&pkt).unwrap();
        let mut b = PacketBuilder::from_view(&v);
        b.set_ttl(7).set_tcp_seq(0xDEADBEEF).unwrap();
        let out = b.into_bytes();
        let v2 = PacketView::parse(&out).unwrap();
        assert_eq!(v2.ttl(), 7);
        assert_eq!(v2.tcp_seq(), Some(0xDEADBEEF));
        assert_eq!(v2.payload(), b"abcdefgh");
    }

    #[test]
    fn truncate_and_replace_fix_ip_len() {
        let pkt = v4_tcp(b"0123456789");
        let v = PacketView::parse(&pkt).unwrap();

        let mut b = PacketBuilder::from_view(&v);
        b.truncate_payload(4);
        let out = b.into_bytes();
        let v2 = PacketView::parse(&out).unwrap();
        assert_eq!(v2.payload(), b"0123");
        assert_eq!(u16::from_be_bytes([out[2], out[3]]), out.len() as u16);

        let mut b = PacketBuilder::from_view(&v);
        b.replace_payload(b"XYZ");
        let out = b.into_bytes();
        let v3 = PacketView::parse(&out).unwrap();
        assert_eq!(v3.payload(), b"XYZ");
        assert_eq!(u16::from_be_bytes([out[2], out[3]]), out.len() as u16);
    }

    #[test]
    fn native_fragment_split_round_trips() {
        let pkt = v4_tcp(b"0123456789");
        let v = PacketView::parse(&pkt).unwrap();
        let seq = v.tcp_seq().unwrap();

        let mut s0 = PacketBuilder::from_view(&v);
        s0.truncate_payload(2);
        let s0 = s0.into_bytes();

        let mut s1 = PacketBuilder::from_view(&v);
        s1.slice_payload_from(2).set_tcp_seq(seq.wrapping_add(2)).unwrap();
        let s1 = s1.into_bytes();

        let p0 = PacketView::parse(&s0).unwrap();
        let p1 = PacketView::parse(&s1).unwrap();
        assert_eq!(p0.payload(), b"01");
        assert_eq!(p1.payload(), b"23456789");
        assert_eq!(p0.tcp_seq(), Some(seq));
        assert_eq!(p1.tcp_seq(), Some(seq.wrapping_add(2)));
        assert_eq!(u16::from_be_bytes([s0[2], s0[3]]), s0.len() as u16);
        assert_eq!(u16::from_be_bytes([s1[2], s1[3]]), s1.len() as u16);
        // Concatenated payloads == original.
        assert_eq!([p0.payload(), p1.payload()].concat(), b"0123456789");
    }
}
