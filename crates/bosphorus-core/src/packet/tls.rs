//! Minimal TLS ClientHello / ServerHello recognition, working on the payload of
//! a single captured TCP segment (WinDivert does no reassembly — verified in
//! M0/V1: a new flow's first inbound data segment starts `16 03 03`).

use std::ops::Range;

/// TLS record ContentType if `payload` looks like a TLS record header
/// (`content_type`, version `03 00..04`).
pub fn tls_content_type(payload: &[u8]) -> Option<u8> {
    if payload.len() >= 3 && payload[1] == 0x03 && payload[2] <= 0x04 {
        Some(payload[0])
    } else {
        None
    }
}

fn is_handshake_of_type(payload: &[u8], hs_type: u8) -> bool {
    payload.len() >= 6
        && payload[0] == 0x16 // handshake record
        && payload[1] == 0x03
        && payload[2] <= 0x04
        && payload[5] == hs_type // handshake message type
}

pub fn looks_like_client_hello(payload: &[u8]) -> bool {
    is_handshake_of_type(payload, 0x01)
}

pub fn looks_like_server_hello(payload: &[u8]) -> bool {
    is_handshake_of_type(payload, 0x02)
}

/// Byte range (within `payload`) of the SNI host name, plus the offset of the
/// TLS record body, for `--frag-by-sni` / the `SniStart` split anchor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SniLocation {
    pub host: Range<usize>,
    pub record_body_start: usize,
}

/// Parse a ClientHello and locate the SNI host name. Works even when the TLS
/// record is truncated (a fragmented ClientHello whose first segment we hold) —
/// `server_name` is almost always early enough to be present. Returns `None`
/// when no `server_name` can be read from the bytes available.
pub fn find_sni(payload: &[u8]) -> Option<SniLocation> {
    // TLS record header (5) + handshake header (4)
    if payload.len() < 9 || payload[0] != 0x16 || payload[1] != 0x03 || payload[5] != 0x01 {
        return None;
    }
    let record_len = u16::from_be_bytes([payload[3], payload[4]]) as usize;
    let record_body_start: usize = 5;
    // Parse as far as we actually captured; the defensive cursor below stops
    // cleanly (returning `None`) if the SNI itself is past the truncation.
    let record_end = record_body_start
        .saturating_add(record_len)
        .min(payload.len());
    if record_end <= record_body_start {
        return None;
    }
    let hs = &payload[record_body_start..record_end];

    let mut c = Cursor::new(hs);
    c.skip(4)?; // handshake type (1) + length (3)
    c.skip(2)?; // client_version
    c.skip(32)?; // random
    let sid_len = c.u8()? as usize;
    c.skip(sid_len)?;
    let cs_len = c.u16()? as usize;
    c.skip(cs_len)?;
    let comp_len = c.u8()? as usize;
    c.skip(comp_len)?;
    let _ext_total = c.u16()? as usize;

    while c.remaining() >= 4 {
        let ext_type = c.u16()?;
        let ext_len = c.u16()? as usize;
        let ext_start = c.pos();
        if ext_len > c.remaining() {
            return None;
        }
        if ext_type == 0x0000 {
            // server_name extension
            let mut sc = Cursor::new(&hs[ext_start..ext_start + ext_len]);
            let _list_len = sc.u16()?;
            let name_type = sc.u8()?;
            let name_len = sc.u16()? as usize;
            if name_type != 0x00 || name_len > sc.remaining() {
                return None;
            }
            // absolute offset of the host name inside `payload`
            let host_start = record_body_start + ext_start + sc.pos();
            return Some(SniLocation {
                host: host_start..host_start + name_len,
                record_body_start,
            });
        }
        c.set_pos(ext_start + ext_len);
    }
    None
}

/// RFC 7685 `padding` extension (type `0x0015`): append `pad_len` zero bytes as
/// a new extension on a ClientHello's extension list, growing the
/// extensions-length / handshake-length / record-length fields to match. Used
/// by M7c (`Strategy::tls_pad`) to push a ClientHello past whatever fixed
/// buffer a DPI's reassembly logic allocates.
///
/// Requires the *whole* ClientHello record to be present in `payload` (the
/// record length must equal `payload.len() - 5`, and the extensions block must
/// run exactly to the end of the record) — a fragmented/truncated capture is
/// refused rather than guessed at. Returns `None` on any parse failure or if
/// growing a length field would overflow its 16-bit range.
pub fn add_padding_extension(payload: &[u8], pad_len: u16) -> Option<Vec<u8>> {
    if !looks_like_client_hello(payload) {
        return None;
    }
    let record_len = u16::from_be_bytes([payload[3], payload[4]]) as usize;
    if record_len != payload.len() - 5 {
        return None; // fragmented — we only hold part of the record
    }
    let hs_len = u32::from_be_bytes([0, payload[6], payload[7], payload[8]]) as usize;
    if 9 + hs_len != payload.len() {
        return None; // handshake message doesn't fill the record — unexpected
    }
    let hs_body = &payload[9..];

    let mut c = Cursor::new(hs_body);
    c.skip(2)?; // client_version
    c.skip(32)?; // random
    let sid_len = c.u8()? as usize;
    c.skip(sid_len)?;
    let cs_len = c.u16()? as usize;
    c.skip(cs_len)?;
    let comp_len = c.u8()? as usize;
    c.skip(comp_len)?;
    let ext_len_pos = c.pos(); // offset of the 2-byte extensions-length within hs_body
    let ext_total = c.u16()? as usize;
    if c.pos() + ext_total != hs_body.len() {
        return None; // extensions don't run exactly to the end — refuse to guess
    }

    let extra = 4usize + pad_len as usize; // ext header (type+len) + zero padding
    let new_ext_total = ext_total.checked_add(extra)?;
    let new_hs_len = hs_len.checked_add(extra)?;
    let new_record_len = record_len.checked_add(extra)?;
    if new_ext_total > u16::MAX as usize || new_record_len > u16::MAX as usize {
        return None;
    }

    let mut out = Vec::with_capacity(payload.len() + extra);
    out.extend_from_slice(payload);
    out.extend_from_slice(&0x0015u16.to_be_bytes()); // padding extension type
    out.extend_from_slice(&pad_len.to_be_bytes());
    out.resize(out.len() + pad_len as usize, 0);

    out[3..5].copy_from_slice(&(new_record_len as u16).to_be_bytes());
    out[6] = (new_hs_len >> 16) as u8;
    out[7] = (new_hs_len >> 8) as u8;
    out[8] = new_hs_len as u8;
    let el = 9 + ext_len_pos;
    out[el..el + 2].copy_from_slice(&(new_ext_total as u16).to_be_bytes());

    Some(out)
}

struct Cursor<'a> {
    b: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(b: &'a [u8]) -> Self {
        Self { b, pos: 0 }
    }
    fn pos(&self) -> usize {
        self.pos
    }
    fn set_pos(&mut self, p: usize) {
        self.pos = p;
    }
    fn remaining(&self) -> usize {
        self.b.len().saturating_sub(self.pos)
    }
    fn skip(&mut self, n: usize) -> Option<()> {
        self.pos = self.pos.checked_add(n).filter(|p| *p <= self.b.len())?;
        Some(())
    }
    fn u8(&mut self) -> Option<u8> {
        let v = *self.b.get(self.pos)?;
        self.pos += 1;
        Some(v)
    }
    fn u16(&mut self) -> Option<u16> {
        let hi = self.u8()? as u16;
        let lo = self.u8()? as u16;
        Some((hi << 8) | lo)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A complete, minimal ClientHello record with a server_name extension for
    /// "example.com" (no cipher suites / other extensions to keep it short).
    fn clienthello_with_sni(host: &str) -> Vec<u8> {
        let mut ext = Vec::new(); // server_name extension body
        let name = host.as_bytes();
        let list_len = (3 + name.len()) as u16;
        ext.extend_from_slice(&list_len.to_be_bytes());
        ext.push(0x00); // name_type host_name
        ext.extend_from_slice(&(name.len() as u16).to_be_bytes());
        ext.extend_from_slice(name);

        let mut extensions = Vec::new();
        extensions.extend_from_slice(&0x0000u16.to_be_bytes()); // ext type server_name
        extensions.extend_from_slice(&(ext.len() as u16).to_be_bytes());
        extensions.extend_from_slice(&ext);

        let mut hs_body = Vec::new();
        hs_body.extend_from_slice(&[0x03, 0x03]); // client_version
        hs_body.extend_from_slice(&[0x11; 32]); // random
        hs_body.push(0x00); // session id len
        hs_body.extend_from_slice(&0x0002u16.to_be_bytes()); // cipher suites len
        hs_body.extend_from_slice(&[0x13, 0x01]); // one cipher suite
        hs_body.push(0x01); // compression methods len
        hs_body.push(0x00); // null compression
        hs_body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        hs_body.extend_from_slice(&extensions);

        let mut hs = Vec::new();
        hs.push(0x01); // ClientHello
        let l = hs_body.len() as u32;
        hs.extend_from_slice(&[(l >> 16) as u8, (l >> 8) as u8, l as u8]);
        hs.extend_from_slice(&hs_body);

        let mut rec = Vec::new();
        rec.extend_from_slice(&[0x16, 0x03, 0x01]);
        rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        rec.extend_from_slice(&hs);
        rec
    }

    #[test]
    fn recognises_hello_types() {
        let ch = clienthello_with_sni("example.com");
        assert!(looks_like_client_hello(&ch));
        assert!(!looks_like_server_hello(&ch));
        assert_eq!(tls_content_type(&ch), Some(0x16));
        assert_eq!(tls_content_type(&[0x17, 0x03, 0x03, 0, 0]), Some(0x17));
        assert_eq!(tls_content_type(&[0x99, 0x00, 0x00]), None);
    }

    #[test]
    fn finds_sni_host() {
        let ch = clienthello_with_sni("example.com");
        let loc = find_sni(&ch).expect("sni found");
        assert_eq!(&ch[loc.host.clone()], b"example.com");
        assert_eq!(loc.record_body_start, 5);
    }

    #[test]
    fn finds_sni_longer_host() {
        let ch = clienthello_with_sni("a-rather-long.subdomain.example.co.uk");
        let loc = find_sni(&ch).unwrap();
        assert_eq!(&ch[loc.host], b"a-rather-long.subdomain.example.co.uk");
    }

    #[test]
    fn no_sni_when_not_clienthello() {
        assert!(find_sni(&[0x16, 0x03, 0x03, 0x00, 0x02, 0x02, 0x00]).is_none());
        assert!(find_sni(b"not tls at all").is_none());
    }

    #[test]
    fn finds_sni_in_truncated_record() {
        // A complete ClientHello, but its TLS record length claims 4000 bytes
        // (fragmented across TCP segments) while we only hold this first one.
        let mut ch = clienthello_with_sni("cdn.updates.example.org");
        ch[3..5].copy_from_slice(&4000u16.to_be_bytes());
        let loc = find_sni(&ch).expect("SNI recovered from a truncated record");
        assert_eq!(&ch[loc.host], b"cdn.updates.example.org");
    }

    // --- M7c: RFC 7685 padding ---

    #[test]
    fn padding_grows_all_three_length_fields_by_extra() {
        let ch = clienthello_with_sni("example.com");
        let record_len_before = u16::from_be_bytes([ch[3], ch[4]]);
        let hs_len_before = u32::from_be_bytes([0, ch[6], ch[7], ch[8]]);

        let padded = add_padding_extension(&ch, 512).expect("pads a complete ClientHello");
        assert_eq!(padded.len(), ch.len() + 4 + 512);

        let record_len_after = u16::from_be_bytes([padded[3], padded[4]]);
        let hs_len_after = u32::from_be_bytes([0, padded[6], padded[7], padded[8]]);
        assert_eq!(record_len_after as usize, record_len_before as usize + 4 + 512);
        assert_eq!(hs_len_after, hs_len_before + 4 + 512);

        // The new extension: type 0x0015, length 512, then 512 zero bytes.
        let tail = &padded[padded.len() - (4 + 512)..];
        assert_eq!(&tail[..2], &[0x00, 0x15]);
        assert_eq!(&tail[2..4], &512u16.to_be_bytes());
        assert!(tail[4..].iter().all(|&b| b == 0));

        // Existing fields (in particular the SNI, which sits before the new
        // extension) are unmoved.
        let loc = find_sni(&padded).expect("SNI still findable after padding");
        assert_eq!(&padded[loc.host], b"example.com");
    }

    #[test]
    fn padding_zero_still_appends_a_valid_empty_extension() {
        let ch = clienthello_with_sni("example.com");
        let padded = add_padding_extension(&ch, 0).unwrap();
        assert_eq!(padded.len(), ch.len() + 4);
        assert_eq!(&padded[padded.len() - 4..], &[0x00, 0x15, 0x00, 0x00]);
    }

    #[test]
    fn padding_rejects_a_fragmented_record() {
        let mut ch = clienthello_with_sni("example.com");
        // Claim a record length far longer than what we actually hold.
        ch[3..5].copy_from_slice(&4000u16.to_be_bytes());
        assert!(add_padding_extension(&ch, 512).is_none());
    }

    #[test]
    fn padding_rejects_non_clienthello() {
        assert!(add_padding_extension(b"not tls at all", 512).is_none());
        assert!(add_padding_extension(&[0x16, 0x03, 0x03, 0x00, 0x02, 0x02, 0x00], 512).is_none());
    }

    #[test]
    fn none_when_extensions_past_the_capture() {
        // Chop the ClientHello right after the extensions-length field:
        // record(5)+hs_hdr(4)+ver(2)+rand(32)+sid(1)+cs(2+2)+comp(1+1)+extlen(2) = 52
        let full = clienthello_with_sni("example.com");
        assert!(find_sni(&full[..52]).is_none());
    }
}
