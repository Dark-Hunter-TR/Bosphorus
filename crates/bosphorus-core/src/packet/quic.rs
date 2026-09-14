//! QUIC long-header parsing, enough to tell a connection attempt from the rest
//! of a QUIC flow.
//!
//! The capture filter can only match the first payload byte and the datagram
//! length, so it hands us every long-header datagram on the port. Deciding
//! whether one is actually an *Initial* — the packet that opens a connection,
//! and therefore the only one worth acting on — needs the version and the
//! packet-type bits, which is what this module reads.
//!
//! No decryption happens here. The SNI inside an Initial sits in a CRYPTO frame
//! encrypted under keys derived from the connection ID, and recovering it would
//! mean pulling in HKDF and AES-GCM to read a name we already learn from the
//! TCP side of the same host.

/// QUIC v1 (RFC 9000).
pub const VERSION_1: u32 = 0x0000_0001;
/// QUIC v2 (RFC 9369). Chrome and Firefox both negotiate it.
pub const VERSION_2: u32 = 0x6b33_43cf;

/// Long-header packet types carry different numbers in v1 and v2, so the type
/// bits are only meaningful next to the version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuicPacketKind {
    /// Opens a connection (and the only long-header type a client pads to the
    /// 1200-byte minimum).
    Initial,
    ZeroRtt,
    Handshake,
    Retry,
    /// Version 0: the server listing versions it speaks. Never client-sent.
    VersionNegotiation,
    /// A long header whose version we don't have a type mapping for.
    UnknownVersion,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LongHeader {
    pub version: u32,
    pub kind: QuicPacketKind,
    pub dcid_len: u8,
}

/// Per RFC 9000 §17.2, a connection ID is at most 20 bytes.
const MAX_CID_LEN: u8 = 20;

/// Parse a QUIC long header out of a UDP payload. `None` for a short header,
/// a datagram too small to hold a header, or a malformed connection-ID length.
///
/// The fixed bit (`0x40`) is deliberately not required: RFC 9287 lets an
/// endpoint negotiate greasing it to zero, and a greased Initial still opens a
/// connection. The capture filter's coarse `>= 0xC0` match is the gate that
/// keeps the volume down; this parser stays permissive behind it.
pub fn parse_long_header(payload: &[u8]) -> Option<LongHeader> {
    // 1 flags + 4 version + 1 DCID length is the shortest possible prefix.
    if payload.len() < 6 {
        return None;
    }
    let first = payload[0];
    if first & 0x80 == 0 {
        return None; // short header — an established connection, not an attempt
    }

    let version = u32::from_be_bytes([payload[1], payload[2], payload[3], payload[4]]);
    let dcid_len = payload[5];
    if dcid_len > MAX_CID_LEN {
        return None;
    }
    // The source connection ID length must at least be present for the header
    // to be well-formed.
    if payload.len() < 6 + dcid_len as usize + 1 {
        return None;
    }
    let scid_len = payload[6 + dcid_len as usize];
    if scid_len > MAX_CID_LEN {
        return None;
    }

    let type_bits = (first >> 4) & 0x03;
    let kind = match version {
        0 => QuicPacketKind::VersionNegotiation,
        VERSION_1 => match type_bits {
            0x0 => QuicPacketKind::Initial,
            0x1 => QuicPacketKind::ZeroRtt,
            0x2 => QuicPacketKind::Handshake,
            _ => QuicPacketKind::Retry,
        },
        // RFC 9369 §3.2 rotates the type numbers so a v2 packet can't be
        // mistaken for a v1 one by a middlebox that only learned v1.
        VERSION_2 => match type_bits {
            0x1 => QuicPacketKind::Initial,
            0x2 => QuicPacketKind::ZeroRtt,
            0x3 => QuicPacketKind::Handshake,
            _ => QuicPacketKind::Retry,
        },
        _ => QuicPacketKind::UnknownVersion,
    };

    Some(LongHeader { version, kind, dcid_len })
}

/// Whether this datagram is a client opening a QUIC connection.
///
/// A long header carrying a version we don't know counts: only Initials are
/// padded to the 1200 bytes the capture filter already required, and a draft or
/// future version opens a connection exactly like v1 does. Version negotiation
/// is server-sent, so it never counts.
pub fn is_connection_attempt(payload: &[u8]) -> bool {
    matches!(
        parse_long_header(payload).map(|h| h.kind),
        Some(QuicPacketKind::Initial) | Some(QuicPacketKind::UnknownVersion)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `first` byte, version, then a 8-byte DCID and empty SCID.
    fn long_header(first: u8, version: u32) -> Vec<u8> {
        let mut p = vec![first];
        p.extend_from_slice(&version.to_be_bytes());
        p.push(8);
        p.extend_from_slice(&[0xab; 8]);
        p.push(0);
        p.extend_from_slice(&[0x00; 32]); // token + payload, contents irrelevant
        p
    }

    #[test]
    fn v1_initial_is_a_connection_attempt() {
        let p = long_header(0xC0, VERSION_1);
        let h = parse_long_header(&p).unwrap();
        assert_eq!(h.version, VERSION_1);
        assert_eq!(h.kind, QuicPacketKind::Initial);
        assert_eq!(h.dcid_len, 8);
        assert!(is_connection_attempt(&p));
    }

    #[test]
    fn v1_handshake_and_zero_rtt_are_not_connection_attempts() {
        let zero_rtt = long_header(0xD0, VERSION_1);
        assert_eq!(parse_long_header(&zero_rtt).unwrap().kind, QuicPacketKind::ZeroRtt);
        assert!(!is_connection_attempt(&zero_rtt));

        let handshake = long_header(0xE0, VERSION_1);
        assert_eq!(parse_long_header(&handshake).unwrap().kind, QuicPacketKind::Handshake);
        assert!(!is_connection_attempt(&handshake));

        let retry = long_header(0xF0, VERSION_1);
        assert_eq!(parse_long_header(&retry).unwrap().kind, QuicPacketKind::Retry);
        assert!(!is_connection_attempt(&retry));
    }

    #[test]
    fn v2_uses_its_own_type_numbering() {
        // The bits that mean Initial in v1 mean Retry in v2, and vice versa.
        let v2_initial = long_header(0xD0, VERSION_2);
        assert_eq!(parse_long_header(&v2_initial).unwrap().kind, QuicPacketKind::Initial);
        assert!(is_connection_attempt(&v2_initial));

        let v2_retry = long_header(0xC0, VERSION_2);
        assert_eq!(parse_long_header(&v2_retry).unwrap().kind, QuicPacketKind::Retry);
        assert!(!is_connection_attempt(&v2_retry));
    }

    #[test]
    fn an_unknown_version_counts_as_a_connection_attempt() {
        let draft29 = long_header(0xC0, 0xff00_001d);
        let h = parse_long_header(&draft29).unwrap();
        assert_eq!(h.kind, QuicPacketKind::UnknownVersion);
        assert!(is_connection_attempt(&draft29));
    }

    #[test]
    fn version_negotiation_is_server_sent_and_never_an_attempt() {
        let vn = long_header(0xC0, 0);
        assert_eq!(parse_long_header(&vn).unwrap().kind, QuicPacketKind::VersionNegotiation);
        assert!(!is_connection_attempt(&vn));
    }

    #[test]
    fn a_greased_fixed_bit_still_parses() {
        // RFC 9287 lets the 0x40 bit be zero once both ends agreed to grease it.
        let greased = long_header(0x80, VERSION_1);
        assert_eq!(parse_long_header(&greased).unwrap().kind, QuicPacketKind::Initial);
    }

    #[test]
    fn short_headers_and_junk_are_rejected() {
        assert!(parse_long_header(&long_header(0x40, VERSION_1)).is_none()); // short header
        assert!(parse_long_header(&[]).is_none());
        assert!(parse_long_header(&[0xC0, 0x00]).is_none()); // truncated version
        assert!(!is_connection_attempt(b"GET / HTTP/1.1\r\n"));
    }

    #[test]
    fn oversized_connection_ids_are_rejected() {
        let mut p = vec![0xC0];
        p.extend_from_slice(&VERSION_1.to_be_bytes());
        p.push(21); // > MAX_CID_LEN
        p.extend_from_slice(&[0; 32]);
        assert!(parse_long_header(&p).is_none());

        let mut p = vec![0xC0];
        p.extend_from_slice(&VERSION_1.to_be_bytes());
        p.push(4);
        p.extend_from_slice(&[0; 4]);
        p.push(21); // SCID too long
        p.extend_from_slice(&[0; 32]);
        assert!(parse_long_header(&p).is_none());
    }

    #[test]
    fn a_header_cut_off_before_the_source_cid_length_is_rejected() {
        let mut p = vec![0xC0];
        p.extend_from_slice(&VERSION_1.to_be_bytes());
        p.push(8);
        p.extend_from_slice(&[0xab; 8]); // DCID present, SCID length byte missing
        assert!(parse_long_header(&p).is_none());
    }
}
