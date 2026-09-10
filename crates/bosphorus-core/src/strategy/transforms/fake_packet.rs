use crate::error::CoreError;
use crate::packet::{add_padding_extension, PacketBuilder, PacketView};
use crate::source_sink::ChecksumOp;
use crate::strategy::model::{FakePayload, FakeSpec, TtlPolicy};
use crate::strategy::transforms::ttl::resolve_ttl;

/// GoodbyeDPI's static fake TLS ClientHello, verbatim from
/// `src/fakepackets.c` (`fake_https_request[]`, 517 bytes: 5-byte record header
/// + 512-byte body). SNI = `www.w3.org`.
pub const FAKE_HTTPS_REQUEST: &[u8] = &[
    0x16, 0x03, 0x01, 0x02, 0x00, 0x01, 0x00, 0x01, 0xfc, 0x03, 0x03, 0x9a, 0x8f, 0xa7, 0x6a, 0x5d,
    0x57, 0xf3, 0x62, 0x19, 0xbe, 0x46, 0x82, 0x45, 0xe2, 0x59, 0x5c, 0xb4, 0x48, 0x31, 0x12, 0x15,
    0x14, 0x79, 0x2c, 0xaa, 0xcd, 0xea, 0xda, 0xf0, 0xe1, 0xfd, 0xbb, 0x20, 0xf4, 0x83, 0x2a, 0x94,
    0xf1, 0x48, 0x3b, 0x9d, 0xb6, 0x74, 0xba, 0x3c, 0x81, 0x63, 0xbc, 0x18, 0xcc, 0x14, 0x45, 0x57,
    0x6c, 0x80, 0xf9, 0x25, 0xcf, 0x9c, 0x86, 0x60, 0x50, 0x31, 0x2e, 0xe9, 0x00, 0x22, 0x13, 0x01,
    0x13, 0x03, 0x13, 0x02, 0xc0, 0x2b, 0xc0, 0x2f, 0xcc, 0xa9, 0xcc, 0xa8, 0xc0, 0x2c, 0xc0, 0x30,
    0xc0, 0x0a, 0xc0, 0x09, 0xc0, 0x13, 0xc0, 0x14, 0x00, 0x33, 0x00, 0x39, 0x00, 0x2f, 0x00, 0x35,
    0x01, 0x00, 0x01, 0x91, 0x00, 0x00, 0x00, 0x0f, 0x00, 0x0d, 0x00, 0x00, 0x0a, 0x77, 0x77, 0x77,
    0x2e, 0x77, 0x33, 0x2e, 0x6f, 0x72, 0x67, 0x00, 0x17, 0x00, 0x00, 0xff, 0x01, 0x00, 0x01, 0x00,
    0x00, 0x0a, 0x00, 0x0e, 0x00, 0x0c, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x18, 0x00, 0x19, 0x01, 0x00,
    0x01, 0x01, 0x00, 0x0b, 0x00, 0x02, 0x01, 0x00, 0x00, 0x23, 0x00, 0x00, 0x00, 0x10, 0x00, 0x0e,
    0x00, 0x0c, 0x02, 0x68, 0x32, 0x08, 0x68, 0x74, 0x74, 0x70, 0x2f, 0x31, 0x2e, 0x31, 0x00, 0x05,
    0x00, 0x05, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x33, 0x00, 0x6b, 0x00, 0x69, 0x00, 0x1d, 0x00,
    0x20, 0xb0, 0xe4, 0xda, 0x34, 0xb4, 0x29, 0x8d, 0xd3, 0x5c, 0x70, 0xd3, 0xbe, 0xe8, 0xa7, 0x2a,
    0x6b, 0xe4, 0x11, 0x19, 0x8b, 0x18, 0x9d, 0x83, 0x9a, 0x49, 0x7c, 0x83, 0x7f, 0xa9, 0x03, 0x8c,
    0x3c, 0x00, 0x17, 0x00, 0x41, 0x04, 0x4c, 0x04, 0xa4, 0x71, 0x4c, 0x49, 0x75, 0x55, 0xd1, 0x18,
    0x1e, 0x22, 0x62, 0x19, 0x53, 0x00, 0xde, 0x74, 0x2f, 0xb3, 0xde, 0x13, 0x54, 0xe6, 0x78, 0x07,
    0x94, 0x55, 0x0e, 0xb2, 0x6c, 0xb0, 0x03, 0xee, 0x79, 0xa9, 0x96, 0x1e, 0x0e, 0x98, 0x17, 0x78,
    0x24, 0x44, 0x0c, 0x88, 0x80, 0x06, 0x8b, 0xd4, 0x80, 0xbf, 0x67, 0x7c, 0x37, 0x6a, 0x5b, 0x46,
    0x4c, 0xa7, 0x98, 0x6f, 0xb9, 0x22, 0x00, 0x2b, 0x00, 0x09, 0x08, 0x03, 0x04, 0x03, 0x03, 0x03,
    0x02, 0x03, 0x01, 0x00, 0x0d, 0x00, 0x18, 0x00, 0x16, 0x04, 0x03, 0x05, 0x03, 0x06, 0x03, 0x08,
    0x04, 0x08, 0x05, 0x08, 0x06, 0x04, 0x01, 0x05, 0x01, 0x06, 0x01, 0x02, 0x03, 0x02, 0x01, 0x00,
    0x2d, 0x00, 0x02, 0x01, 0x01, 0x00, 0x1c, 0x00, 0x02, 0x40, 0x01, 0x00, 0x15, 0x00, 0x96, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00,
];

/// Extra RFC 7685 padding added on top of `FAKE_HTTPS_REQUEST`'s own for
/// [`FakePayload::AggressiveClientHello`] (user-requested, "daha agresif" —
/// bigger padding to push the fake further past a DPI's reassembly buffer).
pub const AGGRESSIVE_PAD_EXTRA: u16 = 2048;

/// `FAKE_HTTPS_REQUEST` with `AGGRESSIVE_PAD_EXTRA` extra zero bytes appended
/// as a second `padding` extension. Hand-built at call time from the verbatim
/// GoodbyeDPI base via `add_padding_extension` (the same RFC 7685 helper M7c
/// uses on the real ClientHello) — **not** copied from a third-party source;
/// the user explicitly waived the verbatim-source rule for this one variant,
/// `FAKE_HTTPS_REQUEST` itself stays untouched and byte-for-byte GoodbyeDPI.
fn aggressive_fake_https_request() -> Option<Vec<u8>> {
    add_padding_extension(FAKE_HTTPS_REQUEST, AGGRESSIVE_PAD_EXTRA)
}

fn add_delta(v: u32, d: i32) -> u32 {
    if d >= 0 {
        v.wrapping_add(d as u32)
    } else {
        v.wrapping_sub(d.unsigned_abs())
    }
}

/// Build one fake packet from `orig` (an outbound ClientHello). Returns the
/// packet bytes and the checksum handling the engine must apply.
///
/// `discovered_ttl` is the target's measured injector distance (see
/// [`TtlPolicy::Discovered`]), if this target has one yet. It substitutes for
/// an `AutoHeuristic` policy — a real measurement beats the blind guess — but
/// never for `UserFixed`, which is an explicit override and always wins.
pub fn build_fake(
    spec: &FakeSpec,
    orig: &PacketView<'_>,
    hops_to_server: Option<u8>,
    discovered_ttl: Option<u8>,
) -> Result<(Vec<u8>, ChecksumOp), CoreError> {
    let payload: Vec<u8> = match spec.payload {
        FakePayload::StaticClientHello => FAKE_HTTPS_REQUEST.to_vec(),
        FakePayload::AggressiveClientHello => aggressive_fake_https_request()
            .ok_or(CoreError::Parse("aggressive fake: failed to pad FAKE_HTTPS_REQUEST"))?,
    };

    let mut b = PacketBuilder::from_view(orig);
    b.replace_payload(&payload);

    let parts = spec
        .desync
        .parts()
        .ok_or(CoreError::Parse("build_fake called for a non-fake desync method"))?;

    if let Some((seq_delta, ack_delta)) = parts.seq_shift {
        let seq = orig.tcp_seq().ok_or(CoreError::Parse("fake: not a TCP packet"))?;
        let ack = orig.tcp_ack().ok_or(CoreError::Parse("fake: not a TCP packet"))?;
        b.set_tcp_seq(add_delta(seq, seq_delta))?;
        b.set_tcp_ack(add_delta(ack, ack_delta))?;
    }

    if parts.set_ttl {
        let policy = spec.ttl.ok_or(CoreError::Parse("fake: TtlLimited needs a ttl policy"))?;
        let policy = match (policy, discovered_ttl) {
            (TtlPolicy::AutoHeuristic { .. }, Some(measured)) => TtlPolicy::Discovered(measured),
            _ => policy,
        };
        let ttl = resolve_ttl(&policy, hops_to_server)
            .ok_or(CoreError::Parse("fake: ttl policy unresolved (no SYN-ACK hop count yet)"))?;
        b.set_ttl(ttl);
    }

    let op = if parts.break_cksum {
        ChecksumOp::RecomputeThenBreakTcp
    } else {
        ChecksumOp::Recompute
    };
    Ok((b.into_bytes(), op))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::strategy::model::{DesyncMethod, FakePayload, FakeSpec, SEQ_DELTA, ACK_DELTA, TtlPolicy};

    fn clienthello_pkt(seq: u32, ack: u32, ttl: u8) -> Vec<u8> {
        let mut p = vec![0x45, 0, 0, 0, 0, 0, 0x40, 0, ttl, 6, 0, 0, 10, 0, 0, 1, 5, 6, 7, 8];
        p.extend_from_slice(&[0x30, 0x39, 0x01, 0xbb]);
        p.extend_from_slice(&seq.to_be_bytes());
        p.extend_from_slice(&ack.to_be_bytes());
        p.extend_from_slice(&[0x50, 0x18, 0xff, 0xff, 0, 0, 0, 0]);
        p.extend_from_slice(&[0x16, 0x03, 0x01, 0x00, 0x30, 0x01]);
        let total = p.len() as u16;
        p[2..4].copy_from_slice(&total.to_be_bytes());
        p
    }

    fn spec(desync: DesyncMethod, ttl: Option<TtlPolicy>) -> FakeSpec {
        FakeSpec { desync, ttl, payload: FakePayload::StaticClientHello, repeats: 1 }
    }

    #[test]
    fn fake_array_is_517_bytes_and_well_formed() {
        assert_eq!(FAKE_HTTPS_REQUEST.len(), 517);
        let rec_len = u16::from_be_bytes([FAKE_HTTPS_REQUEST[3], FAKE_HTTPS_REQUEST[4]]);
        assert_eq!(rec_len as usize + 5, FAKE_HTTPS_REQUEST.len());
    }

    #[test]
    fn aggressive_fake_is_padded_and_still_well_formed() {
        let padded = aggressive_fake_https_request().expect("FAKE_HTTPS_REQUEST pads cleanly");
        assert_eq!(padded.len(), FAKE_HTTPS_REQUEST.len() + 4 + AGGRESSIVE_PAD_EXTRA as usize);
        let rec_len = u16::from_be_bytes([padded[3], padded[4]]);
        assert_eq!(rec_len as usize + 5, padded.len(), "record-length field grown to match");
        // Original bytes preceding the new extension are untouched except the
        // three length fields `add_padding_extension` legitimately rewrites.
        assert_eq!(&padded[9..11], &FAKE_HTTPS_REQUEST[9..11], "client_version unchanged");
        assert_eq!(
            &padded[FAKE_HTTPS_REQUEST.len()..FAKE_HTTPS_REQUEST.len() + 2],
            &0x0015u16.to_be_bytes(),
            "new extension type = padding (RFC 7685)"
        );
    }

    #[test]
    fn aggressive_fake_used_end_to_end_in_build_fake() {
        let v = clienthello_pkt(1_000_000, 2_000_000, 64);
        let v = PacketView::parse(&v).unwrap();
        let s = FakeSpec {
            desync: DesyncMethod::WrongSeq { seq_delta: SEQ_DELTA, ack_delta: ACK_DELTA },
            ttl: None,
            payload: FakePayload::AggressiveClientHello,
            repeats: 1,
        };
        let (fake, op) = build_fake(&s, &v, None, None).unwrap();
        let fv = PacketView::parse(&fake).unwrap();
        assert_eq!(fv.payload().len(), FAKE_HTTPS_REQUEST.len() + 4 + AGGRESSIVE_PAD_EXTRA as usize);
        assert_eq!(fv.tcp_seq(), Some(1_000_000 - 10_000));
        assert_eq!(op, ChecksumOp::Recompute);
    }

    #[test]
    fn wrong_seq() {
        let v = clienthello_pkt(1_000_000, 2_000_000, 64);
        let v = PacketView::parse(&v).unwrap();
        let (fake, op) = build_fake(
            &spec(DesyncMethod::WrongSeq { seq_delta: SEQ_DELTA, ack_delta: ACK_DELTA }, None),
            &v,
            None,
            None,
        )
        .unwrap();
        let fv = PacketView::parse(&fake).unwrap();
        assert_eq!(fv.payload(), FAKE_HTTPS_REQUEST);
        assert_eq!(fv.tcp_seq(), Some(1_000_000 - 10_000));
        assert_eq!(fv.tcp_ack(), Some(2_000_000 - 66_000));
        assert_eq!(fv.ttl(), 64); // unchanged
        assert_eq!(op, ChecksumOp::Recompute);
    }

    #[test]
    fn wrong_checksum_flags_break_op() {
        let v = clienthello_pkt(1, 1, 64);
        let v = PacketView::parse(&v).unwrap();
        let (fake, op) = build_fake(&spec(DesyncMethod::WrongChecksum, None), &v, None, None).unwrap();
        let fv = PacketView::parse(&fake).unwrap();
        assert_eq!(fv.tcp_seq(), Some(1)); // no shift
        assert_eq!(op, ChecksumOp::RecomputeThenBreakTcp);
    }

    #[test]
    fn ttl_limited_sets_ttl_from_hops() {
        let v = clienthello_pkt(1, 1, 64);
        let v = PacketView::parse(&v).unwrap();
        let p = TtlPolicy::AutoHeuristic { delta: 4, min: 3, max: 10 };
        let (fake, op) = build_fake(&spec(DesyncMethod::TtlLimited, Some(p)), &v, Some(11), None).unwrap();
        let fv = PacketView::parse(&fake).unwrap();
        assert_eq!(fv.ttl(), 7); // 11 - 4
        assert_eq!(op, ChecksumOp::Recompute);
    }

    #[test]
    fn ttl_limited_without_hops_errors_not_panics() {
        let v = clienthello_pkt(1, 1, 64);
        let v = PacketView::parse(&v).unwrap();
        let p = TtlPolicy::AutoHeuristic { delta: 4, min: 3, max: 10 };
        assert!(build_fake(&spec(DesyncMethod::TtlLimited, Some(p)), &v, None, None).is_err());
    }

    #[test]
    fn discovered_ttl_overrides_the_auto_heuristic() {
        let v = clienthello_pkt(1, 1, 64);
        let v = PacketView::parse(&v).unwrap();
        let p = TtlPolicy::AutoHeuristic { delta: 4, min: 3, max: 10 };
        // Heuristic alone: 11 - 4 = 7.
        let (fake, _) = build_fake(&spec(DesyncMethod::TtlLimited, Some(p)), &v, Some(11), None).unwrap();
        assert_eq!(PacketView::parse(&fake).unwrap().ttl(), 7);
        // A measured injector distance of 2 hops wins outright — no delta, no
        // dependence on `hops_to_server` at all (irrelevant here, still Some(11)).
        let (fake, _) =
            build_fake(&spec(DesyncMethod::TtlLimited, Some(p)), &v, Some(11), Some(2)).unwrap();
        assert_eq!(PacketView::parse(&fake).unwrap().ttl(), 2);
        // Even with no hop count at all, a measured value alone is enough.
        let (fake, _) =
            build_fake(&spec(DesyncMethod::TtlLimited, Some(p)), &v, None, Some(2)).unwrap();
        assert_eq!(PacketView::parse(&fake).unwrap().ttl(), 2);
    }

    #[test]
    fn discovered_ttl_never_overrides_a_user_fixed_policy() {
        let v = clienthello_pkt(1, 1, 64);
        let v = PacketView::parse(&v).unwrap();
        let p = TtlPolicy::UserFixed(9);
        let (fake, _) =
            build_fake(&spec(DesyncMethod::TtlLimited, Some(p)), &v, Some(11), Some(2)).unwrap();
        assert_eq!(PacketView::parse(&fake).unwrap().ttl(), 9, "explicit override always wins");
    }

    #[test]
    fn seq_plus_ttl_and_cksum_plus_ttl() {
        let v = clienthello_pkt(500_000, 900_000, 128);
        let v = PacketView::parse(&v).unwrap();
        let p = TtlPolicy::UserFixed(5);

        let (f1, o1) = build_fake(
            &spec(DesyncMethod::SeqPlusTtl { seq_delta: SEQ_DELTA, ack_delta: ACK_DELTA }, Some(p)),
            &v,
            None,
            None,
        )
        .unwrap();
        let v1 = PacketView::parse(&f1).unwrap();
        assert_eq!(v1.tcp_seq(), Some(500_000 - 10_000));
        assert_eq!(v1.ttl(), 5);
        assert_eq!(o1, ChecksumOp::Recompute);

        let (_f2, o2) = build_fake(&spec(DesyncMethod::ChecksumPlusTtl, Some(p)), &v, None, None).unwrap();
        assert_eq!(o2, ChecksumOp::RecomputeThenBreakTcp);
    }
}
