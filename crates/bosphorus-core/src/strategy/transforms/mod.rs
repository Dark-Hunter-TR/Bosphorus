//! Turn a [`Strategy`](crate::strategy::model::Strategy) + a captured
//! ClientHello into an ordered [`SendBatch`]. Pure: no I/O. Checksum handling is
//! recorded per item ([`ChecksumOp`]) for the engine to apply.

mod fake_packet;
mod fragment;
mod overlap;
mod ttl;

pub use fake_packet::FAKE_HTTPS_REQUEST;
pub use ttl::resolve_ttl;

use crate::error::CoreError;
use crate::packet::{add_padding_extension, PacketBuilder, PacketView};
use crate::source_sink::{CaptureMeta, ChecksumOp, SendBatch};
use crate::strategy::model::{DesyncMethod, SendOrder, Strategy};

pub struct TransformCtx<'a> {
    pub view: &'a PacketView<'a>,
    pub meta: &'a CaptureMeta,
    /// Hops to the server from the SYN-ACK, for `AutoHeuristic` TTL.
    pub hops_to_server: Option<u8>,
    /// This target's measured injector distance, if discovery has one yet
    /// (see [`crate::strategy::model::TtlPolicy::Discovered`]). Substitutes
    /// for an `AutoHeuristic` fake-packet TTL; never for `UserFixed`.
    pub discovered_ttl: Option<u8>,
    /// Cap each emitted segment's TCP payload at this many bytes (MSS).
    pub max_seg: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Disposition {
    /// The batch fully replaces the original packet.
    EmitBatchDropOriginal,
    /// Emit the batch, then also the original packet unchanged.
    EmitBatchThenOriginal,
    /// Do nothing; forward the original.
    PassThrough,
}

/// Build the batch for `strat` against the ClientHello in `ctx`.
pub fn apply_strategy(
    strat: &Strategy,
    ctx: &TransformCtx<'_>,
    out: &mut SendBatch,
) -> Result<Disposition, CoreError> {
    if strat.fake.is_none() && strat.fragment.is_none() && strat.tls_pad.is_none() {
        return Ok(Disposition::PassThrough);
    }

    let meta = *ctx.meta;

    // M7c: apply tls_pad (RFC 7685) before anything else touches the payload,
    // so fake/fragment/overlap all operate on the padded ClientHello. Requires
    // rebuilding the packet (the padded payload no longer fits `ctx.view`'s
    // buffer) and re-parsing it into a fresh view.
    let padded_storage: Option<Vec<u8>> = match strat.tls_pad {
        Some(pad_len) => {
            let padded_payload = add_padding_extension(ctx.view.payload(), pad_len).ok_or(
                CoreError::Parse("tls_pad: not a complete, parseable ClientHello"),
            )?;
            let mut b = PacketBuilder::from_view(ctx.view);
            b.replace_payload(&padded_payload);
            Some(b.into_bytes())
        }
        None => None,
    };
    let raw: &[u8] = padded_storage.as_deref().unwrap_or_else(|| ctx.view.raw());
    let view = PacketView::parse(raw)?;
    let payload = view.payload();

    // --- OverlapDisorder: no separate fake; real segments overlapped + reordered ---
    if let Some(fs) = &strat.fake {
        if let DesyncMethod::OverlapDisorder { seqovl, fill } = fs.desync {
            let frag = strat
                .fragment
                .as_ref()
                .ok_or(CoreError::Parse("overlap disorder needs a fragment split"))?;
            let anchor = *frag
                .anchors
                .first()
                .ok_or(CoreError::Parse("overlap disorder needs a fragment split"))?;
            let split = fragment::resolve_split(anchor, payload)?;
            let [a, b] = overlap::build_overlap_disorder(&view, payload, split, seqovl, fill)?;
            push_capped(out, a, meta, ctx.max_seg, ChecksumOp::Recompute);
            push_capped(out, b, meta, ctx.max_seg, ChecksumOp::Recompute);
            return Ok(Disposition::EmitBatchDropOriginal);
        }
    }

    // --- separate fake + fragment ---
    let mut fakes: Vec<(Vec<u8>, ChecksumOp)> = Vec::new();
    if let Some(fs) = &strat.fake {
        for _ in 0..fs.repeats.max(1) {
            fakes.push(fake_packet::build_fake(fs, &view, ctx.hops_to_server, ctx.discovered_ttl)?);
        }
    }

    let real_parts: Vec<Vec<u8>> = match &strat.fragment {
        Some(fr) => {
            let mut parts = fragment::native_multi_fragment(fr, &view)?;
            if fr.reverse {
                parts.reverse();
            }
            parts
        }
        None => vec![view.raw().to_vec()],
    };

    let emit_fakes = |out: &mut SendBatch| {
        for (bytes, op) in &fakes {
            push_capped(out, bytes.clone(), meta, ctx.max_seg, *op);
        }
    };
    let emit_real = |out: &mut SendBatch| {
        for bytes in &real_parts {
            push_capped(out, bytes.clone(), meta, ctx.max_seg, ChecksumOp::Recompute);
        }
    };

    match strat.order {
        SendOrder::FakeThenReal => {
            emit_fakes(out);
            emit_real(out);
        }
        SendOrder::RealThenFake => {
            emit_real(out);
            emit_fakes(out);
        }
    }

    Ok(Disposition::EmitBatchDropOriginal)
}

/// Push `pkt` into `out`, first splitting it into `<= max_seg`-payload segments
/// (with sequential TCP seqs and fixed IP length) if it is oversized.
fn push_capped(out: &mut SendBatch, pkt: Vec<u8>, meta: CaptureMeta, max_seg: usize, op: ChecksumOp) {
    let Ok(v) = PacketView::parse(&pkt) else {
        out.push_op(pkt, meta, op);
        return;
    };
    if !v.is_tcp() {
        out.push_op(pkt, meta, op);
        return;
    }
    let payload_off = v.payload_offset();
    let plen = pkt.len().saturating_sub(payload_off);
    if plen <= max_seg || max_seg == 0 {
        out.push_op(pkt, meta, op);
        return;
    }
    let base_seq = v.tcp_seq().unwrap_or(0);
    let seq_field = v.l4_header_range().start + 4;
    let header = pkt[..payload_off].to_vec();

    let mut off = 0usize;
    while off < plen {
        let end = (off + max_seg).min(plen);
        let mut seg = header.clone();
        seg.extend_from_slice(&pkt[payload_off + off..payload_off + end]);
        let s = base_seq.wrapping_add(off as u32);
        seg[seq_field..seq_field + 4].copy_from_slice(&s.to_be_bytes());
        fix_ip_len(&mut seg);
        out.push_op(seg, meta, op);
        off = end;
    }
}

fn fix_ip_len(pkt: &mut [u8]) {
    match pkt.first().map(|b| b >> 4) {
        Some(4) if pkt.len() >= 4 => {
            let t = pkt.len() as u16;
            pkt[2..4].copy_from_slice(&t.to_be_bytes());
        }
        Some(6) if pkt.len() >= 40 => {
            let t = (pkt.len() - 40) as u16;
            pkt[4..6].copy_from_slice(&t.to_be_bytes());
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::strategy::model::{
        DesyncMethod, FakePayload, FakeSpec, FragmentSpec, OverlapFill, SendOrder, SplitAnchor,
        Strategy,
    };

    fn clienthello_pkt() -> Vec<u8> {
        let mut p = vec![0x45, 0, 0, 0, 0, 0, 0x40, 0, 64, 6, 0, 0, 10, 0, 0, 1, 5, 6, 7, 8];
        p.extend_from_slice(&[0x30, 0x39, 0x01, 0xbb]);
        p.extend_from_slice(&1_000_000u32.to_be_bytes());
        p.extend_from_slice(&2_000_000u32.to_be_bytes());
        p.extend_from_slice(&[0x50, 0x18, 0xff, 0xff, 0, 0, 0, 0]);
        p.extend_from_slice(&[0x16, 0x03, 0x01, 0x00, 0x0f, 0x01, 0x00, 0x00, 0x0b, 0x03, 0x03]);
        p.extend_from_slice(&[0xAA; 9]);
        let total = p.len() as u16;
        p[2..4].copy_from_slice(&total.to_be_bytes());
        p
    }

    /// A fully-structured ClientHello (session_id/cipher_suites/compression/
    /// extensions all present, `server_name` for `host`), IPv4/TCP-wrapped.
    /// Unlike `big_clienthello_pkt`, this is real enough for
    /// `add_padding_extension`'s structural walk to succeed — needed for the
    /// `tls_pad` tests.
    fn ch_with_sni(host: &str) -> Vec<u8> {
        let h = host.as_bytes();
        let mut ext = Vec::new();
        ext.extend_from_slice(&((3 + h.len()) as u16).to_be_bytes());
        ext.push(0);
        ext.extend_from_slice(&(h.len() as u16).to_be_bytes());
        ext.extend_from_slice(h);
        let mut exts = Vec::new();
        exts.extend_from_slice(&0u16.to_be_bytes());
        exts.extend_from_slice(&(ext.len() as u16).to_be_bytes());
        exts.extend_from_slice(&ext);
        let mut hb = Vec::new();
        hb.extend_from_slice(&[0x03, 0x03]);
        hb.extend_from_slice(&[0x11; 32]);
        hb.push(0);
        hb.extend_from_slice(&2u16.to_be_bytes());
        hb.extend_from_slice(&[0x13, 0x01]);
        hb.push(1);
        hb.push(0);
        hb.extend_from_slice(&(exts.len() as u16).to_be_bytes());
        hb.extend_from_slice(&exts);
        let mut hs = vec![0x01];
        let l = hb.len() as u32;
        hs.extend_from_slice(&[(l >> 16) as u8, (l >> 8) as u8, l as u8]);
        hs.extend_from_slice(&hb);
        let mut tls = vec![0x16, 0x03, 0x01];
        tls.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        tls.extend_from_slice(&hs);
        let mut p = vec![0x45, 0, 0, 0, 0, 0, 0x40, 0, 64, 6, 0, 0, 10, 0, 0, 1, 5, 6, 7, 8];
        p.extend_from_slice(&[0x30, 0x39, 0x01, 0xbb]);
        p.extend_from_slice(&1000u32.to_be_bytes());
        p.extend_from_slice(&[0, 0, 0, 0, 0x50, 0x18, 0xff, 0xff, 0, 0, 0, 0]);
        p.extend_from_slice(&tls);
        let total = p.len() as u16;
        p[2..4].copy_from_slice(&total.to_be_bytes());
        p
    }

    // --- M7c: RFC 7685 tls_pad ---

    #[test]
    fn tls_pad_grows_the_payload_before_fragmenting() {
        let pkt = ch_with_sni("updates.discord.com");
        let view = PacketView::parse(&pkt).unwrap();
        // Ground truth: what `add_padding_extension` alone produces (its own
        // correctness — length fields grown, bytes appended — is covered by
        // `packet::tls`'s tests). Here we only need to know that fragmentation
        // split *exactly this*, not the pre-padding payload.
        let expected_padded = crate::packet::add_padding_extension(view.payload(), 512).unwrap();

        let strat = Strategy {
            fake: None,
            fragment: Some(FragmentSpec::one(SplitAnchor::AbsoluteOffset(2), false)),
            order: SendOrder::FakeThenReal,
            tls_pad: Some(512),
        };
        let meta = CaptureMeta { outbound: true, ..Default::default() };
        let ctx = TransformCtx { view: &view, meta: &meta, hops_to_server: None, discovered_ttl: None, max_seg: 1200 };
        let mut out = SendBatch::new();
        assert_eq!(
            apply_strategy(&strat, &ctx, &mut out).unwrap(),
            Disposition::EmitBatchDropOriginal
        );
        assert_eq!(out.len(), 2, "one split point -> 2 segments, no fake");

        let rebuilt: Vec<u8> = out
            .items
            .iter()
            .flat_map(|i| PacketView::parse(&i.bytes).unwrap().payload().to_vec())
            .collect();
        assert_eq!(
            rebuilt, expected_padded,
            "fragmentation split the already-padded ClientHello, byte for byte"
        );
    }

    #[test]
    fn tls_pad_alone_still_emits_a_batch() {
        let pkt = ch_with_sni("updates.discord.com");
        let view = PacketView::parse(&pkt).unwrap();
        let orig_len = view.payload().len();

        let strat =
            Strategy { fake: None, fragment: None, order: SendOrder::FakeThenReal, tls_pad: Some(512) };
        let meta = CaptureMeta { outbound: true, ..Default::default() };
        let ctx = TransformCtx { view: &view, meta: &meta, hops_to_server: None, discovered_ttl: None, max_seg: 1200 };
        let mut out = SendBatch::new();
        assert_eq!(
            apply_strategy(&strat, &ctx, &mut out).unwrap(),
            Disposition::EmitBatchDropOriginal
        );
        assert_eq!(out.len(), 1);
        assert_eq!(PacketView::parse(&out.items[0].bytes).unwrap().payload().len(), orig_len + 4 + 512);
    }

    #[test]
    fn tls_pad_composes_with_fake_and_fragment() {
        let pkt = ch_with_sni("updates.discord.com");
        let view = PacketView::parse(&pkt).unwrap();
        let orig_len = view.payload().len();

        let strat = Strategy {
            fake: Some(FakeSpec {
                desync: DesyncMethod::WrongSeq { seq_delta: -1, ack_delta: -2 },
                ttl: None,
                payload: FakePayload::StaticClientHello,
                repeats: 1,
            }),
            fragment: Some(FragmentSpec::one(SplitAnchor::SniStart, false)),
            order: SendOrder::FakeThenReal,
            tls_pad: Some(512),
        };
        let meta = CaptureMeta { outbound: true, ..Default::default() };
        let ctx = TransformCtx { view: &view, meta: &meta, hops_to_server: Some(10), discovered_ttl: None, max_seg: 1200 };
        let mut out = SendBatch::new();
        apply_strategy(&strat, &ctx, &mut out).unwrap();
        assert_eq!(out.len(), 3, "fake + 2 real segments");

        // The real segments (everything after the fake) reassemble to the
        // PADDED payload.
        let real: Vec<u8> = out.items[1..]
            .iter()
            .flat_map(|i| PacketView::parse(&i.bytes).unwrap().payload().to_vec())
            .collect();
        assert_eq!(real.len(), orig_len + 4 + 512);
    }

    #[test]
    fn tls_pad_errors_cleanly_on_an_unparseable_clienthello() {
        // `big_clienthello_pkt` has no real TLS structure past the record
        // header — `add_padding_extension` must refuse it, not panic or guess.
        let pkt = big_clienthello_pkt(300);
        let view = PacketView::parse(&pkt).unwrap();
        let strat = Strategy {
            fake: None,
            fragment: Some(FragmentSpec::one(SplitAnchor::AbsoluteOffset(2), false)),
            order: SendOrder::FakeThenReal,
            tls_pad: Some(512),
        };
        let meta = CaptureMeta { outbound: true, ..Default::default() };
        let ctx = TransformCtx { view: &view, meta: &meta, hops_to_server: None, discovered_ttl: None, max_seg: 1200 };
        assert!(apply_strategy(&strat, &ctx, &mut SendBatch::new()).is_err());
    }

    #[test]
    fn m4_fixed_produces_fake_then_two_segments() {
        let pkt = clienthello_pkt();
        let view = PacketView::parse(&pkt).unwrap();
        let seq = view.tcp_seq().unwrap();
        let payload = view.payload().to_vec();

        let meta = CaptureMeta { outbound: true, ..Default::default() };
        let ctx = TransformCtx { view: &view, meta: &meta, hops_to_server: Some(11), discovered_ttl: None, max_seg: 1200 };
        let mut out = SendBatch::new();
        let disp = apply_strategy(&Strategy::m4_fixed(), &ctx, &mut out).unwrap();

        assert_eq!(disp, Disposition::EmitBatchDropOriginal);
        assert_eq!(out.len(), 3);
        assert_eq!(out.items[0].checksum, ChecksumOp::Recompute);
        let f = PacketView::parse(&out.items[0].bytes).unwrap();
        assert_eq!(f.payload(), FAKE_HTTPS_REQUEST);
        assert_eq!(f.tcp_seq(), Some(seq.wrapping_sub(10_000)));
        let s0 = PacketView::parse(&out.items[1].bytes).unwrap();
        let s1 = PacketView::parse(&out.items[2].bytes).unwrap();
        assert_eq!([s0.payload(), s1.payload()].concat(), payload);
    }

    fn big_clienthello_pkt(payload_len: usize) -> Vec<u8> {
        let mut p = vec![0x45, 0, 0, 0, 0, 0, 0x40, 0, 64, 6, 0, 0, 10, 0, 0, 1, 5, 6, 7, 8];
        p.extend_from_slice(&[0x30, 0x39, 0x01, 0xbb]);
        p.extend_from_slice(&1_000u32.to_be_bytes());
        p.extend_from_slice(&[0, 0, 0, 0, 0x50, 0x18, 0xff, 0xff, 0, 0, 0, 0]);
        p.extend_from_slice(&[0x16, 0x03, 0x01]);
        p.extend_from_slice(&((payload_len - 5) as u16).to_be_bytes());
        p.push(0x01); // ClientHello handshake type
        for i in 0..payload_len - 6 {
            p.push((i % 251) as u8);
        }
        let total = p.len() as u16;
        p[2..4].copy_from_slice(&total.to_be_bytes());
        p
    }

    #[test]
    fn overlap_disorder_produces_two_segments_disorder_order() {
        let pkt = big_clienthello_pkt(400);
        let view = PacketView::parse(&pkt).unwrap();
        let payload = view.payload().to_vec();
        let seq = view.tcp_seq().unwrap();

        let strat = Strategy {
            fake: Some(FakeSpec {
                desync: DesyncMethod::OverlapDisorder { seqovl: 16, fill: OverlapFill::Zeros },
                ttl: None,
                payload: FakePayload::StaticClientHello,
                repeats: 1,
            }),
            fragment: Some(FragmentSpec::one(SplitAnchor::AbsoluteOffset(30), true)),
            order: SendOrder::FakeThenReal,
            tls_pad: None,
        };
        let meta = CaptureMeta { outbound: true, ..Default::default() };
        let ctx = TransformCtx { view: &view, meta: &meta, hops_to_server: None, discovered_ttl: None, max_seg: 1200 };
        let mut out = SendBatch::new();
        assert_eq!(
            apply_strategy(&strat, &ctx, &mut out).unwrap(),
            Disposition::EmitBatchDropOriginal
        );
        assert_eq!(out.len(), 2);

        let a = PacketView::parse(&out.items[0].bytes).unwrap(); // sent first
        let b = PacketView::parse(&out.items[1].bytes).unwrap();
        assert_eq!(&a.payload()[..16], &[0u8; 16]); // fill
        assert_eq!(&a.payload()[16..], &payload[30..]);
        assert_eq!(a.tcp_seq(), Some(seq + 30 - 16));
        assert_eq!(b.payload(), &payload[..30]);
        assert_eq!(b.tcp_seq(), Some(seq));
    }

    #[test]
    fn multi_fragment_strategy_emits_n_plus_one_segments() {
        let pkt = big_clienthello_pkt(300);
        let view = PacketView::parse(&pkt).unwrap();
        let payload = view.payload().to_vec();
        let seq = view.tcp_seq().unwrap();

        let strat = Strategy {
            fake: None,
            fragment: Some(FragmentSpec {
                anchors: vec![
                    SplitAnchor::AbsoluteOffset(3),
                    SplitAnchor::AbsoluteOffset(40),
                    SplitAnchor::AbsoluteOffset(120),
                ],
                reverse: false,
            }),
            order: SendOrder::FakeThenReal,
            tls_pad: None,
        };
        let meta = CaptureMeta { outbound: true, ..Default::default() };
        let ctx = TransformCtx { view: &view, meta: &meta, hops_to_server: None, discovered_ttl: None, max_seg: 1200 };
        let mut out = SendBatch::new();
        apply_strategy(&strat, &ctx, &mut out).unwrap();

        assert_eq!(out.len(), 4, "3 cut points -> 4 segments");
        let mut expect_seq = seq;
        let mut rebuilt = Vec::new();
        for it in &out.items {
            let v = PacketView::parse(&it.bytes).unwrap();
            assert_eq!(v.tcp_seq(), Some(expect_seq));
            expect_seq = expect_seq.wrapping_add(v.payload().len() as u32);
            rebuilt.extend_from_slice(v.payload());
        }
        assert_eq!(rebuilt, payload);
    }

    #[test]
    fn reverse_multi_fragment_sends_last_segment_first() {
        let pkt = big_clienthello_pkt(200);
        let view = PacketView::parse(&pkt).unwrap();
        let payload = view.payload().to_vec();

        let strat = Strategy {
            fake: None,
            fragment: Some(FragmentSpec {
                anchors: vec![SplitAnchor::AbsoluteOffset(10), SplitAnchor::AbsoluteOffset(50)],
                reverse: true,
            }),
            order: SendOrder::FakeThenReal,
            tls_pad: None,
        };
        let meta = CaptureMeta { outbound: true, ..Default::default() };
        let ctx = TransformCtx { view: &view, meta: &meta, hops_to_server: None, discovered_ttl: None, max_seg: 1200 };
        let mut out = SendBatch::new();
        apply_strategy(&strat, &ctx, &mut out).unwrap();

        assert_eq!(out.len(), 3);
        // First on the wire is the logically-last segment: payload[50..].
        assert_eq!(PacketView::parse(&out.items[0].bytes).unwrap().payload(), &payload[50..]);
        assert_eq!(PacketView::parse(&out.items[2].bytes).unwrap().payload(), &payload[..10]);
    }

    #[test]
    fn overlap_disorder_without_fragment_errors() {
        let pkt = big_clienthello_pkt(200);
        let view = PacketView::parse(&pkt).unwrap();
        let strat = Strategy {
            fake: Some(FakeSpec {
                desync: DesyncMethod::OverlapDisorder { seqovl: 8, fill: OverlapFill::Zeros },
                ttl: None,
                payload: FakePayload::StaticClientHello,
                repeats: 1,
            }),
            fragment: None,
            order: SendOrder::FakeThenReal,
            tls_pad: None,
        };
        let meta = CaptureMeta::default();
        let ctx = TransformCtx { view: &view, meta: &meta, hops_to_server: None, discovered_ttl: None, max_seg: 1200 };
        assert!(apply_strategy(&strat, &ctx, &mut SendBatch::new()).is_err());
    }

    #[test]
    fn push_capped_splits_oversized_segments() {
        // A ClientHello with a 3000-byte payload, capped at 1200.
        let pkt = big_clienthello_pkt(3000);
        let view = PacketView::parse(&pkt).unwrap();
        let payload = view.payload().to_vec();
        let seq = view.tcp_seq().unwrap();

        // No fake, single "fragment" at offset 1 -> real path -> push_capped.
        let strat = Strategy {
            fake: None,
            fragment: Some(FragmentSpec::one(SplitAnchor::AbsoluteOffset(1), false)),
            order: crate::strategy::model::SendOrder::FakeThenReal,
            tls_pad: None,
        };
        let meta = CaptureMeta { outbound: true, ..Default::default() };
        let ctx = TransformCtx { view: &view, meta: &meta, hops_to_server: None, discovered_ttl: None, max_seg: 1200 };
        let mut out = SendBatch::new();
        apply_strategy(&strat, &ctx, &mut out).unwrap();

        // Every emitted segment's TCP payload <= 1200.
        let mut rebuilt = Vec::new();
        let mut expect_seq = seq;
        for it in &out.items {
            let v = PacketView::parse(&it.bytes).unwrap();
            assert!(v.payload().len() <= 1200);
            assert_eq!(v.tcp_seq(), Some(expect_seq));
            expect_seq = expect_seq.wrapping_add(v.payload().len() as u32);
            rebuilt.extend_from_slice(v.payload());
            assert_eq!(u16::from_be_bytes([it.bytes[2], it.bytes[3]]), it.bytes.len() as u16);
        }
        assert_eq!(rebuilt, payload);
        assert!(out.len() >= 3);
    }
}
