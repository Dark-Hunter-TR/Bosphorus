//! `OverlapDisorder` (zapret `disorder` + `seqovl`): no separate fake packet —
//! the logically-second segment is sent first with a `seqovl`-byte junk prefix
//! and a lowered sequence number, then the first segment overwrites that prefix.
//! A last-received-wins server reassembles the real bytes; a DPI that extracts
//! the SNI eagerly (or resolves the overlap first-wins) sees corrupted bytes at
//! the record boundary.

use crate::error::CoreError;
use crate::packet::{PacketBuilder, PacketView};
use crate::strategy::model::OverlapFill;

pub(crate) fn fill_bytes(fill: OverlapFill, n: usize) -> Vec<u8> {
    match fill {
        OverlapFill::Zeros => vec![0u8; n],
        OverlapFill::JunkByte(b) => vec![b; n],
    }
}

/// `payload` is the (possibly tls-padded) ClientHello bytes; `split` is the
/// resolved byte offset. Returns `[seg_A, seg_B]` already in disorder order:
///
/// * `seg_A` (send first):  seq = orig_seq + split - seqovl,  payload = fill(seqovl) ++ payload[split..]
/// * `seg_B` (send second): seq = orig_seq,                   payload = payload[..split]
///
/// Constraint: `0 < seqovl < split < payload.len()`.
pub(crate) fn build_overlap_disorder(
    orig: &PacketView<'_>,
    payload: &[u8],
    split: usize,
    seqovl: u16,
    fill: OverlapFill,
) -> Result<[Vec<u8>; 2], CoreError> {
    let seqovl = seqovl as usize;
    if seqovl == 0 || seqovl >= split || split >= payload.len() {
        return Err(CoreError::Parse(
            "overlap disorder: need 0 < seqovl < split < payload length",
        ));
    }
    let orig_seq = orig
        .tcp_seq()
        .ok_or(CoreError::Parse("overlap disorder: not a TCP packet"))?;

    let mut a_payload = fill_bytes(fill, seqovl);
    a_payload.extend_from_slice(&payload[split..]);
    let mut a = PacketBuilder::from_view(orig);
    a.replace_payload(&a_payload)
        .set_tcp_seq(orig_seq.wrapping_add((split - seqovl) as u32))?;

    let mut b = PacketBuilder::from_view(orig);
    b.replace_payload(&payload[..split]); // seq unchanged

    Ok([a.into_bytes(), b.into_bytes()])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::strategy::model::OverlapFill;

    fn tcp_pkt(seq: u32, payload: &[u8]) -> Vec<u8> {
        let mut p = vec![0x45, 0, 0, 0, 0, 0, 0x40, 0, 64, 6, 0, 0, 10, 0, 0, 1, 5, 6, 7, 8];
        p.extend_from_slice(&[0x30, 0x39, 0x01, 0xbb]);
        p.extend_from_slice(&seq.to_be_bytes());
        p.extend_from_slice(&[0, 0, 0, 0, 0x50, 0x18, 0xff, 0xff, 0, 0, 0, 0]);
        p.extend_from_slice(payload);
        let total = p.len() as u16;
        p[2..4].copy_from_slice(&total.to_be_bytes());
        p
    }

    #[test]
    fn seg_layout_and_seqs() {
        let seq = 100_000u32;
        // payload: 0..40, split at 20, seqovl 8
        let payload: Vec<u8> = (0u8..40).collect();
        let pkt = tcp_pkt(seq, &payload);
        let v = PacketView::parse(&pkt).unwrap();

        let [a, b] = build_overlap_disorder(&v, &payload, 20, 8, OverlapFill::JunkByte(0xEE)).unwrap();
        let pa = PacketView::parse(&a).unwrap();
        let pb = PacketView::parse(&b).unwrap();

        // seg_A: 8 x 0xEE  ++  payload[20..40]
        assert_eq!(&pa.payload()[..8], &[0xEE; 8]);
        assert_eq!(&pa.payload()[8..], &payload[20..]);
        assert_eq!(pa.tcp_seq(), Some(seq + 20 - 8));

        // seg_B: payload[..20], seq unchanged
        assert_eq!(pb.payload(), &payload[..20]);
        assert_eq!(pb.tcp_seq(), Some(seq));

        // IP total lengths consistent
        assert_eq!(u16::from_be_bytes([a[2], a[3]]), a.len() as u16);
        assert_eq!(u16::from_be_bytes([b[2], b[3]]), b.len() as u16);
    }

    #[test]
    fn last_wins_reassembly_yields_original() {
        // Simulate a last-received-wins server: lay seg_A, then overwrite its
        // range with seg_B where they overlap.
        let seq = 0u32;
        let payload: Vec<u8> = (0u8..50).collect();
        let pkt = tcp_pkt(seq, &payload);
        let v = PacketView::parse(&pkt).unwrap();
        let split = 30;
        let seqovl = 12u16;

        let [a, b] = build_overlap_disorder(&v, &payload, split, seqovl, OverlapFill::Zeros).unwrap();
        let pa = PacketView::parse(&a).unwrap();
        let pb = PacketView::parse(&b).unwrap();

        let mut stream = vec![0u8; payload.len()];
        // seg_A covers [split-seqovl .. payload.len())
        let a_start = split - seqovl as usize;
        stream[a_start..].copy_from_slice(pa.payload());
        // seg_B arrives later, overwrites [0 .. split)
        stream[..split].copy_from_slice(pb.payload());

        assert_eq!(stream, payload, "last-wins reassembly reconstructs the real payload");
    }

    #[test]
    fn rejects_bad_constraints() {
        let payload: Vec<u8> = (0u8..20).collect();
        let pkt = tcp_pkt(1, &payload);
        let v = PacketView::parse(&pkt).unwrap();
        assert!(build_overlap_disorder(&v, &payload, 10, 0, OverlapFill::Zeros).is_err()); // seqovl 0
        assert!(build_overlap_disorder(&v, &payload, 10, 10, OverlapFill::Zeros).is_err()); // seqovl == split
        assert!(build_overlap_disorder(&v, &payload, 20, 8, OverlapFill::Zeros).is_err()); // split == len
    }
}
