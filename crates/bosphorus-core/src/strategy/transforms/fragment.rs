use crate::error::CoreError;
use crate::packet::{find_sni, PacketBuilder, PacketView};
use crate::strategy::model::{FragmentSpec, SplitAnchor};

pub(crate) fn resolve_split(anchor: SplitAnchor, payload: &[u8]) -> Result<usize, CoreError> {
    match anchor {
        SplitAnchor::AbsoluteOffset(n) => Ok(n as usize),
        SplitAnchor::TlsRecordStart => Ok(5), // after the 5-byte TLS record header
        SplitAnchor::SniStart => find_sni(payload)
            .map(|l| l.host.start)
            .ok_or(CoreError::Parse("fragment: no SNI in ClientHello")),
        SplitAnchor::SniMiddle => find_sni(payload)
            .map(|l| l.host.start + l.host.len() / 2)
            .ok_or(CoreError::Parse("fragment: no SNI in ClientHello")),
    }
}

/// Resolve `spec.anchors` to a sorted, deduped list of cut offsets, each strictly
/// inside `(0, payload.len())`.
fn resolve_cuts(spec: &FragmentSpec, payload: &[u8]) -> Result<Vec<usize>, CoreError> {
    if spec.anchors.is_empty() {
        return Err(CoreError::Parse("fragment: no split anchors"));
    }
    let mut cuts: Vec<usize> = spec
        .anchors
        .iter()
        .map(|a| resolve_split(*a, payload))
        .collect::<Result<_, _>>()?;
    cuts.sort_unstable();
    cuts.dedup();
    if cuts.first().is_some_and(|&c| c == 0) || cuts.last().is_some_and(|&c| c >= payload.len()) {
        return Err(CoreError::Parse("fragment: split offset outside payload"));
    }
    Ok(cuts)
}

/// Split an outbound TCP packet into `cuts.len() + 1` real segments (GoodbyeDPI
/// `--native-frag`, generalised to N cut points). Segment `k` carries
/// `payload[cut[k-1]..cut[k]]` with `seq = orig_seq + cut[k-1]`. Window size is
/// left alone; checksums are stale for the engine to recompute.
///
/// Returns the segments in natural (ascending-seq) order; the caller applies
/// `spec.reverse`.
pub fn native_multi_fragment(
    spec: &FragmentSpec,
    orig: &PacketView<'_>,
) -> Result<Vec<Vec<u8>>, CoreError> {
    let payload = orig.payload();
    let cuts = resolve_cuts(spec, payload)?;
    let seq = orig.tcp_seq().ok_or(CoreError::Parse("fragment: not a TCP packet"))?;

    let mut segs = Vec::with_capacity(cuts.len() + 1);
    let mut lo = 0usize;
    for &hi in cuts.iter().chain(std::iter::once(&payload.len())) {
        let mut seg = PacketBuilder::from_view(orig);
        if lo > 0 {
            seg.slice_payload_from(lo);
        }
        seg.truncate_payload(hi - lo);
        if lo > 0 {
            seg.set_tcp_seq(seq.wrapping_add(lo as u32))?;
        }
        segs.push(seg.into_bytes());
        lo = hi;
    }
    Ok(segs)
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::strategy::model::{FragmentSpec, SplitAnchor};

    /// A ClientHello (contained in one segment) with SNI = "example.com".
    fn ch_with_sni() -> Vec<u8> {
        // record: 16 03 01 <len16>
        // handshake: 01 <len24> 03 03 <rand32> 00(sid) 0002 1301 01 00 <ext_len16> <exts>
        let mut ext = Vec::new();
        let host = b"example.com";
        ext.extend_from_slice(&((3 + host.len()) as u16).to_be_bytes()); // list len
        ext.push(0);
        ext.extend_from_slice(&(host.len() as u16).to_be_bytes());
        ext.extend_from_slice(host);
        let mut exts = Vec::new();
        exts.extend_from_slice(&0u16.to_be_bytes()); // server_name
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

        // wrap in IPv4 + TCP
        let mut p = vec![0x45, 0, 0, 0, 0, 0, 0x40, 0, 64, 6, 0, 0, 10, 0, 0, 1, 5, 6, 7, 8];
        p.extend_from_slice(&[0x30, 0x39, 0x01, 0xbb]);
        p.extend_from_slice(&1000u32.to_be_bytes());
        p.extend_from_slice(&[0, 0, 0, 0, 0x50, 0x18, 0xff, 0xff, 0, 0, 0, 0]);
        p.extend_from_slice(&tls);
        let total = p.len() as u16;
        p[2..4].copy_from_slice(&total.to_be_bytes());
        p
    }

    /// Classic 2-way split via the general N-way path.
    fn two(anchor: SplitAnchor, v: &PacketView<'_>) -> (Vec<u8>, Vec<u8>) {
        let mut segs = native_multi_fragment(&FragmentSpec::one(anchor, false), v).unwrap();
        assert_eq!(segs.len(), 2);
        let s1 = segs.pop().unwrap();
        let s0 = segs.pop().unwrap();
        (s0, s1)
    }

    #[test]
    fn absolute_offset() {
        let pkt = ch_with_sni();
        let v = PacketView::parse(&pkt).unwrap();
        let (s0, s1) = two(SplitAnchor::AbsoluteOffset(2), &v);
        let p0 = PacketView::parse(&s0).unwrap();
        let p1 = PacketView::parse(&s1).unwrap();
        assert_eq!(p0.payload().len(), 2);
        assert_eq!([p0.payload(), p1.payload()].concat(), v.payload());
        assert_eq!(p1.tcp_seq(), Some(1002));
    }

    #[test]
    fn tls_record_start() {
        let pkt = ch_with_sni();
        let v = PacketView::parse(&pkt).unwrap();
        let (s0, _s1) = two(SplitAnchor::TlsRecordStart, &v);
        assert_eq!(PacketView::parse(&s0).unwrap().payload(), &v.payload()[..5]);
    }

    #[test]
    fn sni_start_and_middle_land_inside_the_host() {
        let pkt = ch_with_sni();
        let v = PacketView::parse(&pkt).unwrap();
        let sni = find_sni(v.payload()).unwrap();

        let (s0, _) = two(SplitAnchor::SniStart, &v);
        assert_eq!(PacketView::parse(&s0).unwrap().payload().len(), sni.host.start);

        let (s0, s1) = two(SplitAnchor::SniMiddle, &v);
        let split = PacketView::parse(&s0).unwrap().payload().len();
        assert!(split > sni.host.start && split < sni.host.end);
        assert_eq!([PacketView::parse(&s0).unwrap().payload(), PacketView::parse(&s1).unwrap().payload()].concat(), v.payload());
    }

    // --- M7b: multi-part native fragment ---

    fn ao(n: u16) -> SplitAnchor {
        SplitAnchor::AbsoluteOffset(n)
    }

    #[test]
    fn multi_fragment_three_parts_round_trip() {
        let pkt = ch_with_sni();
        let v = PacketView::parse(&pkt).unwrap();
        let seq = v.tcp_seq().unwrap();
        let spec = FragmentSpec { anchors: vec![ao(2), ao(6)], reverse: false };

        let segs = native_multi_fragment(&spec, &v).unwrap();
        assert_eq!(segs.len(), 3);
        let p: Vec<_> = segs.iter().map(|s| PacketView::parse(s).unwrap()).collect();
        assert_eq!(p[0].payload().len(), 2);
        assert_eq!(p[1].payload().len(), 4);
        assert_eq!(
            [p[0].payload(), p[1].payload(), p[2].payload()].concat(),
            v.payload()
        );
        assert_eq!(p[0].tcp_seq(), Some(seq));
        assert_eq!(p[1].tcp_seq(), Some(seq + 2));
        assert_eq!(p[2].tcp_seq(), Some(seq + 6));
        for s in &segs {
            assert_eq!(u16::from_be_bytes([s[2], s[3]]), s.len() as u16, "ip len fixed");
        }
    }

    #[test]
    fn multi_fragment_sorts_and_dedups_anchors() {
        let pkt = ch_with_sni();
        let v = PacketView::parse(&pkt).unwrap();
        let unordered = FragmentSpec { anchors: vec![ao(6), ao(2), ao(6)], reverse: false };
        let canonical = FragmentSpec { anchors: vec![ao(2), ao(6)], reverse: false };
        assert_eq!(
            native_multi_fragment(&unordered, &v).unwrap(),
            native_multi_fragment(&canonical, &v).unwrap()
        );
    }

    #[test]
    fn multi_fragment_tls_then_sni_lands_on_the_boundaries() {
        let pkt = ch_with_sni();
        let v = PacketView::parse(&pkt).unwrap();
        let sni = find_sni(v.payload()).unwrap();
        let spec = FragmentSpec {
            anchors: vec![SplitAnchor::TlsRecordStart, SplitAnchor::SniStart],
            reverse: false,
        };
        let segs = native_multi_fragment(&spec, &v).unwrap();
        assert_eq!(segs.len(), 3);
        assert_eq!(PacketView::parse(&segs[0]).unwrap().payload(), &v.payload()[..5]);
        assert_eq!(
            PacketView::parse(&segs[1]).unwrap().payload(),
            &v.payload()[5..sni.host.start]
        );
        assert_eq!(
            PacketView::parse(&segs[2]).unwrap().payload(),
            &v.payload()[sni.host.start..]
        );
    }

    #[test]
    fn multi_fragment_rejects_out_of_range_or_zero() {
        let pkt = ch_with_sni();
        let v = PacketView::parse(&pkt).unwrap();
        let plen = v.payload().len() as u16;
        assert!(native_multi_fragment(&FragmentSpec { anchors: vec![ao(0), ao(4)], reverse: false }, &v).is_err());
        assert!(native_multi_fragment(&FragmentSpec { anchors: vec![ao(4), ao(plen)], reverse: false }, &v).is_err());
    }

    #[test]
    fn no_sni_errors_not_panics() {
        // A packet whose payload is not a ClientHello.
        let mut p = vec![0x45, 0, 0, 0, 0, 0, 0x40, 0, 64, 6, 0, 0, 10, 0, 0, 1, 5, 6, 7, 8];
        p.extend_from_slice(&[0x30, 0x39, 0x01, 0xbb, 0, 0, 0, 1, 0, 0, 0, 0, 0x50, 0x18, 0xff, 0xff, 0, 0, 0, 0]);
        p.extend_from_slice(b"not tls");
        let total = p.len() as u16;
        p[2..4].copy_from_slice(&total.to_be_bytes());
        let v = PacketView::parse(&p).unwrap();
        assert!(native_multi_fragment(&FragmentSpec::one(SplitAnchor::SniStart, false), &v).is_err());
    }
}
