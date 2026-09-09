//! The "generative" layer: a curated parameter grid whose cartesian product is
//! the candidate strategy list M6's discovery walks. Protocol-generic — no
//! ISP-specific constants.

use std::collections::HashSet;

use crate::config::EvasionConfig;
use crate::strategy::model::{
    DesyncMethod, FakePayload, FakeSpec, FragmentSpec, OverlapFill, SendOrder, SplitAnchor, Strategy,
    StrategyId, TtlPolicy, ACK_DELTA, SEQ_DELTA,
};

/// True if `s` uses [`DesyncMethod::OverlapDisorder`] — gated away from
/// first-received-wins servers by the scheduler.
pub fn is_overlap_family(s: &Strategy) -> bool {
    matches!(&s.fake, Some(f) if f.desync.is_overlap_disorder())
}

/// The desync axis (fieldless, for enumeration).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DesyncKind {
    None,
    WrongSeq,
    WrongChecksum,
    TtlLimited,
    SeqPlusTtl,
    ChecksumPlusTtl,
}

/// The grid axes. `default()` is curated in rough success-probability order so
/// the earliest candidates are the ones that most often work.
#[derive(Clone, Debug)]
pub struct GridAxes {
    pub frag_anchor: Vec<Option<SplitAnchor>>,
    pub frag_reverse: Vec<bool>,
    pub desync: Vec<DesyncKind>,
    pub repeats: Vec<u8>,
    pub order: Vec<SendOrder>,
    /// Multi-part native-fragment patterns (>= 2 cut points => >= 3 real
    /// segments). Each is crossed with `frag_reverse` and a small desync subset
    /// (`None`, `WrongSeq`) and appended after the main grid. Curated small.
    pub frag_multi: Vec<Vec<SplitAnchor>>,
    /// `OverlapDisorder` candidates: for each anchor here, one strategy per
    /// `seqovl`. Appended AFTER the main grid. Empty = feature off, which is the
    /// default — overlap feeds the server junk bytes and can break the handshake
    /// against a first-received-wins stack, so auto-discovery only sweeps it when
    /// explicitly opted in (`EvasionConfig::enable_overlap_disorder`). Populate
    /// via [`GridAxes::with_overlap`].
    pub overlap_anchors: Vec<SplitAnchor>,
    pub overlap_seqovl: Vec<u16>,
    /// M7c: RFC 7685 padding candidates. Each `(anchors, desync)` pair here
    /// produces exactly one `tls_pad = Some(TLS_PAD_LEN)` strategy, appended
    /// after the multi-part family and before the (opt-in) overlap family —
    /// low priority, TCP-level only (no blackhole/policy risk like overlap).
    /// Curated narrow and deliberately overlaps the two anchors that showed a
    /// partial (1/2) success signal against `updates.discord.com`.
    pub tls_pad_anchors: Vec<Vec<SplitAnchor>>,
    pub tls_pad_desync: Vec<DesyncKind>,
    /// "Aggressive" fake candidates: `FakePayload::AggressiveClientHello`
    /// (GoodbyeDPI's fake + `fake_packet::AGGRESSIVE_PAD_EXTRA` extra RFC 7685
    /// padding) crossed with a small anchor/desync subset. Appended after
    /// tls_pad, before the (opt-in) overlap family — low priority, TCP-level
    /// only. User-requested ("daha agresif"); this fake payload is the one
    /// deliberate, scoped exception to the "verbatim GoodbyeDPI bytes" rule.
    pub aggressive_fake_anchors: Vec<SplitAnchor>,
    pub aggressive_fake_desync: Vec<DesyncKind>,
}

/// The single padding length the `tls_pad_*` grid axis uses.
pub const TLS_PAD_LEN: u16 = 512;

impl Default for GridAxes {
    fn default() -> Self {
        Self {
            frag_anchor: vec![
                Some(SplitAnchor::SniStart),
                Some(SplitAnchor::TlsRecordStart),
                Some(SplitAnchor::AbsoluteOffset(1)),
                Some(SplitAnchor::AbsoluteOffset(2)),
                Some(SplitAnchor::AbsoluteOffset(3)),
                Some(SplitAnchor::SniMiddle),
                None,
            ],
            frag_reverse: vec![false, true],
            desync: vec![
                DesyncKind::WrongSeq,
                DesyncKind::None,
                DesyncKind::WrongChecksum,
                DesyncKind::TtlLimited,
                DesyncKind::SeqPlusTtl,
                DesyncKind::ChecksumPlusTtl,
            ],
            repeats: vec![1, 2],
            order: vec![SendOrder::FakeThenReal],
            frag_multi: vec![
                // record header | TLS body up to SNI | SNI onward
                vec![SplitAnchor::TlsRecordStart, SplitAnchor::SniStart],
                // + a 1-byte lead segment -> 4 parts
                vec![
                    SplitAnchor::AbsoluteOffset(1),
                    SplitAnchor::TlsRecordStart,
                    SplitAnchor::SniStart,
                ],
                // split around and inside the SNI
                vec![SplitAnchor::SniStart, SplitAnchor::SniMiddle],
            ],
            // Off by default. See the field docs / `with_overlap`.
            overlap_anchors: vec![],
            overlap_seqovl: vec![],
            tls_pad_anchors: vec![
                vec![SplitAnchor::AbsoluteOffset(2)], // partial (1/2) signal vs updates.discord.com
                vec![SplitAnchor::TlsRecordStart],    // partial (1/2) signal vs updates.discord.com
                vec![SplitAnchor::SniStart],          // the usual best performer
            ],
            tls_pad_desync: vec![DesyncKind::WrongSeq, DesyncKind::WrongChecksum],
            aggressive_fake_anchors: vec![
                SplitAnchor::SniStart,
                SplitAnchor::TlsRecordStart,
                SplitAnchor::AbsoluteOffset(2),
            ],
            aggressive_fake_desync: vec![DesyncKind::WrongSeq, DesyncKind::WrongChecksum],
        }
    }
}

impl GridAxes {
    /// The default grid plus the curated `OverlapDisorder` axis (4 anchors x
    /// 2 `seqovl` = 8 extra candidates, appended last). Opt-in only.
    pub fn with_overlap() -> Self {
        Self {
            overlap_anchors: vec![
                SplitAnchor::SniStart,
                SplitAnchor::TlsRecordStart,
                SplitAnchor::AbsoluteOffset(3),
                SplitAnchor::SniMiddle,
            ],
            overlap_seqovl: vec![16, 32],
            ..Self::default()
        }
    }
}

/// Default seed for the `AutoHeuristic` TTL (zapret-ish `+4:3-10`).
const HEURISTIC_TTL: TtlPolicy = TtlPolicy::AutoHeuristic { delta: 4, min: 3, max: 10 };

fn fake_for(kind: DesyncKind, repeats: u8) -> Option<FakeSpec> {
    let desync = match kind {
        DesyncKind::None => return None,
        DesyncKind::WrongSeq => DesyncMethod::WrongSeq { seq_delta: SEQ_DELTA, ack_delta: ACK_DELTA },
        DesyncKind::WrongChecksum => DesyncMethod::WrongChecksum,
        DesyncKind::TtlLimited => DesyncMethod::TtlLimited,
        DesyncKind::SeqPlusTtl => DesyncMethod::SeqPlusTtl { seq_delta: SEQ_DELTA, ack_delta: ACK_DELTA },
        DesyncKind::ChecksumPlusTtl => DesyncMethod::ChecksumPlusTtl,
    };
    let ttl = matches!(
        kind,
        DesyncKind::TtlLimited | DesyncKind::SeqPlusTtl | DesyncKind::ChecksumPlusTtl
    )
    .then_some(HEURISTIC_TTL);
    Some(FakeSpec {
        desync,
        ttl,
        payload: FakePayload::StaticClientHello,
        repeats: repeats.max(1),
    })
}

/// Like `fake_for`, but with `FakePayload::AggressiveClientHello`.
fn aggressive_fake_for(kind: DesyncKind, repeats: u8) -> Option<FakeSpec> {
    let mut f = fake_for(kind, repeats)?;
    f.payload = FakePayload::AggressiveClientHello;
    Some(f)
}

fn build_grid(axes: &GridAxes) -> Vec<Strategy> {
    let mut out = Vec::new();
    let mut seen: HashSet<StrategyId> = HashSet::new();
    let mut push = |out: &mut Vec<Strategy>, s: Strategy| {
        if seen.insert(s.id()) {
            out.push(s);
        }
    };

    // --- main "split + fake" grid ---
    for &anchor in &axes.frag_anchor {
        for &reverse in &axes.frag_reverse {
            for &desync in &axes.desync {
                for &repeats in &axes.repeats {
                    for &order in &axes.order {
                        let fragment = anchor.map(|a| FragmentSpec::one(a, reverse));
                        let fake = fake_for(desync, repeats);
                        if fake.is_none() && fragment.is_none() {
                            continue; // pure passthrough — not a strategy
                        }
                        push(&mut out, Strategy { fake, fragment, order, tls_pad: None });
                    }
                }
            }
        }
    }

    // --- multi-part native fragment candidates, appended after the main grid ---
    for pattern in &axes.frag_multi {
        for &reverse in &axes.frag_reverse {
            for &desync in &[DesyncKind::None, DesyncKind::WrongSeq] {
                push(
                    &mut out,
                    Strategy {
                        fake: fake_for(desync, 1),
                        fragment: Some(FragmentSpec { anchors: pattern.clone(), reverse }),
                        order: SendOrder::FakeThenReal,
                        tls_pad: None,
                    },
                );
            }
        }
    }

    // --- tls_pad (RFC 7685) candidates, appended after the multi-part family ---
    for anchors in &axes.tls_pad_anchors {
        for &desync in &axes.tls_pad_desync {
            push(
                &mut out,
                Strategy {
                    fake: fake_for(desync, 1),
                    fragment: Some(FragmentSpec { anchors: anchors.clone(), reverse: false }),
                    order: SendOrder::FakeThenReal,
                    tls_pad: Some(TLS_PAD_LEN),
                },
            );
        }
    }

    // --- "aggressive" fake candidates, appended after tls_pad ---
    for &anchor in &axes.aggressive_fake_anchors {
        for &desync in &axes.aggressive_fake_desync {
            if let Some(fake) = aggressive_fake_for(desync, 1) {
                push(
                    &mut out,
                    Strategy {
                        fake: Some(fake),
                        fragment: Some(FragmentSpec::one(anchor, false)),
                        order: SendOrder::FakeThenReal,
                        tls_pad: None,
                    },
                );
            }
        }
    }

    // --- OverlapDisorder candidates, appended after the main grid ---
    for &anchor in &axes.overlap_anchors {
        for &seqovl in &axes.overlap_seqovl {
            push(
                &mut out,
                Strategy {
                    fake: Some(FakeSpec {
                        desync: DesyncMethod::OverlapDisorder { seqovl, fill: OverlapFill::Zeros },
                        ttl: None,
                        payload: FakePayload::StaticClientHello,
                        repeats: 1,
                    }),
                    fragment: Some(FragmentSpec::one(anchor, true)),
                    order: SendOrder::FakeThenReal,
                    tls_pad: None,
                },
            );
        }
    }

    out
}

/// Build a single strategy from the config overrides.
fn single_from_overrides(cfg: &EvasionConfig) -> Strategy {
    let fake = cfg.desync_override.map(|d| FakeSpec {
        desync: d,
        ttl: cfg.ttl_override.map(TtlPolicy::UserFixed),
        payload: FakePayload::StaticClientHello,
        repeats: 1,
    });
    Strategy {
        fake,
        fragment: cfg.fragment_override.clone(),
        order: SendOrder::FakeThenReal,
        tls_pad: None,
    }
}

pub struct DefaultGenerator {
    strategies: Vec<Strategy>,
}

impl DefaultGenerator {
    /// Build the grid, or (if the config has any strategy override) a
    /// single-entry list.
    pub fn new(cfg: &EvasionConfig) -> Self {
        if cfg.has_strategy_override() {
            return Self { strategies: vec![single_from_overrides(cfg)] };
        }
        let axes = if cfg.enable_overlap_disorder {
            GridAxes::with_overlap()
        } else {
            GridAxes::default()
        };
        Self { strategies: build_grid(&axes) }
    }

    pub fn with_axes(axes: &GridAxes) -> Self {
        Self { strategies: build_grid(axes) }
    }

    pub fn all(&self) -> &[Strategy] {
        &self.strategies
    }
    pub fn len(&self) -> usize {
        self.strategies.len()
    }
    pub fn is_empty(&self) -> bool {
        self.strategies.is_empty()
    }

    /// First grid strategy whose id is not in `tried` and that `accept` allows.
    /// `accept` is the gating hook (e.g. reject overlap-family on Windows servers).
    pub fn next_candidate(
        &self,
        tried: &[StrategyId],
        accept: &dyn Fn(&Strategy) -> bool,
    ) -> Option<&Strategy> {
        self.strategies
            .iter()
            .find(|s| !tried.contains(&s.id()) && accept(s))
    }

    /// Look up a grid strategy by its content id (for seed lists, which carry
    /// ids learned on other targets). `None` if the id is not in this grid
    /// (e.g. the grid was renumbered between builds).
    pub fn get_by_id(&self, id: StrategyId) -> Option<&Strategy> {
        self.strategies.iter().find(|s| s.id() == id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::strategy::model::{DesyncMethod, SplitAnchor};

    #[test]
    fn grid_is_deterministic_and_dedup_free() {
        let a = DefaultGenerator::new(&EvasionConfig::default());
        let b = DefaultGenerator::new(&EvasionConfig::default());
        assert_eq!(a.len(), b.len());
        assert!(a.len() > 20, "grid has a meaningful number of candidates: {}", a.len());

        let ids: HashSet<_> = a.all().iter().map(|s| s.id()).collect();
        assert_eq!(ids.len(), a.len(), "no duplicate strategy ids");

        // same order every time
        let d1: Vec<_> = a.all().iter().map(|s| s.describe()).collect();
        let d2: Vec<_> = b.all().iter().map(|s| s.describe()).collect();
        assert_eq!(d1, d2);
    }

    #[test]
    fn first_candidate_is_the_high_probability_one() {
        let g = DefaultGenerator::new(&EvasionConfig::default());
        assert_eq!(g.all()[0].describe(), "fake(wrong-seq)+frag@sni");
    }

    #[test]
    fn override_collapses_grid_to_one() {
        let cfg = EvasionConfig {
            fragment_override: Some(FragmentSpec::one(SplitAnchor::AbsoluteOffset(7), false)),
            desync_override: Some(DesyncMethod::WrongSeq { seq_delta: -1, ack_delta: -2 }),
            ..Default::default()
        };
        let g = DefaultGenerator::new(&cfg);
        assert_eq!(g.len(), 1);
        assert_eq!(g.all()[0].describe(), "fake(wrong-seq)+frag@7");
    }

    #[test]
    fn next_candidate_skips_tried() {
        let g = DefaultGenerator::new(&EvasionConfig::default());
        let first = g.all()[0].id();
        assert_eq!(g.next_candidate(&[], &|_| true).unwrap().id(), first);
        let second = g.next_candidate(&[first], &|_| true).unwrap().id();
        assert_ne!(second, first);
        // exhausting all ids -> None
        let all_ids: Vec<_> = g.all().iter().map(|s| s.id()).collect();
        assert!(g.next_candidate(&all_ids, &|_| true).is_none());
    }

    /// M7a safety fix: the default grid must never contain an overlap-family
    /// strategy, so organic discovery traffic can never be handed one. Overlap
    /// can break a real TCP handshake against a first-received-wins stack.
    #[test]
    fn default_grid_has_zero_overlap_family() {
        let g = DefaultGenerator::new(&EvasionConfig::default());
        assert!(
            !g.all().iter().any(is_overlap_family),
            "default grid must not contain OverlapDisorder"
        );
        // Even with no gating hook at all, sweeping the whole grid never yields
        // an overlap strategy.
        let mut tried = Vec::new();
        while let Some(s) = g.next_candidate(&tried, &|_| true) {
            assert!(!is_overlap_family(s), "swept an overlap strategy from the default grid");
            tried.push(s.id());
        }
    }

    #[test]
    fn default_grid_has_multi_part_fragment_candidates() {
        let g = DefaultGenerator::new(&EvasionConfig::default());
        let multi: Vec<_> = g
            .all()
            .iter()
            .filter(|s| s.fragment.as_ref().is_some_and(|f| f.anchors.len() >= 2))
            .collect();
        assert_eq!(multi.len(), 12, "3 patterns x 2 reverse x {{none, wrong-seq}}");
        // They come after the 142 single-split entries.
        let first_multi = g
            .all()
            .iter()
            .position(|s| s.fragment.as_ref().is_some_and(|f| f.anchors.len() >= 2))
            .unwrap();
        assert_eq!(first_multi, 142);
        // ...and never any overlap in the default grid (M7a safety fix holds).
        assert!(!g.all().iter().any(is_overlap_family));
    }

    #[test]
    fn default_grid_has_aggressive_fake_candidates() {
        use crate::strategy::model::FakePayload;
        let g = DefaultGenerator::new(&EvasionConfig::default());
        let aggressive: Vec<_> = g
            .all()
            .iter()
            .filter(|s| {
                s.fake.as_ref().is_some_and(|f| f.payload == FakePayload::AggressiveClientHello)
            })
            .collect();
        assert_eq!(aggressive.len(), 6, "3 anchors x {{wrong-seq, wrong-cksum}}");
        // They come after tls_pad (indices 142+12=154..159), before overlap.
        let first = g
            .all()
            .iter()
            .position(|s| {
                s.fake.as_ref().is_some_and(|f| f.payload == FakePayload::AggressiveClientHello)
            })
            .unwrap();
        assert_eq!(first, 160);
        // Every default-grid candidate still uses the verbatim static fake
        // unless explicitly aggressive; StaticClientHello never silently
        // changed size or content (M7a-style regression guard).
        for s in g.all() {
            if let Some(f) = &s.fake {
                assert!(matches!(
                    f.payload,
                    FakePayload::StaticClientHello | FakePayload::AggressiveClientHello
                ));
            }
        }
        // ...and never any overlap in the default grid (M7a safety fix holds).
        assert!(!g.all().iter().any(is_overlap_family));
    }

    #[test]
    fn overlap_is_opt_in_and_gating_filters_it() {
        let cfg = EvasionConfig { enable_overlap_disorder: true, ..Default::default() };
        let g = DefaultGenerator::new(&cfg);
        let overlap: Vec<_> = g.all().iter().filter(|s| is_overlap_family(s)).collect();
        assert_eq!(overlap.len(), 8, "4 anchors x 2 seqovl");
        // overlap candidates come AFTER the main grid
        let first_overlap = g.all().iter().position(is_overlap_family).unwrap();
        assert!(first_overlap > 100);

        // gating: accept = "no overlap" -> next_candidate never returns one
        let accept_no_overlap = |s: &Strategy| !is_overlap_family(s);
        let mut tried: Vec<_> = g
            .all()
            .iter()
            .filter(|s| !is_overlap_family(s))
            .map(|s| s.id())
            .collect();
        // every non-overlap tried -> with the gate, nothing left
        assert!(g.next_candidate(&tried, &accept_no_overlap).is_none());
        // without the gate, the overlap candidates are still available
        assert!(g.next_candidate(&tried, &|_| true).is_some());
        tried.clear();
        assert!(!is_overlap_family(g.next_candidate(&tried, &|_| true).unwrap()));
    }

    /// One-segment ClientHello (IPv4/TCP) with a `server_name` extension.
    fn clienthello_with_sni(host: &str) -> Vec<u8> {
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

    #[test]
    fn every_grid_strategy_builds_without_panicking() {
        use crate::packet::PacketView;
        use crate::source_sink::{CaptureMeta, SendBatch};
        use crate::strategy::transforms::{apply_strategy, TransformCtx};

        let pkt = clienthello_with_sni("updates.discord.com");
        let view = PacketView::parse(&pkt).unwrap();
        let meta = CaptureMeta { outbound: true, ..Default::default() };

        // Sweep both the default grid and the overlap-opted-in grid.
        let overlap_cfg = EvasionConfig { enable_overlap_disorder: true, ..Default::default() };
        let g = DefaultGenerator::new(&overlap_cfg);
        let mut ok = 0;
        for s in g.all() {
            let ctx = TransformCtx {
                view: &view,
                meta: &meta,
                hops_to_server: Some(12),
                discovered_ttl: None,
                max_seg: 1200,
            };
            let mut out = SendBatch::new();
            // Must not panic; Ok (batch produced) or a clean Err are both fine.
            if apply_strategy(s, &ctx, &mut out).is_ok() {
                ok += 1;
                assert!(!out.is_empty());
            }
        }
        assert!(ok > 0, "at least some grid strategies produce a batch");
    }
}
