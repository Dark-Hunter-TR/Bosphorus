//! Strategy description types.

use serde::{Deserialize, Serialize};

/// GoodbyeDPI's fake SEQ/ACK shift (`fakepackets.c:220-222`).
pub const SEQ_DELTA: i32 = -10_000;
pub const ACK_DELTA: i32 = -66_000;

/// Stable content id of a [`Strategy`] (FNV-1a over a canonical field encoding).
/// Stable across builds so M8 can key a profile by it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct StrategyId(pub u64);

/// A complete evasion strategy for one ClientHello.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Strategy {
    pub fake: Option<FakeSpec>,
    pub fragment: Option<FragmentSpec>,
    pub order: SendOrder,
    /// M7c: RFC 7685 padding-extension byte count added to the ClientHello
    /// before `fake`/`fragment` are applied. Grows the record past whatever
    /// fixed buffer a DPI's reassembly logic allocates. `None` = untouched.
    pub tls_pad: Option<u16>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SendOrder {
    /// Fake packet(s) first, then the real (possibly fragmented) packet.
    FakeThenReal,
    RealThenFake,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct FragmentSpec {
    /// One or more split points in TCP-payload byte-offset space. `N` anchors
    /// produce `N + 1` real segments. Resolved offsets are sorted + deduped by
    /// `native_multi_fragment`; a single anchor is the classic 2-way split.
    pub anchors: Vec<SplitAnchor>,
    /// Send the segments in reversed order (GoodbyeDPI `--reverse-frag`): last
    /// segment on the wire first.
    pub reverse: bool,
}

impl FragmentSpec {
    /// The classic single-split fragment.
    pub fn one(anchor: SplitAnchor, reverse: bool) -> Self {
        Self { anchors: vec![anchor], reverse }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SplitAnchor {
    /// Split the TCP payload at this absolute byte offset.
    AbsoluteOffset(u16),
    /// Split right after the 5-byte TLS record header.
    TlsRecordStart,
    /// Split right before the SNI host name (GoodbyeDPI `--frag-by-sni`).
    SniStart,
    /// Split in the middle of the SNI host name.
    SniMiddle,
}

impl SplitAnchor {
    /// Short label for [`Strategy::describe`].
    fn label(&self) -> String {
        match self {
            SplitAnchor::AbsoluteOffset(n) => n.to_string(),
            SplitAnchor::TlsRecordStart => "tls".to_string(),
            SplitAnchor::SniStart => "sni".to_string(),
            SplitAnchor::SniMiddle => "sni-mid".to_string(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct FakeSpec {
    pub desync: DesyncMethod,
    /// TTL for the fake. Required for the `*Ttl*` desync methods, ignored else.
    pub ttl: Option<TtlPolicy>,
    pub payload: FakePayload,
    /// How many copies of the fake to send (GoodbyeDPI `--fake-resend`).
    pub repeats: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum DesyncMethod {
    /// Fake with SEQ/ACK shifted into the past.
    WrongSeq { seq_delta: i32, ack_delta: i32 },
    /// Fake with a deliberately corrupted TCP checksum.
    WrongChecksum,
    /// Fake with a low TTL so it dies before the server (needs `FakeSpec::ttl`).
    TtlLimited,
    /// WrongSeq + low TTL.
    SeqPlusTtl { seq_delta: i32, ack_delta: i32 },
    /// WrongChecksum + low TTL.
    ChecksumPlusTtl,
    /// No separate fake. The real segments are sent disorder (reverse) and the
    /// logically-second segment is prefixed with `seqovl` bytes of `fill` (its
    /// sequence number decreased accordingly). Requires `Strategy::fragment`
    /// and `0 < seqovl < split_pos`. (zapret `disorder` + `seqovl`.)
    OverlapDisorder { seqovl: u16, fill: OverlapFill },
}

/// What fills the `seqovl` overlap region of an [`DesyncMethod::OverlapDisorder`].
/// A prefix cannot be a standalone valid ClientHello, so both options are junk;
/// a last-received-wins server overwrites them with the real bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum OverlapFill {
    Zeros,
    JunkByte(u8),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum TtlPolicy {
    /// Fixed value, from a user override. Always wins — never overridden by a
    /// [`Discovered`](TtlPolicy::Discovered) measurement.
    UserFixed(u8),
    /// `clamp(hops_to_server - delta, min, max)`. The blind default: a guess at
    /// how much closer the censor's middlebox sits than the real server,
    /// before anything about this specific path has been measured.
    AutoHeuristic { delta: u8, min: u8, max: u8 },
    /// A precisely measured TTL: hops from the client to the actual injecting
    /// middlebox, read off a `DpiReset`/`LateReset` packet's own TTL (see
    /// `conntrack::events::guess_hops` and `TargetState::injector_hops`). Used
    /// directly, no `delta` guess needed — `resolve_ttl` substitutes this for
    /// an `AutoHeuristic` policy at the point of use ([`build_fake`
    /// ](crate::strategy::transforms::fake_packet::build_fake)) once a target
    /// has one; never baked into a grid-generated `Strategy` (so it never
    /// changes a `StrategyId`).
    Discovered(u8),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum FakePayload {
    /// GoodbyeDPI's static 517-byte TLS ClientHello (`fake_https_request`),
    /// byte-for-byte verbatim.
    StaticClientHello,
    /// `StaticClientHello` with `fake_packet::AGGRESSIVE_PAD_EXTRA` extra bytes
    /// of RFC 7685 padding appended — bigger fake, pushed further past a DPI's
    /// reassembly buffer. Hand-built at call time from the verbatim base, not
    /// itself copied from a third-party source (an explicit, scoped exception
    /// to the "verbatim GoodbyeDPI bytes" rule, for this variant only).
    AggressiveClientHello,
}

/// Decomposition of a separate-fake desync method for `build_fake`.
pub(crate) struct DesyncParts {
    /// `Some((seq_delta, ack_delta))` if the fake's SEQ/ACK are shifted.
    pub seq_shift: Option<(i32, i32)>,
    /// The fake's TTL is set from `FakeSpec::ttl`.
    pub set_ttl: bool,
    /// The fake's TCP checksum is deliberately corrupted after recompute.
    pub break_cksum: bool,
}

impl DesyncMethod {
    /// Decomposition for the separate-fake-packet methods. `None` for
    /// [`DesyncMethod::OverlapDisorder`], which produces no separate fake and is
    /// handled directly by `apply_strategy`.
    pub(crate) fn parts(&self) -> Option<DesyncParts> {
        let (seq_shift, set_ttl, break_cksum) = match *self {
            DesyncMethod::WrongSeq { seq_delta, ack_delta } => (Some((seq_delta, ack_delta)), false, false),
            DesyncMethod::WrongChecksum => (None, false, true),
            DesyncMethod::TtlLimited => (None, true, false),
            DesyncMethod::SeqPlusTtl { seq_delta, ack_delta } => (Some((seq_delta, ack_delta)), true, false),
            DesyncMethod::ChecksumPlusTtl => (None, true, true),
            DesyncMethod::OverlapDisorder { .. } => return None,
        };
        Some(DesyncParts { seq_shift, set_ttl, break_cksum })
    }

    pub(crate) fn is_overlap_disorder(&self) -> bool {
        matches!(self, DesyncMethod::OverlapDisorder { .. })
    }
}

impl Strategy {
    /// The M4 baseline: `fake(WrongSeq -10000/-66000)` then native-frag at
    /// offset 2, fake first.
    pub fn m4_fixed() -> Self {
        Self {
            fake: Some(FakeSpec {
                desync: DesyncMethod::WrongSeq { seq_delta: SEQ_DELTA, ack_delta: ACK_DELTA },
                ttl: None,
                payload: FakePayload::StaticClientHello,
                repeats: 1,
            }),
            fragment: Some(FragmentSpec::one(SplitAnchor::AbsoluteOffset(2), false)),
            order: SendOrder::FakeThenReal,
            tls_pad: None,
        }
    }

    /// Stable content hash (see [`StrategyId`]).
    pub fn id(&self) -> StrategyId {
        let mut h: u64 = 0xcbf2_9ce4_8422_2325;
        let mut put = |x: u8| {
            h ^= x as u64;
            h = h.wrapping_mul(0x0000_0100_0000_01b3);
        };
        let put_i32 = |put: &mut dyn FnMut(u8), v: i32| {
            for b in v.to_le_bytes() {
                put(b);
            }
        };
        let put_u16 = |put: &mut dyn FnMut(u8), v: u16| {
            for b in v.to_le_bytes() {
                put(b);
            }
        };

        match &self.fake {
            None => put(0),
            Some(f) => {
                put(1);
                match f.desync {
                    DesyncMethod::WrongSeq { seq_delta, ack_delta } => {
                        put(1);
                        put_i32(&mut put, seq_delta);
                        put_i32(&mut put, ack_delta);
                    }
                    DesyncMethod::WrongChecksum => put(2),
                    DesyncMethod::TtlLimited => put(3),
                    DesyncMethod::SeqPlusTtl { seq_delta, ack_delta } => {
                        put(4);
                        put_i32(&mut put, seq_delta);
                        put_i32(&mut put, ack_delta);
                    }
                    DesyncMethod::ChecksumPlusTtl => put(5),
                    DesyncMethod::OverlapDisorder { seqovl, fill } => {
                        put(6);
                        put_u16(&mut put, seqovl);
                        match fill {
                            OverlapFill::Zeros => put(0),
                            OverlapFill::JunkByte(b) => {
                                put(1);
                                put(b);
                            }
                        }
                    }
                }
                match f.ttl {
                    None => put(0),
                    Some(TtlPolicy::UserFixed(v)) => {
                        put(1);
                        put(v);
                    }
                    Some(TtlPolicy::AutoHeuristic { delta, min, max }) => {
                        put(2);
                        put(delta);
                        put(min);
                        put(max);
                    }
                    Some(TtlPolicy::Discovered(v)) => {
                        put(3);
                        put(v);
                    }
                }
                match f.payload {
                    FakePayload::StaticClientHello => put(1),
                    FakePayload::AggressiveClientHello => put(2),
                }
                put(f.repeats);
            }
        }
        match &self.fragment {
            None => put(0),
            Some(fr) => {
                put(1);
                put(fr.anchors.len().min(255) as u8);
                for a in &fr.anchors {
                    match a {
                        SplitAnchor::AbsoluteOffset(n) => {
                            put(1);
                            put_u16(&mut put, *n);
                        }
                        SplitAnchor::TlsRecordStart => put(2),
                        SplitAnchor::SniStart => put(3),
                        SplitAnchor::SniMiddle => put(4),
                    }
                }
                put(fr.reverse as u8);
            }
        }
        match self.tls_pad {
            None => put(0),
            Some(n) => {
                put(1);
                put_u16(&mut put, n);
            }
        }
        put(match self.order {
            SendOrder::FakeThenReal => 1,
            SendOrder::RealThenFake => 2,
        });
        StrategyId(h)
    }

    /// Short human-readable label for logs.
    pub fn describe(&self) -> String {
        let mut s = String::new();
        if let Some(f) = &self.fake {
            match f.desync {
                DesyncMethod::OverlapDisorder { seqovl, .. } => {
                    s.push_str(&format!("overlap({seqovl})"));
                }
                _ => {
                    let d = match f.desync {
                        DesyncMethod::WrongSeq { .. } => "wrong-seq",
                        DesyncMethod::WrongChecksum => "wrong-cksum",
                        DesyncMethod::TtlLimited => "ttl",
                        DesyncMethod::SeqPlusTtl { .. } => "seq+ttl",
                        DesyncMethod::ChecksumPlusTtl => "cksum+ttl",
                        DesyncMethod::OverlapDisorder { .. } => unreachable!(),
                    };
                    s.push_str(&format!("fake({d})"));
                    if f.repeats > 1 {
                        s.push_str(&format!("x{}", f.repeats));
                    }
                    if f.payload == FakePayload::AggressiveClientHello {
                        s.push_str("+big");
                    }
                }
            }
        }
        if let Some(fr) = &self.fragment {
            if !s.is_empty() {
                s.push('+');
            }
            let joined = fr.anchors.iter().map(SplitAnchor::label).collect::<Vec<_>>().join(",");
            s.push_str(&format!("frag@{joined}"));
            if fr.reverse {
                s.push_str("(rev)");
            }
        }
        if let Some(n) = self.tls_pad {
            if !s.is_empty() {
                s.push('+');
            }
            s.push_str(&format!("pad({n})"));
        }
        if self.order == SendOrder::RealThenFake {
            s.push_str("[real-first]");
        }
        if s.is_empty() {
            s.push_str("passthrough");
        }
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn id_is_stable_and_distinguishes() {
        let a = Strategy::m4_fixed();
        assert_eq!(a.id(), a.clone().id());

        let mut b = Strategy::m4_fixed();
        b.fragment = Some(FragmentSpec::one(SplitAnchor::AbsoluteOffset(3), false));
        assert_ne!(a.id(), b.id());

        let mut c = Strategy::m4_fixed();
        c.order = SendOrder::RealThenFake;
        assert_ne!(a.id(), c.id());

        // Anchor count is part of the id: [2] != [2, 6].
        let mut d = Strategy::m4_fixed();
        d.fragment = Some(FragmentSpec {
            anchors: vec![SplitAnchor::AbsoluteOffset(2), SplitAnchor::AbsoluteOffset(6)],
            reverse: false,
        });
        assert_ne!(a.id(), d.id());
    }

    #[test]
    fn round_trips_through_json() {
        let s = Strategy::m4_fixed();
        let j = serde_json::to_string(&s).unwrap();
        let back: Strategy = serde_json::from_str(&j).unwrap();
        assert_eq!(s, back);
        assert_eq!(s.id(), back.id());
    }

    #[test]
    fn describe_labels() {
        assert_eq!(Strategy::m4_fixed().describe(), "fake(wrong-seq)+frag@2");

        let multi = Strategy {
            fake: None,
            fragment: Some(FragmentSpec {
                anchors: vec![SplitAnchor::TlsRecordStart, SplitAnchor::SniStart],
                reverse: true,
            }),
            order: SendOrder::FakeThenReal,
            tls_pad: None,
        };
        assert_eq!(multi.describe(), "frag@tls,sni(rev)");

        let padded = Strategy { tls_pad: Some(512), ..multi };
        assert_eq!(padded.describe(), "frag@tls,sni(rev)+pad(512)");
    }

    #[test]
    fn tls_pad_changes_the_id() {
        let a = Strategy::m4_fixed();
        let b = Strategy { tls_pad: Some(512), ..a.clone() };
        assert_ne!(a.id(), b.id());
        let c = Strategy { tls_pad: Some(513), ..a };
        assert_ne!(b.id(), c.id());
    }
}

