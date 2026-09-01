use std::time::Instant;

use crate::config::ConntrackTuning;
use crate::packet::{looks_like_client_hello, tls_content_type, PacketView};

use super::flow::FlowState;

/// How a flow ended, from the engine's point of view.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FlowOutcome {
    /// Server responded with a TLS handshake / data — the connection worked.
    Success,
    /// A RST arrived from `:443` after our ClientHello and before any server
    /// data — the classic in-path DPI reset.
    DpiReset,
    /// ClientHello sent, no response at all (retransmits / timeout).
    Blackhole,
    /// RST / failure before or during setup, not attributable to a DPI reset.
    TlsError,
    /// Nothing conclusive happened before the flow aged out.
    Inconclusive,
}

/// Common initial TTL values and the hop count implied by an observed TTL.
fn guess_hops(observed_ttl: u8) -> Option<(u8, u8)> {
    for initial in [64u8, 128, 255] {
        if observed_ttl <= initial && initial - observed_ttl <= 32 {
            return Some((initial, initial - observed_ttl));
        }
    }
    None
}

/// Update `st` from an outbound (client -> server) packet. Returns a verdict if
/// one becomes certain (only `Blackhole`, from ClientHello retransmits).
pub fn observe_outbound(st: &mut FlowState, v: &PacketView<'_>, now: Instant, tuning: &ConntrackTuning) -> Option<FlowOutcome> {
    st.bytes_out += v.raw().len() as u64;
    if st.outcome.is_some() {
        return None;
    }
    let payload = v.payload();
    let seq = v.tcp_seq();

    if looks_like_client_hello(payload) || payload.first() == Some(&0x16) {
        if !st.client_hello_seen {
            st.client_hello_seen = true;
            st.client_hello_at = Some(now);
            st.client_hello_seq = seq;
            if let Some(loc) = crate::packet::find_sni(payload) {
                if let Ok(name) = std::str::from_utf8(&payload[loc.host]) {
                    st.server_name = Some(name.to_owned());
                }
            }
        } else if seq.is_some() && seq == st.client_hello_seq {
            st.client_hello_retx = st.client_hello_retx.saturating_add(1);
            if st.client_hello_retx >= tuning.client_hello_retx_fail {
                return set(st, FlowOutcome::Blackhole);
            }
        }
    }
    None
}

/// Update `st` from an inbound (server -> client) packet. Returns a verdict if
/// one becomes certain.
pub fn observe_inbound(st: &mut FlowState, v: &PacketView<'_>, _now: Instant) -> Option<FlowOutcome> {
    st.bytes_in += v.raw().len() as u64;
    if st.outcome.is_some() {
        return None;
    }
    let flags = v.tcp_flags();
    let payload = v.payload();

    // SYN-ACK: connection established; learn the remote TTL.
    if let Some(f) = flags {
        if f.syn && f.ack {
            st.syn_ack_seen = true;
            if let Some((initial, hops)) = guess_hops(v.ttl()) {
                st.remote_initial_ttl = Some(initial);
                st.hops_to_server = Some(hops);
            }
            return None;
        }
        if f.rst {
            st.inbound_rst = true;
            return if st.server_hello_seen {
                None // RST after a successful handshake is just a close
            } else if st.client_hello_seen {
                set(st, FlowOutcome::DpiReset)
            } else {
                set(st, FlowOutcome::TlsError)
            };
        }
    }

    // Any TLS record from the server after our ClientHello => the handshake is
    // progressing. `0x16` handshake (ServerHello) or `0x17` application data.
    match tls_content_type(payload) {
        Some(0x16) => {
            st.server_hello_seen = true;
            if st.client_hello_seen {
                return set(st, FlowOutcome::Success);
            }
        }
        Some(0x17) if st.client_hello_seen => return set(st, FlowOutcome::Success),
        Some(0x15) if st.client_hello_seen && !st.server_hello_seen => {
            return set(st, FlowOutcome::TlsError); // TLS alert before any ServerHello
        }
        _ => {}
    }
    None
}

/// Called periodically by the engine tick. Resolves flows that have gone quiet.
pub fn resolve_timeout(st: &FlowState, tuning: &ConntrackTuning, now: Instant) -> Option<FlowOutcome> {
    if st.outcome.is_some() {
        return None;
    }
    if let Some(ch_at) = st.client_hello_at {
        if !st.server_hello_seen && !st.inbound_rst && now.duration_since(ch_at) >= tuning.verdict_timeout {
            return Some(FlowOutcome::Blackhole);
        }
        return None;
    }
    if now.duration_since(st.created_at) >= tuning.verdict_timeout {
        return Some(FlowOutcome::Inconclusive);
    }
    None
}

fn set(st: &mut FlowState, o: FlowOutcome) -> Option<FlowOutcome> {
    st.outcome = Some(o);
    Some(o)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::conntrack::flow::FlowState;

    const T_CH: u8 = 0x18; // PSH|ACK
    const T_SA: u8 = 0x12; // SYN|ACK
    const T_RST: u8 = 0x04;

    fn v4_tcp(ttl: u8, flags: u8, seq: u32, payload: &[u8]) -> Vec<u8> {
        let mut p = vec![0x45, 0x00, 0x00, 0x00, 0, 0, 0x40, 0x00, ttl, 0x06, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2];
        p.extend_from_slice(&[0x30, 0x39, 0x01, 0xbb]); // ports 12345 -> 443
        p.extend_from_slice(&seq.to_be_bytes());
        p.extend_from_slice(&[0, 0, 0, 0]); // ack
        p.push(0x50); // data offset 5
        p.push(flags);
        p.extend_from_slice(&[0xff, 0xff, 0, 0, 0, 0]);
        p.extend_from_slice(payload);
        let total = p.len() as u16;
        p[2..4].copy_from_slice(&total.to_be_bytes());
        p
    }

    fn view(bytes: &[u8]) -> PacketView<'_> {
        PacketView::parse(bytes).unwrap()
    }

    fn tuning() -> ConntrackTuning {
        ConntrackTuning::default()
    }

    #[test]
    fn open_site_is_success() {
        let now = Instant::now();
        let mut st = FlowState::new(now);
        let t = tuning();

        let sa = v4_tcp(117, T_SA, 0, &[]);
        assert_eq!(observe_inbound(&mut st, &view(&sa), now), None);
        assert!(st.syn_ack_seen);
        assert_eq!(st.remote_initial_ttl, Some(128));
        assert_eq!(st.hops_to_server, Some(11));

        let ch = v4_tcp(64, T_CH, 1000, &[0x16, 0x03, 0x01, 0x00, 0x05, 0x01]);
        assert_eq!(observe_outbound(&mut st, &view(&ch), now, &t), None);
        assert!(st.client_hello_seen);

        let sh = v4_tcp(117, T_CH, 0, &[0x16, 0x03, 0x03, 0x00, 0x05, 0x02]);
        assert_eq!(observe_inbound(&mut st, &view(&sh), now), Some(FlowOutcome::Success));
        assert_eq!(st.outcome, Some(FlowOutcome::Success));
    }

    #[test]
    fn blocked_site_rst_is_dpi_reset() {
        let now = Instant::now();
        let mut st = FlowState::new(now);
        let t = tuning();

        observe_inbound(&mut st, &view(&v4_tcp(117, T_SA, 0, &[])), now);
        observe_outbound(&mut st, &view(&v4_tcp(64, T_CH, 42, &[0x16, 0x03, 0x01, 0, 5, 0x01])), now, &t);

        let rst = v4_tcp(200, T_RST, 0, &[]);
        assert_eq!(observe_inbound(&mut st, &view(&rst), now), Some(FlowOutcome::DpiReset));
    }

    #[test]
    fn rst_before_clienthello_is_tls_error() {
        let now = Instant::now();
        let mut st = FlowState::new(now);
        observe_inbound(&mut st, &view(&v4_tcp(117, T_SA, 0, &[])), now);
        let rst = v4_tcp(117, T_RST, 0, &[]);
        assert_eq!(observe_inbound(&mut st, &view(&rst), now), Some(FlowOutcome::TlsError));
    }

    #[test]
    fn blackhole_via_retransmits() {
        let now = Instant::now();
        let mut st = FlowState::new(now);
        let t = tuning(); // client_hello_retx_fail = 3

        let ch = v4_tcp(64, T_CH, 7, &[0x16, 0x03, 0x01, 0, 5, 0x01]);
        assert_eq!(observe_outbound(&mut st, &view(&ch), now, &t), None); // first
        assert_eq!(observe_outbound(&mut st, &view(&ch), now, &t), None); // retx 1
        assert_eq!(observe_outbound(&mut st, &view(&ch), now, &t), None); // retx 2
        assert_eq!(
            observe_outbound(&mut st, &view(&ch), now, &t),
            Some(FlowOutcome::Blackhole)
        ); // retx 3 -> fail
    }

    #[test]
    fn blackhole_via_timeout() {
        let start = Instant::now();
        let mut st = FlowState::new(start);
        let t = tuning();
        observe_outbound(&mut st, &view(&v4_tcp(64, T_CH, 1, &[0x16, 0x03, 0x01, 0, 5, 0x01])), start, &t);

        let later = start + t.verdict_timeout + std::time::Duration::from_millis(1);
        assert_eq!(resolve_timeout(&st, &t, later), Some(FlowOutcome::Blackhole));
    }

    #[test]
    fn success_not_overwritten_by_later_rst() {
        let now = Instant::now();
        let mut st = FlowState::new(now);
        let t = tuning();
        observe_outbound(&mut st, &view(&v4_tcp(64, T_CH, 1, &[0x16, 0x03, 0x01, 0, 5, 0x01])), now, &t);
        observe_inbound(&mut st, &view(&v4_tcp(117, T_CH, 0, &[0x16, 0x03, 0x03, 0, 5, 0x02])), now);
        assert_eq!(st.outcome, Some(FlowOutcome::Success));
        // A later RST (normal close) must not change the verdict.
        assert_eq!(observe_inbound(&mut st, &view(&v4_tcp(117, T_RST, 0, &[])), now), None);
        assert_eq!(st.outcome, Some(FlowOutcome::Success));
    }
}
