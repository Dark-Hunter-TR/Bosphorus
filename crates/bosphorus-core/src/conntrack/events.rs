use std::time::Instant;

use crate::config::ConntrackTuning;
use crate::packet::{looks_like_client_hello, tls_content_type, PacketView};

use super::flow::FlowState;

/// How a flow ended, from the engine's point of view.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FlowOutcome {
    /// Server responded with a TLS handshake and it held: either real inbound
    /// application data flowed, or the `app_grace` window elapsed after the
    /// `ServerHello` with no teardown.
    Success,
    /// A RST arrived from the server after our ClientHello and before any
    /// `ServerHello` — the classic in-path DPI reset.
    DpiReset,
    /// The `ServerHello` got through, but a RST / fatal TLS alert tore the flow
    /// down within `app_grace` — before the handshake could be confirmed by
    /// surviving traffic. A "delayed reset" DPI. Scored as a failure.
    LateReset,
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

/// Record the hop count implied by a blocking packet's own TTL (a DPI
/// fingerprint: the real server's own reset would carry roughly its SYN-ACK's
/// hop count, so a lower one here points at an in-path injector, and the
/// number is exactly the TTL a `TtlLimited` fake needs to reach it without
/// reaching the real server beyond it — see `TtlPolicy::Discovered`). Best
/// effort: silently leaves `injector_hops` at `None` if the TTL doesn't match
/// any common initial value.
fn note_injector_hops(st: &mut FlowState, v: &PacketView<'_>) {
    st.injector_hops = guess_hops(v.ttl()).map(|(_, hops)| hops);
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
pub fn observe_inbound(
    st: &mut FlowState,
    v: &PacketView<'_>,
    now: Instant,
    tuning: &ConntrackTuning,
) -> Option<FlowOutcome> {
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
                // The handshake got through. Reset inside the grace window =
                // delayed-reset DPI; past it, the flow held and this is a close.
                if within_grace(st, now, tuning) {
                    note_injector_hops(st, v);
                    set(st, FlowOutcome::LateReset)
                } else {
                    set(st, FlowOutcome::Success)
                }
            } else if st.client_hello_seen {
                note_injector_hops(st, v);
                set(st, FlowOutcome::DpiReset)
            } else {
                set(st, FlowOutcome::TlsError)
            };
        }
    }

    // Any TLS record from the server after our ClientHello => the handshake is
    // progressing. `0x16` handshake (ServerHello) or `0x17` application data.
    match tls_content_type(payload) {
        // First ServerHello: verdict deferred. A delayed-reset DPI lets the
        // ServerHello through and RSTs a beat later — confirm via real app data
        // (below) or the `app_grace` window in `resolve_timeout`.
        Some(0x16) if !st.server_hello_seen => {
            st.server_hello_seen = true;
            st.server_hello_at = Some(now);
        }
        // Real inbound application data — the connection is carrying traffic.
        Some(0x17) if st.client_hello_seen => return set(st, FlowOutcome::Success),
        Some(0x15) if st.client_hello_seen && !st.server_hello_seen => {
            return set(st, FlowOutcome::TlsError); // TLS alert before any ServerHello
        }
        // A *fatal* alert (level byte == 2) inside the grace window is a
        // teardown; a warning alert (`close_notify`, level 1) is a clean close.
        Some(0x15)
            if st.server_hello_seen
                && payload.get(5) == Some(&2)
                && within_grace(st, now, tuning) =>
        {
            note_injector_hops(st, v);
            return set(st, FlowOutcome::LateReset)
        }
        _ => {}
    }
    None
}

/// True while we are still inside the post-`ServerHello` `app_grace` window.
fn within_grace(st: &FlowState, now: Instant, tuning: &ConntrackTuning) -> bool {
    st.server_hello_at
        .is_some_and(|at| now.saturating_duration_since(at) < tuning.app_grace)
}

/// Called periodically by the engine tick. Resolves flows that have gone quiet.
pub fn resolve_timeout(st: &FlowState, tuning: &ConntrackTuning, now: Instant) -> Option<FlowOutcome> {
    if st.outcome.is_some() {
        return None;
    }
    // ServerHello seen and no teardown: once `app_grace` has elapsed the
    // delayed-reset window has closed — confirm the handshake a `Success`.
    if let Some(sh_at) = st.server_hello_at {
        if !st.inbound_rst && now.duration_since(sh_at) >= tuning.app_grace {
            return Some(FlowOutcome::Success);
        }
        return None; // still inside the grace window — keep waiting
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
    use std::time::Duration;

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

    const T_FIN: u8 = 0x11; // FIN|ACK

    /// A TLS record: `[type, 0x03, 0x03, len_be16, body..]`.
    fn tls_rec(content_type: u8, body: &[u8]) -> Vec<u8> {
        let mut r = vec![content_type, 0x03, 0x03];
        r.extend_from_slice(&(body.len() as u16).to_be_bytes());
        r.extend_from_slice(body);
        r
    }
    fn server_hello() -> Vec<u8> {
        tls_rec(0x16, &[0x02, 0, 0, 0]) // handshake type 0x02 = ServerHello
    }
    fn app_data() -> Vec<u8> {
        tls_rec(0x17, &[0xaa, 0xbb, 0xcc])
    }
    fn fatal_alert() -> Vec<u8> {
        tls_rec(0x15, &[0x02, 0x28]) // level 2 (fatal), handshake_failure
    }
    fn close_notify() -> Vec<u8> {
        tls_rec(0x15, &[0x01, 0x00]) // level 1 (warning), close_notify
    }

    #[test]
    fn open_site_is_success() {
        let now = Instant::now();
        let mut st = FlowState::new(now);
        let t = tuning();

        let sa = v4_tcp(117, T_SA, 0, &[]);
        assert_eq!(observe_inbound(&mut st, &view(&sa), now, &t), None);
        assert!(st.syn_ack_seen);
        assert_eq!(st.remote_initial_ttl, Some(128));
        assert_eq!(st.hops_to_server, Some(11));

        let ch = v4_tcp(64, T_CH, 1000, &[0x16, 0x03, 0x01, 0x00, 0x05, 0x01]);
        assert_eq!(observe_outbound(&mut st, &view(&ch), now, &t), None);
        assert!(st.client_hello_seen);

        // ServerHello alone no longer decides — the verdict is deferred.
        let sh = v4_tcp(117, T_CH, 0, &server_hello());
        assert_eq!(observe_inbound(&mut st, &view(&sh), now, &t), None);
        assert!(st.server_hello_seen);
        assert!(st.server_hello_at.is_some());
        assert_eq!(st.outcome, None);

        // Real inbound application data confirms it immediately.
        let ad = v4_tcp(117, T_CH, 3, &app_data());
        assert_eq!(observe_inbound(&mut st, &view(&ad), now, &t), Some(FlowOutcome::Success));
        assert_eq!(st.outcome, Some(FlowOutcome::Success));
    }

    #[test]
    fn serverhello_then_quiet_grace_window_is_success() {
        let now = Instant::now();
        let mut st = FlowState::new(now);
        let t = tuning();

        observe_outbound(&mut st, &view(&v4_tcp(64, T_CH, 1, &[0x16, 0x03, 0x01, 0, 5, 0x01])), now, &t);
        assert_eq!(observe_inbound(&mut st, &view(&v4_tcp(117, T_CH, 0, &server_hello())), now, &t), None);

        // Still inside the grace window: no verdict yet.
        let mid = now + t.app_grace / 2;
        assert_eq!(resolve_timeout(&st, &t, mid), None);

        // Grace elapsed with no teardown -> Success.
        let after = now + t.app_grace + Duration::from_millis(1);
        assert_eq!(resolve_timeout(&st, &t, after), Some(FlowOutcome::Success));
    }

    #[test]
    fn rst_within_grace_after_serverhello_is_late_reset() {
        let now = Instant::now();
        let mut st = FlowState::new(now);
        let t = tuning();

        observe_outbound(&mut st, &view(&v4_tcp(64, T_CH, 1, &[0x16, 0x03, 0x01, 0, 5, 0x01])), now, &t);
        observe_inbound(&mut st, &view(&v4_tcp(117, T_CH, 0, &server_hello())), now, &t);

        let early = now + t.app_grace / 2;
        let rst = v4_tcp(200, T_RST, 0, &[]);
        assert_eq!(observe_inbound(&mut st, &view(&rst), early, &t), Some(FlowOutcome::LateReset));
        assert_eq!(st.outcome, Some(FlowOutcome::LateReset));
    }

    #[test]
    fn rst_after_grace_after_serverhello_is_a_clean_close() {
        let now = Instant::now();
        let mut st = FlowState::new(now);
        let t = tuning();

        observe_outbound(&mut st, &view(&v4_tcp(64, T_CH, 1, &[0x16, 0x03, 0x01, 0, 5, 0x01])), now, &t);
        observe_inbound(&mut st, &view(&v4_tcp(117, T_CH, 0, &server_hello())), now, &t);

        // RST arrives only after the grace window: the flow held, this is a close.
        let late = now + t.app_grace + Duration::from_millis(50);
        let rst = v4_tcp(200, T_RST, 0, &[]);
        assert_eq!(observe_inbound(&mut st, &view(&rst), late, &t), Some(FlowOutcome::Success));
    }

    #[test]
    fn clean_close_notify_after_serverhello_is_not_a_reset() {
        let now = Instant::now();
        let mut st = FlowState::new(now);
        let t = tuning();

        observe_outbound(&mut st, &view(&v4_tcp(64, T_CH, 1, &[0x16, 0x03, 0x01, 0, 5, 0x01])), now, &t);
        observe_inbound(&mut st, &view(&v4_tcp(117, T_CH, 0, &server_hello())), now, &t);

        // A warning-level alert (close_notify) inside the grace window is a
        // clean close, not a teardown — no verdict here...
        let mid = now + t.app_grace / 2;
        assert_eq!(observe_inbound(&mut st, &view(&v4_tcp(117, T_CH, 3, &close_notify())), mid, &t), None);
        // ...and a following FIN is ignored too.
        assert_eq!(observe_inbound(&mut st, &view(&v4_tcp(117, T_FIN, 4, &[])), mid, &t), None);
        assert_eq!(st.outcome, None);
        // The grace window still resolves it to Success.
        let after = now + t.app_grace + Duration::from_millis(1);
        assert_eq!(resolve_timeout(&st, &t, after), Some(FlowOutcome::Success));
    }

    #[test]
    fn fatal_alert_within_grace_after_serverhello_is_late_reset() {
        let now = Instant::now();
        let mut st = FlowState::new(now);
        let t = tuning();

        observe_outbound(&mut st, &view(&v4_tcp(64, T_CH, 1, &[0x16, 0x03, 0x01, 0, 5, 0x01])), now, &t);
        observe_inbound(&mut st, &view(&v4_tcp(117, T_CH, 0, &server_hello())), now, &t);

        let mid = now + t.app_grace / 2;
        assert_eq!(
            observe_inbound(&mut st, &view(&v4_tcp(117, T_CH, 3, &fatal_alert())), mid, &t),
            Some(FlowOutcome::LateReset)
        );
    }

    #[test]
    fn app_grace_is_shorter_than_verdict_timeout() {
        let t = ConntrackTuning::default();
        assert!(t.app_grace < t.verdict_timeout, "the Blackhole timer must not race the grace window");
    }

    #[test]
    fn blocked_site_rst_is_dpi_reset() {
        let now = Instant::now();
        let mut st = FlowState::new(now);
        let t = tuning();

        observe_inbound(&mut st, &view(&v4_tcp(117, T_SA, 0, &[])), now, &t);
        observe_outbound(&mut st, &view(&v4_tcp(64, T_CH, 42, &[0x16, 0x03, 0x01, 0, 5, 0x01])), now, &t);

        let rst = v4_tcp(200, T_RST, 0, &[]);
        assert_eq!(observe_inbound(&mut st, &view(&rst), now, &t), Some(FlowOutcome::DpiReset));
    }

    #[test]
    fn rst_before_clienthello_is_tls_error() {
        let now = Instant::now();
        let mut st = FlowState::new(now);
        let t = tuning();
        observe_inbound(&mut st, &view(&v4_tcp(117, T_SA, 0, &[])), now, &t);
        let rst = v4_tcp(117, T_RST, 0, &[]);
        assert_eq!(observe_inbound(&mut st, &view(&rst), now, &t), Some(FlowOutcome::TlsError));
        assert_eq!(st.injector_hops, None, "not a DPI verdict, no injector fingerprint taken");
    }

    #[test]
    fn dpi_reset_records_the_injecting_devices_hop_count() {
        let now = Instant::now();
        let mut st = FlowState::new(now);
        let t = tuning();

        // Server is 11 hops away (SYN-ACK TTL 117 -> initial 128).
        observe_inbound(&mut st, &view(&v4_tcp(117, T_SA, 0, &[])), now, &t);
        observe_outbound(&mut st, &view(&v4_tcp(64, T_CH, 42, &[0x16, 0x03, 0x01, 0, 5, 0x01])), now, &t);

        // The RST itself arrives with TTL 60 -> initial 64 -> only 4 hops away:
        // much closer than the server, the classic in-path-injector signature.
        let rst = v4_tcp(60, T_RST, 0, &[]);
        assert_eq!(observe_inbound(&mut st, &view(&rst), now, &t), Some(FlowOutcome::DpiReset));
        assert_eq!(st.injector_hops, Some(4));
    }

    #[test]
    fn late_reset_also_records_injector_hops() {
        let now = Instant::now();
        let mut st = FlowState::new(now);
        let t = tuning();

        observe_outbound(&mut st, &view(&v4_tcp(64, T_CH, 1, &[0x16, 0x03, 0x01, 0, 5, 0x01])), now, &t);
        observe_inbound(&mut st, &view(&v4_tcp(117, T_CH, 0, &server_hello())), now, &t);

        let early = now + t.app_grace / 2;
        let rst = v4_tcp(60, T_RST, 0, &[]);
        assert_eq!(observe_inbound(&mut st, &view(&rst), early, &t), Some(FlowOutcome::LateReset));
        assert_eq!(st.injector_hops, Some(4));
    }

    #[test]
    fn injector_hops_is_none_when_the_ttl_matches_no_common_initial_value() {
        let now = Instant::now();
        let mut st = FlowState::new(now);
        let t = tuning();
        observe_outbound(&mut st, &view(&v4_tcp(64, T_CH, 42, &[0x16, 0x03, 0x01, 0, 5, 0x01])), now, &t);
        // TTL 200: > 32 hops from every common initial (64/128/255) — guess_hops fails.
        let rst = v4_tcp(200, T_RST, 0, &[]);
        assert_eq!(observe_inbound(&mut st, &view(&rst), now, &t), Some(FlowOutcome::DpiReset));
        assert_eq!(st.injector_hops, None);
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
        observe_inbound(&mut st, &view(&v4_tcp(117, T_CH, 0, &server_hello())), now, &t);
        // App data (well inside the grace window) confirms the Success.
        observe_inbound(&mut st, &view(&v4_tcp(117, T_CH, 3, &app_data())), now, &t);
        assert_eq!(st.outcome, Some(FlowOutcome::Success));
        // A later RST (normal close) must not change the verdict.
        assert_eq!(observe_inbound(&mut st, &view(&v4_tcp(117, T_RST, 0, &[])), now, &t), None);
        assert_eq!(st.outcome, Some(FlowOutcome::Success));
    }
}
