use std::net::IpAddr;
use std::time::Instant;

use crate::packet::FiveTuple;
use crate::profile::TrialRecord;

use super::events::FlowOutcome;

/// Canonical, direction-independent flow identity (client side).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct FlowKey {
    pub client_ip: IpAddr,
    pub client_port: u16,
    pub server_ip: IpAddr,
    pub server_port: u16,
}

impl FlowKey {
    /// `outbound` = the packet the tuple came from was going client -> server.
    pub fn from_five_tuple(ft: &FiveTuple, outbound: bool) -> Self {
        if outbound {
            Self {
                client_ip: ft.src_ip,
                client_port: ft.src_port,
                server_ip: ft.dst_ip,
                server_port: ft.dst_port,
            }
        } else {
            Self {
                client_ip: ft.dst_ip,
                client_port: ft.dst_port,
                server_ip: ft.src_ip,
                server_port: ft.src_port,
            }
        }
    }
}

/// Per-flow observation state. M3: populated but never used to mutate packets.
#[derive(Debug)]
pub struct FlowState {
    pub created_at: Instant,
    pub last_seen: Instant,

    /// SNI from the ClientHello, if seen.
    pub server_name: Option<String>,

    pub syn_ack_seen: bool,
    /// Guessed original TTL of the remote host (64 / 128 / 255).
    pub remote_initial_ttl: Option<u8>,
    /// Hops to the server, inferred from the SYN-ACK TTL.
    pub hops_to_server: Option<u8>,

    pub client_hello_seen: bool,
    pub client_hello_at: Option<Instant>,
    pub client_hello_seq: Option<u32>,
    pub client_hello_retx: u8,

    pub server_hello_seen: bool,
    /// When the first server `0x16` record was seen — starts the `app_grace`
    /// window after which the handshake is confirmed a `Success` (unless a RST /
    /// fatal alert tears it down first, giving `LateReset`).
    pub server_hello_at: Option<Instant>,
    pub inbound_rst: bool,
    /// Hops from the client to whatever sent the blocking RST/alert, guessed
    /// from its TTL the same way as `hops_to_server` — set only on a
    /// `DpiReset` / `LateReset` verdict. A real server's own reset carries
    /// roughly the same hop count as its SYN-ACK; a lower count here is an
    /// in-path injector, and the number itself is the TTL a `TtlLimited` fake
    /// packet needs to reach it without reaching the real server beyond it.
    pub injector_hops: Option<u8>,

    pub bytes_out: u64,
    pub bytes_in: u64,

    /// Discovery: the target key (SNI or server IP) and the trial applied to
    /// this flow's ClientHello, so the verdict can be attributed back.
    pub target_key: Option<String>,
    pub trial: Option<TrialRecord>,
    /// A strategy batch was already emitted for this flow's ClientHello — a
    /// later ClientHello can only be a retransmit and must pass through
    /// unchanged (avoids retransmit-amplification).
    pub strategy_applied: bool,

    /// Set once a verdict is reached; further packets do not reclassify.
    pub outcome: Option<FlowOutcome>,
}

impl FlowState {
    pub fn new(now: Instant) -> Self {
        Self {
            created_at: now,
            last_seen: now,
            server_name: None,
            syn_ack_seen: false,
            remote_initial_ttl: None,
            hops_to_server: None,
            client_hello_seen: false,
            client_hello_at: None,
            client_hello_seq: None,
            client_hello_retx: 0,
            server_hello_seen: false,
            server_hello_at: None,
            inbound_rst: false,
            injector_hops: None,
            bytes_out: 0,
            bytes_in: 0,
            target_key: None,
            trial: None,
            strategy_applied: false,
            outcome: None,
        }
    }
}
