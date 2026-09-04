use std::net::IpAddr;
use std::path::PathBuf;
use std::time::Duration;

use crate::strategy::model::{DesyncMethod, FragmentSpec};

/// Where discovery profiles are persisted (M8). `None` in [`EvasionConfig`]
/// disables persistence entirely (forced `--strategy` runs, tests).
#[derive(Clone, Debug)]
pub struct ProfilePaths {
    /// Directory holding one JSON file per network fingerprint.
    pub dir: PathBuf,
    /// Network fingerprint (gateway IPv4 + subnet CIDR + DNS suffix, hashed).
    /// Used verbatim as the file stem.
    pub net_key: String,
}

/// TCP ports treated as TLS. A ClientHello to any of these is a discovery /
/// strategy candidate, and the capture filter's outbound (`DstPort`) and
/// inbound (`SrcPort`) clauses cover them all.
///
/// This is 443 plus **the complete set of Cloudflare HTTPS-proxied ports**
/// (2053, 2083, 2087, 2096, 8443) — Cloudflare publishes exactly these, and
/// Discord (fully Cloudflare-fronted) rotates its `*.discord.media` voice
/// signalling freely across them. It is deliberately NOT "every port": every
/// extra port multiplies the per-packet capture/reinject tax over all of the
/// machine's traffic on that port, and the fake+fragment strategies are
/// calibrated for HTTPS. Override via [`EvasionConfig::tls_ports`] for a
/// service that genuinely runs TLS elsewhere.
pub const DEFAULT_TLS_PORTS: &[u16] = &[443, 2053, 2083, 2087, 2096, 8443];

/// User-facing configuration. Every field has a safe automatic default; the CLI
/// only fills in explicit overrides.
#[derive(Clone, Debug)]
pub struct EvasionConfig {
    /// Substituted for `%hu` in GoodbyeDPI's `MAXPAYLOADSIZE` clause — only
    /// packets with a TCP payload smaller than this (or that look like a
    /// request / TLS handshake) are captured. GoodbyeDPI preset value: 1200.
    pub max_payload_filter: u16,

    /// TCP ports the capture filter and the outbound-ClientHello gate treat as
    /// TLS. Defaults to [`DEFAULT_TLS_PORTS`]. An empty list is treated as
    /// `[443]` by the filter builder.
    pub tls_ports: Vec<u16>,

    /// When `Some`, `udp/53` is added to the capture filter and DNS is
    /// redirected to this address (M10). When `None`, DNS is never touched
    /// (only poisoning detection is logged).
    pub dns_upstream: Option<IpAddr>,

    /// `Some(true)` = always drop QUIC, `Some(false)` = never, `None` = default
    /// (drop-on). Consumed by the QUIC-drop handle in M9.
    pub quic_drop: Option<bool>,

    /// Connection-tracking / verdict timing.
    pub conntrack: ConntrackTuning,
    /// Discovery loop tuning.
    pub discovery: DiscoveryTuning,
    /// Live network-change / rebind tuning.
    pub network: NetworkTuning,

    /// Cap every emitted TCP segment's payload at this size (a safe MSS).
    /// GoodbyeDPI's `--max-payload` default is 1200.
    pub max_segment: u16,

    /// Include `OverlapDisorder` candidates in the discovery grid. OFF by
    /// default: overlap feeds the server junk bytes and can break the handshake
    /// against a first-received-wins stack or a strict middlebox, so it must be
    /// an explicit opt-in for auto-discovery. `--strategy overlap:...` always
    /// works regardless of this flag.
    pub enable_overlap_disorder: bool,

    /// Force the fake desync method. Collapses the discovery grid to one entry.
    pub desync_override: Option<DesyncMethod>,
    /// Force the fragmentation. Collapses the discovery grid to one entry.
    pub fragment_override: Option<FragmentSpec>,
    /// Force the fake TTL (`UserFixed`).
    pub ttl_override: Option<u8>,

    /// Discovery-profile persistence (M8). `None` = in-memory only.
    pub profile: Option<ProfilePaths>,
}

impl Default for EvasionConfig {
    fn default() -> Self {
        Self {
            max_payload_filter: 1200,
            tls_ports: DEFAULT_TLS_PORTS.to_vec(),
            dns_upstream: None,
            quic_drop: None,
            conntrack: ConntrackTuning::default(),
            discovery: DiscoveryTuning::default(),
            network: NetworkTuning::default(),
            max_segment: 1200,
            enable_overlap_disorder: false,
            desync_override: None,
            fragment_override: None,
            ttl_override: None,
            profile: None,
        }
    }
}

impl EvasionConfig {
    /// Ports the outbound-ClientHello gate and the capture filter treat as TLS.
    /// Falls back to `[443]` if [`tls_ports`](Self::tls_ports) was cleared.
    pub fn effective_tls_ports(&self) -> &[u16] {
        if self.tls_ports.is_empty() {
            &[443]
        } else {
            &self.tls_ports
        }
    }

    /// True if `port` is one this engine mutates ClientHellos on.
    pub fn is_tls_port(&self, port: u16) -> bool {
        self.effective_tls_ports().contains(&port)
    }

    /// True if any override is set (discovery grid should be a single entry).
    pub fn has_strategy_override(&self) -> bool {
        self.desync_override.is_some()
            || self.fragment_override.is_some()
            || self.ttl_override.is_some()
    }
}

impl EvasionConfig {
    /// Whether the QUIC-drop handle should be opened for this config.
    pub fn quic_drop_enabled(&self) -> bool {
        self.quic_drop.unwrap_or(true)
    }
}

/// Timing knobs for [`crate::conntrack`]. (M6's `DiscoveryTuning` will absorb
/// these once discovery exists.)
#[derive(Clone, Debug)]
pub struct ConntrackTuning {
    /// Drop a flow this long after its last packet.
    pub idle_timeout: Duration,
    /// After a ClientHello, wait this long for a verdict before calling it
    /// [`Blackhole`](crate::conntrack::FlowOutcome::Blackhole).
    pub verdict_timeout: Duration,
    /// After a `ServerHello`, wait this long with no teardown (RST / fatal TLS
    /// alert) before the handshake is confirmed a
    /// [`Success`](crate::conntrack::FlowOutcome::Success). Catches a DPI that
    /// lets the `ServerHello` through and then resets the flow a beat later
    /// ([`LateReset`](crate::conntrack::FlowOutcome::LateReset)). Real inbound
    /// application data short-circuits the wait. Must stay `< verdict_timeout`
    /// so the `Blackhole` timer never races it.
    pub app_grace: Duration,
    /// This many ClientHello retransmits (no response) => `Blackhole`.
    pub client_hello_retx_fail: u8,
}

impl Default for ConntrackTuning {
    fn default() -> Self {
        Self {
            idle_timeout: Duration::from_secs(60),
            verdict_timeout: Duration::from_secs(5),
            app_grace: Duration::from_secs(1),
            client_hello_retx_fail: 3,
        }
    }
}

/// Tuning for the M6 discovery loop.
#[derive(Clone, Debug)]
pub struct DiscoveryTuning {
    /// Consecutive `Success` verdicts on a candidate before it is promoted to
    /// the target's active strategy.
    pub promote_after_success: u8,
    /// Consecutive failures of the active strategy before it is demoted and
    /// discovery restarts for that target.
    pub demote_after_failure: u8,
    /// An `Explore` trial that was handed out but never resolved stops blocking
    /// its candidate after this long, so a lost or idle-swept flow cannot
    /// permanently shrink the sweep. Must comfortably exceed
    /// `ConntrackTuning::verdict_timeout` plus the ClientHello retransmit window.
    pub in_flight_ttl: Duration,

    /// A target that is only ever passthrough (`Active` with no strategy) or
    /// never resolved (`Probe`) is evicted this long after its last activity —
    /// re-probed for free on the next connection. Bounds a 7/24 process that
    /// would otherwise keep one `TargetState` per hostname ever contacted.
    pub target_idle_evict: Duration,
    /// Backstop: even a valuable target (`Discover` mid-sweep, `Active` with a
    /// working strategy, `Exhausted`) is evicted after this long with no
    /// activity.
    pub target_max_idle: Duration,
    /// Hard ceiling on tracked targets. Past this, the lowest-value,
    /// least-recently-used targets are evicted on the next maintenance tick.
    pub max_targets: usize,
}

impl Default for DiscoveryTuning {
    fn default() -> Self {
        Self {
            promote_after_success: 2,
            demote_after_failure: 3,
            in_flight_ttl: Duration::from_secs(15),
            target_idle_evict: Duration::from_secs(24 * 3600),
            target_max_idle: Duration::from_secs(7 * 24 * 3600),
            max_targets: 4096,
        }
    }
}

/// Tuning for live network-change handling (`Engine::with_live_netkey`).
/// Conceptually separate from [`DiscoveryTuning`] — this governs *when* the
/// engine re-keys its whole discovery session, not how a single sweep behaves.
#[derive(Clone, Debug)]
pub struct NetworkTuning {
    /// After a route-change notification, wait this long with no further
    /// notification before recomputing the NetKey. Absorbs the flapping a
    /// DHCP renew / VPN toggle / Wi-Fi roam produces.
    pub netkey_debounce: Duration,
    /// Minimum wall-clock gap between two *actual* rebinds. A pathological
    /// adapter cannot thrash the profile store faster than this.
    pub min_rebind_interval: Duration,
}

impl Default for NetworkTuning {
    fn default() -> Self {
        Self {
            netkey_debounce: Duration::from_secs(5),
            min_rebind_interval: Duration::from_secs(30),
        }
    }
}
