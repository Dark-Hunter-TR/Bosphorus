use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;
use parking_lot::Mutex;

use crate::censored::CensoredIps;
use crate::config::{EvasionConfig, ProfilePaths, QuicPolicy};
use crate::conntrack::{self, FlowKey, FlowOutcome, FlowTable};
use crate::discovery::{Discovery, DiscoveryEvent, TargetSummary, VerdictTiming};
use crate::error::CoreError;
use crate::packet::{find_sni, looks_like_client_hello, PacketView};
use crate::profile::{NetPhase, TrialKind, TrialRecord};
use crate::source_sink::{
    CaptureMeta, ChecksumOp, ChecksumWhich, PacketSink, PacketSource, SendBatch,
};
use crate::strategy::{apply_strategy, Disposition, Strategy, TransformCtx};
use crate::MAX_CAPTURE;

/// What the engine decided to do with one captured packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    ForwardOriginal,
    DropOriginal,
    ForwardBatchThenOriginal,
    ForwardBatchOnly,
}

#[derive(Debug, Default, Clone, Copy)]
pub struct RunStats {
    pub packets: u64,
    pub bytes: u64,
    pub dropped: u64,
    pub batches: u64,
    pub injected: u64,
}

/// Cooperative stop flag shared with a Ctrl+C / timer handler.
pub struct StopFlag(AtomicBool);

impl StopFlag {
    pub fn new() -> Self {
        Self(AtomicBool::new(false))
    }
    pub fn stop(&self) {
        self.0.store(true, Ordering::SeqCst);
    }
    pub fn is_stopped(&self) -> bool {
        self.0.load(Ordering::SeqCst)
    }
}

impl Default for StopFlag {
    fn default() -> Self {
        Self::new()
    }
}

/// How often `tick` emits the one-line discovery progress summary.
const DIGEST_EVERY: Duration = Duration::from_secs(10);
/// How often `tick` writes the discovery profile to disk.
const PERSIST_EVERY: Duration = Duration::from_secs(30);
/// How often `tick` emits the `bosphorus::mem` footprint digest.
const MEM_EVERY: Duration = Duration::from_secs(60);
/// How often `tick` sweeps stale discovery targets.
const EVICT_EVERY: Duration = Duration::from_secs(60);

/// Injected NetKey source. Returns `(human, key)` — a readable description and
/// the hashed profile-file stem. The CLI wraps its Windows IP-Helper
/// `netkey::compute`; tests pass a scripted stub. Keeps `bosphorus-core`
/// platform-agnostic.
pub type NetKeyFn = Arc<dyn Fn() -> (String, String) + Send + Sync>;

/// Everything scoped to one network. Swapped wholesale on a live rebind so the
/// per-packet path never sees a half-updated view.
struct NetworkSession {
    discovery: Discovery,
    /// Destinations this network's censor was caught interfering with, used to
    /// decide which QUIC attempts to refuse. Scoped to the session because
    /// interference is a property of the network, not of the host: the same
    /// address can be censored on one network and clean on the next.
    censored: CensoredIps,
    /// Where *this* network's profile lives. `None` = `nonet` (in-memory only,
    /// never persisted — a failed fingerprint must not pollute a real network's
    /// file).
    profile: Option<ProfilePaths>,
    /// Readable NetKey inputs, for logging.
    #[allow(dead_code)]
    net_human: Option<String>,
}

/// Build a fresh session for `profile` (loading its persisted state if present).
/// Shared by `Engine::new` (initial session) and `Engine::rebind`.
fn build_session(
    cfg: &EvasionConfig,
    profile: Option<ProfilePaths>,
    net_human: Option<String>,
) -> NetworkSession {
    let discovery = Discovery::new(cfg);
    if let Some(p) = &profile {
        match crate::profile::persist::load(&p.dir, &p.net_key) {
            Some(file) => {
                let grew = file.grid_signature != discovery.grid_signature();
                let (restored, degraded) = discovery.load_persisted(&file);
                tracing::info!(
                    target: "bosphorus::discovery",
                    restored, degraded, grid_changed = grew,
                    "discovery profile loaded"
                );
            }
            None => tracing::info!(
                target: "bosphorus::discovery", "no discovery profile on disk (starting fresh)"
            ),
        }
    }
    NetworkSession { discovery, censored: CensoredIps::default(), profile, net_human }
}

pub struct Engine {
    cfg: EvasionConfig,
    flows: FlowTable,
    /// The current network's discovery + profile. Read once per `process` /
    /// `tick`; replaced atomically by `rebind` (tick thread only).
    session: ArcSwap<NetworkSession>,
    /// `Some` = CLI `--strategy` override: run exactly this, bypass discovery.
    forced: Option<Strategy>,
    /// Last time `tick` printed the progress digest (throttle).
    digest_at: Mutex<Instant>,
    /// Last time `tick` wrote the profile to disk (throttle).
    persist_at: Mutex<Instant>,
    /// Last time `tick` emitted the `bosphorus::mem` digest (throttle).
    mem_at: Mutex<Instant>,
    /// Last time `tick` swept stale discovery targets (throttle).
    evict_at: Mutex<Instant>,
    /// JSON byte count of the last profile write (0 until the first write, or
    /// in a forced / no-profile run). Read by the `bosphorus::mem` digest.
    last_profile_bytes: AtomicUsize,

    // --- live network re-keying (only populated by `with_live_netkey`) ---
    /// `None` = no live re-keying; `maybe_rebind` is then a no-op.
    netkey_provider: Option<NetKeyFn>,
    /// Set by `mark_netkey_dirty` (route-change callback); consumed by
    /// `maybe_rebind` on the tick thread.
    netkey_dirty: AtomicBool,
    /// Instant of the most recent `mark_netkey_dirty` — the debounce anchor.
    netkey_changed_at: Mutex<Instant>,
    /// Instant of the last *actual* rebind (`None` = never) — the
    /// `min_rebind_interval` anchor. The first rebind is never rate-limited.
    last_rebind_at: Mutex<Option<Instant>>,

    /// Cross-network ISP seed pool (feature C). `None` unless the CLI passed
    /// `--isp`. Held here so a live rebind can re-attach it to the new session's
    /// `Discovery`.
    isp_pool: OnceLock<Arc<crate::profile::IspPool>>,
}

impl Engine {
    /// Automatic per-target discovery (the default). One fixed network session
    /// built from `cfg.profile`; no live re-keying.
    pub fn new(cfg: EvasionConfig) -> Self {
        let flows = FlowTable::new(cfg.conntrack.idle_timeout);
        // Initial session from the configured profile (discovery runs only; the
        // CLI passes `profile: None` for forced `--strategy` runs).
        let session = build_session(&cfg, cfg.profile.clone(), None);

        let now = Instant::now();
        Self {
            cfg,
            flows,
            session: ArcSwap::from_pointee(session),
            forced: None,
            digest_at: Mutex::new(now),
            persist_at: Mutex::new(now),
            mem_at: Mutex::new(now),
            evict_at: Mutex::new(now),
            last_profile_bytes: AtomicUsize::new(0),
            netkey_provider: None,
            netkey_dirty: AtomicBool::new(false),
            netkey_changed_at: Mutex::new(now),
            last_rebind_at: Mutex::new(None),
            isp_pool: OnceLock::new(),
        }
    }

    /// Run one fixed strategy for every ClientHello (manual grid probing).
    pub fn new_with_strategy(cfg: EvasionConfig, strategy: Strategy) -> Self {
        let mut e = Self::new(cfg);
        e.forced = Some(strategy);
        e
    }

    /// Auto-discovery with live NetKey re-keying: when the machine changes
    /// network, [`mark_netkey_dirty`](Self::mark_netkey_dirty) + the next
    /// [`tick`](Self::tick) recompute the NetKey and, if it changed, flush the
    /// old profile and swap in the new network's session — no restart.
    pub fn with_live_netkey(cfg: EvasionConfig, provider: NetKeyFn) -> Self {
        let mut e = Self::new(cfg);
        e.netkey_provider = Some(provider);
        e
    }

    /// Arm a rebind check on the next `tick`. Cheap; safe to call from an OS
    /// route-change callback thread.
    pub fn mark_netkey_dirty(&self) {
        self.netkey_dirty.store(true, Ordering::Relaxed);
        *self.netkey_changed_at.lock() = Instant::now();
    }

    pub fn config(&self) -> &EvasionConfig {
        &self.cfg
    }

    /// Attach the cross-network ISP seed pool (feature C, `--isp`). Write-once;
    /// applied to the current session and re-applied to any session a later
    /// rebind builds.
    pub fn set_isp_pool(&self, pool: Arc<crate::profile::IspPool>) {
        let _ = self.isp_pool.set(Arc::clone(&pool));
        self.session.load().discovery.set_isp_pool(pool);
    }

    /// Run `f` against the current network session's `Discovery` (e.g. to read
    /// `promoted_for_isp` at shutdown). Reflects the live session after a rebind.
    pub fn with_discovery<R>(&self, f: impl FnOnce(&Discovery) -> R) -> R {
        f(&self.session.load().discovery)
    }
    /// The profile the current network session persists to (`None` for `nonet`
    /// or a forced run). Reflects the live session, i.e. survives a rebind.
    pub fn current_profile(&self) -> Option<ProfilePaths> {
        self.session.load().profile.clone()
    }
    pub fn flows(&self) -> &FlowTable {
        &self.flows
    }
    pub fn discovery_summary(&self) -> Vec<TargetSummary> {
        self.session.load().discovery.summary()
    }
    /// Cheap single-target phase lookup (no summary build). Used by `--mem-bench`.
    pub fn target_phase(&self, key: &str) -> Option<crate::profile::NetPhase> {
        self.session.load().discovery.target_phase(key)
    }
    pub fn grid_len(&self) -> usize {
        self.session.load().discovery.grid_len()
    }
    /// True when running auto-discovery (no `--strategy` override).
    pub fn is_discovery(&self) -> bool {
        self.forced.is_none()
    }

    /// Per-packet decision: feed conntrack, feed/act on discovery, decide.
    pub fn process(
        &self,
        packet: &mut [u8],
        meta: &mut CaptureMeta,
        out: &mut SendBatch,
    ) -> Decision {
        if meta.impostor {
            return Decision::ForwardOriginal; // our own injected packet
        }
        let Ok(view) = PacketView::parse(packet) else {
            return Decision::ForwardOriginal;
        };
        let now = Instant::now();

        // One consistent network session for this packet (a rebind on the tick
        // thread swaps atomically; we never straddle two).
        let session = self.session.load();

        if view.is_udp() {
            return self.decide_quic(&session.censored, &view, meta, now);
        }
        if !view.is_tcp() {
            return Decision::ForwardOriginal;
        }
        let Some(ft) = view.five_tuple() else {
            return Decision::ForwardOriginal;
        };
        let key = FlowKey::from_five_tuple(&ft, meta.outbound);

        // --- connection tracking / verdict ---
        let verdict = self.flows.with_mut(key, now, |st| {
            if meta.outbound {
                conntrack::observe_outbound(st, &view, now, &self.cfg.conntrack)
            } else {
                conntrack::observe_inbound(st, &view, now, &self.cfg.conntrack)
            }
        });
        if let Some(outcome) = verdict {
            let (name, trial, target, ch_at, retx, injector_hops) = self
                .flows
                .peek(&key, |st| {
                    (
                        st.server_name.clone(),
                        st.trial,
                        st.target_key.clone(),
                        st.client_hello_at,
                        st.client_hello_retx,
                        st.injector_hops,
                    )
                })
                .unwrap_or((None, None, None, None, 0, None));
            let timing = VerdictTiming {
                latency: ch_at.map(|t| now.saturating_duration_since(t)),
                retx,
                injector_hops,
            };
            log_outcome(&key, name.as_deref(), outcome, "packet");
            note_if_censored(&session.censored, &key, outcome, now);
            self.feed_discovery(&session.discovery, target.as_deref(), trial, outcome, timing);
        }

        // --- strategy on outbound ClientHello ---
        if meta.outbound
            && view.dst_port().is_some_and(|p| self.cfg.is_tls_port(p))
            && looks_like_client_hello(view.payload())
        {
            return self.act_on_client_hello(&session.discovery, &key, &view, meta, out, now);
        }

        Decision::ForwardOriginal
    }

    fn act_on_client_hello(
        &self,
        discovery: &Discovery,
        key: &FlowKey,
        view: &PacketView<'_>,
        meta: &mut CaptureMeta,
        out: &mut SendBatch,
        now: Instant,
    ) -> Decision {
        // Retransmit-aware: a strategy was already emitted for this flow's
        // ClientHello. A later ClientHello can only be a retransmit — pass it
        // through unchanged so it isn't re-desynced (avoids amplification).
        if self.flows.peek(key, |st| st.strategy_applied).unwrap_or(false) {
            tracing::debug!(
                target: "bosphorus::strategy",
                server_ip = %key.server_ip, client_port = key.client_port,
                "ClientHello retransmit after strategy already applied; passthrough"
            );
            return Decision::ForwardOriginal;
        }

        let hops = self.flows.peek(key, |st| st.hops_to_server).flatten();

        // Which strategy? forced override, or ask discovery.
        let (target, strat, trial, discovered_ttl): (String, Option<Strategy>, TrialRecord, Option<u8>) =
            match &self.forced {
                Some(s) => {
                    let target = sni_target(view.payload()).unwrap_or_else(|| key.server_ip.to_string());
                    (
                        target,
                        Some(s.clone()),
                        TrialRecord { id: Some(s.id()), kind: TrialKind::Exploit },
                        None,
                    )
                }
                None => {
                    // Discovery must key by SNI. A fragmented / ECH ClientHello with
                    // no readable SNI is NOT registered as an IP-keyed target and is
                    // NOT mutated — it either reuses a target already learned for
                    // this exact flow, or it passes through untouched.
                    let target = match sni_target(view.payload())
                        .or_else(|| self.flows.peek(key, |st| st.target_key.clone()).flatten())
                    {
                        Some(t) => t,
                        None => {
                            tracing::debug!(
                                target: "bosphorus::discovery",
                                server_ip = %key.server_ip, client_port = key.client_port,
                                "ClientHello without readable SNI (fragmented/ECH); passthrough, no discovery"
                            );
                            return Decision::ForwardOriginal;
                        }
                    };
                    let server_ttl = self.flows.peek(key, |st| st.remote_initial_ttl).flatten();
                    let a = discovery.assign(&target, server_ttl);
                    (target, a.strategy, TrialRecord { id: a.id, kind: a.kind }, a.discovered_ttl)
                }
            };

        self.flows.with_mut(*key, now, |st| {
            st.target_key = Some(target.clone());
            st.trial = Some(trial);
        });

        let Some(strat) = strat else {
            tracing::info!(
                target: "bosphorus::discovery",
                server = %target, kind = ?trial.kind,
                "passthrough (control / not blocked)"
            );
            return Decision::ForwardOriginal;
        };

        let ctx = TransformCtx {
            view,
            meta,
            hops_to_server: hops,
            discovered_ttl,
            max_seg: self.cfg.max_segment as usize,
        };
        match apply_strategy(&strat, &ctx, out) {
            Ok(Disposition::EmitBatchDropOriginal) => {
                self.flows.with_mut(*key, now, |st| st.strategy_applied = true);
                self.log_applied(&target, &strat, trial.kind, out.len());
                Decision::ForwardBatchOnly
            }
            Ok(Disposition::EmitBatchThenOriginal) => {
                self.flows.with_mut(*key, now, |st| st.strategy_applied = true);
                self.log_applied(&target, &strat, trial.kind, out.len());
                Decision::ForwardBatchThenOriginal
            }
            Ok(Disposition::PassThrough) => Decision::ForwardOriginal,
            Err(e) => {
                // This candidate can't be built for this target (e.g. `frag@sni`
                // on a ClientHello with no SNI). Rule it out now and forward
                // the ClientHello unchanged this time.
                tracing::debug!(
                    target: "bosphorus::strategy",
                    server = %target, strategy = %strat.describe(), error = %e,
                    "candidate unbuildable for this target; skipping it"
                );
                if self.forced.is_none() {
                    if let Some(id) = trial.id {
                        if let Some((ev, phase)) =
                            discovery.record(&target, Some(id), FlowOutcome::TlsError)
                        {
                            log_discovery(&target, &ev, phase);
                        }
                    }
                    self.flows.with_mut(*key, now, |st| st.trial = None);
                }
                Decision::ForwardOriginal
            }
        }
    }

    fn log_applied(&self, target: &str, strat: &Strategy, kind: TrialKind, parts: usize) {
        tracing::info!(
            target: "bosphorus::strategy",
            server = %target,
            strategy = %strat.describe(),
            ?kind,
            parts,
            "applied strategy to ClientHello"
        );
    }

    /// Decide a captured UDP datagram. Only reached under
    /// [`QuicPolicy::Blocked`] — the other policies keep UDP out of the capture
    /// filter entirely, so this costs nothing when QUIC handling is off.
    ///
    /// Refusing the datagram is the whole mechanism: a client that gets no
    /// answer to its Initials abandons HTTP/3 for the host and reconnects over
    /// TCP, which is the path Bosphorus actually has a learned strategy for.
    fn decide_quic(
        &self,
        censored: &CensoredIps,
        view: &PacketView<'_>,
        meta: &CaptureMeta,
        now: Instant,
    ) -> Decision {
        if self.cfg.quic != QuicPolicy::Blocked || !meta.outbound {
            return Decision::ForwardOriginal;
        }
        if !view.dst_port().is_some_and(|p| self.cfg.is_tls_port(p)) {
            return Decision::ForwardOriginal;
        }
        if !crate::packet::is_quic_connection_attempt(view.payload()) {
            return Decision::ForwardOriginal;
        }
        let dst = view.dst_ip();
        if !censored.contains(&dst, now) {
            return Decision::ForwardOriginal;
        }
        tracing::debug!(
            target: "bosphorus::quic",
            server_ip = %dst,
            "refused a QUIC connection attempt to a censored destination; falling back to TCP"
        );
        Decision::DropOriginal
    }

    fn feed_discovery(
        &self,
        discovery: &Discovery,
        target: Option<&str>,
        trial: Option<TrialRecord>,
        outcome: FlowOutcome,
        timing: VerdictTiming,
    ) {
        if self.forced.is_some() {
            return;
        }
        let (Some(target), Some(trial)) = (target, trial) else {
            return;
        };
        if let Some((ev, phase)) = discovery.record_timed(target, trial.id, outcome, timing) {
            log_discovery(target, &ev, phase);
        }
    }

    /// Blocking capture loop.
    pub fn run_main(
        &self,
        src: &mut dyn PacketSource,
        sink: &mut dyn PacketSink,
        stop: &StopFlag,
    ) -> Result<RunStats, CoreError> {
        let mut buf = vec![0u8; MAX_CAPTURE];
        let mut stats = RunStats::default();

        while !stop.is_stopped() {
            let captured = match src.recv(&mut buf) {
                Ok(c) => c,
                Err(CoreError::SourceShutdown) => break,
                Err(e) => return Err(e),
            };
            stats.packets += 1;
            stats.bytes += captured.data.len() as u64;

            let mut meta = captured.meta;
            let mut batch = SendBatch::new();
            let decision = self.process(captured.data, &mut meta, &mut batch);

            match decision {
                Decision::ForwardOriginal => {
                    sink.inject(captured.data, &meta)?;
                    stats.injected += 1;
                }
                Decision::DropOriginal => stats.dropped += 1,
                Decision::ForwardBatchThenOriginal => {
                    emit_batch(sink, &mut batch, &mut stats)?;
                    sink.inject(captured.data, &meta)?;
                    stats.injected += 1;
                }
                Decision::ForwardBatchOnly => {
                    emit_batch(sink, &mut batch, &mut stats)?;
                    stats.dropped += 1; // original replaced by the batch
                }
            }
        }
        Ok(stats)
    }

    /// Periodic maintenance: (optionally) rebind to a changed network, sweep
    /// idle flows, resolve verdict timeouts (and feed those verdicts to
    /// discovery). Runs on the caller's tick thread.
    pub fn tick(&self, now: Instant) {
        self.maybe_rebind(now); // may swap the session below

        let session = self.session.load();

        let swept = self.flows.sweep(now);
        if swept > 0 {
            tracing::debug!(target: "bosphorus::conntrack", swept, "swept idle flows");
        }
        for rf in self.flows.resolve_timeouts(&self.cfg.conntrack, now) {
            log_outcome(&rf.key, rf.server_name.as_deref(), rf.outcome, "timeout");
            // A timeout-resolved flow never carries a blocking packet to
            // fingerprint (DpiReset/LateReset only ever fire on the live
            // packet path above).
            let timing = VerdictTiming { latency: rf.latency, retx: rf.retx, injector_hops: None };
            self.feed_discovery(
                &session.discovery,
                rf.target_key.as_deref(),
                rf.trial,
                rf.outcome,
                timing,
            );
        }

        self.progress_digest(&session.discovery, now);
        self.maybe_evict(&session, now);
        self.maybe_persist(&session, now);
        self.mem_digest(&session.discovery, now);
    }

    /// Debounced, rate-limited live NetKey re-keying. No-op unless
    /// [`with_live_netkey`](Self::with_live_netkey) supplied a provider and
    /// [`mark_netkey_dirty`](Self::mark_netkey_dirty) armed it. Tick thread only.
    fn maybe_rebind(&self, now: Instant) {
        let Some(provider) = self.netkey_provider.as_ref() else { return };
        if !self.netkey_dirty.load(Ordering::Relaxed) {
            return;
        }
        let snap = *self.netkey_changed_at.lock();
        if now.saturating_duration_since(snap) < self.cfg.network.netkey_debounce {
            return; // still settling
        }
        if let Some(last) = *self.last_rebind_at.lock() {
            if now.saturating_duration_since(last) < self.cfg.network.min_rebind_interval {
                return; // rate-limited; stays dirty, retried next tick
            }
        }

        let (human, key) = provider();
        let cur_key = self
            .session
            .load()
            .profile
            .as_ref()
            .map(|p| p.net_key.clone())
            .unwrap_or_else(|| "nonet".to_string());

        if key != cur_key {
            self.rebind(&key, &human, now);
            *self.last_rebind_at.lock() = Some(now);
        }
        // Only clear `dirty` if no callback fired while we worked — otherwise
        // leave it armed so the next tick re-evaluates.
        if *self.netkey_changed_at.lock() == snap {
            self.netkey_dirty.store(false, Ordering::Relaxed);
        }
    }

    /// Flush the current network's profile, build the new network's session
    /// (loading its profile if present), swap it in, and drop stale conntrack.
    fn rebind(&self, new_key: &str, new_human: &str, now: Instant) {
        let old = self.session.load_full();

        // 1. flush the old network's learned state to its OWN file.
        if let Some(p) = &old.profile {
            let file = old.discovery.export(&p.net_key);
            match crate::profile::persist::save(&p.dir, &p.net_key, &file) {
                Ok(n) => self.last_profile_bytes.store(n, Ordering::Relaxed),
                Err(e) => tracing::warn!(
                    target: "bosphorus::net", error = %e,
                    "old-profile flush failed on rebind"
                ),
            }
        }

        // 2. resolve where the new profile lives. `nonet` (or no dir anywhere)
        //    => in-memory only.
        let dir = old
            .profile
            .as_ref()
            .map(|p| p.dir.clone())
            .or_else(|| self.cfg.profile.as_ref().map(|p| p.dir.clone()));
        let profile = match (new_key, dir) {
            ("nonet", _) | (_, None) => None,
            (k, Some(dir)) => Some(ProfilePaths { dir, net_key: k.to_string() }),
        };

        let session = build_session(&self.cfg, profile, Some(new_human.to_string()));
        let restored = session.discovery.target_count();
        // The ISP pool is ISP-scoped, not network-scoped — carry it across.
        if let Some(pool) = self.isp_pool.get() {
            session.discovery.set_isp_pool(Arc::clone(pool));
        }

        // 3. atomic swap, 4. drop stale conntrack, 5. persist the new state soon.
        self.session.store(Arc::new(session));
        self.flows.clear();
        *self.persist_at.lock() = now.checked_sub(PERSIST_EVERY).unwrap_or(now);

        tracing::info!(
            target: "bosphorus::net",
            new_key = %new_key, restored,
            "network changed — rebound to profile"
        );
    }

    /// Throttled eviction of stale / low-value discovery targets — the bound
    /// that keeps a 7/24 run from accumulating one `TargetState` per hostname
    /// ever contacted.
    fn maybe_evict(&self, session: &NetworkSession, now: Instant) {
        {
            let mut last = self.evict_at.lock();
            if now.saturating_duration_since(*last) < EVICT_EVERY {
                return;
            }
            *last = now;
        }
        let dropped = session.discovery.evict(now);
        if dropped > 0 {
            tracing::debug!(target: "bosphorus::discovery", dropped, "evicted stale targets");
        }
        session.censored.sweep(now);
    }

    /// Throttled process-footprint digest: flow-table size + capacity, discovery
    /// target counts by phase, and the last profile-JSON byte count. `RUST_LOG`
    /// `bosphorus::mem=debug` turns it on. This is the "is it leaking over a
    /// 7/24 run" instrument.
    fn mem_digest(&self, discovery: &Discovery, now: Instant) {
        {
            let mut last = self.mem_at.lock();
            if now.saturating_duration_since(*last) < MEM_EVERY {
                return;
            }
            *last = now;
        }
        let (flows, flow_cap) = self.flows.stats();
        let [probe, discover, active, exhausted] = discovery.phase_counts();
        tracing::debug!(
            target: "bosphorus::mem",
            flows,
            flow_cap,
            targets = probe + discover + active + exhausted,
            probe,
            discover,
            active,
            exhausted,
            profile_json_bytes = self.last_profile_bytes.load(Ordering::Relaxed),
            "mem"
        );
    }

    /// Throttled profile write (discovery runs only).
    fn maybe_persist(&self, session: &NetworkSession, now: Instant) {
        if self.forced.is_some() {
            return;
        }
        let Some(p) = &session.profile else { return };
        {
            let mut last = self.persist_at.lock();
            if now.saturating_duration_since(*last) < PERSIST_EVERY {
                return;
            }
            *last = now;
        }
        self.write_profile(&session.discovery, p);
    }

    /// Write the discovery profile now (call on shutdown). No-op without a
    /// configured profile or in a forced run.
    pub fn persist_now(&self) {
        if self.forced.is_some() {
            return;
        }
        let session = self.session.load();
        if let Some(p) = &session.profile {
            self.write_profile(&session.discovery, p);
        }
    }

    fn write_profile(&self, discovery: &Discovery, p: &ProfilePaths) {
        let file = discovery.export(&p.net_key);
        match crate::profile::persist::save(&p.dir, &p.net_key, &file) {
            Ok(n) => {
                self.last_profile_bytes.store(n, Ordering::Relaxed);
                tracing::debug!(
                    target: "bosphorus::discovery",
                    targets = file.targets.len(), bytes = n, "discovery profile saved"
                )
            }
            Err(e) => tracing::warn!(
                target: "bosphorus::discovery", error = %e, "discovery profile save failed"
            ),
        }
    }

    /// Throttled one-line-per-target digest of the targets still being worked,
    /// so a slow sweep (e.g. `updates.discord.com` only getting a trial every
    /// Discord retry) is visible while it happens.
    fn progress_digest(&self, discovery: &Discovery, now: Instant) {
        if self.forced.is_some() {
            return;
        }
        let working = discovery.working_targets();
        if working.is_empty() {
            return;
        }
        {
            let mut last = self.digest_at.lock();
            if now.saturating_duration_since(*last) < DIGEST_EVERY {
                return;
            }
            *last = now;
        }

        // One line per interval. A line per target per 10 s buried everything else
        // on a real sweep, so the summary is what INFO carries and the per-target
        // rows moved to DEBUG:  RUST_LOG=bosphorus::discovery=debug
        let summary = digest_summary(&working);
        tracing::info!(
            target: "bosphorus::discovery",
            targets = summary.targets,
            probing = summary.probing,
            trying = summary.trying,
            tried = summary.tried,
            in_flight = summary.in_flight,
            latest = %summary.latest.as_deref().unwrap_or("-"),
            "discovery progress"
        );

        for t in &working {
            tracing::debug!(
                target: "bosphorus::discovery",
                key = %t.key,
                phase = ?t.phase,
                tried = t.tried,
                total = t.total,
                in_flight = t.in_flight,
                last_trial_s = t.last_trial_age.map(|d| d.as_secs()).unwrap_or(0),
                "discovery target"
            );
        }
    }
}

/// The numbers behind the one-line discovery digest.
///
/// Kept separate from the logging call so the readability logic can be tested
/// without installing a subscriber.
#[derive(Debug, Default, PartialEq, Eq)]
struct DigestSummary {
    /// Targets currently being worked (`Probe` or `Discover`).
    targets: usize,
    /// Of those, how many are still in the `Probe` (control) phase.
    probing: usize,
    /// How many are exploring candidates, i.e. `Discover`.
    trying: usize,
    /// Strategies tried across all of them, summed.
    tried: usize,
    /// Trials handed out and not yet resolved, summed.
    in_flight: usize,
    /// Host with the most recent trial — the one a reader is most likely to be
    /// waiting on. `None` when nothing has been assigned yet.
    latest: Option<String>,
}

/// Fold the working targets into the digest the summary line logs.
fn digest_summary(working: &[TargetSummary]) -> DigestSummary {
    let mut out = DigestSummary {
        targets: working.len(),
        // `Duration::MAX` sorts "never assigned" last, so the most recently
        // active host wins however long the process has been running.
        latest: working
            .iter()
            .min_by_key(|t| t.last_trial_age.unwrap_or(Duration::MAX))
            .map(|t| t.key.clone()),
        ..Default::default()
    };
    for t in working {
        match t.phase {
            NetPhase::Probe => out.probing += 1,
            NetPhase::Discover => out.trying += 1,
            _ => {}
        }
        out.tried += t.tried;
        out.in_flight += t.in_flight;
    }
    out
}

/// Lowercased SNI host from a ClientHello, if one can be read (including from a
/// truncated first segment). `None` when the ClientHello has no readable SNI.
fn sni_target(payload: &[u8]) -> Option<String> {
    let loc = find_sni(payload)?;
    let name = std::str::from_utf8(payload.get(loc.host)?)
        .ok()?
        .trim()
        .to_ascii_lowercase();
    (!name.is_empty()).then_some(name)
}

fn log_discovery(target: &str, ev: &DiscoveryEvent, phase: NetPhase) {
    match ev {
        DiscoveryEvent::Noted => {}
        DiscoveryEvent::Exhausted { tried } => tracing::warn!(
            target: "bosphorus::discovery",
            server = %target, tried, ?phase,
            "grid EXHAUSTED — no strategy bypassed this target"
        ),
        _ => tracing::info!(
            target: "bosphorus::discovery",
            server = %target, ?phase, event = ?ev,
            "discovery update"
        ),
    }
}

/// Apply each item's checksum op, then inject the batch in order.
fn emit_batch(
    sink: &mut dyn PacketSink,
    batch: &mut SendBatch,
    stats: &mut RunStats,
) -> Result<(), CoreError> {
    for item in &mut batch.items {
        match item.checksum {
            ChecksumOp::Recompute => {
                sink.recalc_checksums(&mut item.bytes, &mut item.meta, ChecksumWhich::IpAndL4)?;
            }
            ChecksumOp::RecomputeThenBreakTcp => {
                sink.recalc_checksums(&mut item.bytes, &mut item.meta, ChecksumWhich::IpAndL4)?;
                break_tcp_checksum(&mut item.bytes);
                // meta.tcp_checksum_valid stays true: claim it's valid so the
                // backend does not "fix" our deliberate corruption on send.
            }
            ChecksumOp::Keep => {}
        }
    }
    sink.inject_batch(batch)?;
    stats.batches += 1;
    stats.injected += batch.items.len() as u64;
    Ok(())
}

/// GoodbyeDPI `--wrong-chksum`: `Checksum = htons(ntohs(Checksum) - 1)`.
fn break_tcp_checksum(bytes: &mut [u8]) {
    let Ok(v) = PacketView::parse(bytes) else { return };
    if !v.is_tcp() {
        return;
    }
    let off = v.l4_header_range().start + 16;
    if off + 2 <= bytes.len() {
        let c = u16::from_be_bytes([bytes[off], bytes[off + 1]]);
        bytes[off..off + 2].copy_from_slice(&c.wrapping_sub(1).to_be_bytes());
    }
}

/// Record the destination when a verdict is proof of an in-path censor.
///
/// Only the two reset verdicts qualify. A `Blackhole` is indistinguishable from
/// ordinary packet loss, and treating one as proof would cost the destination
/// its HTTP/3 over what may have been a dropped packet.
fn note_if_censored(censored: &CensoredIps, key: &FlowKey, outcome: FlowOutcome, now: Instant) {
    if matches!(outcome, FlowOutcome::DpiReset | FlowOutcome::LateReset) {
        censored.note(key.server_ip, now);
    }
}

fn log_outcome(key: &FlowKey, server_name: Option<&str>, outcome: FlowOutcome, via: &str) {
    tracing::info!(
        target: "bosphorus::conntrack",
        server = server_name.unwrap_or("?"),
        server_ip = %key.server_ip,
        client_port = key.client_port,
        ?outcome,
        via,
        "flow classified"
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::source_sink::{Captured, RawAddr};
    use crate::strategy::FAKE_HTTPS_REQUEST;

    /// Minimal subscriber for asserting on what the digest logs. `tracing-core`
    /// is already a dependency; no test-only crate is pulled in.
    mod test_log {
        use std::sync::{Arc, Mutex};

        use tracing::field::{Field, Visit};
        use tracing::span::{Attributes, Id, Record};
        use tracing::{Event as TracingEvent, Metadata, Subscriber};

        #[derive(Debug, Clone)]
        pub struct Event {
            pub level: tracing::Level,
            pub target: String,
            pub message: String,
        }

        #[derive(Default)]
        pub struct Collector(Mutex<Vec<Event>>);

        impl Collector {
            pub fn events(&self) -> Vec<Event> {
                self.0.lock().unwrap().clone()
            }
        }

        struct Msg(String);
        impl Visit for Msg {
            fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
                if field.name() == "message" {
                    self.0 = format!("{value:?}");
                }
            }
        }

        pub struct Capture(pub Arc<Collector>);

        impl Subscriber for Capture {
            fn enabled(&self, _: &Metadata<'_>) -> bool {
                true
            }
            fn new_span(&self, _: &Attributes<'_>) -> Id {
                Id::from_u64(1)
            }
            fn record(&self, _: &Id, _: &Record<'_>) {}
            fn record_follows_from(&self, _: &Id, _: &Id) {}
            fn event(&self, event: &TracingEvent<'_>) {
                let mut msg = Msg(String::new());
                event.record(&mut msg);
                self.0 .0.lock().unwrap().push(Event {
                    level: *event.metadata().level(),
                    target: event.metadata().target().to_string(),
                    message: msg.0,
                });
            }
            fn enter(&self, _: &Id) {}
            fn exit(&self, _: &Id) {}
        }
    }

    struct VecSource {
        packets: Vec<(Vec<u8>, bool)>, // (bytes, outbound)
        idx: usize,
    }
    impl PacketSource for VecSource {
        fn recv<'b>(&mut self, buf: &'b mut [u8]) -> Result<Captured<'b>, CoreError> {
            if self.idx >= self.packets.len() {
                return Err(CoreError::SourceShutdown);
            }
            let (p, outbound) = &self.packets[self.idx];
            self.idx += 1;
            buf[..p.len()].copy_from_slice(p);
            Ok(Captured {
                data: &mut buf[..p.len()],
                meta: CaptureMeta { outbound: *outbound, raw: RawAddr::default(), ..Default::default() },
            })
        }
        fn shutdown(&mut self) -> Result<(), CoreError> {
            Ok(())
        }
    }

    #[derive(Default)]
    struct RecSink {
        injected: Vec<Vec<u8>>,
        recalc_calls: usize,
    }
    impl PacketSink for RecSink {
        fn inject(&mut self, packet: &[u8], _meta: &CaptureMeta) -> Result<(), CoreError> {
            self.injected.push(packet.to_vec());
            Ok(())
        }
        fn inject_batch(&mut self, batch: &SendBatch) -> Result<(), CoreError> {
            for it in &batch.items {
                self.injected.push(it.bytes.clone());
            }
            Ok(())
        }
        fn recalc_checksums(
            &mut self,
            _packet: &mut [u8],
            _meta: &mut CaptureMeta,
            _which: ChecksumWhich,
        ) -> Result<(), CoreError> {
            self.recalc_calls += 1;
            Ok(())
        }
    }

    fn clienthello_pkt() -> Vec<u8> {
        let mut p = vec![0x45, 0, 0, 0, 0, 0, 0x40, 0, 64, 6, 0, 0, 10, 0, 0, 5, 93, 184, 216, 34];
        p.extend_from_slice(&[0x30, 0x39, 0x01, 0xbb]); // 12345 -> 443
        p.extend_from_slice(&1_000u32.to_be_bytes());
        p.extend_from_slice(&2_000u32.to_be_bytes());
        p.extend_from_slice(&[0x50, 0x18, 0xff, 0xff, 0, 0, 0, 0]);
        p.extend_from_slice(&[0x16, 0x03, 0x01, 0x00, 0x0a, 0x01, 0x00, 0x00, 0x06, 0x03, 0x03, 0xAA, 0xBB, 0xCC]);
        let total = p.len() as u16;
        p[2..4].copy_from_slice(&total.to_be_bytes());
        p
    }

    /// ClientHello (one segment) with a `server_name` extension, IPv4/TCP
    /// 10.0.0.5:<sport> -> 93.184.216.34:443.
    fn ch_with_sni(host: &str, sport: u16) -> Vec<u8> {
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
        let mut p = vec![0x45, 0, 0, 0, 0, 0, 0x40, 0, 64, 6, 0, 0, 10, 0, 0, 5, 93, 184, 216, 34];
        p.extend_from_slice(&sport.to_be_bytes());
        p.extend_from_slice(&[0x01, 0xbb]);
        p.extend_from_slice(&1_000u32.to_be_bytes());
        p.extend_from_slice(&[0, 0, 0, 0, 0x50, 0x18, 0xff, 0xff, 0, 0, 0, 0]);
        p.extend_from_slice(&tls);
        let total = p.len() as u16;
        p[2..4].copy_from_slice(&total.to_be_bytes());
        p
    }

    /// `ch_with_sni` but to an arbitrary destination port (bytes 22..24 of the
    /// IPv4/TCP fixture). Checksums are unverified by `PacketView` / the test
    /// sink, so no recompute is needed.
    fn ch_with_sni_dport(host: &str, sport: u16, dport: u16) -> Vec<u8> {
        let mut p = ch_with_sni(host, sport);
        p[22..24].copy_from_slice(&dport.to_be_bytes());
        p
    }

    /// Inbound TCP packet 93.184.216.34:443 -> 10.0.0.5:<sport> with `flags`.
    fn inbound_tcp(sport: u16, flags: u8, payload: &[u8]) -> Vec<u8> {
        inbound_tcp_ttl(sport, 64, flags, payload)
    }
    fn inbound_tcp_ttl(sport: u16, ttl: u8, flags: u8, payload: &[u8]) -> Vec<u8> {
        let mut p = vec![0x45, 0, 0, 0, 0, 0, 0x40, 0, ttl, 6, 0, 0, 93, 184, 216, 34, 10, 0, 0, 5];
        p.extend_from_slice(&[0x01, 0xbb]);
        p.extend_from_slice(&sport.to_be_bytes());
        p.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0x50, flags, 0xff, 0xff, 0, 0, 0, 0]);
        p.extend_from_slice(payload);
        let total = p.len() as u16;
        p[2..4].copy_from_slice(&total.to_be_bytes());
        p
    }

    fn inbound_rst(sport: u16) -> Vec<u8> {
        inbound_tcp(sport, 0x04, &[])
    }
    fn inbound_serverhello(sport: u16) -> Vec<u8> {
        inbound_tcp(sport, 0x18, &[0x16, 0x03, 0x03, 0x00, 0x05, 0x02])
    }
    /// Real inbound application data — confirms a handshake `Success` without
    /// waiting out the `app_grace` window.
    fn inbound_appdata(sport: u16) -> Vec<u8> {
        inbound_tcp(sport, 0x18, &[0x17, 0x03, 0x03, 0x00, 0x03, 0xaa, 0xbb, 0xcc])
    }

    #[test]
    fn non_ip_packets_pass_through_unchanged() {
        let pkts = vec![(vec![1u8, 2, 3], true), (vec![9u8; 40], false)];
        let mut src = VecSource { packets: pkts.clone(), idx: 0 };
        let mut sink = RecSink::default();
        let engine = Engine::new(EvasionConfig::default());
        let stats = engine.run_main(&mut src, &mut sink, &StopFlag::new()).unwrap();

        assert_eq!(stats.packets, 2);
        assert_eq!(stats.dropped, 0);
        assert_eq!(sink.injected, vec![vec![1u8, 2, 3], vec![9u8; 40]]);
    }

    #[test]
    fn forced_strategy_gets_fake_plus_two_segments_and_conntrack_state() {
        let engine = Engine::new_with_strategy(EvasionConfig::default(), Strategy::m4_fixed());
        let mut ch = clienthello_pkt();
        let mut meta = CaptureMeta { outbound: true, ..Default::default() };
        let mut out = SendBatch::new();

        let decision = engine.process(&mut ch, &mut meta, &mut out);
        assert_eq!(decision, Decision::ForwardBatchOnly);
        assert_eq!(out.len(), 3);

        // conntrack recorded the (original) ClientHello.
        let key = FlowKey {
            client_ip: "10.0.0.5".parse().unwrap(),
            client_port: 12345,
            server_ip: "93.184.216.34".parse().unwrap(),
            server_port: 443,
        };
        assert!(engine.flows().peek(&key, |st| st.client_hello_seen).unwrap());

        // Batch: fake, then two real segments.
        let f = PacketView::parse(&out.items[0].bytes).unwrap();
        assert_eq!(f.payload(), FAKE_HTTPS_REQUEST);
        let s0 = PacketView::parse(&out.items[1].bytes).unwrap();
        let s1 = PacketView::parse(&out.items[2].bytes).unwrap();
        assert_eq!(s0.payload().len(), 2);
        assert_eq!([s0.payload(), s1.payload()].concat().len(), 14);
    }

    #[test]
    fn run_main_recalculates_checksums_for_the_batch() {
        let mut src = VecSource { packets: vec![(clienthello_pkt(), true)], idx: 0 };
        let mut sink = RecSink::default();
        let engine = Engine::new_with_strategy(EvasionConfig::default(), Strategy::m4_fixed());

        let stats = engine.run_main(&mut src, &mut sink, &StopFlag::new()).unwrap();

        assert_eq!(sink.recalc_calls, 3, "one per batch item");
        assert_eq!(sink.injected.len(), 3);
        assert_eq!(stats.batches, 1);
        assert_eq!(stats.dropped, 1); // original replaced
    }

    fn out_meta() -> CaptureMeta {
        CaptureMeta { outbound: true, ..Default::default() }
    }
    fn in_meta() -> CaptureMeta {
        CaptureMeta { outbound: false, ..Default::default() }
    }

    #[test]
    fn discovery_probes_then_enters_discover_after_a_dpi_reset() {
        let engine = Engine::new(EvasionConfig::default());

        // 1) first ClientHello for a fresh target -> Probe control, unchanged.
        let mut ch = ch_with_sni("updates.discord.com", 40001);
        let mut out = SendBatch::new();
        assert_eq!(engine.process(&mut ch, &mut out_meta(), &mut out), Decision::ForwardOriginal);
        assert!(out.is_empty());
        assert_eq!(engine.discovery_summary()[0].phase, NetPhase::Probe);
        assert_eq!(engine.discovery_summary()[0].key, "updates.discord.com");

        // 2) DPI RST for that flow -> discovery learns the target is blocked.
        engine.process(&mut inbound_rst(40001), &mut in_meta(), &mut SendBatch::new());
        assert_eq!(engine.discovery_summary()[0].phase, NetPhase::Discover);

        // 3) next ClientHello (new port = new flow) -> a grid candidate is applied.
        let mut ch2 = ch_with_sni("updates.discord.com", 40002);
        let mut out2 = SendBatch::new();
        assert_eq!(engine.process(&mut ch2, &mut out_meta(), &mut out2), Decision::ForwardBatchOnly);
        assert_eq!(out2.len(), 3);
    }

    #[test]
    fn discovery_promotes_a_working_strategy() {
        // promote_after_success = 2 by default.
        let engine = Engine::new(EvasionConfig::default());

        // Probe fails -> Discover.
        engine.process(&mut ch_with_sni("blocked.example", 41000), &mut out_meta(), &mut SendBatch::new());
        engine.process(&mut inbound_rst(41000), &mut in_meta(), &mut SendBatch::new());
        assert_eq!(engine.discovery_summary()[0].phase, NetPhase::Discover);

        // Two fresh connections, each: candidate applied, then ServerHello +
        // real app data -> Success (the grace window is short-circuited by the
        // inbound `0x17`).
        for (i, port) in [41001u16, 41002].into_iter().enumerate() {
            let mut c = ch_with_sni("blocked.example", port);
            let mut o = SendBatch::new();
            assert_eq!(
                engine.process(&mut c, &mut out_meta(), &mut o),
                Decision::ForwardBatchOnly,
                "iteration {i}"
            );
            engine.process(&mut inbound_serverhello(port), &mut in_meta(), &mut SendBatch::new());
            engine.process(&mut inbound_appdata(port), &mut in_meta(), &mut SendBatch::new());
        }

        let s = engine.discovery_summary();
        let ts = s.iter().find(|t| t.key == "blocked.example").unwrap();
        assert_eq!(ts.phase, NetPhase::Active);
        assert!(ts.active.is_some(), "a strategy was promoted");
        assert!(ts.best.is_some());
    }

    #[test]
    fn discovery_progress_persists_across_engine_restarts() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = || EvasionConfig {
            profile: Some(crate::config::ProfilePaths {
                dir: dir.path().to_path_buf(),
                net_key: "test".into(),
            }),
            ..Default::default()
        };

        // Session 1: block a target, fail two candidates, persist on shutdown.
        {
            let e = Engine::new(cfg());
            e.process(&mut ch_with_sni("blocked.example", 47001), &mut out_meta(), &mut SendBatch::new());
            e.process(&mut inbound_rst(47001), &mut in_meta(), &mut SendBatch::new()); // -> Discover
            for port in [47002u16, 47003] {
                e.process(&mut ch_with_sni("blocked.example", port), &mut out_meta(), &mut SendBatch::new());
                e.process(&mut inbound_rst(port), &mut in_meta(), &mut SendBatch::new());
            }
            assert!(e.discovery_summary()[0].tried >= 2);
            e.persist_now();
        }

        // Session 2: a fresh Engine on the same profile dir resumes mid-sweep.
        {
            let e = Engine::new(cfg());
            let s = e.discovery_summary();
            let ts = s.iter().find(|t| t.key == "blocked.example").expect("target restored from disk");
            assert!(ts.tried >= 2, "sweep progress restored (tried={})", ts.tried);
            assert!(ts.from_disk);
        }
    }

    #[test]
    fn forced_multi_part_fragment_emits_n_plus_one_segments() {
        use crate::strategy::model::{FragmentSpec, SendOrder, SplitAnchor, Strategy};
        let strat = Strategy {
            fake: None,
            fragment: Some(FragmentSpec {
                anchors: vec![
                    SplitAnchor::AbsoluteOffset(1),
                    SplitAnchor::TlsRecordStart,
                    SplitAnchor::SniStart,
                ],
                reverse: false,
            }),
            order: SendOrder::FakeThenReal,
            tls_pad: None,
        };
        let engine = Engine::new_with_strategy(EvasionConfig::default(), strat);
        let mut ch = ch_with_sni("updates.discord.com", 46001);
        let mut meta = CaptureMeta { outbound: true, ..Default::default() };
        let mut out = SendBatch::new();
        assert_eq!(engine.process(&mut ch, &mut meta, &mut out), Decision::ForwardBatchOnly);
        assert_eq!(out.len(), 4, "3 cut points -> 4 segments, no fake");

        let orig = ch_with_sni("updates.discord.com", 46001);
        let orig_payload = PacketView::parse(&orig).unwrap().payload().to_vec();
        let cat: Vec<u8> = out
            .items
            .iter()
            .flat_map(|i| PacketView::parse(&i.bytes).unwrap().payload().to_vec())
            .collect();
        assert_eq!(cat, orig_payload, "segments reassemble to the original ClientHello");
    }

    #[test]
    fn concurrent_clienthellos_to_one_target_explore_distinct_candidates() {
        let engine = Engine::new(EvasionConfig::default());

        // Probe fails -> Discover.
        engine.process(&mut ch_with_sni("updates.discord.com", 45001), &mut out_meta(), &mut SendBatch::new());
        engine.process(&mut inbound_rst(45001), &mut in_meta(), &mut SendBatch::new());
        assert_eq!(engine.discovery_summary()[0].phase, NetPhase::Discover);

        // Two fresh connections, no verdict in between.
        let mut a = ch_with_sni("updates.discord.com", 45002);
        let mut oa = SendBatch::new();
        assert_eq!(engine.process(&mut a, &mut out_meta(), &mut oa), Decision::ForwardBatchOnly);

        let mut b = ch_with_sni("updates.discord.com", 45003);
        let mut ob = SendBatch::new();
        assert_eq!(engine.process(&mut b, &mut out_meta(), &mut ob), Decision::ForwardBatchOnly);

        // Both are counted in flight and they used different candidates.
        let ts = &engine.discovery_summary()[0];
        assert_eq!(ts.in_flight, 2, "two unresolved explores tracked");
        assert_ne!(
            oa.items.iter().map(|i| i.bytes.clone()).collect::<Vec<_>>(),
            ob.items.iter().map(|i| i.bytes.clone()).collect::<Vec<_>>(),
            "concurrent connections swept different candidates, not the same one twice"
        );
    }

    #[test]
    fn fragmented_clienthello_stays_under_one_target_key() {
        let engine = Engine::new(EvasionConfig::default());

        // Connection A: SNI readable -> target "updates.discord.com", then blocked.
        engine.process(&mut ch_with_sni("updates.discord.com", 42001), &mut out_meta(), &mut SendBatch::new());
        engine.process(&mut inbound_rst(42001), &mut in_meta(), &mut SendBatch::new());
        assert_eq!(engine.discovery_summary()[0].phase, NetPhase::Discover);

        // Connection B: SAME server, but the captured ClientHello segment has no
        // SNI (extensions past the truncation). Must not be mutated and must not
        // create an IP-keyed target.
        let mut b = ch_with_sni("updates.discord.com", 42002);
        b.truncate(92); // 40 (ip+tcp) + 52 (through the extensions-length field)
        let tl = b.len() as u16;
        b[2..4].copy_from_slice(&tl.to_be_bytes());
        let mut out = SendBatch::new();
        assert_eq!(engine.process(&mut b, &mut out_meta(), &mut out), Decision::ForwardOriginal);
        assert!(out.is_empty(), "no-SNI ClientHello must not be mutated");

        let s = engine.discovery_summary();
        assert_eq!(s.len(), 1, "exactly one discovery target — no IP-keyed junk");
        assert_eq!(s[0].key, "updates.discord.com");

        // Connection C: full SNI again -> the same target keeps sweeping.
        let mut c = ch_with_sni("updates.discord.com", 42003);
        let mut oc = SendBatch::new();
        assert_eq!(engine.process(&mut c, &mut out_meta(), &mut oc), Decision::ForwardBatchOnly);
        assert_eq!(engine.discovery_summary().len(), 1);
    }

    #[test]
    fn strategy_applies_on_a_cloudflare_https_alt_port_but_not_a_plain_one() {
        let engine = Engine::new_with_strategy(EvasionConfig::default(), Strategy::m4_fixed());

        // *.discord.media voice signalling rides Cloudflare's 2096 - must be mutated.
        let mut ch = ch_with_sni_dport("c-fra07.discord.media", 48001, 2096);
        let mut out = SendBatch::new();
        assert_eq!(engine.process(&mut ch, &mut out_meta(), &mut out), Decision::ForwardBatchOnly);
        assert!(!out.is_empty(), "strategy not applied on port 2096");

        // A non-TLS port is left alone.
        let mut other = ch_with_sni_dport("example.com", 48002, 8080);
        let mut o2 = SendBatch::new();
        assert_eq!(engine.process(&mut other, &mut out_meta(), &mut o2), Decision::ForwardOriginal);
        assert!(o2.is_empty());
    }

    #[test]
    fn clienthello_retransmit_after_strategy_passes_through() {
        let engine = Engine::new_with_strategy(EvasionConfig::default(), Strategy::m4_fixed());

        // First ClientHello -> strategy applied.
        let mut ch = ch_with_sni("blocked.example", 43001);
        let mut o1 = SendBatch::new();
        assert_eq!(engine.process(&mut ch, &mut out_meta(), &mut o1), Decision::ForwardBatchOnly);
        assert!(!o1.is_empty());

        // Same flow, another ClientHello (a retransmit) -> unchanged, no batch.
        let mut ch2 = ch_with_sni("blocked.example", 43001);
        let mut o2 = SendBatch::new();
        assert_eq!(engine.process(&mut ch2, &mut out_meta(), &mut o2), Decision::ForwardOriginal);
        assert!(o2.is_empty());
    }

    #[test]
    fn windows_synack_ttl_reaches_conntrack_for_gating() {
        // Overlap-family gating itself is unit-tested in discovery/scheduler;
        // here we only confirm the engine plumbs the SYN-ACK initial TTL through
        // to `remote_initial_ttl` (which `assign` reads).
        let engine = Engine::new(EvasionConfig::default());
        engine.process(
            &mut inbound_tcp_ttl(44001, 120, 0x12, &[]),
            &mut in_meta(),
            &mut SendBatch::new(),
        );
        let key = FlowKey {
            client_ip: "10.0.0.5".parse().unwrap(),
            client_port: 44001,
            server_ip: "93.184.216.34".parse().unwrap(),
            server_port: 443,
        };
        assert_eq!(engine.flows().peek(&key, |st| st.remote_initial_ttl).flatten(), Some(128));
    }

    #[test]
    fn break_tcp_checksum_decrements_the_field() {
        let mut pkt = clienthello_pkt();
        let off = {
            let v = PacketView::parse(&pkt).unwrap();
            v.l4_header_range().start + 16
        };
        pkt[off] = 0x12;
        pkt[off + 1] = 0x34;
        break_tcp_checksum(&mut pkt);
        assert_eq!(&pkt[off..off + 2], &[0x12, 0x33]);
    }

    #[test]
    fn wrong_checksum_strategy_runs_through_emit_batch() {
        use crate::strategy::model::{
            DesyncMethod, FakePayload, FakeSpec, FragmentSpec, SendOrder, SplitAnchor, Strategy,
        };
        let strat = Strategy {
            fake: Some(FakeSpec {
                desync: DesyncMethod::WrongChecksum,
                ttl: None,
                payload: FakePayload::StaticClientHello,
                repeats: 1,
            }),
            fragment: Some(FragmentSpec::one(SplitAnchor::AbsoluteOffset(2), false)),
            order: SendOrder::FakeThenReal,
            tls_pad: None,
        };
        let mut src = VecSource { packets: vec![(clienthello_pkt(), true)], idx: 0 };
        let mut sink = RecSink::default();
        let engine = Engine::new_with_strategy(EvasionConfig::default(), strat);

        let stats = engine.run_main(&mut src, &mut sink, &StopFlag::new()).unwrap();
        assert_eq!(sink.injected.len(), 3);
        assert_eq!(sink.recalc_calls, 3); // break op still recalcs first
        assert_eq!(stats.batches, 1);
    }

    // --- live NetKey rebind (sub-step 2) -----------------------------------

    /// A `NetKeyFn` whose returned key the test flips at will.
    fn cell_provider(initial: &str) -> (crate::engine::NetKeyFn, Arc<Mutex<String>>) {
        let cell = Arc::new(Mutex::new(initial.to_string()));
        let c = cell.clone();
        let f: crate::engine::NetKeyFn = Arc::new(move || {
            let k = c.lock().clone();
            (format!("human-{k}"), k)
        });
        (f, cell)
    }

    fn live_engine(dir: &std::path::Path, initial_key: &str) -> (Arc<Engine>, Arc<Mutex<String>>) {
        let (provider, cell) = cell_provider(initial_key);
        let cfg = EvasionConfig {
            profile: Some(crate::config::ProfilePaths {
                dir: dir.to_path_buf(),
                net_key: initial_key.into(),
            }),
            ..Default::default()
        };
        (Arc::new(Engine::with_live_netkey(cfg, provider)), cell)
    }

    #[test]
    fn rebind_swaps_session_and_clears_flows() {
        let dir = tempfile::tempdir().unwrap();
        let (engine, cell) = live_engine(dir.path(), "keyA");

        // keyA session: block a target -> it has discovery + flow state.
        engine.process(&mut ch_with_sni("blocked.example", 51001), &mut out_meta(), &mut SendBatch::new());
        engine.process(&mut inbound_rst(51001), &mut in_meta(), &mut SendBatch::new());
        engine.process(&mut ch_with_sni("blocked.example", 51002), &mut out_meta(), &mut SendBatch::new());
        assert!(engine.flows().stats().0 > 0, "flows populated");
        assert!(!engine.discovery_summary().is_empty(), "keyA has a target");
        assert_eq!(engine.current_profile().unwrap().net_key, "keyA");

        // Network changes to keyB.
        *cell.lock() = "keyB".into();
        let t0 = Instant::now();
        engine.mark_netkey_dirty();
        engine.tick(t0 + Duration::from_secs(10));

        assert_eq!(engine.current_profile().unwrap().net_key, "keyB", "session swapped");
        assert_eq!(engine.flows().stats().0, 0, "stale conntrack cleared on rebind");
        assert!(engine.discovery_summary().is_empty(), "fresh session for keyB (nothing on disk)");
        assert!(
            crate::profile::persist::profile_path(dir.path(), "keyA").exists(),
            "old network's learned state flushed to its own file on the way out"
        );
    }

    #[test]
    fn maybe_rebind_debounces() {
        let dir = tempfile::tempdir().unwrap();
        let (engine, cell) = live_engine(dir.path(), "keyA");
        *cell.lock() = "keyB".into();
        let t0 = Instant::now();
        engine.mark_netkey_dirty();

        engine.tick(t0 + Duration::from_secs(2)); // inside the 5s debounce
        assert_eq!(engine.current_profile().unwrap().net_key, "keyA", "still settling");

        engine.tick(t0 + Duration::from_secs(8)); // quiet period elapsed
        assert_eq!(engine.current_profile().unwrap().net_key, "keyB", "rebound after debounce");
    }

    #[test]
    fn maybe_rebind_noop_when_key_unchanged() {
        let dir = tempfile::tempdir().unwrap();
        let (engine, _cell) = live_engine(dir.path(), "keyA"); // provider keeps returning keyA

        engine.process(&mut ch_with_sni("blocked.example", 52001), &mut out_meta(), &mut SendBatch::new());
        let flows_before = engine.flows().stats().0;
        assert!(flows_before > 0);

        let t0 = Instant::now();
        engine.mark_netkey_dirty();
        engine.tick(t0 + Duration::from_secs(8)); // debounce passed; recompute == "keyA"

        assert_eq!(engine.current_profile().unwrap().net_key, "keyA");
        assert_eq!(engine.flows().stats().0, flows_before, "no rebind -> flows untouched");
        assert!(
            !engine.netkey_dirty.load(Ordering::Relaxed),
            "dirty cleared on a same-key recompute"
        );
    }

    #[test]
    fn maybe_rebind_respects_min_interval() {
        let dir = tempfile::tempdir().unwrap();
        let (engine, cell) = live_engine(dir.path(), "keyA");

        // First change A -> B rebinds at t0+8s.
        *cell.lock() = "keyB".into();
        let t0 = Instant::now();
        engine.mark_netkey_dirty();
        engine.tick(t0 + Duration::from_secs(8));
        assert_eq!(engine.current_profile().unwrap().net_key, "keyB");

        // Second change B -> C only 12s after the last rebind: rate-limited.
        *cell.lock() = "keyC".into();
        engine.mark_netkey_dirty();
        engine.tick(t0 + Duration::from_secs(20)); // 20 - 8 = 12s < 30s
        assert_eq!(engine.current_profile().unwrap().net_key, "keyB", "rate-limited, not yet rebound");
        assert!(engine.netkey_dirty.load(Ordering::Relaxed), "stays armed while rate-limited");

        engine.tick(t0 + Duration::from_secs(45)); // 45 - 8 = 37s >= 30s
        assert_eq!(engine.current_profile().unwrap().net_key, "keyC", "rebinds once the interval elapses");
    }

    #[test]
    fn nonet_session_does_not_persist() {
        let dir = tempfile::tempdir().unwrap();
        let (engine, cell) = live_engine(dir.path(), "keyA");

        engine.process(&mut ch_with_sni("blocked.example", 53001), &mut out_meta(), &mut SendBatch::new());
        engine.process(&mut inbound_rst(53001), &mut in_meta(), &mut SendBatch::new());

        // Network lost -> provider returns "nonet".
        *cell.lock() = "nonet".into();
        let t0 = Instant::now();
        engine.mark_netkey_dirty();
        engine.tick(t0 + Duration::from_secs(8));
        assert!(engine.current_profile().is_none(), "nonet -> no profile path");

        // Learn something on the nonet session, then force writes.
        engine.process(&mut ch_with_sni("other.example", 53002), &mut out_meta(), &mut SendBatch::new());
        engine.process(&mut inbound_rst(53002), &mut in_meta(), &mut SendBatch::new());
        engine.persist_now();
        engine.tick(t0 + Duration::from_secs(60)); // maybe_persist path too

        assert!(
            !crate::profile::persist::profile_path(dir.path(), "nonet").exists(),
            "a nonet session must never write a profile file"
        );
        assert!(
            crate::profile::persist::profile_path(dir.path(), "keyA").exists(),
            "keyA's file was flushed on the way into nonet"
        );
    }

    /// A-guarantee: switching networks NEVER destroys another network's saved
    /// profile. Drive keyA -> keyB -> keyA -> keyB, blocking a distinct target
    /// on each of keyA and keyB, and assert that after the round trips both
    /// files still exist, each parses, and each holds ONLY its own network's
    /// target. `rebind` only ever writes a network's file (atomic temp+rename)
    /// on the way out and reads it on the way in — there is no delete path.
    #[test]
    fn round_trip_between_two_networks_never_loses_either_profile() {
        let dir = tempfile::tempdir().unwrap();
        let (engine, cell) = live_engine(dir.path(), "keyA");
        let t0 = Instant::now();

        // keyA: block a.example -> Discover.
        engine.process(&mut ch_with_sni("a.example", 60001), &mut out_meta(), &mut SendBatch::new());
        engine.process(&mut inbound_rst(60001), &mut in_meta(), &mut SendBatch::new());
        assert_eq!(engine.discovery_summary()[0].phase, NetPhase::Discover);

        // A -> B (flushes keyA/a.example to its own file).
        *cell.lock() = "keyB".into();
        engine.mark_netkey_dirty();
        engine.tick(t0 + Duration::from_secs(8));
        assert_eq!(engine.current_profile().unwrap().net_key, "keyB");

        // keyB: block b.example -> Discover.
        engine.process(&mut ch_with_sni("b.example", 60002), &mut out_meta(), &mut SendBatch::new());
        engine.process(&mut inbound_rst(60002), &mut in_meta(), &mut SendBatch::new());
        assert_eq!(engine.discovery_summary()[0].phase, NetPhase::Discover);

        // B -> A (flushes keyB/b.example; reloads keyA -> a.example from disk).
        *cell.lock() = "keyA".into();
        engine.mark_netkey_dirty();
        engine.tick(t0 + Duration::from_secs(40)); // 40 - 8 = 32s >= min_rebind_interval
        assert_eq!(engine.current_profile().unwrap().net_key, "keyA");
        let a = engine
            .discovery_summary()
            .into_iter()
            .find(|t| t.key == "a.example")
            .expect("keyA's target survived the round trip and reloaded");
        assert!(a.from_disk);
        assert_eq!(a.phase, NetPhase::Discover);

        // A -> B again (flushes keyA/a.example again; reloads keyB -> b.example).
        *cell.lock() = "keyB".into();
        engine.mark_netkey_dirty();
        engine.tick(t0 + Duration::from_secs(72));
        let b = engine
            .discovery_summary()
            .into_iter()
            .find(|t| t.key == "b.example")
            .expect("keyB's target survived the round trip and reloaded");
        assert!(b.from_disk);

        // Both files intact on disk, each with only its own target.
        let fa = crate::profile::persist::load(dir.path(), "keyA").expect("keyA file parses");
        assert!(fa.targets.iter().any(|t| t.key == "a.example"));
        assert!(
            !fa.targets.iter().any(|t| t.key == "b.example"),
            "keyA's file must never contain keyB's target"
        );
        let fb = crate::profile::persist::load(dir.path(), "keyB").expect("keyB file parses");
        assert!(fb.targets.iter().any(|t| t.key == "b.example"));
        assert!(
            !fb.targets.iter().any(|t| t.key == "a.example"),
            "keyB's file must never contain keyA's target"
        );
    }

    /// The race guard: a `mark_netkey_dirty` that lands *during* a rebind (here
    /// simulated from inside the provider call, which runs after `snap` is
    /// captured) must leave the flag armed so the next tick re-evaluates.
    #[test]
    fn maybe_rebind_keeps_flag_armed_if_signalled_during_rebind() {
        let dir = tempfile::tempdir().unwrap();
        let key_cell = Arc::new(Mutex::new("keyA".to_string()));
        let hook: Arc<std::sync::OnceLock<std::sync::Weak<Engine>>> =
            Arc::new(std::sync::OnceLock::new());
        let fire_during = Arc::new(AtomicBool::new(false));

        let provider: crate::engine::NetKeyFn = {
            let key_cell = key_cell.clone();
            let hook = hook.clone();
            let fire_during = fire_during.clone();
            Arc::new(move || {
                if fire_during.swap(false, Ordering::SeqCst) {
                    if let Some(e) = hook.get().and_then(|w| w.upgrade()) {
                        e.mark_netkey_dirty(); // callback lands mid-rebind
                    }
                }
                let k = key_cell.lock().clone();
                (format!("human-{k}"), k)
            })
        };
        let cfg = EvasionConfig {
            profile: Some(crate::config::ProfilePaths {
                dir: dir.path().to_path_buf(),
                net_key: "keyA".into(),
            }),
            ..Default::default()
        };
        let engine = Arc::new(Engine::with_live_netkey(cfg, provider));
        hook.set(Arc::downgrade(&engine)).ok();

        *key_cell.lock() = "keyB".into();
        fire_during.store(true, Ordering::SeqCst);
        let t0 = Instant::now();
        engine.mark_netkey_dirty();
        engine.tick(t0 + Duration::from_secs(10));

        assert_eq!(engine.current_profile().unwrap().net_key, "keyB", "the rebind still happened");
        assert!(
            engine.netkey_dirty.load(Ordering::Relaxed),
            "a signal during the rebind must keep the flag armed (snap captured at entry)"
        );

        // No signal this time -> the flag clears on the next (no-op) evaluation.
        engine.tick(t0 + Duration::from_secs(45));
        assert_eq!(engine.current_profile().unwrap().net_key, "keyB");
        assert!(
            !engine.netkey_dirty.load(Ordering::Relaxed),
            "with no signal during, the flag clears"
        );
    }

    // --- QUIC -------------------------------------------------------------

    /// Outbound UDP 10.0.0.5:50000 -> `dst`:443 carrying `payload`, padded to
    /// the 1200 bytes a real QUIC Initial datagram has to reach.
    fn quic_out(dst: [u8; 4], payload: &[u8]) -> Vec<u8> {
        let mut p = vec![0x45, 0, 0, 0, 0, 0, 0x40, 0, 64, 17, 0, 0, 10, 0, 0, 5];
        p.extend_from_slice(&dst);
        p.extend_from_slice(&50_000u16.to_be_bytes());
        p.extend_from_slice(&[0x01, 0xbb]); // 443
        let udp_len = (8 + 1200) as u16;
        p.extend_from_slice(&udp_len.to_be_bytes());
        p.extend_from_slice(&[0, 0]); // checksum (unverified by PacketView)
        let mut body = payload.to_vec();
        body.resize(1200, 0);
        p.extend_from_slice(&body);
        let total = p.len() as u16;
        p[2..4].copy_from_slice(&total.to_be_bytes());
        p
    }

    /// A v1 Initial: long header, 8-byte DCID, empty SCID.
    fn quic_initial() -> Vec<u8> {
        let mut h = vec![0xC0];
        h.extend_from_slice(&crate::packet::quic::VERSION_1.to_be_bytes());
        h.push(8);
        h.extend_from_slice(&[0xab; 8]);
        h.push(0);
        h
    }

    /// The address `ch_with_sni` / `inbound_rst` use.
    const BLOCKED_DST: [u8; 4] = [93, 184, 216, 34];

    /// Drive a target to a `DpiReset` verdict, which is what marks its address.
    fn provoke_dpi_reset(engine: &Engine, host: &str, sport: u16) {
        engine.process(&mut ch_with_sni(host, sport), &mut out_meta(), &mut SendBatch::new());
        engine.process(&mut inbound_rst(sport), &mut in_meta(), &mut SendBatch::new());
    }

    #[test]
    fn quic_to_a_destination_no_censor_touched_is_left_alone() {
        let engine = Engine::new(EvasionConfig::default());
        let mut p = quic_out(BLOCKED_DST, &quic_initial());
        assert_eq!(
            engine.process(&mut p, &mut out_meta(), &mut SendBatch::new()),
            Decision::ForwardOriginal
        );
    }

    #[test]
    fn a_dpi_reset_over_tcp_makes_the_engine_refuse_quic_to_that_destination() {
        let engine = Engine::new(EvasionConfig::default());
        provoke_dpi_reset(&engine, "blocked.example", 40100);

        let mut p = quic_out(BLOCKED_DST, &quic_initial());
        assert_eq!(
            engine.process(&mut p, &mut out_meta(), &mut SendBatch::new()),
            Decision::DropOriginal,
            "the browser has to fall back to TCP for the learned strategy to apply"
        );
    }

    #[test]
    fn only_the_censored_destination_loses_quic() {
        let engine = Engine::new(EvasionConfig::default());
        provoke_dpi_reset(&engine, "blocked.example", 40101);

        let mut elsewhere = quic_out([1, 1, 1, 1], &quic_initial());
        assert_eq!(
            engine.process(&mut elsewhere, &mut out_meta(), &mut SendBatch::new()),
            Decision::ForwardOriginal
        );
    }

    #[test]
    fn established_quic_traffic_to_a_censored_destination_still_flows() {
        let engine = Engine::new(EvasionConfig::default());
        provoke_dpi_reset(&engine, "blocked.example", 40102);

        // A short header — a connection that is already up, which dropping
        // would break outright rather than pushing towards TCP.
        let mut short_header = quic_out(BLOCKED_DST, &[0x40, 0xab, 0xcd]);
        assert_eq!(
            engine.process(&mut short_header, &mut out_meta(), &mut SendBatch::new()),
            Decision::ForwardOriginal
        );

        // Likewise a Handshake packet, which only exists mid-negotiation.
        let mut handshake = quic_out(BLOCKED_DST, &{
            let mut h = quic_initial();
            h[0] = 0xE0;
            h
        });
        assert_eq!(
            engine.process(&mut handshake, &mut out_meta(), &mut SendBatch::new()),
            Decision::ForwardOriginal
        );
    }

    #[test]
    fn the_off_policy_never_refuses_quic() {
        let cfg = EvasionConfig { quic: QuicPolicy::Off, ..Default::default() };
        let engine = Engine::new(cfg);
        provoke_dpi_reset(&engine, "blocked.example", 40103);

        let mut p = quic_out(BLOCKED_DST, &quic_initial());
        assert_eq!(
            engine.process(&mut p, &mut out_meta(), &mut SendBatch::new()),
            Decision::ForwardOriginal
        );
    }

    #[test]
    fn the_all_policy_drops_in_the_driver_so_the_engine_stays_out_of_it() {
        // `QuicPolicy::All` keeps UDP out of the capture filter entirely, so a
        // datagram reaching `process` at all would be a bug in the wiring; the
        // engine must not second-guess it either way.
        let cfg = EvasionConfig { quic: QuicPolicy::All, ..Default::default() };
        let engine = Engine::new(cfg);
        provoke_dpi_reset(&engine, "blocked.example", 40104);

        let mut p = quic_out(BLOCKED_DST, &quic_initial());
        assert_eq!(
            engine.process(&mut p, &mut out_meta(), &mut SendBatch::new()),
            Decision::ForwardOriginal
        );
    }

    #[test]
    fn inbound_quic_is_never_refused() {
        let engine = Engine::new(EvasionConfig::default());
        provoke_dpi_reset(&engine, "blocked.example", 40105);

        let mut p = quic_out(BLOCKED_DST, &quic_initial());
        assert_eq!(
            engine.process(&mut p, &mut in_meta(), &mut SendBatch::new()),
            Decision::ForwardOriginal
        );
    }

    #[test]
    fn a_blackhole_alone_does_not_cost_a_destination_its_quic() {
        // Silence is indistinguishable from packet loss, so it must not be
        // treated as proof of a censor.
        let engine = Engine::new(EvasionConfig::default());
        let t0 = Instant::now();
        engine.process(&mut ch_with_sni("quiet.example", 40106), &mut out_meta(), &mut SendBatch::new());
        engine.tick(t0 + Duration::from_secs(30)); // verdict timeout -> Blackhole

        let mut p = quic_out(BLOCKED_DST, &quic_initial());
        assert_eq!(
            engine.process(&mut p, &mut out_meta(), &mut SendBatch::new()),
            Decision::ForwardOriginal
        );
    }

    #[test]
    fn rebinding_to_another_network_forgets_what_the_old_one_censored() {
        let key = Arc::new(Mutex::new("keyA".to_string()));
        let k2 = Arc::clone(&key);
        let dir = std::env::temp_dir().join(format!("bosph-quic-rebind-{}", std::process::id()));
        let cfg = EvasionConfig {
            profile: Some(ProfilePaths { dir: dir.clone(), net_key: "keyA".into() }),
            ..Default::default()
        };
        let engine = Engine::with_live_netkey(
            cfg,
            Arc::new(move || {
                let k = k2.lock().clone();
                (k.clone(), k)
            }),
        );

        provoke_dpi_reset(&engine, "blocked.example", 40107);
        let mut p = quic_out(BLOCKED_DST, &quic_initial());
        assert_eq!(
            engine.process(&mut p, &mut out_meta(), &mut SendBatch::new()),
            Decision::DropOriginal
        );

        *key.lock() = "keyB".to_string();
        engine.mark_netkey_dirty();
        engine.tick(Instant::now() + Duration::from_secs(10));

        let mut p = quic_out(BLOCKED_DST, &quic_initial());
        assert_eq!(
            engine.process(&mut p, &mut out_meta(), &mut SendBatch::new()),
            Decision::ForwardOriginal,
            "interference is a property of the network that was left behind"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
    // --- discovery digest --------------------------------------------------

    fn summary_of(
        key: &str,
        phase: NetPhase,
        tried: usize,
        in_flight: usize,
        age: Option<u64>,
    ) -> TargetSummary {
        TargetSummary {
            key: key.to_string(),
            phase,
            tried,
            total: 10,
            in_flight,
            last_trial_age: age.map(Duration::from_secs),
            from_disk: false,
            active: None,
            active_is_passthrough: false,
            best: None,
        }
    }

    #[test]
    fn the_digest_summary_folds_every_working_target_into_one_line() {
        let working = vec![
            summary_of("a.example", NetPhase::Probe, 1, 1, Some(30)),
            summary_of("b.example", NetPhase::Discover, 4, 2, Some(2)),
            summary_of("c.example", NetPhase::Discover, 3, 0, None),
        ];
        let d = digest_summary(&working);
        assert_eq!(d.targets, 3);
        assert_eq!(d.probing, 1);
        assert_eq!(d.trying, 2);
        assert_eq!(d.tried, 8);
        assert_eq!(d.in_flight, 3);
        assert_eq!(
            d.latest.as_deref(),
            Some("b.example"),
            "the most recently trialled host is the useful one to name"
        );
    }

    #[test]
    fn the_digest_summary_of_nothing_is_empty() {
        assert_eq!(digest_summary(&[]), DigestSummary::default());
    }

    /// Regression: the digest used to log one INFO line per working target every
    /// 10 s. It must now be a single INFO line, with the per-target rows only at
    /// DEBUG so `RUST_LOG=bosphorus::discovery=debug` still has them.
    #[test]
    fn one_info_summary_per_digest_and_per_target_detail_only_at_debug() {
        let captured = Arc::new(test_log::Collector::default());
        let subscriber = test_log::Capture(captured.clone());

        let engine = Engine::new(EvasionConfig::default());
        // Two targets in flow state, so the digest has something to summarise.
        for (host, port) in [
            ("digest-a.example", 42_001u16),
            ("digest-b.example", 42_002),
        ] {
            let mut ch = ch_with_sni(host, port);
            let mut meta = out_meta();
            engine.process(&mut ch, &mut meta, &mut SendBatch::new());
            let mut rst = inbound_rst(port);
            let mut meta = in_meta();
            engine.process(&mut rst, &mut meta, &mut SendBatch::new());
        }

        let now = Instant::now();
        tracing::subscriber::with_default(subscriber, || {
            engine.tick(now + Duration::from_secs(30));
        });

        let events = captured.events();
        let info: Vec<_> = events
            .iter()
            .filter(|e| e.level == tracing::Level::INFO && e.target == "bosphorus::discovery")
            .collect();
        assert_eq!(
            info.len(),
            1,
            "expected exactly one INFO digest line, got {:?}",
            info.iter().map(|e| &e.message).collect::<Vec<_>>()
        );
        assert!(
            info[0].message.contains("discovery progress"),
            "{}",
            info[0].message
        );

        let per_target: Vec<_> = events
            .iter()
            .filter(|e| e.level == tracing::Level::DEBUG && e.target == "bosphorus::discovery")
            .filter(|e| e.message.contains("discovery target"))
            .collect();
        assert_eq!(
            per_target.len(),
            2,
            "one DEBUG row per working target, got {}",
            per_target.len()
        );
        assert!(
            !events
                .iter()
                .any(|e| e.level == tracing::Level::INFO && e.message.contains("discovery target")),
            "per-target rows must not be logged at INFO"
        );
    }
}
