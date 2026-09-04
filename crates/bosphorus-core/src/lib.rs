//! Bosphorus evasion + discovery core.
//!
//! Platform-agnostic: no dependency on WinDivert or `windows`. The engine talks
//! to the network through the [`PacketSource`] / [`PacketSink`] traits, which a
//! backend (currently WinDivert, in `bosphorus-cli`) implements.
//!
//! M2 scope: skeleton only — `Engine::process` always returns
//! [`Decision::ForwardOriginal`] (observe, never mutate). Conntrack, strategy
//! discovery, auto-TTL and DNS arrive in M3+.

pub mod config;
pub mod conntrack;
pub mod discovery;
pub mod engine;
pub mod error;
pub mod filter;
pub mod packet;
pub mod profile;
mod source_sink;
pub mod strategy;

pub use config::{ConntrackTuning, DiscoveryTuning, EvasionConfig, NetworkTuning, ProfilePaths};
pub use conntrack::{FlowKey, FlowOutcome};
pub use discovery::{Discovery, DiscoveryEvent, TargetSummary};
pub use engine::{Decision, Engine, NetKeyFn, RunStats, StopFlag};
pub use error::CoreError;
pub use profile::{IspPool, NetPhase};
pub use source_sink::{
    CaptureMeta, Captured, ChecksumOp, ChecksumWhich, PacketSink, PacketSource, RawAddr, SendBatch,
    SendItem,
};
pub use strategy::{DefaultGenerator, OverlapFill, Strategy};

/// Recv buffer size for the capture loop (offload/coalesced segments fit).
pub const MAX_CAPTURE: usize = 65_535;
