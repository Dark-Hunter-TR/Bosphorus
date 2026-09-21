//! Bosphorus evasion + discovery core.
//!
//! Platform-agnostic: no dependency on WinDivert or `windows`. The engine talks
//! to the network through the [`PacketSource`] / [`PacketSink`] traits, which a
//! backend (currently WinDivert, in `bosphorus-cli`) implements.
//!
//! One captured packet flows through [`conntrack`] (raw packets to a verdict),
//! [`discovery`] (verdict to the next candidate, or the strategy already proven
//! for this target), and [`strategy::transforms`] (chosen strategy to the
//! packets actually sent). [`profile`] persists what was learned, per network.

pub mod censored;
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

pub use censored::CensoredIps;
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

/// This crate's version, which moves independently of the CLI's — the binary
/// reports both so a bug report says which engine is inside it.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
