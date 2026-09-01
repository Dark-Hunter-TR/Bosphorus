//! Connection tracking + verdict classification.
//!
//! M3: the engine feeds every captured packet here to build per-flow state and
//! classify the outcome ([`FlowOutcome`]). No packet is mutated. Outcomes are
//! logged via `tracing` by the engine.

mod events;
mod flow;
mod table;

pub use events::{observe_inbound, observe_outbound, resolve_timeout, FlowOutcome};
pub use flow::{FlowKey, FlowState};
pub use table::{FlowTable, ResolvedFlow};
