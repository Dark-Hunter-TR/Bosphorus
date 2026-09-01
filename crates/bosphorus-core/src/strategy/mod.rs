//! Evasion strategies, the generator grid, and the transforms that realise
//! them.
//!
//! M5: the full [`model`] type set (+serde), plus [`generator::DefaultGenerator`]
//! producing the candidate grid. The engine still runs one strategy at a time
//! (M4 baseline or a CLI `--strategy` override); dynamic per-flow selection is
//! M6.

pub mod generator;
pub mod model;
pub mod transforms;

pub use generator::{DefaultGenerator, DesyncKind, GridAxes};
pub use model::{
    DesyncMethod, FakePayload, FakeSpec, FragmentSpec, OverlapFill, SendOrder, SplitAnchor, Strategy,
    StrategyId, TtlPolicy, ACK_DELTA, SEQ_DELTA,
};
pub use transforms::{apply_strategy, resolve_ttl, Disposition, TransformCtx, FAKE_HTTPS_REQUEST};
