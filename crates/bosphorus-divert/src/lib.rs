//! Thin, allocation-free safe wrapper around WinDivert 2.2 via `windivert-sys`.
//!
//! The FFI surface is exactly what GoodbyeDPI drives:
//! `WinDivertOpen`, `WinDivertRecv`, `WinDivertSend`,
//! `WinDivertHelperCalcChecksums`, `WinDivertSetParam` / `WinDivertGetParam`,
//! `WinDivertShutdown`, `WinDivertClose`.
//!
//! Not yet wrapped (later milestones): batched `RecvEx` / `SendEx`, and address
//! mutation helpers (`set_outbound`, per-checksum valid bits, interface index)
//! needed once the engine reinjects synthesised inbound packets.
//!
//! # Capture / reinject loop
//!
//! ```no_run
//! use std::ffi::CString;
//! use bosphorus_divert::{Layer, OpenFlags, WinDivertHandle};
//!
//! let filter = CString::new("tcp and tcp.DstPort == 443").unwrap();
//! let h = WinDivertHandle::open(&filter, Layer::Network, 0, OpenFlags::new())?;
//! let mut buf = vec![0u8; 65_535];
//! loop {
//!     let pkt = h.recv(&mut buf)?;           // blocks
//!     // ... inspect / mutate pkt.data ...
//!     h.send(pkt.data, &pkt.addr)?;          // reinject
//! }
//! # Ok::<(), bosphorus_divert::DivertError>(())
//! ```
#![cfg(windows)]

mod address;
mod checksum;
mod compile;
mod error;
mod handle;
mod open;
mod param;

pub use address::{Address, ADDRESS_SIZE};
pub use checksum::{calc_checksums, ChecksumFlags};
pub use compile::{compile_filter, FilterCompileError};
pub use error::{DivertError, WinError};
pub use handle::{Recv, WinDivertHandle};
pub use open::{Layer, OpenFlags};
pub use param::Param;

/// Recommended `recv` buffer size. Large enough for offload/coalesced segments
/// (WinDivert itself caps captured packets around 9 KB; 64 KiB is generous).
pub const RECV_BUF_HINT: usize = 65_535;
