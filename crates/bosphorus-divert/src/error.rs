use std::fmt;

use windows::Win32::Foundation::GetLastError;

/// A Win32 error code captured from `GetLastError()`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WinError(pub u32);

impl WinError {
    /// Snapshot `GetLastError()` right after a failed FFI call.
    pub(crate) fn last() -> Self {
        // SAFETY: `GetLastError` has no preconditions and no side effects beyond
        // reading the calling thread's last-error slot.
        WinError(unsafe { GetLastError().0 })
    }
}

impl fmt::Display for WinError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Win32 error {} (0x{:08X})", self.0, self.0)
    }
}

/// Errors surfaced by the WinDivert wrapper.
#[derive(Debug, thiserror::Error)]
pub enum DivertError {
    #[error("WinDivertOpen failed: {0}")]
    Open(WinError),
    #[error("WinDivertRecv failed: {0}")]
    Recv(WinError),
    #[error("recv buffer too small: packet larger than {0} bytes")]
    RecvBufferTooSmall(usize),
    /// `WinDivertRecv` returned `ERROR_NO_DATA` after `WinDivertShutdown` — the
    /// handle is drained and closed for receiving. Normal loop-exit signal.
    #[error("handle shut down")]
    ShutDown,
    #[error("WinDivertSend failed: {0}")]
    Send(WinError),
    #[error("WinDivertSetParam/GetParam failed: {0}")]
    Param(WinError),
    #[error("WinDivertShutdown failed: {0}")]
    Shutdown(WinError),
    #[error("WinDivertHelperCalcChecksums failed: {0}")]
    Checksum(WinError),
}
