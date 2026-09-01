use std::ffi::CStr;

use windows::Win32::Foundation::{HANDLE, INVALID_HANDLE_VALUE};

use crate::error::{DivertError, WinError};
use crate::{Address, Layer, OpenFlags, Param};

// Win32 error codes we special-case on recv.
const ERROR_INSUFFICIENT_BUFFER: u32 = 122;
const ERROR_NO_DATA: u32 = 232;

/// An open WinDivert handle. Closed on drop.
pub struct WinDivertHandle {
    raw: HANDLE,
}

// SAFETY: WinDivert handles are documented as safe for concurrent
// Recv/Send/Shutdown from multiple threads; the wrapper only stores the raw
// `HANDLE` (a plain pointer-sized integer). `shutdown` from another thread is
// the sanctioned way to unblock a blocking `recv`.
unsafe impl Send for WinDivertHandle {}
unsafe impl Sync for WinDivertHandle {}

/// Result of [`WinDivertHandle::recv`]: a prefix of the caller's buffer plus
/// the packet's address metadata.
pub struct Recv<'b> {
    pub data: &'b mut [u8],
    pub addr: Address,
}

impl WinDivertHandle {
    /// `WinDivertOpen`. Loads and installs the driver on first use (requires
    /// Administrator). `filter` is WinDivert filter-language.
    pub fn open(
        filter: &CStr,
        layer: Layer,
        priority: i16,
        flags: OpenFlags,
    ) -> Result<Self, DivertError> {
        // SAFETY: `filter` is a valid NUL-terminated C string for the duration
        // of the call; the layer/flags newtypes carry only valid bit patterns.
        let raw = unsafe {
            windivert_sys::WinDivertOpen(filter.as_ptr(), layer.to_sys(), priority, flags.to_sys())
        };
        if raw == INVALID_HANDLE_VALUE {
            return Err(DivertError::Open(WinError::last()));
        }
        Ok(Self { raw })
    }

    /// `WinDivertRecv`. Blocks until a packet matches the filter or the handle
    /// is shut down (then returns [`DivertError::ShutDown`]).
    pub fn recv<'b>(&self, buf: &'b mut [u8]) -> Result<Recv<'b>, DivertError> {
        let mut addr = Address::zeroed();
        let mut recv_len: u32 = 0;
        // SAFETY: `buf` is a valid mutable region of `buf.len()` bytes;
        // `recv_len` and `addr` are valid out-params.
        let ok = unsafe {
            windivert_sys::WinDivertRecv(
                self.raw,
                buf.as_mut_ptr().cast(),
                buf.len() as u32,
                &mut recv_len,
                addr.as_mut_ptr(),
            )
        };
        if !ok.as_bool() {
            let e = WinError::last();
            return Err(match e.0 {
                ERROR_NO_DATA => DivertError::ShutDown,
                ERROR_INSUFFICIENT_BUFFER => DivertError::RecvBufferTooSmall(buf.len()),
                _ => DivertError::Recv(e),
            });
        }
        Ok(Recv {
            data: &mut buf[..recv_len as usize],
            addr,
        })
    }

    /// `WinDivertSend`. Injects `data`; direction follows `addr.Outbound`.
    pub fn send(&self, data: &[u8], addr: &Address) -> Result<u32, DivertError> {
        let mut sent: u32 = 0;
        // SAFETY: `data` is a valid region of `data.len()` bytes; `addr` points
        // to a valid `WINDIVERT_ADDRESS`; `sent` is a valid out-param.
        let ok = unsafe {
            windivert_sys::WinDivertSend(
                self.raw,
                data.as_ptr().cast(),
                data.len() as u32,
                &mut sent,
                addr.as_ptr(),
            )
        };
        if ok.as_bool() {
            Ok(sent)
        } else {
            Err(DivertError::Send(WinError::last()))
        }
    }

    pub fn get_param(&self, p: Param) -> Result<u64, DivertError> {
        let mut v: u64 = 0;
        // SAFETY: `v` is a valid out-param; handle is valid.
        let ok = unsafe { windivert_sys::WinDivertGetParam(self.raw, p.to_sys(), &mut v) };
        if ok.as_bool() {
            Ok(v)
        } else {
            Err(DivertError::Param(WinError::last()))
        }
    }

    pub fn set_param(&self, p: Param, value: u64) -> Result<(), DivertError> {
        // SAFETY: handle is valid; no other preconditions.
        let ok = unsafe { windivert_sys::WinDivertSetParam(self.raw, p.to_sys(), value) };
        if ok.as_bool() {
            Ok(())
        } else {
            Err(DivertError::Param(WinError::last()))
        }
    }

    /// WinDivert driver version as `(major, minor)`.
    pub fn version(&self) -> Result<(u64, u64), DivertError> {
        Ok((
            self.get_param(Param::VersionMajor)?,
            self.get_param(Param::VersionMinor)?,
        ))
    }

    /// `WinDivertShutdown(BOTH)` — unblocks any in-flight `recv` and stops
    /// further recv/send. Safe to call from another thread.
    pub fn shutdown_both(&self) -> Result<(), DivertError> {
        // SAFETY: handle is valid; `Both` = 3 is a valid shutdown mode.
        let ok = unsafe {
            windivert_sys::WinDivertShutdown(self.raw, windivert_sys::WinDivertShutdownMode::Both)
        };
        if ok.as_bool() {
            Ok(())
        } else {
            Err(DivertError::Shutdown(WinError::last()))
        }
    }
}

impl Drop for WinDivertHandle {
    fn drop(&mut self) {
        // SAFETY: `raw` came from `WinDivertOpen`, is non-invalid, and is closed
        // exactly once here.
        unsafe {
            let _ = windivert_sys::WinDivertClose(self.raw);
        }
    }
}
