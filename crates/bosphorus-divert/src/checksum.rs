use crate::error::{DivertError, WinError};
use crate::Address;

pub use windivert_sys::ChecksumFlags;

/// Recompute IP/TCP/UDP checksums in-place over `packet`.
///
/// Mirrors GoodbyeDPI's use of `WinDivertHelperCalcChecksums` after packet
/// mutation. Pass `ChecksumFlags::new()` to recompute everything. When `addr`
/// is `Some`, WinDivert also sets the matching `*Checksum` valid-bits on the
/// address so a later `send` does not recompute them again.
pub fn calc_checksums(
    packet: &mut [u8],
    addr: Option<&mut Address>,
    flags: ChecksumFlags,
) -> Result<(), DivertError> {
    let addr_ptr = match addr {
        Some(a) => a.as_mut_ptr(),
        None => std::ptr::null_mut(),
    };
    // SAFETY: `packet` is a valid mutable region of exactly `packet.len()`
    // bytes; `addr_ptr` is null or a valid `WINDIVERT_ADDRESS`.
    let ok = unsafe {
        windivert_sys::WinDivertHelperCalcChecksums(
            packet.as_mut_ptr().cast(),
            packet.len() as u32,
            addr_ptr,
            flags,
        )
    };
    if ok.as_bool() {
        Ok(())
    } else {
        Err(DivertError::Checksum(WinError::last()))
    }
}
