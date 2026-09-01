use std::ffi::CStr;
use std::os::raw::c_char;

use crate::Layer;

/// A filter-string syntax error from [`compile_filter`].
#[derive(Debug, Clone, thiserror::Error)]
#[error("filter syntax error at position {pos}: {msg}")]
pub struct FilterCompileError {
    pub pos: u32,
    pub msg: String,
}

/// Validate a WinDivert filter string via `WinDivertHelperCompileFilter`.
///
/// User-mode only: no driver, no Administrator. Requires `WinDivert.dll` to be
/// loadable (it is, wherever this crate links).
pub fn compile_filter(filter: &CStr, layer: Layer) -> Result<(), FilterCompileError> {
    let mut err_str: *const c_char = std::ptr::null();
    let mut err_pos: u32 = 0;
    // SAFETY: `filter` is a valid NUL-terminated C string; `object`/`objLen` are
    // NULL/0 (validation only); `err_str`/`err_pos` are valid out-params.
    let ok = unsafe {
        windivert_sys::WinDivertHelperCompileFilter(
            filter.as_ptr(),
            layer.to_sys(),
            std::ptr::null_mut(),
            0,
            &mut err_str,
            &mut err_pos,
        )
    };
    if ok.as_bool() {
        return Ok(());
    }
    let msg = if err_str.is_null() {
        String::from("unknown error")
    } else {
        // SAFETY: on failure WinDivert points `err_str` at a static,
        // NUL-terminated string owned by the DLL; we only read it.
        unsafe { CStr::from_ptr(err_str) }.to_string_lossy().into_owned()
    };
    Err(FilterCompileError { pos: err_pos, msg })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;

    #[test]
    fn accepts_valid_filter() {
        let f = CString::new("outbound and tcp and tcp.DstPort == 443").unwrap();
        compile_filter(&f, Layer::Network).expect("valid filter");
    }

    #[test]
    fn rejects_garbage_filter() {
        let f = CString::new("outbound and tcp and ((( bogus").unwrap();
        let e = compile_filter(&f, Layer::Network).unwrap_err();
        assert!(!e.msg.is_empty());
    }
}
