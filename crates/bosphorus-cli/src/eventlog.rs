//! Minimal Windows Event Log writer for the service (`RegisterEventSourceW` +
//! `ReportEventW`). An unregistered source still logs; `service install` adds
//! the `...\EventLog\Application\Bosphorus` registry key so entries render
//! without the "description cannot be found" wrapper.

use std::sync::OnceLock;

use windows::core::PCWSTR;
use windows::Win32::Foundation::PSID;
use windows::Win32::System::EventLog::{
    EventSourceHandle, RegisterEventSourceW, ReportEventW, EVENTLOG_ERROR_TYPE,
    EVENTLOG_INFORMATION_TYPE, EVENTLOG_WARNING_TYPE, REPORT_EVENT_TYPE,
};

pub const ID_STARTED: u32 = 1000;
pub const ID_STOPPED: u32 = 1001;
pub const ID_OPEN_FAILED: u32 = 1002;
pub const ID_NET_CHANGED: u32 = 1003;
pub const ID_GRID_EXHAUSTED: u32 = 1004;
pub const ID_PANIC: u32 = 1005;
/// A stored service argument could not be read; the default was used instead.
pub const ID_BAD_ARGUMENT: u32 = 1006;

pub const SOURCE_NAME: &str = "Bosphorus";

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Cached event-source handle (`0` = registration failed; calls become no-ops).
fn source() -> isize {
    static H: OnceLock<isize> = OnceLock::new();
    *H.get_or_init(|| {
        let name = wide(SOURCE_NAME);
        // SAFETY: null server = local machine; `name` is a valid NUL-terminated
        // wide string that outlives the call.
        match unsafe { RegisterEventSourceW(PCWSTR::null(), PCWSTR(name.as_ptr())) } {
            Ok(h) => h.0,
            Err(_) => 0,
        }
    })
}

fn report(kind: REPORT_EVENT_TYPE, id: u32, msg: &str) {
    let h = source();
    if h == 0 {
        return;
    }
    let msg_w = wide(msg);
    let strings = [PCWSTR(msg_w.as_ptr())];
    // SAFETY: valid source handle; exactly one insertion string; no SID, no
    // binary data.
    unsafe {
        let _ = ReportEventW(
            EventSourceHandle(h),
            kind,
            0,
            id,
            PSID::default(),
            0,
            Some(&strings),
            None,
        );
    }
}

pub fn info(id: u32, msg: &str) {
    report(EVENTLOG_INFORMATION_TYPE, id, msg);
}
pub fn warn(id: u32, msg: &str) {
    report(EVENTLOG_WARNING_TYPE, id, msg);
}
pub fn error(id: u32, msg: &str) {
    report(EVENTLOG_ERROR_TYPE, id, msg);
}
