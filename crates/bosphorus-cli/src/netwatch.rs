//! Live Windows route / address change watch — no polling.
//!
//! Registers `NotifyRouteChange2` + `NotifyUnicastIpAddressChange`. Each
//! notification only fires a cheap user callback (in practice
//! [`bosphorus_core::Engine::mark_netkey_dirty`]); the actual NetKey recompute
//! and rebind are debounced on the engine tick thread.

use std::ffi::c_void;
use std::io;

use windows::Win32::Foundation::{BOOLEAN, HANDLE};
use windows::Win32::NetworkManagement::IpHelper::{
    CancelMibChangeNotify2, NotifyRouteChange2, NotifyUnicastIpAddressChange, MIB_IPFORWARD_ROW2,
    MIB_NOTIFICATION_TYPE, MIB_UNICASTIPADDRESS_ROW,
};
use windows::Win32::Networking::WinSock::AF_UNSPEC;

struct Ctx {
    on_change: Box<dyn Fn() + Send + Sync>,
}

/// Two live change subscriptions. Both are cancelled on drop;
/// `CancelMibChangeNotify2` blocks until no callback is running, so the boxed
/// context is safe to free right after.
pub struct NetWatch {
    route_handle: HANDLE,
    addr_handle: HANDLE,
    /// Heap address stays fixed for the life of the registration — the raw
    /// pointer handed to the OS points here.
    _ctx: Box<Ctx>,
}

impl NetWatch {
    /// Start watching. `on_change` runs on an OS thread-pool thread on every
    /// route / unicast-address change — keep it trivial.
    pub fn start(on_change: impl Fn() + Send + Sync + 'static) -> io::Result<NetWatch> {
        let ctx = Box::new(Ctx { on_change: Box::new(on_change) });
        let ctx_ptr = &*ctx as *const Ctx as *const c_void;

        let mut route_handle = HANDLE::default();
        let mut addr_handle = HANDLE::default();

        // SAFETY: both callbacks are valid `extern "system"` fns; `ctx_ptr`
        // points at heap memory owned by the returned `NetWatch` (the `Box`
        // move below only moves the 8-byte pointer, not the `Ctx`); the handle
        // out-params are valid.
        unsafe {
            let e = NotifyRouteChange2(
                AF_UNSPEC,
                Some(route_trampoline),
                ctx_ptr,
                BOOLEAN(0),
                &mut route_handle,
            );
            if e.0 != 0 {
                return Err(io::Error::from_raw_os_error(e.0 as i32));
            }

            let e = NotifyUnicastIpAddressChange(
                AF_UNSPEC,
                Some(addr_trampoline),
                Some(ctx_ptr),
                BOOLEAN(0),
                &mut addr_handle,
            );
            if e.0 != 0 {
                let _ = CancelMibChangeNotify2(route_handle);
                return Err(io::Error::from_raw_os_error(e.0 as i32));
            }
        }

        Ok(NetWatch { route_handle, addr_handle, _ctx: ctx })
    }
}

impl Drop for NetWatch {
    fn drop(&mut self) {
        // SAFETY: valid notification handles; each call blocks until its
        // callbacks have finished, after which `_ctx` is safe to drop.
        unsafe {
            let _ = CancelMibChangeNotify2(self.route_handle);
            let _ = CancelMibChangeNotify2(self.addr_handle);
        }
    }
}

unsafe extern "system" fn route_trampoline(
    ctx: *const c_void,
    _row: *const MIB_IPFORWARD_ROW2,
    _ntype: MIB_NOTIFICATION_TYPE,
) {
    if !ctx.is_null() {
        ((*(ctx as *const Ctx)).on_change)();
    }
}

unsafe extern "system" fn addr_trampoline(
    ctx: *const c_void,
    _row: *const MIB_UNICASTIPADDRESS_ROW,
    _ntype: MIB_NOTIFICATION_TYPE,
) {
    if !ctx.is_null() {
        ((*(ctx as *const Ctx)).on_change)();
    }
}
