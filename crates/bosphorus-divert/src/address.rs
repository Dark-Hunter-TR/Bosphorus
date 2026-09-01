use windivert_sys::address::WINDIVERT_ADDRESS;

/// `sizeof(WINDIVERT_ADDRESS)` in WinDivert 2.2: `timestamp` (8) + bitfield (4)
/// + reserved (4) + union (64) = 80.
///
/// [`Address::to_bytes`] / [`Address::from_bytes`] depend on this; a mismatch
/// is a compile error.
pub const ADDRESS_SIZE: usize = 80;
const _: () = assert!(core::mem::size_of::<WINDIVERT_ADDRESS>() == ADDRESS_SIZE);

/// Owned copy of a `WINDIVERT_ADDRESS`.
///
/// Obtained from [`crate::Recv`]; passed back verbatim to
/// [`crate::WinDivertHandle::send`]. Direction of injection is decided by the
/// `Outbound` bit that WinDivert already set on the captured address.
#[repr(transparent)]
#[derive(Clone, Copy)]
pub struct Address(pub(crate) WINDIVERT_ADDRESS);

impl Address {
    /// A zeroed address, used as the out-param for `recv`.
    pub fn zeroed() -> Self {
        // SAFETY: `WINDIVERT_ADDRESS` is a plain C struct (`#[repr(C)]`, only
        // `Copy`/`Clone`). All-zero is a valid inhabitant: layer 0 = Network,
        // every flag bit clear, union payload zeroed.
        Address(unsafe { std::mem::zeroed() })
    }

    pub fn outbound(&self) -> bool {
        self.0.outbound()
    }
    pub fn impostor(&self) -> bool {
        self.0.impostor()
    }
    pub fn ipv6(&self) -> bool {
        self.0.ipv6()
    }
    pub fn loopback(&self) -> bool {
        self.0.loopback()
    }
    pub fn ip_checksum_valid(&self) -> bool {
        self.0.ipchecksum()
    }
    pub fn tcp_checksum_valid(&self) -> bool {
        self.0.tcpchecksum()
    }
    pub fn udp_checksum_valid(&self) -> bool {
        self.0.udpchecksum()
    }
    pub fn set_ip_checksum_valid(&mut self, v: bool) {
        self.0.set_ipchecksum(v);
    }
    pub fn set_tcp_checksum_valid(&mut self, v: bool) {
        self.0.set_tcpchecksum(v);
    }
    pub fn set_udp_checksum_valid(&mut self, v: bool) {
        self.0.set_udpchecksum(v);
    }

    pub(crate) fn as_ptr(&self) -> *const WINDIVERT_ADDRESS {
        &self.0
    }
    pub(crate) fn as_mut_ptr(&mut self) -> *mut WINDIVERT_ADDRESS {
        &mut self.0
    }

    /// Serialize to the raw 80-byte `WINDIVERT_ADDRESS` blob (for carrying
    /// through a backend-agnostic `RawAddr`).
    pub fn to_bytes(&self) -> [u8; ADDRESS_SIZE] {
        let mut out = [0u8; ADDRESS_SIZE];
        // SAFETY: `WINDIVERT_ADDRESS` is `#[repr(C)]`, exactly `ADDRESS_SIZE`
        // bytes (checked above), and POD (integers + bitfield + union of PODs).
        let src = unsafe {
            core::slice::from_raw_parts(
                (&self.0 as *const WINDIVERT_ADDRESS).cast::<u8>(),
                ADDRESS_SIZE,
            )
        };
        out.copy_from_slice(src);
        out
    }

    /// Inverse of [`to_bytes`](Self::to_bytes).
    pub fn from_bytes(b: [u8; ADDRESS_SIZE]) -> Self {
        // SAFETY: any bit pattern of `ADDRESS_SIZE` bytes is a valid
        // `WINDIVERT_ADDRESS` (no reference/enum-with-niche fields; `layer`/
        // `event` are read through checked accessors, not on this path).
        Address(unsafe { core::ptr::read_unaligned(b.as_ptr().cast::<WINDIVERT_ADDRESS>()) })
    }
}

impl Default for Address {
    fn default() -> Self {
        Self::zeroed()
    }
}
