//! The seam between the engine and the network. A backend (WinDivert today,
//! nfqueue conceivable later) implements [`PacketSource`] + [`PacketSink`].

use crate::error::CoreError;

/// Opaque backend address blob. For the WinDivert backend this is exactly a
/// `WINDIVERT_ADDRESS` (80 bytes in WinDivert 2.2). The core never interprets
/// it — it only carries it from a `recv` back to the matching `inject`.
#[derive(Clone, Copy)]
pub struct RawAddr(pub [u8; 80]);

impl Default for RawAddr {
    fn default() -> Self {
        RawAddr([0u8; 80])
    }
}

/// Direction + checksum-validity + the opaque backend address for one packet.
#[derive(Clone, Copy, Default)]
pub struct CaptureMeta {
    pub outbound: bool,
    pub ipv6: bool,
    pub impostor: bool,
    pub loopback: bool,
    pub ip_checksum_valid: bool,
    pub tcp_checksum_valid: bool,
    pub udp_checksum_valid: bool,
    pub raw: RawAddr,
}

/// A received packet: a prefix of the caller's buffer plus its metadata.
pub struct Captured<'a> {
    pub data: &'a mut [u8],
    pub meta: CaptureMeta,
}

pub trait PacketSource: Send {
    /// Blocking receive into `buf`. Returns [`CoreError::SourceShutdown`] once
    /// the source has been shut down.
    fn recv<'b>(&mut self, buf: &'b mut [u8]) -> Result<Captured<'b>, CoreError>;
    /// Unblock any in-flight `recv` and stop receiving.
    fn shutdown(&mut self) -> Result<(), CoreError>;
}

/// Which checksums to recompute over a mutated packet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChecksumWhich {
    /// IP + transport (the normal case after a mutation).
    IpAndL4,
    /// IP header only.
    Ip,
    /// Transport (TCP/UDP) only.
    L4,
}

pub trait PacketSink: Send {
    /// Inject one packet; `meta` decides direction (and, for inbound, the
    /// interface). Pass a `meta` obtained from a `recv` to reinject verbatim.
    fn inject(&mut self, packet: &[u8], meta: &CaptureMeta) -> Result<(), CoreError>;
    /// Inject a batch in order (fake packets, fragments …).
    fn inject_batch(&mut self, batch: &SendBatch) -> Result<(), CoreError>;
    /// Recompute checksums in-place over a mutated packet and refresh the
    /// checksum-valid bits in `meta` (so a following `inject` is correct).
    /// Mirrors GoodbyeDPI's `WinDivertHelperCalcChecksums` after mutation.
    fn recalc_checksums(
        &mut self,
        packet: &mut [u8],
        meta: &mut CaptureMeta,
        which: ChecksumWhich,
    ) -> Result<(), CoreError>;
}

/// What the engine should do to a batch item's checksums before injecting it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum ChecksumOp {
    /// Recompute IP + TCP/UDP checksums (the normal case).
    #[default]
    Recompute,
    /// Recompute, then flip the TCP checksum by 1 (GoodbyeDPI `--wrong-chksum`).
    RecomputeThenBreakTcp,
    /// Leave the bytes exactly as the transform produced them.
    Keep,
}

/// Ordered list of packets to inject.
#[derive(Default)]
pub struct SendBatch {
    pub items: Vec<SendItem>,
}

pub struct SendItem {
    pub bytes: Vec<u8>,
    pub meta: CaptureMeta,
    pub checksum: ChecksumOp,
}

impl SendBatch {
    pub fn new() -> Self {
        Self::default()
    }
    /// Push an item whose checksums the engine will recompute.
    pub fn push(&mut self, bytes: Vec<u8>, meta: CaptureMeta) {
        self.push_op(bytes, meta, ChecksumOp::Recompute);
    }
    pub fn push_op(&mut self, bytes: Vec<u8>, meta: CaptureMeta, checksum: ChecksumOp) {
        self.items.push(SendItem { bytes, meta, checksum });
    }
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }
    pub fn len(&self) -> usize {
        self.items.len()
    }
}
