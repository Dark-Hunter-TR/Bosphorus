//! WinDivert implementation of the core `PacketSource` / `PacketSink` traits.

use std::sync::Arc;

use bosphorus_core::{
    CaptureMeta, Captured, ChecksumWhich, CoreError, PacketSink, PacketSource, RawAddr, SendBatch,
};
use bosphorus_divert::{calc_checksums, Address, ChecksumFlags, DivertError, WinDivertHandle, ADDRESS_SIZE};

// `RawAddr`'s inner array must match the WinDivert address size exactly.
const _: () = assert!(ADDRESS_SIZE == 80);

fn meta_from_addr(a: &Address) -> CaptureMeta {
    CaptureMeta {
        outbound: a.outbound(),
        ipv6: a.ipv6(),
        impostor: a.impostor(),
        loopback: a.loopback(),
        ip_checksum_valid: a.ip_checksum_valid(),
        tcp_checksum_valid: a.tcp_checksum_valid(),
        udp_checksum_valid: a.udp_checksum_valid(),
        raw: RawAddr(a.to_bytes()),
    }
}

fn addr_from_meta(m: &CaptureMeta) -> Address {
    Address::from_bytes(m.raw.0)
}

pub struct WinDivertSource {
    pub h: Arc<WinDivertHandle>,
}

pub struct WinDivertSink {
    pub h: Arc<WinDivertHandle>,
}

impl PacketSource for WinDivertSource {
    fn recv<'b>(&mut self, buf: &'b mut [u8]) -> Result<Captured<'b>, CoreError> {
        match self.h.recv(buf) {
            Ok(r) => Ok(Captured {
                meta: meta_from_addr(&r.addr),
                data: r.data,
            }),
            Err(DivertError::ShutDown) => Err(CoreError::SourceShutdown),
            Err(e) => Err(CoreError::Source(e.to_string())),
        }
    }
    fn shutdown(&mut self) -> Result<(), CoreError> {
        self.h
            .shutdown_both()
            .map_err(|e| CoreError::Source(e.to_string()))
    }
}

impl PacketSink for WinDivertSink {
    fn inject(&mut self, packet: &[u8], meta: &CaptureMeta) -> Result<(), CoreError> {
        let addr = addr_from_meta(meta);
        self.h
            .send(packet, &addr)
            .map(|_| ())
            .map_err(|e| CoreError::Sink(e.to_string()))
    }
    fn inject_batch(&mut self, batch: &SendBatch) -> Result<(), CoreError> {
        for item in &batch.items {
            let addr = addr_from_meta(&item.meta);
            self.h
                .send(&item.bytes, &addr)
                .map_err(|e| CoreError::Sink(e.to_string()))?;
        }
        Ok(())
    }

    fn recalc_checksums(
        &mut self,
        packet: &mut [u8],
        meta: &mut CaptureMeta,
        which: ChecksumWhich,
    ) -> Result<(), CoreError> {
        let mut addr = addr_from_meta(meta);
        // Mark the checksums invalid so WinDivert recomputes them (GoodbyeDPI
        // does the same before `WinDivertHelperCalcChecksums`).
        addr.set_ip_checksum_valid(false);
        addr.set_tcp_checksum_valid(false);
        addr.set_udp_checksum_valid(false);

        let flags = match which {
            ChecksumWhich::IpAndL4 => ChecksumFlags::new(),
            ChecksumWhich::Ip => ChecksumFlags::new().set_no_tcp().set_no_udp(),
            ChecksumWhich::L4 => ChecksumFlags::new().set_no_ip(),
        };
        calc_checksums(packet, Some(&mut addr), flags).map_err(|e| CoreError::Sink(e.to_string()))?;

        meta.raw = RawAddr(addr.to_bytes());
        meta.ip_checksum_valid = addr.ip_checksum_valid();
        meta.tcp_checksum_valid = addr.tcp_checksum_valid();
        meta.udp_checksum_valid = addr.udp_checksum_valid();
        Ok(())
    }
}
