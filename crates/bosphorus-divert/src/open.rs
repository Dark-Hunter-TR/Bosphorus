use windivert_sys::{WinDivertFlags, WinDivertLayer};

/// WinDivert capture layer. M0 uses only [`Layer::Network`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Layer {
    Network,
    NetworkForward,
}

impl Layer {
    pub(crate) fn to_sys(self) -> WinDivertLayer {
        match self {
            Layer::Network => WinDivertLayer::Network,
            Layer::NetworkForward => WinDivertLayer::Forward,
        }
    }
}

/// Open flags for [`crate::WinDivertHandle::open`].
///
/// `sniff` = observe without removing packets from the stack (no reinjection
/// needed, cannot break connections). `drop` = silently discard matches
/// (used later for the QUIC-block handle).
#[derive(Debug, Clone, Copy, Default)]
pub struct OpenFlags {
    pub sniff: bool,
    pub drop: bool,
    pub recv_only: bool,
    pub send_only: bool,
    pub no_installs: bool,
    pub fragments: bool,
}

impl OpenFlags {
    pub const fn new() -> Self {
        Self {
            sniff: false,
            drop: false,
            recv_only: false,
            send_only: false,
            no_installs: false,
            fragments: false,
        }
    }
    pub const fn sniff(mut self) -> Self {
        self.sniff = true;
        self
    }
    pub const fn drop(mut self) -> Self {
        self.drop = true;
        self
    }
    pub const fn recv_only(mut self) -> Self {
        self.recv_only = true;
        self
    }
    pub const fn send_only(mut self) -> Self {
        self.send_only = true;
        self
    }
    pub const fn fragments(mut self) -> Self {
        self.fragments = true;
        self
    }

    pub(crate) fn to_sys(self) -> WinDivertFlags {
        let mut f = WinDivertFlags::new();
        if self.sniff {
            f = f.set_sniff();
        }
        if self.drop {
            f = f.set_drop();
        }
        if self.recv_only {
            f = f.set_recv_only();
        }
        if self.send_only {
            f = f.set_send_only();
        }
        if self.no_installs {
            f = f.set_no_installs();
        }
        if self.fragments {
            f = f.set_fragments();
        }
        f
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Bit values per the WinDivert 2.2 header (WINDIVERT_FLAG_*).
    #[test]
    fn open_flag_bits() {
        assert_eq!(u64::from(OpenFlags::new().to_sys()), 0x0);
        assert_eq!(u64::from(OpenFlags::new().sniff().to_sys()), 0x0001);
        assert_eq!(u64::from(OpenFlags::new().drop().to_sys()), 0x0002);
        assert_eq!(u64::from(OpenFlags::new().recv_only().to_sys()), 0x0004);
        assert_eq!(u64::from(OpenFlags::new().send_only().to_sys()), 0x0008);
        assert_eq!(u64::from(OpenFlags::new().fragments().to_sys()), 0x0020);
        assert_eq!(
            u64::from(OpenFlags::new().sniff().fragments().to_sys()),
            0x0021
        );
    }

    #[test]
    fn layer_maps() {
        assert!(matches!(Layer::Network.to_sys(), WinDivertLayer::Network));
        assert!(matches!(
            Layer::NetworkForward.to_sys(),
            WinDivertLayer::Forward
        ));
    }
}
