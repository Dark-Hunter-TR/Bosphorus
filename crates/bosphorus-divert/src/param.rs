use windivert_sys::WinDivertParam;

/// Tunable handle parameters (`WinDivertSetParam` / `WinDivertGetParam`).
#[derive(Debug, Clone, Copy)]
pub enum Param {
    QueueLength,
    QueueTime,
    QueueSize,
    VersionMajor,
    VersionMinor,
}

impl Param {
    pub(crate) fn to_sys(self) -> WinDivertParam {
        match self {
            Param::QueueLength => WinDivertParam::QueueLength,
            Param::QueueTime => WinDivertParam::QueueTime,
            Param::QueueSize => WinDivertParam::QueueSize,
            Param::VersionMajor => WinDivertParam::VersionMajor,
            Param::VersionMinor => WinDivertParam::VersionMinor,
        }
    }
}
