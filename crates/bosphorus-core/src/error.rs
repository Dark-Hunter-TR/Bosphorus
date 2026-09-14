/// Errors from the core engine and its helpers.
#[derive(Debug, thiserror::Error)]
pub enum CoreError {
    #[error("packet parse: {0}")]
    Parse(&'static str),
    #[error("packet too short for the requested operation")]
    ShortPacket,
    #[error("filter build: {0}")]
    Filter(String),
    #[error("config: {0}")]
    Config(String),
    /// The [`PacketSource`](crate::PacketSource) was shut down — normal loop exit.
    #[error("source shut down")]
    SourceShutdown,
    #[error("source: {0}")]
    Source(String),
    #[error("sink: {0}")]
    Sink(String),
}
