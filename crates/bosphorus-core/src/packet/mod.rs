//! Hand-rolled IPv4/IPv6 + TCP/UDP parsing and (M4) mutation.
//!
//! Deliberately dependency-free (no `etherparse`): the surface we need is small,
//! every branch is covered by fixture tests, and we avoid tracking an external
//! parser's API across versions.

mod builder;
pub mod quic;
mod tls;
mod view;

pub use builder::PacketBuilder;
pub use quic::is_connection_attempt as is_quic_connection_attempt;
pub use tls::{
    add_padding_extension, find_sni, looks_like_client_hello, looks_like_server_hello,
    tls_content_type, SniLocation,
};
pub use view::{FiveTuple, PacketView, TcpFlags};
