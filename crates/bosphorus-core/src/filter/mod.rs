//! WinDivert filter-string assembly (verbatim GoodbyeDPI fragments + a
//! 443-focused main filter with the inbound verdict clause).

mod builder;
pub mod templates;

pub use builder::{build, Filters};
