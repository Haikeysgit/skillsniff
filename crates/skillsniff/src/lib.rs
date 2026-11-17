//! Core engine of skillsniff.

pub mod acquire;
pub mod model;
pub mod score;
pub mod source;

/// Crate version, as published.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
