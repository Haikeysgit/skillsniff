//! Core engine of skillsniff.

pub mod model;
pub mod score;

/// Crate version, as published.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
