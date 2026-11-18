//! Core engine of skillsniff.

pub mod acquire;
pub mod analyzers;
pub mod frontmatter;
pub mod inventory;
pub mod model;
pub mod progress;
pub mod rules;
pub mod score;
pub mod source;
pub mod target;

/// Crate version, as published.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
