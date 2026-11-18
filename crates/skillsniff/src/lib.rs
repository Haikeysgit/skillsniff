//! Core engine of skillsniff.

pub mod acquire;
pub mod analyzers;
pub mod export;
pub mod frontmatter;
pub mod inventory;
pub mod model;
pub mod progress;
pub mod review;
pub mod rules;
pub mod scan;
pub mod score;
pub mod source;
pub mod suppress;
pub mod target;

/// Crate version, as published.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
