//! What is being scanned and how its files are classified.

use std::collections::BTreeMap;
use std::fmt;

use crate::inventory::Inventory;

pub mod skill;

pub use skill::{SkillTarget, detect_skill};

/// Scripting language of a script file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lang {
    Python,
    JavaScript,
    TypeScript,
    Bash,
    PowerShell,
}

/// Role a file plays in the scanned tree.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileRole {
    Instructions,
    Script(Lang),
    Manifest,
    Config,
    Asset,
    Binary,
}

/// A kind of scan target.
pub trait Target {
    fn kind(&self) -> &'static str;
    /// Role of every inventory file, keyed by its path relative to the scan root.
    fn classify(&self, inv: &Inventory) -> BTreeMap<String, FileRole>;
}

/// Why no usable skill could be detected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TargetError {
    NoSkill,
    /// Parent directories of every `SKILL.md`, relative, `/`-separated, sorted.
    MultipleSkills(Vec<String>),
    BadFrontmatter(String),
}

impl fmt::Display for TargetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoSkill => write!(f, "no SKILL.md found"),
            Self::MultipleSkills(dirs) => {
                write!(f, "more than one SKILL.md found: {}", dirs.join(", "))
            }
            Self::BadFrontmatter(why) => write!(f, "invalid SKILL.md frontmatter: {why}"),
        }
    }
}

impl std::error::Error for TargetError {}
