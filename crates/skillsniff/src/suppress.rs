//! User-controlled suppressions of findings.
//!
//! Suppressions come only from the user's own configuration file (or a path
//! the user passes explicitly). They are never read from the scanned target or
//! the current directory, so a skill cannot silence its own findings.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use yaml_rust2::{Yaml, YamlLoader};

use crate::model::{Finding, Severity};

/// Largest accepted suppressions file, in bytes.
const MAX_FILE_BYTES: u64 = 256 * 1024;

/// Silences one rule for one exact target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Suppression {
    pub rule: String,
    /// A commit SHA or a `tree_sha256` value.
    pub target: String,
    pub reason: String,
}

fn absolute_env(name: &str) -> Option<PathBuf> {
    let v = std::env::var_os(name).filter(|v| !v.is_empty())?;
    let p = PathBuf::from(v);
    p.is_absolute().then_some(p)
}

/// Default location of the suppressions file: `$XDG_CONFIG_HOME/skillsniff/`,
/// else `%APPDATA%\skillsniff\` on Windows, else `~/.config/skillsniff/`.
/// Only absolute locations are used.
pub fn default_suppressions_path() -> Option<PathBuf> {
    let base = absolute_env("XDG_CONFIG_HOME")
        .or_else(|| {
            if cfg!(windows) {
                absolute_env("APPDATA")
            } else {
                None
            }
        })
        .or_else(|| {
            let home = absolute_env("HOME").or_else(|| absolute_env("USERPROFILE"))?;
            Some(home.join(".config"))
        })?;
    Some(base.join("skillsniff").join("suppressions.yaml"))
}

/// Loads suppressions from `path`, or from the default location when `None`.
/// A missing default file means no suppressions; a missing explicit file is an
/// error. An empty `reason` is an error.
pub fn load_suppressions(path: Option<&Path>) -> Result<Vec<Suppression>, String> {
    let (path, explicit) = match path {
        Some(p) => (p.to_path_buf(), true),
        None => match default_suppressions_path() {
            Some(p) => (p, false),
            None => return Ok(Vec::new()),
        },
    };
    let shown = path.display();
    let meta = match fs::metadata(&path) {
        Ok(m) => m,
        Err(e) if !explicit && e.kind() == std::io::ErrorKind::NotFound => {
            return Ok(Vec::new());
        }
        Err(e) => return Err(format!("cannot read suppressions file {shown}: {e}")),
    };
    if meta.len() > MAX_FILE_BYTES {
        return Err(format!("{shown}: suppressions file is larger than 256 KiB"));
    }
    let text = fs::read_to_string(&path).map_err(|e| format!("{shown}: {e}"))?;
    parse(&text).map_err(|e| format!("{shown}: {e}"))
}

fn parse(text: &str) -> Result<Vec<Suppression>, String> {
    let docs = YamlLoader::load_from_str(text).map_err(|e| format!("invalid YAML: {e}"))?;
    let Some(doc) = docs.first() else {
        return Ok(Vec::new());
    };
    if docs.len() > 1 {
        return Err("suppressions file must hold one YAML document".to_string());
    }
    let list = match &doc["suppressions"] {
        Yaml::Array(list) => list,
        Yaml::BadValue | Yaml::Null => return Ok(Vec::new()),
        _ => return Err("`suppressions` must be a list".to_string()),
    };
    let mut out = Vec::new();
    for (i, node) in list.iter().enumerate() {
        let field = |key: &str| {
            node[key]
                .as_str()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string)
        };
        let n = i + 1;
        out.push(Suppression {
            rule: field("rule").ok_or_else(|| format!("suppression {n}: missing `rule`"))?,
            target: field("target").ok_or_else(|| format!("suppression {n}: missing `target`"))?,
            reason: field("reason").ok_or_else(|| {
                format!("suppression {n}: `reason` is required and must not be empty")
            })?,
        });
    }
    Ok(out)
}

/// Marks findings suppressed when a suppression names their rule and either
/// the commit or the tree hash of the scanned target. Critical findings are
/// never suppressed; each ignored attempt is returned as a message for
/// `ReviewInfo.rejected_changes`.
pub fn apply_suppressions(
    findings: &mut [Finding],
    sup: &[Suppression],
    commit: Option<&str>,
    tree: &str,
) -> Vec<String> {
    let mut rejected = BTreeSet::new();
    for s in sup {
        if commit != Some(s.target.as_str()) && tree != s.target {
            continue;
        }
        for f in findings.iter_mut().filter(|f| f.rule == s.rule) {
            if f.severity == Severity::Critical {
                rejected.insert(format!("suppression ignored for critical rule {}", f.rule));
            } else {
                f.suppressed = true;
            }
        }
    }
    rejected.into_iter().collect()
}
