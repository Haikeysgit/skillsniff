//! The agent skill target: one directory with a `SKILL.md`.

use std::collections::BTreeMap;
use std::io::Read;
use std::path::{Path, PathBuf};

use super::{FileRole, Lang, Target, TargetError};
use crate::frontmatter::parse_typed;
use crate::inventory::{ContentType, FileEntry, Inventory};

/// A detected skill.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkillTarget {
    /// Path of `SKILL.md` relative to the scan root.
    pub skill_md: String,
    pub name: String,
    pub description: String,
    /// Scan root; needed to read shebang lines during classification.
    pub root: PathBuf,
}

fn parent_dir(path: &str) -> String {
    match path.rsplit_once('/') {
        Some((dir, _)) => dir.to_string(),
        None => ".".to_string(),
    }
}

fn basename(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

/// Find the single skill in `inv`, reading its frontmatter from under `root`.
pub fn detect_skill(inv: &Inventory, root: &Path) -> Result<SkillTarget, TargetError> {
    let skills: Vec<&FileEntry> = inv
        .files
        .iter()
        .filter(|f| basename(&f.path) == "SKILL.md")
        .collect();
    let entry = match skills.as_slice() {
        [] => return Err(TargetError::NoSkill),
        [one] => *one,
        many => {
            let mut dirs: Vec<String> = many.iter().map(|f| parent_dir(&f.path)).collect();
            dirs.sort();
            return Err(TargetError::MultipleSkills(dirs));
        }
    };
    let bad = |why: String| TargetError::BadFrontmatter(why);
    if entry.content_type == ContentType::Binary {
        return Err(bad("SKILL.md is not text".to_string()));
    }
    let bytes = std::fs::read(root.join(&entry.path)).map_err(|e| bad(e.to_string()))?;
    let text = String::from_utf8(bytes).map_err(|_| bad("SKILL.md is not valid UTF-8".into()))?;
    let (map, _) = parse_typed(&text).map_err(bad)?;
    let field = |key: &str| match map.get(key).map(|(v, is_str)| (v.trim(), *is_str)) {
        Some((v, true)) if !v.is_empty() => Ok(v.to_string()),
        _ => Err(bad(format!("`{key}` is missing, empty or not a string"))),
    };
    Ok(SkillTarget {
        skill_md: entry.path.clone(),
        name: field("name")?,
        description: field("description")?,
        root: root.to_path_buf(),
    })
}

fn lang_for_extension(ext: &str) -> Option<Lang> {
    Some(match ext {
        "py" => Lang::Python,
        "js" | "mjs" | "cjs" => Lang::JavaScript,
        "ts" | "mts" | "cts" => Lang::TypeScript,
        "sh" | "bash" => Lang::Bash,
        "ps1" | "psm1" => Lang::PowerShell,
        _ => return None,
    })
}

/// True when the first line is a `bash` or `sh` shebang.
fn has_shell_shebang(path: &Path) -> bool {
    let Ok(file) = std::fs::File::open(path) else {
        return false;
    };
    let mut buf = Vec::new();
    if file.take(256).read_to_end(&mut buf).is_err() {
        return false;
    }
    let first = buf.split(|&b| b == b'\n').next().unwrap_or(&[]);
    let Some(rest) = first.strip_prefix(b"#!") else {
        return false;
    };
    let line = String::from_utf8_lossy(rest);
    let mut words = line.split_whitespace();
    let Some(interp) = words.next() else {
        return false;
    };
    let mut name = basename(interp);
    if name == "env" {
        // Skip `env` options such as `-S`.
        name = words.find(|w| !w.starts_with('-')).map_or("", basename);
    }
    matches!(name, "bash" | "sh")
}

fn is_manifest(name: &str) -> bool {
    name == "package.json"
        || name == "pyproject.toml"
        || name == "Cargo.toml"
        || (name.starts_with("requirements") && name.ends_with(".txt"))
}

fn is_config(path: &str) -> bool {
    let name = basename(path);
    if name == "settings.json" {
        return true;
    }
    name.ends_with(".json")
        && path
            .split('/')
            .rev()
            .skip(1)
            .any(|seg| matches!(seg, ".claude" | ".codex" | "hooks"))
}

fn classify_file(root: &Path, f: &FileEntry) -> FileRole {
    if f.content_type == ContentType::Binary {
        return FileRole::Binary;
    }
    let name = basename(&f.path);
    let ext = name
        .rsplit_once('.')
        .map(|(_, e)| e.to_ascii_lowercase())
        .unwrap_or_default();
    if name == "SKILL.md" || ext == "md" || ext == "markdown" {
        return FileRole::Instructions;
    }
    if let Some(lang) = lang_for_extension(&ext) {
        return FileRole::Script(lang);
    }
    if is_manifest(name) {
        return FileRole::Manifest;
    }
    if is_config(&f.path) {
        return FileRole::Config;
    }
    if has_shell_shebang(&root.join(&f.path)) {
        return FileRole::Script(Lang::Bash);
    }
    FileRole::Asset
}

impl Target for SkillTarget {
    fn kind(&self) -> &'static str {
        "skill"
    }

    fn classify(&self, inv: &Inventory) -> BTreeMap<String, FileRole> {
        inv.files
            .iter()
            .map(|f| (f.path.clone(), classify_file(&self.root, f)))
            .collect()
    }
}
