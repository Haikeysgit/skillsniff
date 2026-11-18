//! Parsing of the source argument: a GitHub reference, a folder or an archive.

use std::path::{Path, PathBuf};

use crate::acquire::validate_entry_path;

/// Where a skill comes from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Source {
    GitHub {
        owner: String,
        repo: String,
        /// Subfolder (or file) inside the repository, normalised with `/`.
        path: Option<String>,
        /// Branch, tag or commit; `None` means the default branch.
        git_ref: Option<String>,
    },
    LocalDir(PathBuf),
    Archive(PathBuf),
}

/// Parses a source argument.
///
/// Accepted: an existing folder or file on disk (local paths win over the
/// shorthand), `https://github.com/o/r`, `github.com/o/r/tree/<ref>/<path>`,
/// `o/r`, `o/r/path`, `o/r@ref` and `o/r/path@ref`.
pub fn parse_source(s: &str) -> Result<Source, String> {
    let p = Path::new(s);
    if let Ok(meta) = std::fs::metadata(p) {
        return Ok(if meta.is_dir() {
            Source::LocalDir(p.to_path_buf())
        } else {
            Source::Archive(p.to_path_buf())
        });
    }
    if let Some(rest) = strip_github_prefix(s) {
        return parse_url_tail(rest);
    }
    if s.contains("://") {
        return Err(format!("unsupported source \"{}\"", shown(s)));
    }
    parse_shorthand(s)
}

fn shown(s: &str) -> String {
    crate::model::sanitize_evidence(s)
}

fn strip_github_prefix(s: &str) -> Option<&str> {
    s.strip_prefix("https://github.com/")
        .or_else(|| s.strip_prefix("github.com/"))
}

fn valid_name(n: &str) -> bool {
    !n.is_empty()
        && n != "."
        && n != ".."
        && n.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

fn valid_ref(r: &str) -> bool {
    !r.is_empty()
        && !r.contains("..")
        && !r.starts_with('/')
        && !r.ends_with('/')
        && !r.contains("//")
        && r.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b'/'))
}

fn github(
    owner: &str,
    repo: &str,
    path: Option<&str>,
    git_ref: Option<&str>,
) -> Result<Source, String> {
    let repo = repo.strip_suffix(".git").unwrap_or(repo);
    if !valid_name(owner) {
        return Err(format!("invalid GitHub owner \"{}\"", shown(owner)));
    }
    if !valid_name(repo) {
        return Err(format!("invalid GitHub repository \"{}\"", shown(repo)));
    }
    let path = match path {
        Some(p) if !p.is_empty() => {
            let norm = validate_entry_path(p).map_err(|e| e.to_string())?;
            if norm.is_empty() { None } else { Some(norm) }
        }
        _ => None,
    };
    if let Some(r) = git_ref
        && !valid_ref(r)
    {
        return Err(format!("invalid git ref \"{}\"", shown(r)));
    }
    Ok(Source::GitHub {
        owner: owner.to_string(),
        repo: repo.to_string(),
        path,
        git_ref: git_ref.map(str::to_string),
    })
}

/// `o/r`, `o/r/path`, each with an optional `@ref` at the end.
fn parse_shorthand(s: &str) -> Result<Source, String> {
    let (body, git_ref) = match s.rsplit_once('@') {
        Some((b, r)) => (b, Some(r)),
        None => (s, None),
    };
    let mut it = body.splitn(3, '/');
    let (Some(owner), Some(repo)) = (it.next(), it.next()) else {
        return Err(format!(
            "\"{}\" is not a path on disk or a GitHub reference like owner/repo",
            shown(s)
        ));
    };
    github(owner, repo, it.next(), git_ref)
}

/// What follows `github.com/`: `o/r` or `o/r/tree/<ref>[/<path>]`.
fn parse_url_tail(rest: &str) -> Result<Source, String> {
    let rest = rest.trim_end_matches('/');
    let parts: Vec<&str> = rest.split('/').collect();
    match parts.as_slice() {
        [o, r] => github(o, r, None, None),
        [o, r, "tree", git_ref] => github(o, r, None, Some(git_ref)),
        [o, r, "tree", git_ref, path @ ..] => github(o, r, Some(&path.join("/")), Some(git_ref)),
        _ => Err(format!(
            "unsupported GitHub URL \"{}\" (expected github.com/owner/repo or .../tree/<ref>/<path>)",
            shown(rest)
        )),
    }
}
