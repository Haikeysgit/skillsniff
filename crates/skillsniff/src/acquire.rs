//! Quarantine and acquisition of untrusted skill sources.
//!
//! Everything read here is attacker-controlled. Content is copied into a
//! private temporary directory (the quarantine) and nothing else:
//!
//! - every entry path goes through [`validate_entry_path`] before any write;
//! - symlinks, hard links, junctions and case-colliding paths are never
//!   created, they become `INVENTORY` signals;
//! - files are created with `create_new`, so nothing is ever written through
//!   an existing path, and without executable bits;
//! - sizes, counts and the decompression ratio are checked while streaming.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use tempfile::TempDir;

use crate::model::signal::INVENTORY;
use crate::model::{Location, Signal, sanitize_evidence};

mod archive;
mod github;
mod limits;
mod local;

pub use archive::acquire_archive;
pub use github::{acquire_github, acquire_github_with_token};
pub use limits::Limits;
pub use local::acquire_local_dir;

/// Values of the `pattern` field on `INVENTORY` signals produced here.
pub const INVENTORY_PATTERNS: &[&str] = &["symlink", "hardlink", "case_collision"];

const PATTERN_SYMLINK: &str = "symlink";
const PATTERN_HARDLINK: &str = "hardlink";
const PATTERN_CASE_COLLISION: &str = "case_collision";

/// Longest accepted entry path, in bytes.
const MAX_PATH_BYTES: usize = 1024;

/// A private temporary directory holding acquired content. Dropping it
/// deletes the directory and everything in it.
#[derive(Debug)]
pub struct Quarantine {
    dir: TempDir,
}

impl Quarantine {
    /// Creates an empty quarantine under the OS temporary directory.
    pub fn new() -> io::Result<Quarantine> {
        let dir = tempfile::Builder::new().prefix("skillsniff-").tempdir()?;
        Ok(Quarantine { dir })
    }

    /// Root of the acquired tree.
    pub fn root(&self) -> &Path {
        self.dir.path()
    }

    /// Keeps the directory on disk (for `--keep`) and returns its path.
    pub fn keep(self) -> PathBuf {
        self.dir.keep()
    }
}

/// Result of acquiring a source into a quarantine.
#[derive(Debug)]
pub struct Acquired {
    pub quarantine: Quarantine,
    /// The source as given (path or URL).
    pub source: String,
    /// Commit SHA for git sources; `None` for folders and archives.
    pub commit: Option<String>,
    /// `INVENTORY` signals for entries that were not extracted.
    pub signals: Vec<Signal>,
}

#[derive(Debug)]
pub enum AcquireError {
    NotFound(String),
    LimitExceeded(String),
    Unsupported(String),
    Network(String),
    Io(io::Error),
}

impl fmt::Display for AcquireError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AcquireError::NotFound(s) => write!(f, "not found: {s}"),
            AcquireError::LimitExceeded(s) => write!(f, "limit exceeded: {s}"),
            AcquireError::Unsupported(s) => write!(f, "unsupported: {s}"),
            AcquireError::Network(s) => write!(f, "network error: {s}"),
            AcquireError::Io(e) => write!(f, "i/o error: {e}"),
        }
    }
}

impl std::error::Error for AcquireError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            AcquireError::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for AcquireError {
    fn from(e: io::Error) -> Self {
        AcquireError::Io(e)
    }
}

fn unsafe_path(raw: &str, why: &str) -> AcquireError {
    AcquireError::Unsupported(format!(
        "unsafe entry path \"{}\": {why}",
        sanitize_evidence(raw)
    ))
}

/// Validates an entry path from any source and returns it normalised:
/// components joined by `/`, with empty and `.` components dropped. An empty
/// result means the root itself.
///
/// Both `/` and `\` count as separators. Rejected: NUL and control
/// characters, absolute and UNC paths, drive prefixes and any `:` (NTFS
/// streams), `..`, components ending in `.` or space (Windows strips them, so
/// `.. ` would become `..`), characters Windows forbids, reserved device
/// names, 8.3 short-name aliases, and paths over 1024 bytes. The same rules
/// apply on every OS so results do not depend on the host.
pub(crate) fn validate_entry_path(raw: &str) -> Result<String, AcquireError> {
    if raw.is_empty() {
        return Err(unsafe_path(raw, "empty path"));
    }
    if raw.len() > MAX_PATH_BYTES {
        return Err(unsafe_path(raw, "path too long"));
    }
    if raw.contains('\0') {
        return Err(unsafe_path(raw, "NUL character"));
    }
    if raw.starts_with('/') || raw.starts_with('\\') {
        return Err(unsafe_path(raw, "absolute or UNC path"));
    }
    if raw.contains(':') {
        return Err(unsafe_path(raw, "drive prefix or stream separator"));
    }
    let mut parts: Vec<&str> = Vec::new();
    for comp in raw.split(['/', '\\']) {
        match comp {
            "" | "." => continue,
            ".." => return Err(unsafe_path(raw, "parent directory component")),
            _ => {}
        }
        if comp
            .chars()
            .any(|c| c.is_control() || matches!(c, '<' | '>' | '"' | '|' | '?' | '*'))
        {
            return Err(unsafe_path(raw, "character not allowed in file names"));
        }
        if comp.ends_with('.') || comp.ends_with(' ') {
            return Err(unsafe_path(raw, "component ends with a dot or space"));
        }
        if is_reserved_device_name(comp) {
            return Err(unsafe_path(raw, "reserved device name"));
        }
        if is_short_name_alias(comp) {
            return Err(unsafe_path(raw, "8.3 short-name alias"));
        }
        parts.push(comp);
    }
    Ok(parts.join("/"))
}

/// `CON`, `nul.txt`, `COM1 .log` and similar open devices on Windows.
fn is_reserved_device_name(comp: &str) -> bool {
    let stem = comp.split('.').next().unwrap_or("").trim_end_matches(' ');
    let upper = stem.to_ascii_uppercase();
    if matches!(
        upper.as_str(),
        "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$"
    ) {
        return true;
    }
    let mut chars = stem.chars();
    let head: String = chars
        .by_ref()
        .take(3)
        .collect::<String>()
        .to_ascii_uppercase();
    let rest: Vec<char> = chars.collect();
    (head == "COM" || head == "LPT")
        && rest.len() == 1
        && (rest[0].is_ascii_digit() || matches!(rest[0], '¹' | '²' | '³'))
}

/// `PROGRA~1`-style names can alias another entry on Windows volumes that
/// generate 8.3 names.
fn is_short_name_alias(comp: &str) -> bool {
    let bytes = comp.as_bytes();
    bytes.iter().enumerate().any(|(i, &b)| {
        if b != b'~' {
            return false;
        }
        let digits = bytes[i + 1..]
            .iter()
            .take_while(|d| d.is_ascii_digit())
            .count();
        digits > 0 && matches!(bytes.get(i + 1 + digits), None | Some(b'.'))
    })
}

/// What an archive or directory entry is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum EntryKind {
    File,
    Dir,
    Symlink { target: Option<String> },
    Hardlink { target: Option<String> },
}

/// One entry with a validated, non-empty path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Entry {
    pub(crate) path: String,
    pub(crate) kind: EntryKind,
}

impl Entry {
    /// Validates `raw` and builds the entry. Returns `None` for the root
    /// directory itself (`./`), which needs no work.
    pub(crate) fn new(raw: &str, kind: EntryKind) -> Result<Option<Entry>, AcquireError> {
        let path = validate_entry_path(raw)?;
        if path.is_empty() {
            return match kind {
                EntryKind::Dir => Ok(None),
                _ => Err(unsafe_path(raw, "empty path")),
            };
        }
        Ok(Some(Entry { path, kind }))
    }
}

/// Which entries to extract, and the signals for those that are not.
#[derive(Debug)]
pub(crate) struct Plan {
    /// Parallel to the entries: `true` means do not create it.
    pub(crate) skip: Vec<bool>,
    pub(crate) signals: Vec<Signal>,
}

/// Case-folds one path component. Folding through upper case makes `ς`, `σ`
/// and `Σ` equal, as case-insensitive file systems do; over-matching is
/// safe because colliding entries are only skipped.
fn fold(comp: &str) -> String {
    comp.chars()
        .flat_map(char::to_uppercase)
        .flat_map(char::to_lowercase)
        .collect()
}

/// Calls `f(original_prefix, folded_prefix, is_last)` for each prefix of
/// `path`: `a`, `a/b`, `a/b/c`.
fn for_each_prefix(path: &str, mut f: impl FnMut(&str, &str, bool)) {
    let comps: Vec<&str> = path.split('/').collect();
    let mut orig = String::new();
    let mut folded = String::new();
    for (i, c) in comps.iter().enumerate() {
        if i > 0 {
            orig.push('/');
            folded.push('/');
        }
        orig.push_str(c);
        folded.push_str(&fold(c));
        f(&orig, &folded, i + 1 == comps.len());
    }
}

/// Compares every path, case-insensitively, before anything is written.
/// A collision is two spellings of one folded path, two non-directory
/// entries at one path, or one path used both as a file and as a directory.
/// Colliding paths and everything below them are skipped; links are always
/// skipped.
pub(crate) fn plan(entries: &[Entry]) -> Plan {
    #[derive(Default)]
    struct Key {
        spellings: BTreeSet<String>,
        as_dir: bool,
        non_dirs: usize,
    }
    let mut keys: BTreeMap<String, Key> = BTreeMap::new();
    for e in entries {
        for_each_prefix(&e.path, |orig, folded, last| {
            let k = keys.entry(folded.to_string()).or_default();
            k.spellings.insert(orig.to_string());
            if !last || e.kind == EntryKind::Dir {
                k.as_dir = true;
            } else {
                k.non_dirs += 1;
            }
        });
    }
    let colliding: BTreeMap<String, Vec<String>> = keys
        .into_iter()
        .filter(|(_, k)| k.spellings.len() > 1 || k.non_dirs > 1 || (k.non_dirs > 0 && k.as_dir))
        .map(|(folded, k)| (folded, k.spellings.into_iter().collect()))
        .collect();

    let mut signals = Vec::new();
    let mut skip = Vec::with_capacity(entries.len());
    for e in entries {
        let mut collides = false;
        for_each_prefix(&e.path, |_, folded, _| {
            collides |= colliding.contains_key(folded);
        });
        let (is_link, pattern, target) = match &e.kind {
            EntryKind::Symlink { target } => (true, PATTERN_SYMLINK, target.as_deref()),
            EntryKind::Hardlink { target } => (true, PATTERN_HARDLINK, target.as_deref()),
            _ => (false, "", None),
        };
        if is_link {
            let label = if pattern == PATTERN_SYMLINK {
                "symlink"
            } else {
                "hard link"
            };
            let evidence = match target {
                Some(t) => format!("{label} {} -> {t}", e.path),
                None => format!("{label} {}", e.path),
            };
            signals.push(inventory_signal(
                pattern,
                vec![e.path.clone()],
                target,
                &evidence,
            ));
        }
        skip.push(collides || is_link);
    }
    for paths in colliding.into_values() {
        let evidence = format!("paths collide when case is ignored: {}", paths.join(", "));
        signals.push(inventory_signal(
            PATTERN_CASE_COLLISION,
            paths,
            None,
            &evidence,
        ));
    }
    signals.sort_by(|a, b| {
        (a.fields.get("pattern"), &a.locations[0].file)
            .cmp(&(b.fields.get("pattern"), &b.locations[0].file))
    });
    Plan { skip, signals }
}

fn inventory_signal(
    pattern: &str,
    paths: Vec<String>,
    target: Option<&str>,
    evidence: &str,
) -> Signal {
    let mut fields = BTreeMap::new();
    fields.insert("pattern".to_string(), pattern.to_string());
    if let Some(t) = target {
        fields.insert("target".to_string(), sanitize_evidence(t));
    }
    Signal {
        kind: INVENTORY.to_string(),
        fields,
        locations: paths
            .into_iter()
            .map(|file| Location { file, line: 0 })
            .collect(),
        evidence: sanitize_evidence(evidence),
    }
}

/// Joins a validated relative path onto the quarantine root.
fn dest(root: &Path, rel: &str) -> PathBuf {
    let mut p = root.to_path_buf();
    p.extend(rel.split('/'));
    p
}

/// Creates the directory `rel` (and its parents) inside the quarantine.
pub(crate) fn create_dir(root: &Path, rel: &str) -> Result<(), AcquireError> {
    fs::create_dir_all(dest(root, rel))?;
    Ok(())
}

/// Streams `reader` into a new file at `rel` inside the quarantine, charging
/// every chunk to `budget` before writing it. The file must not exist yet,
/// and gets no executable bits.
pub(crate) fn write_file(
    root: &Path,
    rel: &str,
    mut reader: impl Read,
    budget: &mut limits::Budget<'_>,
) -> Result<(), AcquireError> {
    let path = dest(root, rel);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o644);
    }
    let mut out = opts.open(&path)?;
    let mut buf = vec![0u8; 64 * 1024];
    let mut written: u64 = 0;
    loop {
        let n = match reader.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e.into()),
        };
        budget.charge(rel, written, n as u64)?;
        out.write_all(&buf[..n])?;
        written += n as u64;
    }
    out.flush()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        out.set_permissions(fs::Permissions::from_mode(0o644))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_and_normalises_ordinary_paths() {
        let ok =
            |raw: &str, want: &str| assert_eq!(validate_entry_path(raw).unwrap(), want, "{raw:?}");
        ok("SKILL.md", "SKILL.md");
        ok("./SKILL.md", "SKILL.md");
        ok("a//b/./c.py", "a/b/c.py");
        ok("a\\b.py", "a/b.py");
        ok("scripts/", "scripts");
        ok("./", "");
        ok(".hidden/.env", ".hidden/.env");
        ok("console.md", "console.md");
        ok("com10.txt", "com10.txt");
        ok("a~b.txt", "a~b.txt");
        ok("ünïcödé/файл.md", "ünïcödé/файл.md");
    }

    #[test]
    fn rejects_hostile_paths() {
        for raw in [
            "",
            "../x",
            "a/../../x",
            "a/..",
            "..\\x",
            "a\\..\\..\\x",
            "/etc/passwd",
            "\\x",
            "\\\\server\\share\\x",
            "//server/share/x",
            "C:\\x",
            "C:x",
            "c:/x",
            "x:stream",
            "x::$DATA",
            "a\0b",
            "a\nb",
            "a\u{7f}b",
            ".. /x",
            "... /x",
            "...",
            "x.",
            "x ",
            "a/b./c",
            "CON",
            "con.txt",
            "dir/Nul.tar.gz",
            "COM1",
            "lpt9.log",
            "COM¹",
            "CON .txt",
            "CONIN$",
            "PROGRA~1",
            "dir/LONGFI~12.TXT",
            "a<b",
            "a>b",
            "a\"b",
            "a|b",
            "a?b",
            "a*b",
        ] {
            assert!(
                matches!(validate_entry_path(raw), Err(AcquireError::Unsupported(_))),
                "{raw:?} was accepted"
            );
        }
        let long = "a/".repeat(600);
        assert!(validate_entry_path(&long).is_err());
    }

    #[test]
    fn empty_path_is_only_valid_for_the_root_directory() {
        assert_eq!(Entry::new("./", EntryKind::Dir).unwrap(), None);
        assert!(Entry::new(".", EntryKind::File).is_err());
    }

    fn e(path: &str, kind: EntryKind) -> Entry {
        Entry::new(path, kind).unwrap().unwrap()
    }

    #[test]
    fn plan_skips_collisions_and_links_only() {
        let entries = vec![
            e("SKILL.md", EntryKind::File),
            e("Run.sh", EntryKind::File),
            e("run.sh", EntryKind::File),
            e("docs", EntryKind::Dir),
            e("docs/a.md", EntryKind::File),
            e(
                "l",
                EntryKind::Symlink {
                    target: Some("/".into()),
                },
            ),
            e("ΣIGMA/x", EntryKind::File),
            e("ςigma/y", EntryKind::File),
        ];
        let p = plan(&entries);
        assert_eq!(p.skip, [false, true, true, false, false, true, true, true]);
        let summary: Vec<(String, Vec<String>)> = p
            .signals
            .iter()
            .map(|s| {
                (
                    s.fields["pattern"].clone(),
                    s.locations.iter().map(|l| l.file.clone()).collect(),
                )
            })
            .collect();
        assert_eq!(
            summary,
            [
                (
                    "case_collision".to_string(),
                    vec!["Run.sh".to_string(), "run.sh".to_string()]
                ),
                (
                    "case_collision".to_string(),
                    vec!["ΣIGMA".to_string(), "ςigma".to_string()]
                ),
                ("symlink".to_string(), vec!["l".to_string()]),
            ]
        );
    }

    #[test]
    fn signal_text_is_sanitised() {
        let entries = vec![e(
            "l",
            EntryKind::Symlink {
                target: Some("/x\u{202e}y".into()),
            },
        )];
        let p = plan(&entries);
        assert_eq!(p.signals[0].fields["target"], "/x\\u{202E}y");
        assert!(!p.signals[0].evidence.contains('\u{202e}'));
    }
}
