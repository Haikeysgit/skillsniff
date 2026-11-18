//! File inventory and deterministic tree hash of a scanned tree.

use std::fmt::Write as _;
use std::io;
use std::path::Path;

use sha2::{Digest, Sha256};
use walkdir::WalkDir;

/// Bytes sampled when deciding whether a file is text.
const SNIFF_LEN: usize = 8 * 1024;
/// Average line length above which a text file counts as minified.
const MINIFIED_AVG_LINE: usize = 500;

/// Whether a file is text or binary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContentType {
    Text,
    Binary,
}

/// One regular file in the scanned tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileEntry {
    /// Path relative to the root, `/`-separated.
    pub path: String,
    pub sha256: String,
    pub size: u64,
    pub content_type: ContentType,
    pub minified: bool,
    pub crlf: bool,
}

/// All regular files of a tree plus a hash over them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Inventory {
    /// Sorted by byte order of `path`.
    pub files: Vec<FileEntry>,
    pub tree_sha256: String,
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

fn is_text(data: &[u8]) -> bool {
    let sample = &data[..data.len().min(SNIFF_LEN)];
    let sample = sample.strip_prefix(b"\xef\xbb\xbf").unwrap_or(sample);
    if sample.contains(&0) {
        return false;
    }
    match std::str::from_utf8(sample) {
        Ok(_) => true,
        // An error with no length means the sample was cut inside a character.
        Err(e) => e.error_len().is_none() && data.len() > SNIFF_LEN,
    }
}

fn is_minified(data: &[u8]) -> bool {
    if data.is_empty() {
        return false;
    }
    let mut lines = data.iter().filter(|&&b| b == b'\n').count();
    if !data.ends_with(b"\n") {
        lines += 1;
    }
    data.len() / lines > MINIFIED_AVG_LINE
}

/// Walk `root` without following links and describe every regular file.
pub fn build_inventory(root: &Path) -> Result<Inventory, io::Error> {
    let mut files = Vec::new();
    for entry in WalkDir::new(root).follow_links(false) {
        let entry = entry.map_err(io::Error::other)?;
        if !entry.file_type().is_file() {
            continue;
        }
        let rel = entry
            .path()
            .strip_prefix(root)
            .map_err(io::Error::other)?
            .components()
            .map(|c| c.as_os_str().to_string_lossy().into_owned())
            .collect::<Vec<_>>()
            .join("/");
        let data = std::fs::read(entry.path())?;
        let text = is_text(&data);
        files.push(FileEntry {
            path: rel,
            sha256: hex(&Sha256::digest(&data)),
            size: data.len() as u64,
            content_type: if text {
                ContentType::Text
            } else {
                ContentType::Binary
            },
            minified: text && is_minified(&data),
            crlf: text && data.windows(2).any(|w| w == b"\r\n"),
        });
    }
    files.sort_by(|a, b| a.path.as_bytes().cmp(b.path.as_bytes()));
    let mut tree = Sha256::new();
    for f in &files {
        tree.update(format!("{}\0{}\n", f.path, f.sha256).as_bytes());
    }
    Ok(Inventory {
        files,
        tree_sha256: hex(&tree.finalize()),
    })
}
