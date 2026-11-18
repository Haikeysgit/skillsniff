//! Export of the exact scanned tree.

use std::fmt;
use std::fs;
use std::io::{self, Write as _};
use std::path::{Component, Path, PathBuf};

use crate::inventory::build_inventory;
use crate::model::Verdict;
use crate::scan::ScanOutcome;

/// Why an export did not happen.
#[derive(Debug)]
pub enum ExportError {
    /// The verdict is BLOCK.
    Blocked,
    /// The verdict is CAUTION and the caller did not allow it.
    CautionNotAllowed,
    /// The destination already exists.
    DestinationExists,
    /// The copy does not hash to the scanned tree.
    HashMismatch,
    Io(io::Error),
}

impl fmt::Display for ExportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ExportError::Blocked => f.write_str("export refused: the verdict is BLOCK"),
            ExportError::CautionNotAllowed => {
                f.write_str("export refused: the verdict is CAUTION and was not allowed")
            }
            ExportError::DestinationExists => f.write_str("the destination already exists"),
            ExportError::HashMismatch => {
                f.write_str("the exported tree does not match the scanned tree")
            }
            ExportError::Io(e) => write!(f, "export failed: {e}"),
        }
    }
}

impl std::error::Error for ExportError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ExportError::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for ExportError {
    fn from(e: io::Error) -> Self {
        ExportError::Io(e)
    }
}

fn relative_target(dest: &Path, rel: &str) -> Result<PathBuf, io::Error> {
    let mut out = dest.to_path_buf();
    for part in rel.split('/') {
        let comp = Path::new(part);
        let plain = comp.components().count() == 1
            && matches!(comp.components().next(), Some(Component::Normal(_)));
        if part.is_empty() || !plain {
            return Err(io::Error::other(format!("unsafe path in tree: {rel}")));
        }
        out.push(part);
    }
    Ok(out)
}

fn copy_files(root: &Path, dest: &Path, files: &[String]) -> Result<(), io::Error> {
    for rel in files {
        let to = relative_target(dest, rel)?;
        if let Some(parent) = to.parent() {
            fs::create_dir_all(parent)?;
        }
        let from = relative_target(root, rel)?;
        let data = fs::read(&from)?;
        let mut out = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&to)?;
        out.write_all(&data)?;
    }
    Ok(())
}

/// Copies the regular files of the scanned tree into the new folder `dest`.
///
/// Refuses on BLOCK, and on CAUTION unless `allow_caution`. After copying, the
/// destination is hashed again and must equal the report's tree hash;
/// otherwise `dest` is removed. Links are never followed or created.
pub fn export(outcome: &ScanOutcome, dest: &Path, allow_caution: bool) -> Result<(), ExportError> {
    match outcome.report.verdict {
        Verdict::Block => return Err(ExportError::Blocked),
        Verdict::Caution if !allow_caution => return Err(ExportError::CautionNotAllowed),
        _ => {}
    }
    let quarantine = outcome
        .quarantine
        .as_ref()
        .ok_or_else(|| io::Error::other("the scanned tree is no longer available"))?;
    let root = quarantine.root();

    match fs::create_dir(dest) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
            return Err(ExportError::DestinationExists);
        }
        Err(e) => return Err(e.into()),
    }

    let result = (|| {
        let inventory = build_inventory(root)?;
        let paths: Vec<String> = inventory.files.into_iter().map(|f| f.path).collect();
        copy_files(root, dest, &paths)?;
        let copied = build_inventory(dest)?;
        if copied.tree_sha256 == outcome.report.target.tree_sha256 {
            Ok(())
        } else {
            Err(ExportError::HashMismatch)
        }
    })();
    if result.is_err() {
        let _ = fs::remove_dir_all(dest);
    }
    result
}
