//! Copying a local folder into a quarantine without following links.

use std::fs;
use std::path::{Path, PathBuf};

use super::limits::{Budget, EntryCounter};
use super::{
    AcquireError, Acquired, Entry, EntryKind, Limits, Quarantine, create_dir, plan, write_file,
};

/// Windows `FILE_ATTRIBUTE_REPARSE_POINT`.
#[cfg(windows)]
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;

/// Windows `FILE_FLAG_OPEN_REPARSE_POINT`: open a link itself, not its target.
#[cfg(windows)]
const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;

/// Symlinks, junctions and any other reparse point that is not a plain file.
fn is_link(meta: &fs::Metadata) -> bool {
    meta.file_type().is_symlink() || is_non_file_reparse_point(meta)
}

#[cfg(windows)]
fn is_non_file_reparse_point(meta: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 && !meta.is_file()
}

#[cfg(not(windows))]
fn is_non_file_reparse_point(_meta: &fs::Metadata) -> bool {
    false
}

/// A regular file with more than one name.
fn is_hardlinked(meta: &fs::Metadata) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        meta.nlink() > 1
    }
    #[cfg(not(unix))]
    {
        // The link count is not exposed by stable std on Windows.
        let _ = meta;
        false
    }
}

/// Copies the regular files of `path` into a new quarantine. Links are
/// recorded as `INVENTORY` signals and never followed; only `path` itself
/// may be a link (the user named it).
pub fn acquire_local_dir(path: &Path, limits: &Limits) -> Result<Acquired, AcquireError> {
    let source = path.display().to_string();
    let meta = match fs::metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(AcquireError::NotFound(source));
        }
        Err(e) => return Err(e.into()),
    };
    if !meta.is_dir() {
        return Err(AcquireError::Unsupported(format!(
            "{source} is not a directory"
        )));
    }

    // Walk first: validate every name, count, and classify with
    // `symlink_metadata` so nothing is followed.
    let mut counter = EntryCounter::new(limits);
    let mut entries: Vec<Entry> = Vec::new();
    let mut sources: Vec<(PathBuf, Option<fs::Metadata>)> = Vec::new();
    let mut stack: Vec<(PathBuf, String)> = vec![(path.to_path_buf(), String::new())];
    while let Some((dir, rel)) = stack.pop() {
        let mut children = fs::read_dir(&dir)?.collect::<Result<Vec<_>, _>>()?;
        children.sort_by_key(|c| c.file_name());
        for child in children {
            let name = child.file_name();
            let name = name.to_str().ok_or_else(|| {
                AcquireError::Unsupported(format!(
                    "file name in {} is not valid UTF-8",
                    dir.display()
                ))
            })?;
            let raw = if rel.is_empty() {
                name.to_string()
            } else {
                format!("{rel}/{name}")
            };
            let abs = child.path();
            let meta = fs::symlink_metadata(&abs)?;
            let kind = if is_link(&meta) {
                let target = fs::read_link(&abs)
                    .ok()
                    .map(|t| t.to_string_lossy().into_owned());
                EntryKind::Symlink { target }
            } else if meta.is_dir() {
                EntryKind::Dir
            } else if meta.is_file() {
                if is_hardlinked(&meta) {
                    EntryKind::Hardlink { target: None }
                } else {
                    EntryKind::File
                }
            } else {
                // FIFO, socket or device: validate the name, never open it.
                super::validate_entry_path(&raw)?;
                continue;
            };
            let Some(entry) = Entry::new(&raw, kind)? else {
                continue;
            };
            match entry.kind {
                EntryKind::Dir => {
                    counter.add_dir()?;
                    stack.push((abs.clone(), entry.path.clone()));
                }
                _ => counter.add_file()?,
            }
            let keep_meta = (entry.kind == EntryKind::File).then_some(meta);
            entries.push(entry);
            sources.push((abs, keep_meta));
        }
    }
    let plan = plan(&entries);

    let quarantine = Quarantine::new()?;
    let root = quarantine.root();
    let mut budget = Budget::new(limits, None);
    for ((entry, (abs, meta)), &skip) in entries.iter().zip(&sources).zip(&plan.skip) {
        if skip {
            continue;
        }
        match (&entry.kind, meta) {
            (EntryKind::Dir, _) => create_dir(root, &entry.path)?,
            (EntryKind::File, Some(meta)) => {
                let file = open_unchanged(abs, meta)?;
                write_file(root, &entry.path, file, &mut budget)?;
            }
            _ => {}
        }
    }
    Ok(Acquired {
        quarantine,
        source,
        commit: None,
        signals: plan.signals,
    })
}

fn swapped(abs: &Path) -> AcquireError {
    AcquireError::Unsupported(format!(
        "{} changed while it was being copied",
        abs.display()
    ))
}

/// Opens a file seen during the walk, refusing it if it was replaced by a
/// link or another file since.
fn open_unchanged(abs: &Path, seen: &fs::Metadata) -> Result<fs::File, AcquireError> {
    let mut opts = fs::OpenOptions::new();
    opts.read(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        opts.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let file = opts.open(abs)?;
    let now = file.metadata()?;
    if !now.is_file() || is_link(&now) {
        return Err(swapped(abs));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if now.dev() != seen.dev() || now.ino() != seen.ino() || now.nlink() > 1 {
            return Err(swapped(abs));
        }
    }
    #[cfg(not(unix))]
    let _ = seen;
    Ok(file)
}
