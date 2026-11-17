//! `.zip`, `.tar.gz` and `.tgz` extraction into a quarantine.
//!
//! The archive is read into memory once (it may not exceed
//! `max_total_bytes`), so the pre-scan and the extraction see the same bytes.
//! The pre-scan validates every path, counts entries, checks declared sizes
//! and plans collisions before anything is written.

use std::fs;
use std::io::{Cursor, Read};
use std::path::Path;

use flate2::read::MultiGzDecoder;
use zip::ZipArchive;
use zip::result::ZipError;

use super::limits::{
    Budget, EntryCounter, StreamGuard, file_too_large, ratio_exceeded, total_exceeded,
};
use super::{
    AcquireError, Acquired, Entry, EntryKind, Limits, Quarantine, create_dir, plan, write_file,
};
use crate::model::Signal;

/// Longest symlink target read from a zip entry.
const MAX_LINK_TARGET: u64 = 4096;

enum Format {
    Zip,
    TarGz,
}

fn format_of(path: &Path) -> Option<Format> {
    let name = path.file_name()?.to_string_lossy().to_ascii_lowercase();
    if name.ends_with(".zip") {
        Some(Format::Zip)
    } else if name.ends_with(".tar.gz") || name.ends_with(".tgz") {
        Some(Format::TarGz)
    } else {
        None
    }
}

/// Extracts a `.zip`, `.tar.gz` or `.tgz` archive into a new quarantine.
pub fn acquire_archive(path: &Path, limits: &Limits) -> Result<Acquired, AcquireError> {
    let source = path.display().to_string();
    let meta = match fs::metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(AcquireError::NotFound(source));
        }
        Err(e) => return Err(e.into()),
    };
    if !meta.is_file() {
        return Err(AcquireError::Unsupported(format!("{source} is not a file")));
    }
    let format = format_of(path).ok_or_else(|| {
        AcquireError::Unsupported(format!(
            "{source}: archive type not supported (expected .zip, .tar.gz or .tgz)"
        ))
    })?;
    let bytes = read_capped(path, limits.max_total_bytes)?;

    let quarantine = Quarantine::new()?;
    let signals = match format {
        Format::Zip => extract_zip(&bytes, limits, quarantine.root())?,
        Format::TarGz => extract_tar_gz(&bytes, limits, quarantine.root())?,
    };
    Ok(Acquired {
        quarantine,
        source,
        commit: None,
        signals,
    })
}

/// Reads at most `cap` bytes, failing if the file is larger.
fn read_capped(path: &Path, cap: u64) -> Result<Vec<u8>, AcquireError> {
    let file = fs::File::open(path)?;
    let mut bytes = Vec::new();
    file.take(cap.saturating_add(1)).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > cap {
        return Err(AcquireError::LimitExceeded(format!(
            "archive is larger than the total limit of {cap} bytes"
        )));
    }
    Ok(bytes)
}

/// Checks a declared entry size against the limits before any data is read.
fn check_declared(
    limits: &Limits,
    path: &str,
    size: u64,
    declared_total: &mut u64,
    compressed: u64,
) -> Result<(), AcquireError> {
    if size > limits.max_file_bytes {
        return Err(file_too_large(limits, path));
    }
    *declared_total = declared_total.saturating_add(size);
    if *declared_total > limits.max_total_bytes {
        return Err(total_exceeded(limits));
    }
    if *declared_total > u64::from(limits.max_ratio).saturating_mul(compressed) {
        return Err(ratio_exceeded(limits));
    }
    Ok(())
}

// ------------------------------------------------------------------- tar

/// Turns a tar entry into an [`Entry`], validating its path. Follows GNU
/// tar: sparse entries and unknown typeflags are regular files, and `D`
/// (dumpdir) is a directory. `None` only for entries no extractor writes as
/// content: pax global headers, extension records, devices and FIFOs (which
/// carry no data), and the root directory.
fn tar_entry<R: Read>(e: &tar::Entry<'_, R>) -> Result<Option<(Entry, u64)>, AcquireError> {
    use tar::EntryType as T;
    let ty = e.header().entry_type();
    let link_target = || {
        e.link_name_bytes()
            .map(|b| String::from_utf8_lossy(&b).into_owned())
    };
    let kind = match ty {
        T::Regular | T::Continuous | T::GNUSparse => EntryKind::File,
        T::Directory => EntryKind::Dir,
        _ if ty.as_byte() == b'D' => EntryKind::Dir,
        T::Symlink => EntryKind::Symlink {
            target: link_target(),
        },
        T::Link => EntryKind::Hardlink {
            target: link_target(),
        },
        T::Char
        | T::Block
        | T::Fifo
        | T::XGlobalHeader
        | T::XHeader
        | T::GNULongName
        | T::GNULongLink => {
            // Still refuse hostile names on entries we skip.
            if let Ok(raw) = std::str::from_utf8(&e.path_bytes()) {
                super::validate_entry_path(raw)?;
            }
            return Ok(None);
        }
        _ => EntryKind::File,
    };
    let raw = std::str::from_utf8(&e.path_bytes())
        .map_err(|_| AcquireError::Unsupported("entry path is not valid UTF-8".into()))?
        .to_string();
    let size = e.size();
    Ok(Entry::new(&raw, kind)?.map(|entry| (entry, size)))
}

/// Runs `f` over the decompressed tar stream, mapping a tripped stream
/// guard to its limit error.
fn with_tar<T>(
    bytes: &[u8],
    limits: &Limits,
    f: impl FnOnce(
        &mut tar::Archive<&mut StreamGuard<MultiGzDecoder<&[u8]>>>,
    ) -> Result<T, AcquireError>,
) -> Result<T, AcquireError> {
    // Every gzip member, as `gzip -d` reads them: a first-member-only
    // decoder would hide entries stored in later members.
    let mut stream = StreamGuard::new(MultiGzDecoder::new(bytes), limits, bytes.len() as u64);
    let result = {
        let mut archive = tar::Archive::new(&mut stream);
        f(&mut archive)
    };
    if let Some(limit) = stream.take_tripped() {
        return Err(limit);
    }
    result
}

/// Extracts a gzip-compressed tar held in memory into `root`.
pub(crate) fn extract_tar_gz(
    bytes: &[u8],
    limits: &Limits,
    root: &Path,
) -> Result<Vec<Signal>, AcquireError> {
    let compressed = bytes.len() as u64;

    // Pass 1: validate, count and plan.
    let entries = with_tar(bytes, limits, |archive| {
        let mut counter = EntryCounter::new(limits);
        let mut declared = 0u64;
        let mut entries = Vec::new();
        for e in archive.entries().map_err(bad_tar)? {
            let e = e.map_err(bad_tar)?;
            let Some((entry, size)) = tar_entry(&e)? else {
                continue;
            };
            match entry.kind {
                EntryKind::Dir => counter.add_dir()?,
                EntryKind::File => {
                    counter.add_file()?;
                    check_declared(limits, &entry.path, size, &mut declared, compressed)?;
                }
                _ => counter.add_file()?,
            }
            entries.push(entry);
        }
        Ok(entries)
    })?;
    let plan = plan(&entries);

    // Pass 2: extract what the plan allows, re-checking that each entry is
    // the one planned.
    with_tar(bytes, limits, |archive| {
        let mut budget = Budget::new(limits, Some(compressed));
        let mut planned = entries.iter().zip(&plan.skip);
        for e in archive.entries().map_err(bad_tar)? {
            let e = e.map_err(bad_tar)?;
            let Some((entry, _)) = tar_entry(&e)? else {
                continue;
            };
            let Some((want, &skip)) = planned.next() else {
                return Err(changed());
            };
            if *want != entry {
                return Err(changed());
            }
            if skip {
                continue;
            }
            match entry.kind {
                EntryKind::Dir => create_dir(root, &entry.path)?,
                EntryKind::File => write_file(root, &entry.path, e, &mut budget)?,
                _ => {}
            }
        }
        Ok(())
    })?;
    Ok(plan.signals)
}

fn bad_tar(e: std::io::Error) -> AcquireError {
    AcquireError::Unsupported(format!("invalid tar.gz archive: {e}"))
}

fn changed() -> AcquireError {
    AcquireError::Unsupported("archive entries changed between passes".into())
}

// ------------------------------------------------------------------- zip

fn zip_err(e: ZipError) -> AcquireError {
    match e {
        ZipError::Io(io) => AcquireError::Unsupported(format!("invalid zip archive: {io}")),
        other => AcquireError::Unsupported(format!("zip: {other}")),
    }
}

/// Extracts a zip held in memory into `root`.
fn extract_zip(bytes: &[u8], limits: &Limits, root: &Path) -> Result<Vec<Signal>, AcquireError> {
    let compressed = bytes.len() as u64;
    let mut archive = ZipArchive::new(Cursor::new(bytes)).map_err(zip_err)?;
    if archive.len() as u64 > 2 * u64::from(limits.max_files) {
        return Err(super::limits::files_exceeded(limits));
    }

    // Pass 1: validate, count and plan. Declared sizes are checked early but
    // cannot be trusted; the budget re-checks real bytes in pass 2.
    let mut counter = EntryCounter::new(limits);
    let mut declared = 0u64;
    let mut entries = Vec::new();
    let mut indices = Vec::new();
    for i in 0..archive.len() {
        let (raw, mode, size) = {
            let f = archive.by_index_raw(i).map_err(zip_err)?;
            (f.name().to_string(), f.unix_mode(), f.size())
        };
        // As in Info-ZIP and Python's zipfile, only a trailing `/` makes a
        // directory; mode bits never do. Every other non-symlink entry is a
        // regular file whatever its mode says, so no data is dropped.
        let kind = if raw.ends_with('/') {
            EntryKind::Dir
        } else if mode.map(|m| m & 0o170_000) == Some(0o120_000) {
            EntryKind::Symlink { target: None }
        } else {
            EntryKind::File
        };
        let Some(mut entry) = Entry::new(&raw, kind)? else {
            continue;
        };
        match entry.kind {
            EntryKind::Dir => counter.add_dir()?,
            EntryKind::File => {
                counter.add_file()?;
                check_declared(limits, &entry.path, size, &mut declared, compressed)?;
            }
            EntryKind::Symlink { .. } => {
                counter.add_file()?;
                let f = archive.by_index(i).map_err(zip_err)?;
                let mut target = Vec::new();
                f.take(MAX_LINK_TARGET).read_to_end(&mut target)?;
                entry.kind = EntryKind::Symlink {
                    target: Some(String::from_utf8_lossy(&target).into_owned()),
                };
            }
            EntryKind::Hardlink { .. } => counter.add_file()?,
        }
        entries.push(entry);
        indices.push(i);
    }
    let plan = plan(&entries);

    // Pass 2: extract what the plan allows.
    let mut budget = Budget::new(limits, Some(compressed));
    for ((entry, &i), &skip) in entries.iter().zip(&indices).zip(&plan.skip) {
        if skip {
            continue;
        }
        match entry.kind {
            EntryKind::Dir => create_dir(root, &entry.path)?,
            EntryKind::File => {
                let f = archive.by_index(i).map_err(zip_err)?;
                write_file(root, &entry.path, f, &mut budget)?;
            }
            _ => {}
        }
    }
    Ok(plan.signals)
}
