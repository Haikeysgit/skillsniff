//! Acquisition limits and the counters that enforce them while streaming.

use std::io::{self, Read};
use std::time::Duration;

use super::AcquireError;
use crate::model::sanitize_evidence;

/// Bounds on what an acquisition may produce (spec §7.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Limits {
    /// Total bytes of file content written into the quarantine.
    pub max_total_bytes: u64,
    /// Number of non-directory entries (files and links). Directories are
    /// bounded separately by the same number.
    pub max_files: u32,
    /// Bytes of content in any single file.
    pub max_file_bytes: u64,
    /// Bytes written may not exceed `max_ratio` times the archive size.
    pub max_ratio: u32,
    /// Network fetch timeout, used by remote sources.
    pub fetch_timeout: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            max_total_bytes: 50 * 1024 * 1024,
            max_files: 5_000,
            max_file_bytes: 10 * 1024 * 1024,
            max_ratio: 100,
            fetch_timeout: Duration::from_secs(60),
        }
    }
}

/// Extra decompressed bytes allowed for tar headers, padding and long-name
/// records on top of `max_total_bytes`.
const STREAM_OVERHEAD: u64 = 16 * 1024 * 1024;

/// Decompressed bytes always allowed, so tiny archives whose fixed tar
/// padding compresses extremely well are not mistaken for bombs.
const STREAM_FLOOR: u64 = 1024 * 1024;

pub(crate) fn files_exceeded(limits: &Limits) -> AcquireError {
    AcquireError::LimitExceeded(format!("more than {} files", limits.max_files))
}

pub(crate) fn dirs_exceeded(limits: &Limits) -> AcquireError {
    AcquireError::LimitExceeded(format!("more than {} directories", limits.max_files))
}

pub(crate) fn file_too_large(limits: &Limits, path: &str) -> AcquireError {
    AcquireError::LimitExceeded(format!(
        "file {} is larger than the per-file limit of {} bytes",
        sanitize_evidence(path),
        limits.max_file_bytes
    ))
}

pub(crate) fn total_exceeded(limits: &Limits) -> AcquireError {
    AcquireError::LimitExceeded(format!(
        "total extracted size exceeds the limit of {} bytes",
        limits.max_total_bytes
    ))
}

pub(crate) fn ratio_exceeded(limits: &Limits) -> AcquireError {
    AcquireError::LimitExceeded(format!(
        "decompression ratio exceeds {}:1",
        limits.max_ratio
    ))
}

/// Largest number of content bytes allowed for an archive of `compressed`
/// bytes.
fn ratio_cap(limits: &Limits, compressed: u64) -> u64 {
    u64::from(limits.max_ratio).saturating_mul(compressed)
}

/// Counts entries by kind against `max_files`.
#[derive(Debug)]
pub(crate) struct EntryCounter<'a> {
    limits: &'a Limits,
    files: u32,
    dirs: u32,
}

impl<'a> EntryCounter<'a> {
    pub(crate) fn new(limits: &'a Limits) -> Self {
        EntryCounter {
            limits,
            files: 0,
            dirs: 0,
        }
    }

    pub(crate) fn add_file(&mut self) -> Result<(), AcquireError> {
        self.files = self.files.saturating_add(1);
        if self.files > self.limits.max_files {
            return Err(files_exceeded(self.limits));
        }
        Ok(())
    }

    pub(crate) fn add_dir(&mut self) -> Result<(), AcquireError> {
        self.dirs = self.dirs.saturating_add(1);
        if self.dirs > self.limits.max_files {
            return Err(dirs_exceeded(self.limits));
        }
        Ok(())
    }
}

/// Byte budget charged as content is written (or, for a pre-scan, as sizes
/// are declared). Every check runs before the bytes are accepted.
#[derive(Debug)]
pub(crate) struct Budget<'a> {
    limits: &'a Limits,
    total: u64,
    /// Compressed archive size, when a ratio applies.
    compressed: Option<u64>,
}

impl<'a> Budget<'a> {
    pub(crate) fn new(limits: &'a Limits, compressed: Option<u64>) -> Self {
        Budget {
            limits,
            total: 0,
            compressed,
        }
    }

    /// Accepts `n` more bytes for the file at `path`, which already holds
    /// `file_so_far` bytes.
    pub(crate) fn charge(
        &mut self,
        path: &str,
        file_so_far: u64,
        n: u64,
    ) -> Result<(), AcquireError> {
        if file_so_far.saturating_add(n) > self.limits.max_file_bytes {
            return Err(file_too_large(self.limits, path));
        }
        let total = self.total.saturating_add(n);
        if total > self.limits.max_total_bytes {
            return Err(total_exceeded(self.limits));
        }
        if let Some(c) = self.compressed
            && total > ratio_cap(self.limits, c)
        {
            return Err(ratio_exceeded(self.limits));
        }
        self.total = total;
        Ok(())
    }
}

/// Wraps a decompressor and fails once more than a fixed number of bytes
/// has come out of it. Bounds work and memory spent on data that never
/// reaches the budget, such as long-name records and skipped entries.
pub(crate) struct StreamGuard<R> {
    inner: R,
    read: u64,
    cap: u64,
    error: Option<AcquireError>,
    tripped: Option<AcquireError>,
}

impl<R: Read> StreamGuard<R> {
    pub(crate) fn new(inner: R, limits: &Limits, compressed: u64) -> Self {
        let by_ratio = ratio_cap(limits, compressed).max(STREAM_FLOOR);
        let by_size = limits.max_total_bytes.saturating_add(STREAM_OVERHEAD);
        let (cap, error) = if by_ratio <= by_size {
            (by_ratio, ratio_exceeded(limits))
        } else {
            (by_size, total_exceeded(limits))
        };
        StreamGuard {
            inner,
            read: 0,
            cap,
            error: Some(error),
            tripped: None,
        }
    }

    /// The limit error, if the guard tripped.
    pub(crate) fn take_tripped(&mut self) -> Option<AcquireError> {
        self.tripped.take()
    }
}

impl<R: Read> Read for StreamGuard<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.tripped.is_some() || self.error.is_none() {
            return Err(io::Error::other("decompression limit exceeded"));
        }
        // Never hand out more than one byte past the cap.
        let room = (self.cap - self.read).saturating_add(1);
        let want = buf.len().min(usize::try_from(room).unwrap_or(usize::MAX));
        let n = self.inner.read(&mut buf[..want])?;
        self.read += n as u64;
        if self.read > self.cap {
            self.tripped = self.error.take();
            return Err(io::Error::other("decompression limit exceeded"));
        }
        Ok(n)
    }
}
