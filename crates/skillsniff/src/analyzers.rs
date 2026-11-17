//! Analyzer interface and the parallel, isolated runner.

pub mod hidden;

use std::collections::BTreeMap;
use std::fs;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::mpsc;
use std::time::{Duration, Instant};

use crate::inventory::Inventory;
use crate::model::{Coverage, Signal};
use crate::progress::{ProgressEvent, ProgressSink};
use crate::target::{FileRole, SkillTarget};

/// Default per-analyzer time budget.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);
/// Largest file `read_text` will load.
const MAX_READ_BYTES: u64 = 10 * 1024 * 1024;

/// Everything an analyzer may look at.
#[derive(Debug, Clone)]
pub struct ScanContext {
    pub root: PathBuf,
    pub inventory: Inventory,
    pub roles: BTreeMap<String, FileRole>,
    pub skill: SkillTarget,
}

impl ScanContext {
    /// Read an inventoried file as UTF-8 (an optional BOM is stripped).
    ///
    /// Returns `None` for paths outside the inventory, files over 10 MiB and
    /// content that is not valid UTF-8.
    pub fn read_text(&self, path: &str) -> Option<String> {
        let entry = self
            .inventory
            .files
            .binary_search_by(|f| f.path.as_str().cmp(path))
            .ok()
            .map(|i| &self.inventory.files[i])
            .or_else(|| self.inventory.files.iter().find(|f| f.path == path))?;
        if entry.size > MAX_READ_BYTES {
            return None;
        }
        let full = self.root.join(&entry.path);
        if fs::metadata(&full).ok()?.len() > MAX_READ_BYTES {
            return None;
        }
        let bytes = fs::read(full).ok()?;
        let bytes = bytes.strip_prefix(b"\xef\xbb\xbf").unwrap_or(&bytes);
        String::from_utf8(bytes.to_vec()).ok()
    }
}

/// What one analyzer produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnalyzerOutput {
    pub signals: Vec<Signal>,
    pub coverage: Coverage,
}

/// A static check over a scanned tree.
pub trait Analyzer: Send + Sync {
    fn id(&self) -> &'static str;
    fn run(&self, ctx: &ScanContext) -> AnalyzerOutput;
}

fn timeout_reason(timeout: Duration) -> String {
    let secs = timeout.as_secs() + u64::from(timeout.subsec_nanos() > 0);
    format!("timed out after {secs}s")
}

fn failed(reason: String) -> AnalyzerOutput {
    AnalyzerOutput {
        signals: Vec::new(),
        coverage: Coverage::Failed { reason },
    }
}

/// Run every analyzer on its own thread.
///
/// A panic or running past `timeout` marks that analyzer `Failed` without
/// affecting the others. Signals are concatenated in analyzer id order. Threads
/// that time out are detached.
pub fn run_analyzers(
    ctx: Arc<ScanContext>,
    mut analyzers: Vec<Arc<dyn Analyzer>>,
    timeout: Duration,
    progress: &dyn ProgressSink,
) -> (Vec<Signal>, BTreeMap<String, Coverage>) {
    analyzers.sort_by_key(|a| a.id());
    let (tx, rx) = mpsc::channel::<(usize, Option<AnalyzerOutput>)>();
    for a in &analyzers {
        progress.event(ProgressEvent::Started { id: a.id() });
    }
    for (i, a) in analyzers.iter().enumerate() {
        let a = Arc::clone(a);
        let ctx = Arc::clone(&ctx);
        let tx = tx.clone();
        std::thread::spawn(move || {
            let out = catch_unwind(AssertUnwindSafe(|| a.run(&ctx))).ok();
            let _ = tx.send((i, out));
        });
    }
    drop(tx);
    let deadline = Instant::now() + timeout;

    let mut results: Vec<Option<AnalyzerOutput>> = vec![None; analyzers.len()];
    let mut pending = analyzers.len();
    while pending > 0 {
        let wait = deadline.saturating_duration_since(Instant::now());
        match rx.recv_timeout(wait) {
            Ok((i, out)) => {
                let id = analyzers[i].id();
                let out = out.unwrap_or_else(|| failed("analyzer panicked".to_string()));
                match &out.coverage {
                    Coverage::Failed { .. } => progress.event(ProgressEvent::Failed { id }),
                    _ => progress.event(ProgressEvent::Finished {
                        id,
                        signals: out.signals.len(),
                    }),
                }
                results[i] = Some(out);
                pending -= 1;
            }
            Err(_) => break,
        }
    }

    let mut signals = Vec::new();
    let mut coverage = BTreeMap::new();
    for (a, res) in analyzers.iter().zip(results) {
        let out = res.unwrap_or_else(|| {
            progress.event(ProgressEvent::Failed { id: a.id() });
            failed(timeout_reason(timeout))
        });
        signals.extend(out.signals);
        coverage.insert(a.id().to_string(), out.coverage);
    }
    (signals, coverage)
}
