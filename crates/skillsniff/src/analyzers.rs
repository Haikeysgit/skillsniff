//! Analyzer interface and the parallel, isolated runner.

pub mod agent_config;
pub mod code;
pub mod hidden;
pub mod instructions;

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
        let bytes = self.read_bytes(path)?;
        let bytes = bytes.strip_prefix(b"\xef\xbb\xbf").unwrap_or(&bytes);
        String::from_utf8(bytes.to_vec()).ok()
    }

    /// Read an inventoried file's raw bytes.
    ///
    /// Returns `None` for paths outside the inventory and files over 10 MiB.
    pub fn read_bytes(&self, path: &str) -> Option<Vec<u8>> {
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
        fs::read(full).ok()
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

/// Characters that render as nothing (zero-width, bidi, joiners, tags) and so
/// can hide text inside a phrase.
pub(crate) fn is_invisible(c: char) -> bool {
    matches!(
        c,
        '\u{00AD}'
            | '\u{034F}'
            | '\u{061C}'
            | '\u{180B}'..='\u{180D}'
            | '\u{200B}'..='\u{200F}'
            | '\u{202A}'..='\u{202E}'
            | '\u{2060}'..='\u{2064}'
            | '\u{2066}'..='\u{2069}'
            | '\u{FE00}'..='\u{FE0F}'
            | '\u{FEFF}'
            | '\u{E0000}'..='\u{E007F}'
    )
}

/// Evidence text: control and invisible characters are escaped as `\u{XXXX}`
/// and the result is at most 200 characters.
pub(crate) fn safe_evidence(s: &str) -> String {
    const MAX: usize = 200;
    let mut out = String::new();
    let mut count = 0;
    for c in s.chars() {
        let piece = if c.is_control() || is_invisible(c) {
            format!("\\u{{{:04X}}}", c as u32)
        } else {
            c.to_string()
        };
        let n = piece.chars().count();
        if count + n > MAX {
            break;
        }
        out.push_str(&piece);
        count += n;
    }
    out
}

/// File text, decoded lossily when it is not valid UTF-8. `None` only when the
/// file is outside the inventory or over the read limit.
pub(crate) fn read_lossy(ctx: &ScanContext, path: &str) -> Option<String> {
    let bytes = ctx.read_bytes(path)?;
    let bytes = bytes.strip_prefix(b"\xef\xbb\xbf").unwrap_or(&bytes);
    Some(String::from_utf8_lossy(bytes).into_owned())
}

/// Signal for a file that could not be read, so it is never skipped silently.
pub(crate) fn unreadable_signal(file: &str) -> Signal {
    Signal {
        kind: crate::model::signal::HIDDEN.to_string(),
        fields: BTreeMap::from([("pattern".to_string(), "parse_budget_exceeded".to_string())]),
        locations: vec![crate::model::Location {
            file: file.to_string(),
            line: 1,
        }],
        evidence: "file could not be read for analysis (over the size limit)".to_string(),
    }
}

/// Signal for a file only partly checked because the time budget ran out.
pub(crate) fn budget_signal(file: &str, secs: u64) -> Signal {
    Signal {
        kind: crate::model::signal::HIDDEN.to_string(),
        fields: BTreeMap::from([("pattern".to_string(), "parse_budget_exceeded".to_string())]),
        locations: vec![crate::model::Location {
            file: file.to_string(),
            line: 1,
        }],
        evidence: format!("analysis stopped after {secs}s; file only partly checked"),
    }
}
