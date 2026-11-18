//! The scan pipeline: acquire, inventory, analyze, apply rules, score.

use std::fmt;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use crate::VERSION;
use crate::acquire::{
    AcquireError, Acquired, Limits, Quarantine, acquire_archive, acquire_github, acquire_local_dir,
};
use crate::analyzers::agent_config::AgentConfigAnalyzer;
use crate::analyzers::code::CodeAnalyzer;
use crate::analyzers::hidden::HiddenAnalyzer;
use crate::analyzers::instructions::InstructionsAnalyzer;
use crate::analyzers::{Analyzer, DEFAULT_TIMEOUT, ScanContext, run_analyzers};
use crate::inventory::build_inventory;
use crate::model::{
    Report, ReviewInfo, Severity, Summary, TargetInfo, ToolInfo, sanitize_evidence, sort_findings,
};
use crate::progress::ProgressSink;
use crate::rules::{apply, builtin, load_extra, merge};
use crate::score::compute_verdict;
use crate::source::{Source, parse_source};
use crate::suppress::{apply_suppressions, load_suppressions};
use crate::target::{Target, TargetError, detect_skill};

const GITHUB_API: &str = "https://api.github.com";
const GITHUB_CODELOAD: &str = "https://codeload.github.com";
/// Analyzers whose absence stops a scan from passing.
const REQUIRED_ANALYZERS: &[&str] = &["instructions", "code", "hidden", "agent_config"];
const SCHEMA_VERSION: &str = "1";

/// Settings for one scan.
#[derive(Debug, Clone)]
pub struct ScanOptions {
    /// Refuse remote sources.
    pub offline: bool,
    /// The caller intends to keep the quarantine; informational for the caller.
    pub keep: bool,
    /// Folder of extra rule files.
    pub extra_rules: Option<PathBuf>,
    /// Suppressions file; the user's default location when `None`.
    pub suppressions: Option<PathBuf>,
    pub limits: Limits,
    pub analyzer_timeout: Duration,
}

impl Default for ScanOptions {
    fn default() -> Self {
        ScanOptions {
            offline: false,
            keep: false,
            extra_rules: None,
            suppressions: None,
            limits: Limits::default(),
            analyzer_timeout: DEFAULT_TIMEOUT,
        }
    }
}

/// A finished scan. The quarantine holds the scanned tree; dropping it deletes
/// the tree, `keep()` leaves it on disk.
#[derive(Debug)]
pub struct ScanOutcome {
    pub report: Report,
    pub quarantine: Option<Quarantine>,
}

/// Why a scan could not produce a report.
#[derive(Debug)]
pub enum ScanError {
    Usage(String),
    Fetch(AcquireError),
    Target(TargetError),
    Internal(String),
}

impl fmt::Display for ScanError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ScanError::Usage(s) => f.write_str(s),
            ScanError::Fetch(e) => e.fmt(f),
            ScanError::Target(e) => e.fmt(f),
            ScanError::Internal(s) => write!(f, "internal error: {s}"),
        }
    }
}

impl std::error::Error for ScanError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ScanError::Fetch(e) => Some(e),
            ScanError::Target(e) => Some(e),
            _ => None,
        }
    }
}

impl From<AcquireError> for ScanError {
    fn from(e: AcquireError) -> Self {
        ScanError::Fetch(e)
    }
}

impl From<TargetError> for ScanError {
    fn from(e: TargetError) -> Self {
        ScanError::Target(e)
    }
}

fn acquire(source: Source, opts: &ScanOptions) -> Result<Acquired, AcquireError> {
    match &source {
        Source::GitHub { .. } => acquire_github(
            &source,
            &opts.limits,
            GITHUB_API,
            GITHUB_CODELOAD,
            opts.offline,
        ),
        Source::LocalDir(p) => acquire_local_dir(p, &opts.limits),
        Source::Archive(p) => acquire_archive(p, &opts.limits),
    }
}

/// Scans `source` and returns the report plus the quarantine holding the tree.
pub fn scan(
    source: &str,
    opts: &ScanOptions,
    progress: &dyn ProgressSink,
) -> Result<ScanOutcome, ScanError> {
    let parsed = parse_source(source).map_err(ScanError::Usage)?;
    let suppressions = load_suppressions(opts.suppressions.as_deref()).map_err(ScanError::Usage)?;
    let mut pack = builtin();
    if let Some(dir) = &opts.extra_rules {
        let extra = load_extra(dir).map_err(ScanError::Usage)?;
        pack = merge(pack, extra).map_err(ScanError::Usage)?;
    }

    let acquired = acquire(parsed, opts)?;
    let Acquired {
        quarantine,
        source: shown_source,
        commit,
        mut signals,
    } = acquired;
    let root = quarantine.root().to_path_buf();

    let inventory = build_inventory(&root)
        .map_err(|e| ScanError::Internal(format!("cannot list the scanned files: {e}")))?;
    let skill = detect_skill(&inventory, &root)?;
    let roles = skill.classify(&inventory);
    let tree = inventory.tree_sha256.clone();
    let kind = skill.kind();
    let ctx = Arc::new(ScanContext {
        root,
        inventory,
        roles,
        skill,
    });

    let analyzers: Vec<Arc<dyn Analyzer>> = vec![
        Arc::new(InstructionsAnalyzer),
        Arc::new(CodeAnalyzer),
        Arc::new(HiddenAnalyzer),
        Arc::new(AgentConfigAnalyzer),
    ];
    let (found, coverage) = run_analyzers(ctx, analyzers, opts.analyzer_timeout, progress);
    signals.extend(found);

    let mut findings = apply(&pack, &signals);
    let rejected = apply_suppressions(&mut findings, &suppressions, commit.as_deref(), &tree);
    sort_findings(&mut findings);

    let mut summary = Summary::default();
    for f in findings.iter().filter(|f| !f.suppressed) {
        match f.severity {
            Severity::Critical => summary.critical += 1,
            Severity::High => summary.high += 1,
            Severity::Medium => summary.medium += 1,
            Severity::Low => summary.low += 1,
        }
    }
    let verdict = compute_verdict(&findings, &coverage, REQUIRED_ANALYZERS);

    let report = Report {
        schema_version: SCHEMA_VERSION.to_string(),
        tool: ToolInfo {
            name: "skillsniff".to_string(),
            version: VERSION.to_string(),
            rules: pack.version.clone(),
        },
        target: TargetInfo {
            source: sanitize_evidence(&shown_source),
            kind: kind.to_string(),
            commit,
            tree_sha256: tree,
        },
        verdict,
        summary,
        findings,
        coverage,
        review: ReviewInfo {
            applied: false,
            rejected_changes: rejected,
        },
    };
    Ok(ScanOutcome {
        report,
        quarantine: Some(quarantine),
    })
}
