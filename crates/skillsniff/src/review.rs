//! Escalate-only merge of an external review into a report.
//!
//! A review can add findings under the `review.` rule namespace and raise the
//! severity of existing findings. It can never lower, remove or suppress
//! anything, and the verdict never decreases.

use serde::Deserialize;

use crate::model::{
    Finding, FindingSource, Location, Report, Severity, Summary, sanitize_evidence, sort_findings,
};
use crate::scan::REQUIRED_ANALYZERS;
use crate::score::compute_verdict;

/// Largest accepted review document.
const MAX_INPUT_BYTES: usize = 1024 * 1024;
const MAX_ADDITIONS: usize = 200;
const MAX_LOCATIONS: usize = 20;
const MAX_RULE_LEN: usize = 64;
const MAX_PATH_LEN: usize = 260;
const RULE_PREFIX: &str = "review.";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReviewDoc {
    schema_version: String,
    #[serde(default)]
    additions: Vec<Addition>,
    #[serde(default)]
    raises: Vec<Raise>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Addition {
    rule: String,
    severity: Severity,
    title: String,
    locations: Vec<Loc>,
    evidence: String,
    reason: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Loc {
    file: String,
    line: u32,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Raise {
    rule: String,
    file: String,
    line: u32,
    to: Severity,
    reason: String,
}

fn valid_rule(rule: &str) -> bool {
    rule.len() <= MAX_RULE_LEN
        && rule.len() > RULE_PREFIX.len()
        && rule.starts_with(RULE_PREFIX)
        && rule[RULE_PREFIX.len()..]
            .starts_with(|c: char| c.is_ascii_lowercase() || c.is_ascii_digit())
        && rule
            .bytes()
            .all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'.' | b'_' | b'-'))
}

fn valid_path(path: &str) -> bool {
    !path.is_empty()
        && path.len() <= MAX_PATH_LEN
        && !path.starts_with('/')
        && !path.contains(['\\', ':'])
        && !path.chars().any(char::is_control)
        && path
            .split('/')
            .all(|part| !part.is_empty() && part != "." && part != "..")
}

fn shown(s: &str) -> String {
    sanitize_evidence(s)
}

fn build_addition(a: &Addition) -> Result<Finding, String> {
    if !valid_rule(&a.rule) {
        return Err(format!(
            "addition {:?} rejected: rule must start with `review.` and match [a-z0-9._-]{{1,64}}",
            shown(&a.rule)
        ));
    }
    if a.locations.len() > MAX_LOCATIONS {
        return Err(format!(
            "addition {:?} rejected: more than {MAX_LOCATIONS} locations",
            shown(&a.rule)
        ));
    }
    if let Some(bad) = a.locations.iter().find(|l| !valid_path(&l.file)) {
        return Err(format!(
            "addition {:?} rejected: invalid location path {:?}",
            shown(&a.rule),
            shown(&bad.file)
        ));
    }
    Ok(Finding {
        rule: a.rule.clone(),
        severity: a.severity,
        title: sanitize_evidence(&a.title),
        locations: a
            .locations
            .iter()
            .map(|l| Location {
                file: l.file.clone(),
                line: l.line,
            })
            .collect(),
        evidence: sanitize_evidence(&a.evidence),
        explain: sanitize_evidence(&a.reason),
        advice: String::new(),
        source: FindingSource::Review,
        suppressed: false,
    })
}

/// Applies `review_json` to `report`.
///
/// The whole document is refused (`Err`) when it is too large, is not valid
/// JSON, has the wrong schema version or contains any unknown key. Problems
/// with single entries are recorded in `review.rejected_changes` and the rest
/// is applied. The final verdict is the higher of the old and the recomputed
/// one.
pub fn apply_review(mut report: Report, review_json: &str) -> Result<Report, String> {
    if review_json.len() > MAX_INPUT_BYTES {
        return Err(format!(
            "review rejected: input is larger than {MAX_INPUT_BYTES} bytes"
        ));
    }
    let doc: ReviewDoc = serde_json::from_str(review_json)
        .map_err(|e| format!("review rejected: invalid review document: {e}"))?;
    if doc.schema_version != "1" {
        return Err(format!(
            "review rejected: unsupported schema_version {:?}",
            shown(&doc.schema_version)
        ));
    }

    let mut rejected = Vec::new();
    for (i, a) in doc.additions.iter().enumerate() {
        if i >= MAX_ADDITIONS {
            rejected.push(format!(
                "addition {:?} rejected: more than {MAX_ADDITIONS} additions",
                shown(&a.rule)
            ));
            continue;
        }
        match build_addition(a) {
            Ok(f) => report.findings.push(f),
            Err(why) => rejected.push(why),
        }
    }

    for r in &doc.raises {
        let matches_loc = |f: &Finding| {
            f.rule == r.rule
                && f.locations
                    .iter()
                    .any(|l| l.file == r.file && l.line == r.line)
        };
        let mut matched = 0usize;
        let mut raised = 0usize;
        for f in report.findings.iter_mut().filter(|f| matches_loc(f)) {
            matched += 1;
            if r.to > f.severity {
                f.severity = r.to;
                let note = sanitize_evidence(&r.reason);
                f.explain = format!("{} Review: {note}", f.explain);
                raised += 1;
                if f.suppressed && r.to < Severity::Critical {
                    rejected.push(format!(
                        "raise of {:?} at {:?}:{} applied to a suppressed finding; it stays suppressed",
                        shown(&r.rule),
                        shown(&r.file),
                        r.line
                    ));
                }
            }
        }
        if matched == 0 {
            rejected.push(format!(
                "raise of {:?} at {:?}:{} rejected: no matching finding",
                shown(&r.rule),
                shown(&r.file),
                r.line
            ));
        } else if raised == 0 {
            rejected.push(format!(
                "raise of {:?} at {:?}:{} rejected: target severity is not higher",
                shown(&r.rule),
                shown(&r.file),
                r.line
            ));
        } else if raised < matched {
            rejected.push(format!(
                "raise of {:?} at {:?}:{} applied to {raised} of {matched} matching findings; the rest are not lower than the target",
                shown(&r.rule),
                shown(&r.file),
                r.line
            ));
        }
    }

    for f in report.findings.iter_mut() {
        if f.suppressed && f.severity == Severity::Critical {
            f.suppressed = false;
            rejected.push(format!(
                "suppression lifted: {} is critical",
                shown(&f.rule)
            ));
        }
    }

    sort_findings(&mut report.findings);
    let mut summary = Summary::default();
    for f in report.findings.iter().filter(|f| !f.suppressed) {
        match f.severity {
            Severity::Critical => summary.critical += 1,
            Severity::High => summary.high += 1,
            Severity::Medium => summary.medium += 1,
            Severity::Low => summary.low += 1,
        }
    }
    report.summary = summary;
    let recomputed = compute_verdict(&report.findings, &report.coverage, REQUIRED_ANALYZERS);
    report.verdict = report.verdict.max(recomputed);
    report.review.applied = true;
    report.review.rejected_changes.extend(rejected);
    Ok(report)
}
