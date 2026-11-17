//! Deterministic verdict scoring (design section 7.6).

use std::collections::{BTreeMap, BTreeSet};

use crate::model::{Coverage, Finding, Severity, Verdict};

/// Computes the verdict from unsuppressed findings and analyzer coverage.
///
/// Rules, in order: any critical blocks; two or more high findings from
/// different rules block; any high or medium cautions; a failed analyzer or a
/// skipped required analyzer cautions; otherwise pass.
pub fn compute_verdict(
    findings: &[Finding],
    coverage: &BTreeMap<String, Coverage>,
    required: &[&str],
) -> Verdict {
    let active = || findings.iter().filter(|f| !f.suppressed);

    if active().any(|f| f.severity == Severity::Critical) {
        return Verdict::Block;
    }
    let high_rules: BTreeSet<&str> = active()
        .filter(|f| f.severity == Severity::High)
        .map(|f| f.rule.as_str())
        .collect();
    if high_rules.len() >= 2 {
        return Verdict::Block;
    }
    if active().any(|f| matches!(f.severity, Severity::High | Severity::Medium)) {
        return Verdict::Caution;
    }
    let coverage_gap = coverage.iter().any(|(name, c)| match c {
        Coverage::Failed { .. } => true,
        Coverage::Skipped { .. } => required.contains(&name.as_str()),
        Coverage::Ran => false,
    });
    if coverage_gap {
        return Verdict::Caution;
    }
    Verdict::Pass
}
