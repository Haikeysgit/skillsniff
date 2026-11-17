use std::collections::BTreeMap;

use skillsniff::model::*;
use skillsniff::score::compute_verdict;

fn f(rule: &str, severity: Severity, suppressed: bool) -> Finding {
    Finding {
        rule: rule.into(),
        severity,
        title: String::new(),
        locations: vec![],
        evidence: String::new(),
        explain: String::new(),
        advice: String::new(),
        source: FindingSource::Engine,
        suppressed,
    }
}

fn cov(entries: &[(&str, Coverage)]) -> BTreeMap<String, Coverage> {
    entries
        .iter()
        .map(|(k, v)| (k.to_string(), v.clone()))
        .collect()
}

#[test]
fn verdict_rules_table() {
    let ran = || cov(&[("code", Coverage::Ran), ("hidden", Coverage::Ran)]);
    let cases: Vec<(
        &str,
        Vec<Finding>,
        BTreeMap<String, Coverage>,
        Vec<&str>,
        Verdict,
    )> = vec![
        (
            "one critical blocks",
            vec![f("a", Severity::Critical, false)],
            ran(),
            vec!["code"],
            Verdict::Block,
        ),
        (
            "two highs, different rules, block",
            vec![f("a", Severity::High, false), f("b", Severity::High, false)],
            ran(),
            vec!["code"],
            Verdict::Block,
        ),
        (
            "two highs, same rule, caution",
            vec![f("a", Severity::High, false), f("a", Severity::High, false)],
            ran(),
            vec!["code"],
            Verdict::Caution,
        ),
        (
            "one medium cautions",
            vec![f("a", Severity::Medium, false)],
            ran(),
            vec!["code"],
            Verdict::Caution,
        ),
        (
            "failed analyzer cautions",
            vec![],
            cov(&[("code", Coverage::Failed { reason: "x".into() })]),
            vec![],
            Verdict::Caution,
        ),
        (
            "required analyzer skipped cautions",
            vec![],
            cov(&[(
                "code",
                Coverage::Skipped {
                    reason: "offline".into(),
                },
            )]),
            vec!["code"],
            Verdict::Caution,
        ),
        (
            "non-required skipped passes",
            vec![],
            cov(&[(
                "code",
                Coverage::Skipped {
                    reason: "offline".into(),
                },
            )]),
            vec![],
            Verdict::Pass,
        ),
        (
            "lows with full coverage pass",
            vec![f("a", Severity::Low, false), f("b", Severity::Low, false)],
            ran(),
            vec!["code", "hidden"],
            Verdict::Pass,
        ),
        (
            "suppressed critical alone passes",
            vec![f("a", Severity::Critical, true)],
            ran(),
            vec!["code"],
            Verdict::Pass,
        ),
    ];
    for (name, findings, coverage, required, expected) in cases {
        assert_eq!(
            compute_verdict(&findings, &coverage, &required),
            expected,
            "{name}"
        );
    }
}
