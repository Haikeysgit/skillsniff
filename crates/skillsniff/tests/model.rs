use std::collections::BTreeMap;

use skillsniff::model::*;

fn loc(file: &str, line: u32) -> Location {
    Location {
        file: file.into(),
        line,
    }
}

fn finding(rule: &str, severity: Severity, file: &str, line: u32) -> Finding {
    Finding {
        rule: rule.into(),
        severity,
        title: "t".into(),
        locations: vec![loc(file, line)],
        evidence: String::new(),
        explain: String::new(),
        advice: String::new(),
        source: FindingSource::Engine,
        suppressed: false,
    }
}

fn sample_report() -> Report {
    let mut coverage = BTreeMap::new();
    coverage.insert("instructions".to_string(), Coverage::Ran);
    coverage.insert("code".to_string(), Coverage::Ran);
    coverage.insert("hidden".to_string(), Coverage::Ran);
    coverage.insert(
        "supply_chain".to_string(),
        Coverage::Skipped {
            reason: "offline".into(),
        },
    );
    coverage.insert(
        "extra".to_string(),
        Coverage::Failed {
            reason: "boom".into(),
        },
    );
    Report {
        schema_version: "1".into(),
        tool: ToolInfo {
            name: "skillsniff".into(),
            version: "0.1.0".into(),
            rules: "2026.11.1".into(),
        },
        target: TargetInfo {
            source: "github.com/example/pdf-tools".into(),
            kind: "skill".into(),
            commit: Some("a41f9c2".into()),
            tree_sha256: "deadbeef".into(),
        },
        verdict: Verdict::Block,
        summary: Summary {
            critical: 2,
            high: 1,
            medium: 0,
            low: 0,
        },
        findings: vec![Finding {
            rule: "exfil.secret-to-network".into(),
            severity: Severity::Critical,
            title: "Secret sent to the network".into(),
            locations: vec![loc("scripts/convert.py", 41), loc("scripts/convert.py", 58)],
            evidence: "open('~/.aws/credentials') -> buf -> requests.post(data=buf)".into(),
            explain: "Code reads a credential file and sends its contents to a remote host.".into(),
            advice: "Do not install. Report the skill to its registry.".into(),
            source: FindingSource::Engine,
            suppressed: false,
        }],
        coverage,
        review: ReviewInfo {
            applied: false,
            rejected_changes: vec![],
        },
    }
}

#[test]
fn report_json_matches_spec_shape() {
    insta::assert_json_snapshot!(sample_report());
}

#[test]
fn report_round_trips_through_json() {
    let report = sample_report();
    let json = serde_json::to_string(&report).unwrap();
    let back: Report = serde_json::from_str(&json).unwrap();
    assert_eq!(report, back);
}

#[test]
fn sanitize_escapes_bidi_and_caps_length() {
    assert_eq!(sanitize_evidence("a\u{202E}b"), "a\\u{202E}b");
    let long = "x".repeat(500);
    let out = sanitize_evidence(&long);
    assert_eq!(out.chars().count(), 201);
    assert!(out.ends_with('…'));
}

#[test]
fn findings_sort_by_severity_then_path_line_rule() {
    let mut v = vec![
        finding("r", Severity::Low, "a.py", 1),
        finding("r", Severity::Critical, "b.py", 1),
        finding("r", Severity::Critical, "a.py", 10),
        finding("r", Severity::Critical, "a.py", 2),
    ];
    sort_findings(&mut v);
    let order: Vec<(Severity, String, u32)> = v
        .iter()
        .map(|f| (f.severity, f.locations[0].file.clone(), f.locations[0].line))
        .collect();
    assert_eq!(
        order,
        vec![
            (Severity::Critical, "a.py".to_string(), 2),
            (Severity::Critical, "a.py".to_string(), 10),
            (Severity::Critical, "b.py".to_string(), 1),
            (Severity::Low, "a.py".to_string(), 1),
        ]
    );
}

#[test]
fn verdict_exit_codes() {
    assert_eq!(Verdict::Pass.exit_code(), 0);
    assert_eq!(Verdict::Caution.exit_code(), 1);
    assert_eq!(Verdict::Block.exit_code(), 2);
}
