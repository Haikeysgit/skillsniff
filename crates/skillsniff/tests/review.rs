use std::collections::BTreeMap;

use skillsniff::model::*;
use skillsniff::review::apply_review;

fn finding(rule: &str, severity: Severity, file: &str, line: u32) -> Finding {
    Finding {
        rule: rule.into(),
        severity,
        title: "t".into(),
        locations: vec![Location {
            file: file.into(),
            line,
        }],
        evidence: "e".into(),
        explain: "x".into(),
        advice: "a".into(),
        source: FindingSource::Engine,
        suppressed: false,
    }
}

fn report(findings: Vec<Finding>, verdict: Verdict) -> Report {
    let mut summary = Summary::default();
    for f in &findings {
        match f.severity {
            Severity::Critical => summary.critical += 1,
            Severity::High => summary.high += 1,
            Severity::Medium => summary.medium += 1,
            Severity::Low => summary.low += 1,
        }
    }
    let coverage: BTreeMap<String, Coverage> = ["instructions", "code", "hidden", "agent_config"]
        .iter()
        .map(|n| (n.to_string(), Coverage::Ran))
        .collect();
    Report {
        schema_version: "1".into(),
        tool: ToolInfo {
            name: "skillsniff".into(),
            version: "0".into(),
            rules: "r".into(),
        },
        target: TargetInfo {
            source: "s".into(),
            kind: "skill".into(),
            commit: None,
            tree_sha256: "00".into(),
        },
        verdict,
        summary,
        findings,
        coverage,
        review: ReviewInfo {
            applied: false,
            rejected_changes: vec![],
        },
    }
}

fn pass_report() -> Report {
    report(vec![], Verdict::Pass)
}

fn addition(rule: &str, severity: &str) -> String {
    format!(
        r#"{{"rule":"{rule}","severity":"{severity}","title":"Odd step","locations":[{{"file":"SKILL.md","line":3}}],"evidence":"ev","reason":"why"}}"#
    )
}

fn doc(additions: &[String], raises: &[String]) -> String {
    format!(
        r#"{{"schema_version":"1","additions":[{}],"raises":[{}]}}"#,
        additions.join(","),
        raises.join(",")
    )
}

const RAISE_CRIT: &str =
    r#"{"rule":"exec.run-command","file":"a.py","line":3,"to":"critical","reason":"worse"}"#;

#[test]
fn addition_with_review_prefix_is_accepted() {
    let r = apply_review(
        pass_report(),
        &doc(&[addition("review.odd-step", "medium")], &[]),
    )
    .unwrap();
    assert_eq!(r.findings.len(), 1);
    assert_eq!(r.findings[0].source, FindingSource::Review);
    assert!(!r.findings[0].suppressed);
    assert_eq!(r.summary.medium, 1);
    assert_eq!(r.verdict, Verdict::Caution);
    assert!(r.review.applied);
    assert!(r.review.rejected_changes.is_empty());
}

#[test]
fn addition_impersonating_engine_rule_is_rejected() {
    let r = apply_review(
        pass_report(),
        &doc(&[addition("exec.run-command", "critical")], &[]),
    )
    .unwrap();
    assert!(r.findings.is_empty());
    assert_eq!(r.verdict, Verdict::Pass);
    assert_eq!(r.review.rejected_changes.len(), 1);
}

#[test]
fn raise_to_higher_is_accepted_and_verdict_recomputed() {
    let base = report(
        vec![finding("exec.run-command", Severity::Medium, "a.py", 3)],
        Verdict::Caution,
    );
    let r = apply_review(base, &doc(&[], &[RAISE_CRIT.into()])).unwrap();
    assert_eq!(r.findings[0].severity, Severity::Critical);
    assert_eq!(r.summary.critical, 1);
    assert_eq!(r.summary.medium, 0);
    assert_eq!(r.verdict, Verdict::Block);
}

#[test]
fn raise_matches_any_location_of_a_finding() {
    let mut f = finding("exec.run-command", Severity::Low, "a.py", 3);
    f.locations.push(Location {
        file: "b.py".into(),
        line: 9,
    });
    let base = report(vec![f], Verdict::Pass);
    let raise = r#"{"rule":"exec.run-command","file":"b.py","line":9,"to":"high","reason":"r"}"#;
    let r = apply_review(base, &doc(&[], &[raise.into()])).unwrap();
    assert_eq!(r.findings[0].severity, Severity::High);
    assert_eq!(r.verdict, Verdict::Caution);
}

#[test]
fn lowering_is_rejected_and_recorded() {
    let base = report(
        vec![finding("exec.run-command", Severity::High, "a.py", 3)],
        Verdict::Caution,
    );
    let lower = r#"{"rule":"exec.run-command","file":"a.py","line":3,"to":"low","reason":"fine"}"#;
    let equal = r#"{"rule":"exec.run-command","file":"a.py","line":3,"to":"high","reason":"same"}"#;
    let missing =
        r#"{"rule":"exec.run-command","file":"zzz.py","line":1,"to":"critical","reason":"x"}"#;
    let raises = [lower.into(), equal.into(), missing.into()];
    let r = apply_review(base, &doc(&[], &raises)).unwrap();
    assert_eq!(r.findings[0].severity, Severity::High);
    assert_eq!(r.review.rejected_changes.len(), 3);
    assert_eq!(r.verdict, Verdict::Caution);
}

#[test]
fn unknown_keys_are_rejected() {
    for body in [
        r#"{"schema_version":"1","additions":[],"raises":[],"remove":["x"]}"#,
        r#"{"schema_version":"1","additions":[],"raises":[],"lowers":[]}"#,
        r#"{"schema_version":"1","raises":[{"rule":"a","file":"f","line":1,"to":"low","reason":"r","suppress":true}]}"#,
        r#"{"schema_version":"1","additions":[{"rule":"review.a","severity":"low","title":"t","locations":[],"evidence":"e","reason":"r","suppressed":true}]}"#,
        r#"not json"#,
        r#"{"schema_version":"2"}"#,
    ] {
        assert!(apply_review(pass_report(), body).is_err(), "{body}");
    }
}

#[test]
fn oversized_input_is_rejected() {
    let big = format!(
        r#"{{"schema_version":"1","additions":[],"raises":[],"pad":"{}"}}"#,
        "a".repeat(1024 * 1024)
    );
    assert!(apply_review(pass_report(), &big).is_err());
}

#[test]
fn bad_addition_shapes_are_rejected_per_entry() {
    let long_rule = format!("review.{}", "a".repeat(64));
    let many_locs: Vec<String> = (0..21)
        .map(|i| format!(r#"{{"file":"a","line":{i}}}"#))
        .collect();
    let too_many = format!(
        r#"{{"rule":"review.x","severity":"low","title":"t","locations":[{}],"evidence":"e","reason":"r"}}"#,
        many_locs.join(",")
    );
    let bad_path = |p: &str| {
        format!(
            r#"{{"rule":"review.x","severity":"low","title":"t","locations":[{{"file":"{p}","line":1}}],"evidence":"e","reason":"r"}}"#
        )
    };
    let adds = vec![
        addition(&long_rule, "low"),
        addition("review.UPPER", "low"),
        too_many,
        bad_path("../etc/passwd"),
        bad_path("/abs"),
        bad_path("a\\\\b"),
        addition("review.good", "low"),
    ];
    let r = apply_review(pass_report(), &doc(&adds, &[])).unwrap();
    assert_eq!(r.findings.len(), 1);
    assert_eq!(r.review.rejected_changes.len(), 6);
}

#[test]
fn text_fields_are_sanitized_and_capped() {
    let add = format!(
        r#"{{"rule":"review.x","severity":"low","title":"a\u202Eb","locations":[],"evidence":"{}","reason":"r"}}"#,
        "e".repeat(500)
    );
    let r = apply_review(pass_report(), &doc(&[add], &[])).unwrap();
    assert!(r.findings[0].title.contains("\\u{202E}"));
    assert!(r.findings[0].evidence.chars().count() <= 200);
}

#[test]
fn additions_are_capped_at_200() {
    let adds: Vec<String> = (0..205)
        .map(|i| addition(&format!("review.r{i}"), "low"))
        .collect();
    let r = apply_review(pass_report(), &doc(&adds, &[])).unwrap();
    assert_eq!(r.findings.len(), 200);
    assert_eq!(r.review.rejected_changes.len(), 5);
}

#[test]
fn verdict_never_decreases() {
    let mut seed: u64 = 0x1234_5678;
    let mut next = move || {
        seed = seed
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        (seed >> 33) as usize
    };
    let sevs = ["low", "medium", "high", "critical"];
    for _ in 0..200 {
        let base = report(
            vec![finding("exec.run-command", Severity::Critical, "a.py", 3)],
            Verdict::Block,
        );
        let mut adds = Vec::new();
        let mut raises = Vec::new();
        for _ in 0..(next() % 4) {
            adds.push(addition(
                &format!("review.r{}", next() % 5),
                sevs[next() % 4],
            ));
        }
        for _ in 0..(next() % 4) {
            raises.push(format!(
                r#"{{"rule":"exec.run-command","file":"a.py","line":3,"to":"{}","reason":"r"}}"#,
                sevs[next() % 4]
            ));
        }
        let r = apply_review(base, &doc(&adds, &raises)).unwrap();
        assert_eq!(r.verdict, Verdict::Block);
        assert!(
            r.findings
                .iter()
                .any(|f| f.rule == "exec.run-command" && f.severity == Severity::Critical)
        );
    }
}
