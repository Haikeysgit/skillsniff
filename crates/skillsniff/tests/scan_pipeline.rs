use std::fs;
use std::path::{Path, PathBuf};

use skillsniff::model::{Coverage, Finding, FindingSource, Location, Severity, Verdict};
use skillsniff::progress::NoopProgress;
use skillsniff::scan::{ScanError, ScanOptions, ScanOutcome, scan};
use skillsniff::suppress::{Suppression, apply_suppressions, load_suppressions};

fn fixture(rel: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures")
        .join(rel)
}

fn run(path: &Path, opts: &ScanOptions) -> Result<ScanOutcome, ScanError> {
    scan(path.to_str().unwrap(), opts, &NoopProgress)
}

fn run_ok(path: &Path, opts: &ScanOptions) -> ScanOutcome {
    run(path, opts).unwrap_or_else(|e| panic!("scan failed: {e}"))
}

const SKILL_MD: &str = "---\nname: runner\ndescription: Lists a folder. Use when asked to list files.\n---\nList files.\n";

/// A skill whose only finding is one MEDIUM `exec.run-command`.
fn medium_skill() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("SKILL.md"), SKILL_MD).unwrap();
    fs::create_dir(dir.path().join("scripts")).unwrap();
    fs::write(
        dir.path().join("scripts/run.py"),
        "import subprocess\n\nsubprocess.run([\"ls\", \"-l\"])\n",
    )
    .unwrap();
    dir
}

fn write_suppressions(dir: &Path, body: &str) -> PathBuf {
    let p = dir.join("suppressions.yaml");
    fs::write(&p, body).unwrap();
    p
}

fn rule_ids(findings: &[Finding]) -> Vec<&str> {
    findings.iter().map(|f| f.rule.as_str()).collect()
}

#[test]
fn end_to_end_block_on_exfil_fixture() {
    let out = run_ok(&fixture("malicious/exfil-aws"), &ScanOptions::default());
    let r = &out.report;
    assert_eq!(r.verdict, Verdict::Block);
    assert!(rule_ids(&r.findings).contains(&"exfil.secret-to-network"));
    assert!(r.summary.critical >= 1);
    assert_eq!(r.target.kind, "skill");
    assert_eq!(r.target.tree_sha256.len(), 64);
    assert_eq!(r.target.commit, None);
    assert_eq!(r.tool.name, "skillsniff");
    assert_eq!(r.tool.rules, "2026.11.1");
    assert!(out.quarantine.is_some());

    let mut sorted = r.findings.clone();
    skillsniff::model::sort_findings(&mut sorted);
    assert_eq!(sorted, r.findings, "findings are sorted");
    assert_eq!(r.findings[0].severity, Severity::Critical);
}

#[test]
fn end_to_end_pass_on_clean_fixture() {
    let out = run_ok(&fixture("clean/minimal-skill"), &ScanOptions::default());
    let r = &out.report;
    assert_eq!(r.verdict, Verdict::Pass, "findings: {:?}", r.findings);
    assert!(r.findings.is_empty(), "findings: {:?}", r.findings);
    for id in ["instructions", "code", "hidden", "agent_config"] {
        assert_eq!(r.coverage.get(id), Some(&Coverage::Ran), "{id}");
    }
    assert!(r.coverage.values().all(|c| *c == Coverage::Ran));
    assert_eq!(r.summary.critical + r.summary.high + r.summary.medium, 0);
}

#[test]
fn fixtures_meet_their_expected_yaml() {
    for (dir, verdict, must) in [
        (
            "malicious/exfil-aws",
            Verdict::Block,
            "exfil.secret-to-network",
        ),
        ("clean/minimal-skill", Verdict::Pass, ""),
    ] {
        let expected = fs::read_to_string(fixture(dir).join("expected.yaml")).unwrap();
        assert!(expected.contains(&format!("verdict: {}", verdict_name(verdict))));
        assert!(expected.contains(must));
    }
}

fn verdict_name(v: Verdict) -> &'static str {
    match v {
        Verdict::Pass => "PASS",
        Verdict::Caution => "CAUTION",
        Verdict::Block => "BLOCK",
    }
}

#[test]
fn suppression_marks_medium_but_not_critical() {
    let skill = medium_skill();
    let first = run_ok(skill.path(), &ScanOptions::default());
    assert_eq!(first.report.verdict, Verdict::Caution);
    assert_eq!(rule_ids(&first.report.findings), ["exec.run-command"]);
    let tree = first.report.target.tree_sha256.clone();

    let cfg = tempfile::tempdir().unwrap();
    let path = write_suppressions(
        cfg.path(),
        &format!(
            "suppressions:\n  - rule: exec.run-command\n    target: {tree}\n    reason: lists a folder on purpose\n"
        ),
    );
    let opts = ScanOptions {
        suppressions: Some(path),
        ..ScanOptions::default()
    };
    let second = run_ok(skill.path(), &opts);
    let r = &second.report;
    assert_eq!(r.findings.len(), 1);
    assert!(r.findings[0].suppressed);
    assert_eq!(r.summary.medium, 0);
    assert_eq!(r.verdict, Verdict::Pass);

    // A suppression for another tree changes nothing.
    let other = write_suppressions(
        cfg.path(),
        "suppressions:\n  - rule: exec.run-command\n    target: deadbeef\n    reason: wrong tree\n",
    );
    let opts = ScanOptions {
        suppressions: Some(other),
        ..ScanOptions::default()
    };
    let third = run_ok(skill.path(), &opts);
    assert!(!third.report.findings[0].suppressed);

    // A critical finding stays active and the attempt is recorded.
    let bad = fixture("malicious/exfil-aws");
    let tree = run_ok(&bad, &ScanOptions::default())
        .report
        .target
        .tree_sha256;
    let path = write_suppressions(
        cfg.path(),
        &format!(
            "suppressions:\n  - rule: exfil.secret-to-network\n    target: {tree}\n    reason: trust me\n"
        ),
    );
    let opts = ScanOptions {
        suppressions: Some(path),
        ..ScanOptions::default()
    };
    let r = run_ok(&bad, &opts).report;
    assert_eq!(r.verdict, Verdict::Block);
    assert!(r.findings.iter().all(|f| !f.suppressed));
    assert!(
        r.review
            .rejected_changes
            .contains(&"suppression ignored for critical rule exfil.secret-to-network".to_string())
    );
}

#[test]
fn suppressions_never_read_from_target() {
    let skill = medium_skill();
    let before = run_ok(skill.path(), &ScanOptions::default());
    let tree = before.report.target.tree_sha256;
    // The target ships suppressions for every name it can think of.
    let body = format!(
        "suppressions:\n  - rule: exec.run-command\n    target: {tree}\n    reason: shipped by the target\n"
    );
    for rel in [
        "suppressions.yaml",
        ".skillsniff/suppressions.yaml",
        "skillsniff/suppressions.yaml",
    ] {
        let p = skill.path().join(rel);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(p, &body).unwrap();
    }
    let r = run_ok(skill.path(), &ScanOptions::default()).report;
    assert!(r.findings.iter().all(|f| !f.suppressed));
    assert_eq!(r.verdict, Verdict::Caution);
    assert!(r.review.rejected_changes.is_empty());
}

#[test]
fn suppression_without_reason_is_usage_error() {
    let cfg = tempfile::tempdir().unwrap();
    for body in [
        "suppressions:\n  - rule: a.b\n    target: abc\n    reason: \"\"\n",
        "suppressions:\n  - rule: a.b\n    target: abc\n",
        "suppressions:\n  - rule: a.b\n    target: abc\n    reason: \"  \"\n",
    ] {
        let path = write_suppressions(cfg.path(), body);
        assert!(load_suppressions(Some(&path)).is_err(), "{body}");
        let opts = ScanOptions {
            suppressions: Some(path),
            ..ScanOptions::default()
        };
        let err = run(&fixture("clean/minimal-skill"), &opts).unwrap_err();
        assert!(matches!(err, ScanError::Usage(_)), "{err}");
    }
}

#[test]
fn load_suppressions_reads_entries_and_rejects_missing_explicit_file() {
    let cfg = tempfile::tempdir().unwrap();
    let path = write_suppressions(
        cfg.path(),
        "suppressions:\n  - rule: a.b\n    target: abc\n    reason: because\n",
    );
    assert_eq!(
        load_suppressions(Some(&path)).unwrap(),
        vec![Suppression {
            rule: "a.b".into(),
            target: "abc".into(),
            reason: "because".into()
        }]
    );
    assert!(load_suppressions(Some(&cfg.path().join("nope.yaml"))).is_err());
    let empty = cfg.path().join("empty.yaml");
    fs::write(&empty, "").unwrap();
    assert!(load_suppressions(Some(&empty)).unwrap().is_empty());
}

fn finding(rule: &str, severity: Severity) -> Finding {
    Finding {
        rule: rule.to_string(),
        severity,
        title: "t".into(),
        locations: vec![Location {
            file: "a".into(),
            line: 1,
        }],
        evidence: "e".into(),
        explain: "x".into(),
        advice: "y".into(),
        source: FindingSource::Engine,
        suppressed: false,
    }
}

#[test]
fn apply_suppressions_matches_commit_or_tree() {
    let sup = |rule: &str, target: &str| Suppression {
        rule: rule.into(),
        target: target.into(),
        reason: "r".into(),
    };
    let mut f = vec![
        finding("a.one", Severity::Medium),
        finding("a.two", Severity::Low),
        finding("a.three", Severity::High),
        finding("a.crit", Severity::Critical),
    ];
    let rejected = apply_suppressions(
        &mut f,
        &[
            sup("a.one", "commit1"),
            sup("a.two", "tree1"),
            sup("a.three", "other"),
            sup("a.crit", "tree1"),
            sup("a.crit", "commit1"),
        ],
        Some("commit1"),
        "tree1",
    );
    assert!(f[0].suppressed && f[1].suppressed);
    assert!(!f[2].suppressed, "target does not match");
    assert!(!f[3].suppressed);
    assert_eq!(rejected, ["suppression ignored for critical rule a.crit"]);
}

#[test]
fn high_findings_can_be_suppressed() {
    let mut f = vec![finding("a.high", Severity::High)];
    let s = Suppression {
        rule: "a.high".into(),
        target: "tree1".into(),
        reason: "r".into(),
    };
    assert!(apply_suppressions(&mut f, &[s], None, "tree1").is_empty());
    assert!(f[0].suppressed);
}

#[test]
fn bad_source_is_usage_error() {
    let opts = ScanOptions::default();
    let err = scan("https://example.com/x", &opts, &NoopProgress).unwrap_err();
    assert!(matches!(err, ScanError::Usage(_)), "{err}");
}

#[test]
fn folder_without_skill_is_target_error() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("notes.txt"), "hi").unwrap();
    let err = run(dir.path(), &ScanOptions::default()).unwrap_err();
    assert!(matches!(err, ScanError::Target(_)), "{err}");
}

#[test]
fn offline_remote_source_is_fetch_error() {
    let opts = ScanOptions {
        offline: true,
        ..ScanOptions::default()
    };
    let err = scan("owner/repo", &opts, &NoopProgress).unwrap_err();
    assert!(matches!(err, ScanError::Fetch(_)), "{err}");
}

#[test]
fn bad_extra_rules_are_usage_error() {
    let dir = tempfile::tempdir().unwrap();
    let opts = ScanOptions {
        extra_rules: Some(dir.path().join("missing")),
        ..ScanOptions::default()
    };
    let err = run(&fixture("clean/minimal-skill"), &opts).unwrap_err();
    assert!(matches!(err, ScanError::Usage(_)), "{err}");
}

#[test]
fn extra_rules_apply() {
    let rules = tempfile::tempdir().unwrap();
    fs::write(
        rules.path().join("extra.yaml"),
        "rules:\n  - id: custom.exec\n    severity: low\n    title: T\n    signal: Sink\n    where: {class: exec, lang: python}\n    explain: E\n    advice: A\n",
    )
    .unwrap();
    let skill = medium_skill();
    let opts = ScanOptions {
        extra_rules: Some(rules.path().to_path_buf()),
        ..ScanOptions::default()
    };
    let r = run_ok(skill.path(), &opts).report;
    assert_eq!(rule_ids(&r.findings), ["custom.exec"]);
}

#[test]
fn file_names_are_sanitized_in_the_report() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("SKILL.md"), SKILL_MD).unwrap();
    let name = "notes\u{200B}.bin";
    fs::write(dir.path().join(name), [0u8, 1, 2, 3]).unwrap();
    let r = run_ok(dir.path(), &ScanOptions::default()).report;
    let f = r
        .findings
        .iter()
        .find(|f| f.rule == "hidden.binary-file")
        .expect("binary finding");
    assert_eq!(f.locations[0].file, "notes\\u{200B}.bin");
    assert!(
        r.findings
            .iter()
            .all(|f| f.locations.iter().all(|l| !l.file.contains('\u{200B}')))
    );
}
