//! Scans every fixture under `tests/fixtures` and checks the verdict, the
//! required rule ids and a JSON snapshot of the report.

mod corpus_gen;

use std::collections::BTreeSet;
use std::fs;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::{Path, PathBuf};

use skillsniff::model::{Report, Verdict};
use skillsniff::progress::NoopProgress;
use skillsniff::scan::{ScanOptions, scan};
use yaml_rust2::{Yaml, YamlLoader};

const KINDS: &[&str] = &["malicious", "caution", "clean"];

struct Expect {
    verdict: String,
    must_find: Vec<String>,
    known_gap: bool,
    /// The scan must be refused with an error containing this text.
    error: Option<String>,
}

fn fixtures_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures")
}

fn empty_suppressions() -> PathBuf {
    let p = Path::new(env!("CARGO_TARGET_TMPDIR")).join("corpus-empty-suppressions.yaml");
    fs::write(&p, "suppressions: []\n").unwrap();
    p
}

fn parse_expected(path: &Path) -> Expect {
    let text = fs::read_to_string(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    let docs =
        YamlLoader::load_from_str(&text).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    let doc = &docs[0];
    let verdict = doc["verdict"]
        .as_str()
        .unwrap_or_else(|| panic!("{}: no verdict", path.display()))
        .to_string();
    let must_find = match &doc["must_find"] {
        Yaml::Array(a) => a
            .iter()
            .filter_map(|y| y.as_str().map(String::from))
            .collect(),
        _ => Vec::new(),
    };
    Expect {
        verdict,
        must_find,
        known_gap: doc["known_gap"].as_bool().unwrap_or(false),
        error: doc["error"].as_str().map(String::from),
    }
}

fn verdict_name(v: Verdict) -> &'static str {
    match v {
        Verdict::Pass => "PASS",
        Verdict::Caution => "CAUTION",
        Verdict::Block => "BLOCK",
    }
}

fn try_scan(path: &Path, suppressions: &Path) -> Result<Report, String> {
    let opts = ScanOptions {
        offline: true,
        suppressions: Some(suppressions.to_path_buf()),
        ..ScanOptions::default()
    };
    scan(path.to_str().unwrap(), &opts, &NoopProgress)
        .map(|o| o.report)
        .map_err(|e| e.to_string())
}

fn scan_path(path: &Path, suppressions: &Path) -> Report {
    try_scan(path, suppressions)
        .unwrap_or_else(|e| panic!("scan of {} failed: {e}", path.display()))
}

/// The report as JSON with machine- and release-specific values replaced.
fn redacted(report: &Report) -> serde_json::Value {
    let mut v = serde_json::to_value(report).unwrap();
    v["tool"]["version"] = "[version]".into();
    v["target"]["source"] = "[source]".into();
    v
}

fn check(name: &str, report: &Report, expect: &Expect, failures: &mut Vec<String>) {
    let got = verdict_name(report.verdict);
    if got != expect.verdict {
        let rules: BTreeSet<&str> = report.findings.iter().map(|f| f.rule.as_str()).collect();
        failures.push(format!(
            "{name}: verdict {got}, expected {} (rules: {rules:?})",
            expect.verdict
        ));
    }
    if expect.known_gap {
        return;
    }
    let found: BTreeSet<&str> = report.findings.iter().map(|f| f.rule.as_str()).collect();
    for rule in &expect.must_find {
        if !found.contains(rule.as_str()) {
            failures.push(format!("{name}: missing {rule} (found: {found:?})"));
        }
    }
}

/// Set `CORPUS_SKIP_SNAPSHOTS` to check verdicts only while editing rules.
fn snapshot(name: &str, report: &Report, failures: &mut Vec<String>) {
    if std::env::var_os("CORPUS_SKIP_SNAPSHOTS").is_some() {
        return;
    }
    let value = redacted(report);
    let result = catch_unwind(AssertUnwindSafe(|| {
        insta::assert_json_snapshot!(name.to_string(), value);
    }));
    if result.is_err() {
        failures.push(format!("{name}: snapshot differs"));
    }
}

#[test]
fn corpus() {
    let suppressions = empty_suppressions();
    let mut failures = Vec::new();
    let mut covered: BTreeSet<String> = BTreeSet::new();
    let mut count = 0;

    for kind in KINDS {
        let dir = fixtures_root().join(kind);
        let Ok(entries) = fs::read_dir(&dir) else {
            continue;
        };
        let mut names: Vec<_> = entries
            .filter_map(Result::ok)
            .filter(|e| e.path().is_dir())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        for name in names {
            let path = dir.join(&name);
            let expect = parse_expected(&path.join("expected.yaml"));
            let label = format!("{kind}/{name}");
            count += 1;
            if let Some(want) = &expect.error {
                match try_scan(&path, &suppressions) {
                    Err(e) if e.contains(want.as_str()) => {}
                    other => {
                        failures.push(format!("{label}: expected error \"{want}\", got {other:?}"))
                    }
                }
                continue;
            }
            let report = scan_path(&path, &suppressions);
            check(&label, &report, &expect, &mut failures);
            if !expect.known_gap {
                covered.extend(expect.must_find.iter().cloned());
            }
            snapshot(&format!("{kind}__{name}"), &report, &mut failures);
        }
    }

    let work = tempfile::tempdir().unwrap();
    for g in corpus_gen::all() {
        let target = (g.build)(work.path());
        let report = scan_path(&target, &suppressions);
        let expect = Expect {
            verdict: g.verdict.to_string(),
            must_find: g.must_find.iter().map(|s| s.to_string()).collect(),
            known_gap: false,
            error: None,
        };
        let label = format!("{}/{} (generated)", g.kind, g.name);
        check(&label, &report, &expect, &mut failures);
        covered.extend(expect.must_find.iter().cloned());
        if g.snapshot {
            snapshot(&format!("{}__{}", g.kind, g.name), &report, &mut failures);
        }
        count += 1;
    }

    let pack = skillsniff::rules::builtin();
    for rule in pack.rules.iter().map(|r| r.id.as_str()) {
        if !covered.contains(rule) {
            failures.push(format!("rule {rule} has no fixture"));
        }
    }

    assert!(
        failures.is_empty(),
        "{} problems:\n{}",
        failures.len(),
        failures.join("\n")
    );
    assert!(count >= 100, "only {count} fixtures");
}
