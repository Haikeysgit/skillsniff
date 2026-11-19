//! Entry points shared by the fuzz targets and their smoke tests.
//!
//! Each function takes arbitrary bytes and must return without panicking.
//! They exist so the logic lives in one place that compiles on every
//! platform, while the `fuzz/` crate only forwards its input here.

use std::collections::BTreeMap;
use std::fs;
use std::time::Duration;

use crate::acquire::{Limits, acquire_archive};
use crate::analyzers::ScanContext;
use crate::analyzers::code::CodeAnalyzer;
use crate::frontmatter::parse_frontmatter;
use crate::inventory::build_inventory;
use crate::model::{Coverage, Report, ReviewInfo, Summary, TargetInfo, ToolInfo, Verdict};
use crate::review::apply_review;
use crate::target::{Target, detect_skill};

/// Feeds `data` to the archive reader. The first byte picks the container
/// type; the rest is the archive.
pub fn fuzz_archive(data: &[u8]) {
    let Some((&kind, rest)) = data.split_first() else {
        return;
    };
    let name = match kind % 3 {
        0 => "input.zip",
        1 => "input.tar.gz",
        _ => "input.tgz",
    };
    let Ok(dir) = tempfile::tempdir() else {
        return;
    };
    let path = dir.path().join(name);
    if fs::write(&path, rest).is_err() {
        return;
    }
    let limits = Limits {
        max_total_bytes: 4 * 1024 * 1024,
        max_files: 200,
        max_file_bytes: 1024 * 1024,
        ..Limits::default()
    };
    let _ = acquire_archive(&path, &limits);
}

/// Feeds `data` to the front matter parser.
pub fn fuzz_frontmatter(data: &[u8]) {
    let text = String::from_utf8_lossy(data);
    let _ = parse_frontmatter(&text);
}

/// Analyzes `data` as a single script. The first byte picks the language.
pub fn fuzz_code_parse(data: &[u8]) {
    let Some((&kind, rest)) = data.split_first() else {
        return;
    };
    let ext = match kind % 5 {
        0 => "py",
        1 => "js",
        2 => "ts",
        3 => "sh",
        _ => "ps1",
    };
    let Ok(dir) = tempfile::tempdir() else {
        return;
    };
    let wrote = fs::write(
        dir.path().join("SKILL.md"),
        "---\nname: demo\ndescription: a demo\n---\nbody\n",
    )
    .and_then(|()| fs::write(dir.path().join(format!("script.{ext}")), rest));
    if wrote.is_err() {
        return;
    }
    let Ok(inventory) = build_inventory(dir.path()) else {
        return;
    };
    let Ok(skill) = detect_skill(&inventory, dir.path()) else {
        return;
    };
    let roles = skill.classify(&inventory);
    let ctx = ScanContext {
        root: dir.path().to_path_buf(),
        inventory,
        roles,
        skill,
    };
    let _ = CodeAnalyzer.run_with_deadline(&ctx, Duration::from_secs(5));
}

fn base_report() -> Report {
    let coverage: BTreeMap<String, Coverage> = ["instructions", "code", "hidden", "agent_config"]
        .iter()
        .map(|n| ((*n).to_string(), Coverage::Ran))
        .collect();
    Report {
        schema_version: "1".into(),
        tool: ToolInfo {
            name: "skillsniff".into(),
            version: "0".into(),
            rules: "fuzz".into(),
        },
        target: TargetInfo {
            source: "fuzz".into(),
            kind: "skill".into(),
            commit: None,
            tree_sha256: "00".into(),
        },
        verdict: Verdict::Pass,
        summary: Summary::default(),
        findings: Vec::new(),
        coverage,
        review: ReviewInfo {
            applied: false,
            rejected_changes: Vec::new(),
        },
    }
}

/// Feeds `data` to the review merger as a review document.
pub fn fuzz_review(data: &[u8]) {
    let text = String::from_utf8_lossy(data);
    let _ = apply_review(base_report(), &text);
}
