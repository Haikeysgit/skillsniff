use std::fs;
use std::path::{Path, PathBuf};

use skillsniff::export::{ExportError, export};
use skillsniff::inventory::build_inventory;
use skillsniff::model::Verdict;
use skillsniff::progress::NoopProgress;
use skillsniff::scan::{ScanOptions, ScanOutcome, scan};

const SKILL_MD: &str = "---\nname: runner\ndescription: Lists a folder. Use when asked to list files.\n---\nList files.\n";

fn base() -> ScanOptions {
    static EMPTY: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();
    let path = EMPTY.get_or_init(|| {
        let p = Path::new(env!("CARGO_TARGET_TMPDIR")).join("empty-suppressions-export.yaml");
        fs::write(&p, "suppressions: []\n").unwrap();
        p
    });
    ScanOptions {
        suppressions: Some(path.clone()),
        ..ScanOptions::default()
    }
}

fn scan_dir(dir: &Path) -> ScanOutcome {
    scan(dir.to_str().unwrap(), &base(), &NoopProgress).unwrap()
}

fn plain_skill() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("SKILL.md"), SKILL_MD).unwrap();
    fs::create_dir(dir.path().join("docs")).unwrap();
    fs::write(dir.path().join("docs/notes.txt"), "plain notes\n").unwrap();
    dir
}

fn medium_skill() -> tempfile::TempDir {
    let dir = plain_skill();
    fs::create_dir(dir.path().join("scripts")).unwrap();
    fs::write(
        dir.path().join("scripts/run.py"),
        "import subprocess\n\nsubprocess.run([\"ls\", \"-l\"])\n",
    )
    .unwrap();
    dir
}

#[test]
fn pass_exports_identical_tree() {
    let src = plain_skill();
    let outcome = scan_dir(src.path());
    assert_eq!(outcome.report.verdict, Verdict::Pass);
    let out = tempfile::tempdir().unwrap();
    let dest = out.path().join("copy");
    export(&outcome, &dest, false).unwrap();
    let inv = build_inventory(&dest).unwrap();
    assert_eq!(inv.tree_sha256, outcome.report.target.tree_sha256);
    assert!(dest.join("docs/notes.txt").is_file());
}

#[test]
fn block_refuses() {
    let src = plain_skill();
    let mut outcome = scan_dir(src.path());
    outcome.report.verdict = Verdict::Block;
    let out = tempfile::tempdir().unwrap();
    let dest = out.path().join("copy");
    assert!(matches!(
        export(&outcome, &dest, true),
        Err(ExportError::Blocked)
    ));
    assert!(!dest.exists());
}

#[test]
fn caution_refuses_without_flag_and_exports_with_it() {
    let src = medium_skill();
    let outcome = scan_dir(src.path());
    assert_eq!(outcome.report.verdict, Verdict::Caution);
    let out = tempfile::tempdir().unwrap();
    let dest = out.path().join("copy");
    assert!(matches!(
        export(&outcome, &dest, false),
        Err(ExportError::CautionNotAllowed)
    ));
    assert!(!dest.exists());
    export(&outcome, &dest, true).unwrap();
    assert!(dest.join("scripts/run.py").is_file());
}

#[test]
fn existing_destination_refuses() {
    let src = plain_skill();
    let outcome = scan_dir(src.path());
    let out = tempfile::tempdir().unwrap();
    assert!(matches!(
        export(&outcome, out.path(), false),
        Err(ExportError::DestinationExists)
    ));
}

#[test]
fn changed_tree_reports_mismatch_and_removes_destination() {
    let src = plain_skill();
    let outcome = scan_dir(src.path());
    // The quarantine copy changes after the scan.
    let root = outcome.quarantine.as_ref().unwrap().root().to_path_buf();
    fs::write(root.join("docs/notes.txt"), "changed\n").unwrap();
    let out = tempfile::tempdir().unwrap();
    let dest = out.path().join("copy");
    assert!(matches!(
        export(&outcome, &dest, false),
        Err(ExportError::HashMismatch)
    ));
    assert!(!dest.exists());
}
