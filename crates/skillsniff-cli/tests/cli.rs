use std::fs;
use std::path::{Path, PathBuf};

use assert_cmd::Command;
use skillsniff::model::{Report, Verdict};

fn fixture(rel: &str) -> String {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures")
        .join(rel)
        .to_str()
        .unwrap()
        .to_string()
}

fn empty_suppressions() -> PathBuf {
    let p = Path::new(env!("CARGO_TARGET_TMPDIR")).join("cli-empty-suppressions.yaml");
    fs::write(&p, "suppressions: []\n").unwrap();
    p
}

fn skillsniff() -> Command {
    let mut cmd = Command::cargo_bin("skillsniff").unwrap();
    cmd.env_remove("SKILLSNIFF_TEST_PANIC").env("NO_COLOR", "1");
    cmd
}

fn scan(rel: &str, extra: &[&str]) -> std::process::Output {
    skillsniff()
        .arg("scan")
        .arg(fixture(rel))
        .arg("--suppressions")
        .arg(empty_suppressions())
        .args(extra)
        .output()
        .unwrap()
}

fn code(out: &std::process::Output) -> i32 {
    out.status.code().expect("exited normally")
}

#[test]
fn pass_fixture_exits_0() {
    let out = scan("clean/minimal-skill", &[]);
    assert_eq!(code(&out), 0, "{}", String::from_utf8_lossy(&out.stderr));
    assert!(String::from_utf8_lossy(&out.stdout).contains("PASS"));
}

#[test]
fn caution_fixture_exits_1() {
    let out = scan("caution/broad-trigger", &[]);
    assert_eq!(code(&out), 1, "{}", String::from_utf8_lossy(&out.stdout));
}

#[test]
fn block_fixture_exits_2() {
    let out = scan("malicious/exfil-aws", &[]);
    assert_eq!(code(&out), 2);
    assert!(String::from_utf8_lossy(&out.stdout).contains("BLOCK"));
}

#[test]
fn unknown_flag_exits_3() {
    let out = skillsniff().args(["scan", "--bogus"]).output().unwrap();
    assert_eq!(code(&out), 3);
    assert!(out.stdout.is_empty());
}

#[test]
fn missing_skill_exits_3() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("README.md"), "nothing here\n").unwrap();
    let out = skillsniff()
        .arg("scan")
        .arg(dir.path())
        .arg("--suppressions")
        .arg(empty_suppressions())
        .output()
        .unwrap();
    assert_eq!(code(&out), 3);
    assert!(String::from_utf8_lossy(&out.stderr).contains("no skill found"));
}

#[test]
fn offline_remote_exits_4() {
    let out = skillsniff()
        .args(["scan", "github.com/x/y", "--offline", "--json"])
        .output()
        .unwrap();
    assert_eq!(code(&out), 4);
    assert!(out.stdout.is_empty());
}

#[cfg(debug_assertions)]
#[test]
fn panic_exits_5_quietly() {
    let out = skillsniff()
        .env("SKILLSNIFF_TEST_PANIC", "1")
        .args(["scan", "x", "--json"])
        .output()
        .unwrap();
    assert_eq!(code(&out), 5);
    assert!(out.stdout.is_empty());
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(
        err.trim(),
        concat!(
            "internal error (skillsniff ",
            env!("CARGO_PKG_VERSION"),
            ")"
        )
    );
}

#[test]
fn help_and_version_exit_0() {
    assert_eq!(code(&skillsniff().arg("--help").output().unwrap()), 0);
    assert_eq!(code(&skillsniff().arg("--version").output().unwrap()), 0);
    assert_eq!(
        code(&skillsniff().args(["scan", "--help"]).output().unwrap()),
        0
    );
}

#[test]
fn fail_on_block_maps_caution_to_zero() {
    let out = scan("caution/broad-trigger", &["--fail-on", "block"]);
    assert_eq!(code(&out), 0);
    let out = scan("malicious/exfil-aws", &["--fail-on", "block"]);
    assert_eq!(code(&out), 1);
    let out = scan("caution/broad-trigger", &["--fail-on", "caution"]);
    assert_eq!(code(&out), 1);
    let out = scan("clean/minimal-skill", &["--fail-on", "caution"]);
    assert_eq!(code(&out), 0);
}

#[test]
fn json_output_is_only_the_report() {
    let out = scan("malicious/exfil-aws", &["--json"]);
    assert_eq!(code(&out), 2);
    let report: Report = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(report.verdict, Verdict::Block);
    assert!(!out.stdout.contains(&0x1b));
}

#[test]
fn no_args_shows_welcome() {
    let out = skillsniff().output().unwrap();
    assert_eq!(code(&out), 0);
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("skillsniff"));
    for example in [
        "skillsniff scan github.com/owner/repo",
        "skillsniff scan ./my-skill",
        "skillsniff scan skill.zip --json",
    ] {
        assert!(text.contains(example), "missing {example}");
    }
}

#[test]
fn export_refused_on_block_exits_2() {
    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join("out");
    let out = scan("malicious/exfil-aws", &["--export", dest.to_str().unwrap()]);
    assert_eq!(code(&out), 2);
    assert!(!dest.exists());
    assert!(String::from_utf8_lossy(&out.stderr).contains("export refused"));
}

#[test]
fn export_on_pass_copies_the_tree() {
    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join("out");
    let out = scan("clean/minimal-skill", &["--export", dest.to_str().unwrap()]);
    assert_eq!(code(&out), 0, "{}", String::from_utf8_lossy(&out.stderr));
    assert!(dest.join("SKILL.md").is_file());
}

#[test]
fn review_apply_cli_round_trip() {
    let dir = tempfile::tempdir().unwrap();
    let report_path = dir.path().join("report.json");
    let out = scan("clean/minimal-skill", &["--json"]);
    assert_eq!(code(&out), 0);
    fs::write(&report_path, &out.stdout).unwrap();

    let review_path = dir.path().join("review.json");
    fs::write(
        &review_path,
        r#"{"schema_version":"1","additions":[{"rule":"review.hidden-upload","severity":"critical","title":"Uploads notes","locations":[{"file":"SKILL.md","line":3}],"evidence":"upload","reason":"sends data out"}],"raises":[]}"#,
    )
    .unwrap();
    let out = skillsniff()
        .args(["review", "apply"])
        .arg(&report_path)
        .arg(&review_path)
        .arg("--json")
        .output()
        .unwrap();
    assert_eq!(code(&out), 2, "{}", String::from_utf8_lossy(&out.stderr));
    let merged: Report = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(merged.verdict, Verdict::Block);
    assert!(merged.review.applied);

    let bad = dir.path().join("bad.json");
    fs::write(&bad, "{not json").unwrap();
    let before = fs::read(&report_path).unwrap();
    let out = skillsniff()
        .args(["review", "apply"])
        .arg(&report_path)
        .arg(&bad)
        .output()
        .unwrap();
    assert_eq!(code(&out), 3);
    assert!(out.stdout.is_empty());
    assert_eq!(fs::read(&report_path).unwrap(), before);
}

fn adapter_scan(name: &str) -> std::process::Output {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../skills")
        .join(name);
    skillsniff()
        .arg("scan")
        .arg(dir)
        .args(["--json", "--offline", "--suppressions"])
        .arg(empty_suppressions())
        .output()
        .unwrap()
}

#[test]
fn shipped_skill_scans_pass() {
    let out = adapter_scan("skillsniff");
    assert_eq!(
        code(&out),
        0,
        "skill must scan PASS: {}",
        String::from_utf8_lossy(&out.stdout)
    );
    let report: Report = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(report.verdict, Verdict::Pass);
    assert!(report.findings.is_empty(), "{:?}", report.findings);
}

fn install_skill_cmd(home: &Path) -> Command {
    let mut cmd = Command::cargo_bin("skillsniff").unwrap();
    cmd.env("HOME", home).env("USERPROFILE", home);
    cmd
}

#[test]
fn install_skill_writes_the_shipped_adapters() {
    let home = tempfile::tempdir().unwrap();
    install_skill_cmd(home.path())
        .args(["install-skill", "all"])
        .assert()
        .code(0);
    let claude = home.path().join(".claude/skills/skillsniff/SKILL.md");
    let codex = home.path().join(".agents/skills/skillsniff/SKILL.md");
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    assert_eq!(
        fs::read_to_string(&claude).unwrap(),
        fs::read_to_string(root.join("skills/skillsniff/SKILL.md")).unwrap()
    );
    assert_eq!(
        fs::read_to_string(&codex).unwrap(),
        fs::read_to_string(root.join("skills/skillsniff/SKILL.md")).unwrap()
    );
    // Running again is a no-op.
    let out = install_skill_cmd(home.path())
        .args(["install-skill", "all"])
        .assert()
        .code(0);
    assert!(String::from_utf8_lossy(&out.get_output().stdout).contains("already up to date"));
}

#[test]
fn install_skill_detects_agents_and_needs_one() {
    let home = tempfile::tempdir().unwrap();
    install_skill_cmd(home.path())
        .arg("install-skill")
        .assert()
        .code(3);
    fs::create_dir_all(home.path().join(".claude")).unwrap();
    install_skill_cmd(home.path())
        .arg("install-skill")
        .assert()
        .code(0);
    assert!(
        home.path()
            .join(".claude/skills/skillsniff/SKILL.md")
            .is_file()
    );
    assert!(!home.path().join(".agents").exists());
}

#[test]
fn install_skill_keeps_a_foreign_skill_unless_forced() {
    let home = tempfile::tempdir().unwrap();
    let dir = home.path().join(".claude/skills/skillsniff");
    fs::create_dir_all(&dir).unwrap();
    fs::write(
        dir.join("SKILL.md"),
        "---\nname: skillsniff\n---\nsomething else\n",
    )
    .unwrap();
    install_skill_cmd(home.path())
        .args(["install-skill", "claude-code"])
        .assert()
        .code(3);
    assert!(
        fs::read_to_string(dir.join("SKILL.md"))
            .unwrap()
            .contains("something else")
    );
    install_skill_cmd(home.path())
        .args(["install-skill", "claude-code", "--force"])
        .assert()
        .code(0);
    assert!(
        fs::read_to_string(dir.join("SKILL.md"))
            .unwrap()
            .contains("skillsniff scan")
    );
}

#[test]
fn install_skill_keeps_a_newer_skill_and_replaces_an_older_one() {
    let home = tempfile::tempdir().unwrap();
    let dir = home.path().join(".claude/skills/skillsniff");
    fs::create_dir_all(&dir).unwrap();
    let newer = "---
name: skillsniff
---

<!-- skillsniff-skill-version: 9999 -->

Run skillsniff scan first.
";
    fs::write(dir.join("SKILL.md"), newer).unwrap();
    install_skill_cmd(home.path())
        .args(["install-skill", "claude-code"])
        .assert()
        .code(0);
    assert_eq!(fs::read_to_string(dir.join("SKILL.md")).unwrap(), newer);

    let older = "---
name: skillsniff
---

Run skillsniff scan first.
";
    fs::write(dir.join("SKILL.md"), older).unwrap();
    install_skill_cmd(home.path())
        .args(["install-skill", "claude-code"])
        .assert()
        .code(0);
    assert!(
        fs::read_to_string(dir.join("SKILL.md"))
            .unwrap()
            .contains("skillsniff-skill-version:")
    );
}
