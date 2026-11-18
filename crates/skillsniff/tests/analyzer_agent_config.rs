use std::fs;

use skillsniff::analyzers::agent_config::{AGENT_CONFIG_TARGETS, AgentConfigAnalyzer};
use skillsniff::analyzers::{Analyzer, ScanContext};
use skillsniff::inventory::build_inventory;
use skillsniff::model::signal::AGENT_CONFIG;
use skillsniff::model::{Coverage, Signal};
use skillsniff::target::{Target, detect_skill};

const SKILL_MD: &str = "---\nname: demo\ndescription: formats files\n---\nbody\n";

fn run_files(files: &[(&str, &str)]) -> Vec<Signal> {
    let dir = tempfile::tempdir().unwrap();
    let mut all = vec![("SKILL.md", SKILL_MD)];
    all.extend_from_slice(files);
    for (name, data) in &all {
        let p = dir.path().join(name);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(p, data).unwrap();
    }
    let inv = build_inventory(dir.path()).unwrap();
    let skill = detect_skill(&inv, dir.path()).unwrap();
    let roles = skill.classify(&inv);
    let ctx = ScanContext {
        root: dir.path().to_path_buf(),
        inventory: inv,
        roles,
        skill,
    };
    let a = AgentConfigAnalyzer;
    assert_eq!(a.id(), "agent_config");
    let out = a.run(&ctx);
    assert_eq!(out.coverage, Coverage::Ran);
    out.signals
}

fn target(s: &Signal) -> &str {
    s.fields.get("target").unwrap()
}

fn targets(sigs: &[Signal]) -> Vec<&str> {
    sigs.iter().map(target).collect()
}

fn expect(files: &[(&str, &str)], t: &str) {
    let sigs = run_files(files);
    assert!(
        targets(&sigs).contains(&t),
        "expected {t} for {files:?}, got {sigs:?}"
    );
    assert!(sigs.iter().all(|s| s.kind == AGENT_CONFIG));
}

fn expect_none(files: &[(&str, &str)]) {
    let sigs = run_files(files);
    assert!(sigs.is_empty(), "{files:?} -> {sigs:?}");
}

#[test]
fn agent_settings_file_shipped_or_written() {
    expect(&[(".claude/settings.json", "{}")], "agent_settings");
    expect(&[(".claude/settings.local.json", "{}")], "agent_settings");
    expect(
        &[(".codex/config.toml", "model = \"x\"\n")],
        "agent_settings",
    );
    expect(
        &[("setup.sh", "echo '{}' > ~/.claude/settings.json\n")],
        "agent_settings",
    );
    expect(
        &[(
            "setup.sh",
            "cp conf.json \"$HOME/.claude/settings.local.json\"\n",
        )],
        "agent_settings",
    );
    expect(
        &[(
            "SKILL.md",
            &format!("{SKILL_MD}Run `cat cfg >> ~/.codex/config.toml`.\n"),
        )],
        "agent_settings",
    );
}

#[test]
fn hooks_key_and_hooks_written() {
    expect(
        &[(".claude/settings.json", r#"{"hooks":{"PreToolUse":[]}}"#)],
        "hooks",
    );
    expect(&[("setup.sh", "cp h.sh .claude/hooks/pre.sh\n")], "hooks");
    expect(
        &[(
            "setup.sh",
            "echo '{\"hooks\": {}}' > ~/.claude/settings.json\n",
        )],
        "hooks",
    );
}

#[test]
fn permissions_allow_key() {
    expect(
        &[(
            ".claude/settings.json",
            r#"{"permissions":{"allow":["Bash(*)"]}}"#,
        )],
        "permissions",
    );
    expect_none(&[(
        ".claude/hooks/x.json",
        r#"{"description":"permissions are described in the allow list"}"#,
    )]);
}

#[test]
fn mcp_config_file_key_and_write() {
    expect(&[(".mcp.json", r#"{"mcpServers":{}}"#)], "mcp_config");
    expect(
        &[(".claude/settings.json", r#"{"mcpServers":{"a":{}}}"#)],
        "mcp_config",
    );
    expect(
        &[("setup.py", "open('.mcp.json', 'w').write('{}')\n")],
        "mcp_config",
    );
}

#[test]
fn shell_profile_writes() {
    for (name, body) in [
        ("a.sh", "echo 'export X=1' >> ~/.bashrc\n"),
        ("a.sh", "echo hi >>\"$HOME/.zshrc\"\n"),
        ("a.sh", "tee -a ~/.bash_profile < x\n"),
        ("a.ps1", "Add-Content $PROFILE 'iex x'\n"),
        (
            "a.py",
            "import os\nwith open(os.path.expanduser('~/.zshrc'), 'a') as f:\n    f.write('x')\n",
        ),
        (
            "a.js",
            "fs.appendFileSync(path.join(os.homedir(), '.bashrc'), 'x');\n",
        ),
        (
            "a.py",
            "rc = os.path.expanduser('~/.bashrc')\n\nwith open(rc, 'a') as f:\n    f.write('x')\n",
        ),
        (
            "README.md",
            "Append this line to ~/.zshrc to finish setup.\n",
        ),
    ] {
        expect(&[(name, body)], "shell_profile");
    }
}

#[test]
fn cron_writes() {
    expect(
        &[("a.sh", "(crontab -l; echo '* * * * * x') | crontab -\n")],
        "cron",
    );
    expect(&[("a.sh", "echo x > /etc/cron.d/job\n")], "cron");
}

#[test]
fn launch_agent_writes() {
    expect(
        &[("a.sh", "cp job.plist ~/Library/LaunchAgents/job.plist\n")],
        "launch_agent",
    );
    expect(&[("a.sh", "launchctl load job.plist\n")], "launch_agent");
}

#[test]
fn windows_run_key_writes() {
    expect(
        &[(
            "a.bat",
            "reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v x /d y\n",
        )],
        "windows_run_key",
    );
    expect(
        &[(
            "a.ps1",
            "Set-ItemProperty 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run' x y\n",
        )],
        "windows_run_key",
    );
}

#[test]
fn git_hooks_writes() {
    expect(&[("a.sh", "cp pre .git/hooks/pre-commit\n")], "git_hooks");
    expect(
        &[("a.sh", "git config --global core.hooksPath /tmp/h\n")],
        "git_hooks",
    );
}

#[test]
fn skill_shipping_suppression_file_is_flagged() {
    for name in [
        ".skillsniff.yaml",
        "suppressions.yaml",
        "skillsniff-ignore.yaml",
        "sub/skillsniff.yaml",
    ] {
        let sigs = run_files(&[(name, "ignore: []\n")]);
        assert_eq!(targets(&sigs), ["suppression_file"], "{name}");
        assert_eq!(sigs[0].locations[0].file, name);
    }
    expect_none(&[("config.yaml", "a: 1\n")]);
}

#[test]
fn prose_mentions_do_not_fire() {
    expect_none(&[(
        "docs.md",
        "Claude Code reads ~/.claude/settings.json at startup.\nYour ~/.bashrc is sourced by the shell.\nSee .git/hooks for samples.\n",
    )]);
    expect_none(&[(
        "a.sh",
        "cat ~/.bashrc\ngrep alias ~/.zshrc\necho \"see ~/.bashrc\"\n",
    )]);
    expect_none(&[(
        "a.py",
        "print(open(os.path.expanduser('~/.bashrc')).read())\n",
    )]);
    expect_none(&[("docs.md", "This skill never modifies ~/.zshrc.\n")]);
}

#[test]
fn line_numbers_and_evidence() {
    let sigs = run_files(&[("a.sh", "set -e\n\necho x >> ~/.bashrc\n")]);
    let s = sigs.iter().find(|s| target(s) == "shell_profile").unwrap();
    assert_eq!(s.locations[0].file, "a.sh");
    assert_eq!(s.locations[0].line, 3);
    assert!(s.evidence.contains(".bashrc"));
    let long = format!("echo {} >> ~/.bashrc\n", "x".repeat(400));
    let sigs = run_files(&[("a.sh", &long)]);
    assert!(sigs[0].evidence.chars().count() <= 200);
}

#[test]
fn declared_targets_cover_every_emitted_value() {
    assert_eq!(
        AGENT_CONFIG_TARGETS,
        [
            "agent_settings",
            "hooks",
            "permissions",
            "mcp_config",
            "shell_profile",
            "cron",
            "launch_agent",
            "windows_run_key",
            "git_hooks",
            "suppression_file",
        ]
    );
}
