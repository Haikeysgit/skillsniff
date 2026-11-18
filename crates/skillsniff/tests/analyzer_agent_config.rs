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
            "agent_instructions",
            "suppression_file",
        ]
    );
}

fn md(body: &str) -> String {
    format!("{SKILL_MD}{body}\n")
}

#[test]
fn soft_documentation_lines_do_not_fire() {
    for line in [
        "Creates ~/.claude/settings.json on first run.",
        "See .claude/settings.json for options (add a key).",
        "edit `~/.claude/settings.json` and add the permissions block",
        "Update your .zshrc to add the alias.",
        "Add a cron entry to /etc/crontab",
        "Use `git config core.hooksPath` to see hooks",
    ] {
        expect_none_with_skill(&md(line));
    }
}

fn expect_none_with_skill(skill_md: &str) {
    let sigs = run_files(&[("SKILL.md", skill_md)]);
    assert!(sigs.is_empty(), "{skill_md:?} -> {sigs:?}");
}

#[test]
fn strong_prose_verb_fires_with_prose_context() {
    let sigs = run_files(&[(
        "SKILL.md",
        &md("This skill will overwrite ~/.claude/settings.json"),
    )]);
    let s = sigs.iter().find(|s| target(s) == "agent_settings").unwrap();
    assert_eq!(s.fields.get("context").unwrap(), "prose");
}

#[test]
fn script_hits_carry_code_context() {
    let sigs = run_files(&[("a.sh", "echo x >> ~/.bashrc\n")]);
    assert_eq!(sigs[0].fields.get("context").unwrap(), "code");
    let sigs = run_files(&[(".claude/settings.json", "{}")]);
    assert_eq!(sigs[0].fields.get("context").unwrap(), "code");
}

#[test]
fn git_config_read_is_not_a_write() {
    expect_none(&[(
        "a.sh",
        "dir=$(git config core.hooksPath)\ngit config --get core.hooksPath\n",
    )]);
    expect(
        &[("a.sh", "git config --unset core.hooksPath\n")],
        "git_hooks",
    );
}

#[test]
fn unrelated_command_near_a_path_does_not_fire() {
    expect_none(&[("a.sh", "cat ~/.bashrc\n# note\ncp a b\n")]);
    expect_none(&[("a.sh", "source ~/.bashrc\ncp x y\necho done\n")]);
    expect_none(&[(
        "a.py",
        "rc = os.path.expanduser('~/.bashrc')\nprint(open(rc).read())\nshutil.copy('a', 'b')\n",
    )]);
}

#[test]
fn variable_holding_a_path_is_tracked_to_its_write() {
    expect(
        &[("a.sh", "P=~/.bashrc\nls\necho x >> \"$P\"\n")],
        "shell_profile",
    );
    let sigs = run_files(&[("a.sh", "P=~/.bashrc\nls\necho x >> \"$P\"\n")]);
    assert_eq!(sigs[0].locations[0].line, 3);
    expect(
        &[(
            "a.ps1",
            "$p = \"$HOME/.zshrc\"\nAdd-Content -Path $p -Value x\n",
        )],
        "shell_profile",
    );
}

#[test]
fn copy_destination_must_be_the_guarded_path() {
    expect_none(&[("a.sh", "cp ~/.bashrc ./backup\n")]);
    expect(&[("a.sh", "cp ./mine ~/.bashrc\n")], "shell_profile");
}

#[test]
fn trailing_comment_does_not_hide_the_write() {
    expect(&[("a.sh", "cp a ~/.bashrc # backup\n")], "shell_profile");
    expect(
        &[("a.ps1", "Copy-Item a $PROFILE # keep\n")],
        "shell_profile",
    );
    expect_none(&[("a.sh", "cp ~/.bashrc b # backup\n")]);
}

#[test]
fn git_config_read_in_prose_is_not_a_write() {
    expect_none_with_skill(&md("Run git config core.hooksPath to see hooks"));
    let sigs = run_files(&[("SKILL.md", &md("Run git config core.hooksPath ./evil"))]);
    assert!(targets(&sigs).contains(&"git_hooks"), "{sigs:?}");
}

#[test]
fn one_line_with_a_hundred_thousand_hits_is_bounded() {
    let line = "~/.bashrc ".repeat(100_000);
    let start = std::time::Instant::now();
    let sigs = run_files(&[("a.sh", &format!("{line}\n"))]);
    assert!(start.elapsed().as_secs() < 5, "{:?}", start.elapsed());
    assert!(
        sigs.iter().any(|s| s.kind == "Hidden"
            && s.fields.get("pattern").map(String::as_str) == Some("parse_budget_exceeded")),
        "{sigs:?}"
    );
}

#[test]
fn many_hits_without_spaces_and_dense_lines_are_bounded() {
    let line = "~/.bashrc".repeat(200_000);
    let many = "echo a >> ~/.zshrc\n".repeat(50_000);
    let start = std::time::Instant::now();
    run_files(&[("a.sh", &format!("{line}\n{many}"))]);
    assert!(start.elapsed().as_secs() < 10, "{:?}", start.elapsed());
}

#[test]
fn files_past_the_deadline_are_reported() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("SKILL.md"), SKILL_MD).unwrap();
    fs::write(dir.path().join("a.sh"), "echo x >> ~/.bashrc\n").unwrap();
    let inv = build_inventory(dir.path()).unwrap();
    let skill = detect_skill(&inv, dir.path()).unwrap();
    let roles = skill.classify(&inv);
    let ctx = ScanContext {
        root: dir.path().to_path_buf(),
        inventory: inv,
        roles,
        skill,
    };
    let out = AgentConfigAnalyzer.run_with_deadline(&ctx, std::time::Duration::ZERO);
    assert_eq!(out.signals.len(), 2);
    assert!(out.signals.iter().all(|s| s.kind == "Hidden"));
}

#[test]
fn long_commands_are_still_linked_to_their_write_targets() {
    let long = "x".repeat(300);
    let spaces = " ".repeat(300);
    for (name, body) in [
        ("a.sh", format!("cp {long} ~/.bashrc\n")),
        ("a.sh", format!("cp {long} ~/.bashrc # x\n")),
        ("a.sh", format!("mv {long} ~/.zshrc\n")),
        ("a.sh", format!("cp \"{long}\" ~/.bashrc\n")),
        ("a.sh", format!("cp {}~/.bashrc\n", "a ".repeat(150))),
        ("a.sh", format!("cp {}a ~/.bashrc\n", "-f ".repeat(100))),
        ("a.sh", format!("cp{spaces}a ~/.bashrc\n")),
        ("a.ps1", format!("Copy-Item {long} $PROFILE\n")),
        ("a.sh", format!("sed -e '{long}' -i ~/.bashrc\n")),
        (
            "a.ps1",
            format!("Set-Content -Value '{long}' -Path ~/.bashrc\n"),
        ),
    ] {
        expect(&[(name, &body)], "shell_profile");
    }
    let long = "x".repeat(300);
    expect_none(&[("a.sh", &format!("cp ~/.bashrc {long}\n"))]);
    expect_none(&[("a.sh", &format!("cat {long} ~/.bashrc\n"))]);
}
