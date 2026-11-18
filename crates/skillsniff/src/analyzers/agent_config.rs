//! Changes to the agent's own configuration, the user's shell or scheduled
//! jobs, and files that silence this scanner.
//!
//! Two kinds of evidence are reported:
//! - the skill ships an agent settings file (or a settings file with `hooks`,
//!   `permissions.allow` or `mcpServers` keys);
//! - some text in the skill writes to one of the guarded paths. A path that is
//!   only mentioned, for example "Claude Code reads ~/.claude/settings.json",
//!   does not count: the line must hold a write (redirect, copy, move, tee,
//!   `Set-Content`, `open(.., "w")`, `writeFile`, or a verb such as "append").

use std::collections::BTreeMap;

use serde_json::Value;

use crate::analyzers::{
    Analyzer, AnalyzerOutput, ScanContext, is_invisible, read_lossy, safe_evidence,
    unreadable_signal,
};
use crate::inventory::ContentType;
use crate::model::signal::AGENT_CONFIG;
use crate::model::{Coverage, Location, Signal};
use crate::target::FileRole;

/// Every `target` value this analyzer can emit.
pub const AGENT_CONFIG_TARGETS: &[&str] = &[
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
];

/// Lines of script around a path that may hold the write.
const SCRIPT_WINDOW: usize = 4;
/// Deepest JSON nesting searched for settings keys.
const MAX_JSON_DEPTH: usize = 64;

/// Flags writes to agent settings, shell profiles and other persistence points.
pub struct AgentConfigAnalyzer;

struct Spec {
    target: &'static str,
    /// Lower-case, `/`-separated path fragments.
    paths: &'static [&'static str],
    /// Commands that change the target without naming a path.
    commands: &'static [&'static str],
}

const SPECS: &[Spec] = &[
    Spec {
        target: "agent_settings",
        paths: &[
            ".claude/settings",
            ".claude.json",
            ".codex/config.toml",
            ".gemini/settings.json",
        ],
        commands: &[],
    },
    Spec {
        target: "hooks",
        paths: &[".claude/hooks", ".codex/hooks"],
        commands: &[],
    },
    Spec {
        target: "mcp_config",
        paths: &[
            ".mcp.json",
            "claude_desktop_config.json",
            ".cursor/mcp.json",
            ".vscode/mcp.json",
        ],
        commands: &[],
    },
    Spec {
        target: "shell_profile",
        paths: &[
            ".bashrc",
            ".bash_profile",
            ".bash_login",
            ".bash_logout",
            ".zshrc",
            ".zprofile",
            ".zshenv",
            ".zlogin",
            ".profile",
            "config.fish",
            "powershell_profile.ps1",
            "profile.ps1",
            "$profile",
            "/etc/profile",
            "/etc/bash.bashrc",
            "/etc/zshrc",
            "/etc/environment",
        ],
        commands: &[],
    },
    Spec {
        target: "cron",
        paths: &[
            "/etc/cron",
            "/etc/crontab",
            "/var/spool/cron",
            "cron.d/",
            "cron.daily",
            "cron.hourly",
        ],
        commands: &[
            "| crontab",
            "crontab -e",
            "crontab /",
            "crontab ./",
            "crontab ~",
            "crontab $",
            "schtasks /create",
            "schtasks.exe /create",
        ],
    },
    Spec {
        target: "launch_agent",
        paths: &[
            "library/launchagents",
            "library/launchdaemons",
            "/launchagents/",
            "/launchdaemons/",
        ],
        commands: &["launchctl load", "launchctl bootstrap", "launchctl submit"],
    },
    Spec {
        target: "windows_run_key",
        paths: &[
            "currentversion/run",
            "currentversion/runonce",
            "programs/startup",
        ],
        commands: &[],
    },
    Spec {
        target: "git_hooks",
        paths: &[".git/hooks", "core.hookspath"],
        commands: &[],
    },
];

/// Commands and functions that write, matched as whole words.
const CODE_WORDS: &[&str] = &[
    "cp",
    "mv",
    "tee",
    "ln",
    "set-content",
    "out-file",
    "add-content",
    "new-item",
    "copy-item",
    "move-item",
    "rename-item",
    "xcopy",
    "robocopy",
    "writefile",
    "writefilesync",
    "appendfile",
    "appendfilesync",
    "write_text",
    "write_bytes",
    "copyfile",
    "copyfilesync",
    "set-itemproperty",
    "new-itemproperty",
];

/// Multi-word writes, matched from a word start.
const CODE_PHRASES: &[&str] = &[
    "sed -i",
    "reg add",
    "reg.exe add",
    "shutil.copy",
    "shutil.move",
    "git config",
    "curl -o",
    "wget -o",
];

/// Verbs in prose or comments that describe a write.
const PROSE_WORDS: &[&str] = &[
    "write",
    "writes",
    "writing",
    "append",
    "appends",
    "appending",
    "overwrite",
    "overwrites",
    "modify",
    "modifies",
    "edit",
    "edits",
    "patch",
    "patches",
    "inject",
    "injects",
    "insert",
    "inserts",
    "add",
    "adds",
    "create",
    "creates",
    "update",
    "updates",
];

const NEGATIONS: &[&str] = &["not", "never", "n't", "without", "cannot", "no"];

fn is_word_char(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

/// Start offsets of `needle` in `line`, with a word boundary before it and
/// after it when it ends in a word character.
fn find_all(line: &str, needle: &str) -> Vec<usize> {
    let ends_word = needle.chars().last().is_some_and(is_word_char);
    let mut out = Vec::new();
    let mut from = 0;
    while let Some(rel) = line[from..].find(needle) {
        let at = from + rel;
        let end = at + needle.len();
        let before_ok = line[..at]
            .chars()
            .next_back()
            .is_none_or(|c| !is_word_char(c));
        let after_ok = !ends_word || line[end..].chars().next().is_none_or(|c| !is_word_char(c));
        if before_ok && after_ok {
            out.push(at);
        }
        from = at + needle.chars().next().map_or(1, char::len_utf8);
    }
    out
}

fn has_word(line: &str, words: &[&str]) -> bool {
    words.iter().any(|w| !find_all(line, w).is_empty())
}

fn negated(line: &str, at: usize) -> bool {
    let before = line[..at].trim_end();
    NEGATIONS.iter().any(|n| {
        before.ends_with(n)
            && before[..before.len() - n.len()]
                .chars()
                .next_back()
                .is_none_or(|c| !c.is_alphanumeric() || *n == "n't")
    })
}

fn has_prose_verb(line: &str) -> bool {
    PROSE_WORDS
        .iter()
        .flat_map(|w| find_all(line, w))
        .any(|at| !negated(line, at))
}

/// `open(..., "w")`, `"a"`, `"x"` or `"r+"` style calls.
fn open_for_write(line: &str) -> bool {
    find_all(line, "open(").into_iter().any(|at| {
        let rest = &line[at + 5..];
        rest.match_indices(['"', '\'']).any(|(i, q)| {
            let before = rest[..i].trim_end();
            let mode = &rest[i + 1..];
            (before.ends_with(',') || before.ends_with("mode="))
                && (mode.starts_with(['w', 'a', 'x']) || mode.starts_with("r+"))
                && !mode.starts_with(q)
        })
    })
}

/// Whether the text just before `idx` is a `>` or `>>` redirect.
fn redirected(line: &str, idx: usize) -> bool {
    let b = line[..idx].trim_end_matches(|c: char| !c.is_whitespace() && !"(,>".contains(c));
    let b = b.trim_end();
    if !b.ends_with('>') || b.ends_with("->") || b.ends_with("=>") {
        return false;
    }
    !b.trim_end_matches('>').trim().is_empty()
}

/// A write that does not depend on where the path sits in the line.
fn code_write(line: &str) -> bool {
    has_word(line, CODE_WORDS)
        || CODE_PHRASES.iter().any(|p| !find_all(line, p).is_empty())
        || open_for_write(line)
}

fn normalize_line(line: &str) -> String {
    line.chars()
        .filter(|&c| !is_invisible(c))
        .flat_map(char::to_lowercase)
        .map(|c| if c == '\\' { '/' } else { c })
        .collect()
}

/// Settings keys present in a JSON document.
#[derive(Default)]
struct Keys {
    hooks: bool,
    permissions: bool,
    mcp: bool,
}

fn walk_json(v: &Value, k: &mut Keys, depth: usize) {
    if depth > MAX_JSON_DEPTH {
        return;
    }
    match v {
        Value::Object(map) => {
            for (key, val) in map {
                match key.as_str() {
                    "hooks" => k.hooks = true,
                    "mcpServers" => k.mcp = true,
                    "permissions"
                        if val.as_object().is_some_and(|o| {
                            o.contains_key("allow") || o.contains_key("defaultMode")
                        }) =>
                    {
                        k.permissions = true;
                    }
                    _ => {}
                }
                walk_json(val, k, depth + 1);
            }
        }
        Value::Array(items) => items.iter().for_each(|i| walk_json(i, k, depth + 1)),
        _ => {}
    }
}

/// `"key"` followed by a colon, for JSON that does not parse.
fn text_has_key(lower: &str, key: &str) -> bool {
    let quoted = format!("\"{key}\"");
    lower
        .match_indices(&quoted)
        .any(|(i, _)| lower[i + quoted.len()..].trim_start().starts_with(':'))
}

fn line_of(lower: &str, needle: &str) -> u32 {
    lower
        .split('\n')
        .position(|l| l.contains(needle))
        .map_or(1, |i| i as u32 + 1)
}

fn path_parts(path: &str) -> (Vec<String>, String) {
    let mut segs: Vec<String> = path.split('/').map(str::to_ascii_lowercase).collect();
    let name = segs.pop().unwrap_or_default();
    (segs, name)
}

fn parent_is(dirs: &[String], want: &str) -> bool {
    dirs.last().is_some_and(|d| d == want)
}

fn is_suppression_name(name: &str) -> bool {
    let stem = name.strip_prefix('.').unwrap_or(name);
    let yaml = name.ends_with(".yaml") || name.ends_with(".yml");
    yaml && (stem.starts_with("skillsniff")
        || stem == "suppressions.yaml"
        || stem == "suppressions.yml")
}

/// Per-file hits: (line, target) -> evidence.
type Hits = BTreeMap<(u32, &'static str), String>;

fn add(hits: &mut Hits, line: u32, target: &'static str, evidence: &str) {
    hits.entry((line, target))
        .or_insert_with(|| safe_evidence(evidence.trim()));
}

/// Settings files the skill ships, and the keys inside them.
fn scan_shipped(path: &str, role: FileRole, text: Option<&str>, hits: &mut Hits) {
    let (dirs, name) = path_parts(path);
    let agent_settings =
        (parent_is(&dirs, ".claude") && name.starts_with("settings") && name.ends_with(".json"))
            || (parent_is(&dirs, ".codex") && name == "config.toml")
            || (parent_is(&dirs, ".gemini") && name == "settings.json")
            || name == ".claude.json";
    let mcp_named = name == ".mcp.json"
        || name == "claude_desktop_config.json"
        || (name == "mcp.json" && (parent_is(&dirs, ".cursor") || parent_is(&dirs, ".vscode")));
    if agent_settings {
        add(hits, 1, "agent_settings", path);
    }
    if mcp_named {
        add(hits, 1, "mcp_config", path);
    }
    let is_toml = name.ends_with(".toml");
    if !(role == FileRole::Config || agent_settings || mcp_named) {
        return;
    }
    let Some(text) = text else { return };
    let lower = text.to_lowercase();
    if is_toml {
        for (needle, target) in [
            ("[hooks", "hooks"),
            ("mcp_servers", "mcp_config"),
            ("approval_policy", "permissions"),
            ("sandbox_mode", "permissions"),
            ("[permissions", "permissions"),
        ] {
            if lower.contains(needle) {
                add(hits, line_of(&lower, needle), target, needle);
            }
        }
        return;
    }
    let mut keys = Keys::default();
    match serde_json::from_str::<Value>(text.trim_start_matches('\u{feff}')) {
        Ok(v) => walk_json(&v, &mut keys, 0),
        Err(_) => {
            keys.hooks = text_has_key(&lower, "hooks");
            keys.mcp = text_has_key(&lower, "mcpservers");
            keys.permissions = text_has_key(&lower, "permissions") && text_has_key(&lower, "allow");
        }
    }
    for (found, key, target) in [
        (keys.hooks, "\"hooks\"", "hooks"),
        (keys.mcp, "\"mcpservers\"", "mcp_config"),
        (keys.permissions, "\"permissions\"", "permissions"),
    ] {
        if found {
            add(hits, line_of(&lower, key), target, key);
        }
    }
}

/// Writes to guarded paths in any text.
fn scan_writes(text: &str, is_script: bool, hits: &mut Hits) {
    let raw: Vec<&str> = text.split('\n').collect();
    let lines: Vec<String> = text
        .split('\n')
        .map(|l| normalize_line(l.strip_suffix('\r').unwrap_or(l)))
        .collect();
    for (i, line) in lines.iter().enumerate() {
        let n = i as u32 + 1;
        let shown = raw[i];
        let same_line_write = || code_write(line) || line.contains(">>") || has_prose_verb(line);
        let window_write = || {
            let lo = i.saturating_sub(SCRIPT_WINDOW);
            let hi = (i + SCRIPT_WINDOW + 1).min(lines.len());
            lines[lo..hi]
                .iter()
                .any(|l| code_write(l) || l.contains(">>"))
        };
        for spec in SPECS {
            if spec.commands.iter().any(|c| !find_all(line, c).is_empty()) {
                add(hits, n, spec.target, shown);
            }
            let at: Vec<usize> = spec.paths.iter().flat_map(|p| find_all(line, p)).collect();
            if at.is_empty() {
                continue;
            }
            let writes = at.iter().any(|&a| redirected(line, a))
                || same_line_write()
                || (is_script && window_write());
            if !writes {
                continue;
            }
            add(hits, n, spec.target, shown);
            if spec.target == "agent_settings" {
                for (needle, target) in [
                    ("hooks", "hooks"),
                    ("permissions", "permissions"),
                    ("mcpservers", "mcp_config"),
                ] {
                    if line.contains(&format!("\"{needle}\"")) {
                        add(hits, n, target, shown);
                    }
                }
            }
        }
    }
}

fn signal(target: &str, file: &str, line: u32, evidence: String) -> Signal {
    Signal {
        kind: AGENT_CONFIG.to_string(),
        fields: BTreeMap::from([("target".to_string(), target.to_string())]),
        locations: vec![Location {
            file: file.to_string(),
            line,
        }],
        evidence,
    }
}

impl Analyzer for AgentConfigAnalyzer {
    fn id(&self) -> &'static str {
        "agent_config"
    }

    fn run(&self, ctx: &ScanContext) -> AnalyzerOutput {
        let mut signals = Vec::new();
        for f in &ctx.inventory.files {
            let mut hits = Hits::new();
            let name = f.path.rsplit('/').next().unwrap_or(&f.path);
            if is_suppression_name(&name.to_ascii_lowercase()) {
                add(&mut hits, 1, "suppression_file", &f.path);
            }
            if f.content_type == ContentType::Text {
                let role = ctx.roles.get(&f.path).copied().unwrap_or(FileRole::Asset);
                match read_lossy(ctx, &f.path) {
                    Some(text) => {
                        scan_shipped(&f.path, role, Some(&text), &mut hits);
                        scan_writes(&text, matches!(role, FileRole::Script(_)), &mut hits);
                    }
                    None => {
                        scan_shipped(&f.path, role, None, &mut hits);
                        signals.push(unreadable_signal(&f.path));
                    }
                }
            }
            for ((line, target), evidence) in hits {
                signals.push(signal(target, &f.path, line, evidence));
            }
        }
        AnalyzerOutput {
            signals,
            coverage: Coverage::Ran,
        }
    }
}
