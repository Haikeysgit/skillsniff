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

use std::collections::{BTreeMap, BTreeSet};
use std::time::{Duration, Instant};

use serde_json::Value;

use crate::analyzers::{
    Analyzer, AnalyzerOutput, ScanContext, budget_signal, is_invisible, partial_signal, read_lossy,
    safe_evidence, unreadable_signal,
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
    "agent_instructions",
    "suppression_file",
];

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
        target: "agent_instructions",
        paths: &[
            "claude.md",
            "claude.local.md",
            "agents.md",
            ".claude/commands",
            ".claude/agents",
            ".claude/skills",
            ".codex/",
        ],
        commands: &[],
    },
    Spec {
        target: "git_hooks",
        paths: &[".git/hooks", "core.hookspath"],
        commands: &[],
    },
];

/// Lines after an assignment in which the variable may be used as a write
/// target (`P=~/.bashrc; echo x >> "$P"`).
const VAR_WINDOW: usize = 12;

/// Commands whose last argument is the destination.
const LAST_ARG_CMDS: &[&str] = &[
    "cp",
    "mv",
    "install",
    "ln",
    "copy-item",
    "move-item",
    "copy",
    "move",
    "xcopy",
    "robocopy",
    "rsync",
];

/// Commands that write to the first non-flag argument or to `-Path`.
const FIRST_ARG_CMDS: &[&str] = &[
    "set-content",
    "add-content",
    "out-file",
    "new-item",
    "set-itemproperty",
    "new-itemproperty",
    "rename-item",
];

/// Commands that take an output file after `-o` style flags.
const OUTPUT_FLAG_CMDS: &[&str] = &["curl", "wget", "invoke-webrequest", "iwr"];

const PATH_FLAGS: &[&str] = &[
    "-path",
    "-filepath",
    "-literalpath",
    "-destination",
    "-o",
    "-outfile",
    "--output",
];

/// Calls that write to the path named before or after them on the line.
const CALL_WORDS: &[&str] = &[
    "writefile",
    "writefilesync",
    "appendfile",
    "appendfilesync",
    "copyfile",
    "copyfilesync",
    "shutil.copy",
    "shutil.copyfile",
    "shutil.move",
    "os.rename",
    "os.replace",
];

/// Methods called on a path object, so the path comes first.
const METHOD_WORDS: &[&str] = &["write_text", "write_bytes"];

/// Words that hand the next command over (`then cp ...`, `sudo cp ...`).
const WRAPPERS: &[&str] = &[
    "sudo", "doas", "command", "env", "exec", "nohup", "time", "then", "do", "else", "if",
];

/// Prose verbs that clearly describe a write. Softer verbs (add, create,
/// update, edit, insert) are left out: they describe reading docs as often
/// as writing.
const STRONG_PROSE: &[&str] = &[
    "write",
    "writes",
    "append",
    "appends",
    "appending",
    "overwrite",
    "overwrites",
    "inject",
    "injects",
    "modify",
    "modifies",
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

fn has_strong_prose_verb(line: &str) -> bool {
    STRONG_PROSE
        .iter()
        .flat_map(|w| find_all(line, w))
        .any(|at| !negated(line, at))
}

/// Wall-clock budget for the whole analyzer, below the runner timeout.
pub const ANALYZER_DEADLINE: Duration = Duration::from_secs(20);
/// Guarded-path matches examined per line; the rest are reported as unchecked.
const MAX_HITS_PER_LINE: usize = 1000;
/// Bytes looked at on either side of a path when reading its command.
const LOCAL_WINDOW: usize = 256;

/// Whether the text after an `open(` call opens a file for writing. Only the
/// next few hundred characters are read; a mode argument sits right there.
fn open_mode_writes(rest: &str) -> bool {
    let cut = rest
        .char_indices()
        .nth(LOCAL_WINDOW)
        .map_or(rest.len(), |(i, _)| i);
    let rest = &rest[..cut];
    rest.match_indices(['"', '\'']).any(|(i, q)| {
        let before = rest[..i].trim_end();
        let mode = &rest[i + 1..];
        (before.ends_with(',') || before.ends_with("mode="))
            && (mode.starts_with(['w', 'a', 'x']) || mode.starts_with("r+"))
            && !mode.starts_with(q)
    })
}

/// Facts about one line, computed once so every hit on it is a lookup.
struct LineIdx {
    /// Offsets of `| ; & ` (` that start a new command.
    seps: Vec<usize>,
    /// Offsets that end a command's arguments: separators, redirects, `)`
    /// and an unquoted `#` comment.
    terms: Vec<usize>,
    /// Offsets of `=`.
    eqs: Vec<usize>,
    /// First write-call word (writeFile, shutil.copy, ...).
    first_call: Option<usize>,
    /// A `write_text`/`write_bytes` method call is on the line.
    has_method: bool,
    /// First `open(` call with a write mode.
    open_write: Option<usize>,
    /// Whitespace-separated tokens as byte spans.
    tokens: Vec<(usize, usize)>,
    /// For each token index (plus one past the end), the first token at or
    /// after it that does not start with `-`.
    next_non_flag: Vec<usize>,
    /// Same, for a token that is neither a flag nor all digits.
    next_non_flag_digit: Vec<usize>,
    /// Same, for a token starting with `-i`.
    next_dash_i: Vec<usize>,
}

/// `next[i]` is the first index at or after `i` where `hit` holds, or the
/// token count.
fn suffix_next(n: usize, hit: impl Fn(usize) -> bool) -> Vec<usize> {
    let mut next = vec![n; n + 2];
    for i in (0..n).rev() {
        next[i] = if hit(i) { i } else { next[i + 1] };
    }
    next
}

fn comment_start(line: &str) -> Option<usize> {
    let mut quote: Option<char> = None;
    let mut prev_space = true;
    for (i, c) in line.char_indices() {
        match (quote, c) {
            (None, '\'' | '"') => quote = Some(c),
            (Some(q), _) if q == c => quote = None,
            (None, '#') if prev_space => return Some(i),
            _ => {}
        }
        prev_space = c.is_whitespace();
    }
    None
}

fn index_line(line: &str) -> LineIdx {
    let mut seps = Vec::new();
    let mut terms = Vec::new();
    let mut eqs = Vec::new();
    for (i, c) in line.char_indices() {
        if "|;&`(".contains(c) {
            seps.push(i);
        }
        if "|;&<>`)".contains(c) {
            terms.push(i);
        }
        if c == '=' {
            eqs.push(i);
        }
    }
    if let Some(c) = comment_start(line) {
        terms.push(c);
        terms.sort_unstable();
    }
    let first_call = CALL_WORDS
        .iter()
        .filter_map(|w| find_all(line, w).first().copied())
        .min();
    let open_write = find_all(line, "open(")
        .into_iter()
        .find(|&o| open_mode_writes(&line[o + 5..]));
    let tokens: Vec<(usize, usize)> = line
        .split_whitespace()
        .map(|t| {
            let s = t.as_ptr() as usize - line.as_ptr() as usize;
            (s, s + t.len())
        })
        .collect();
    let n = tokens.len();
    let tok = |i: usize| &line[tokens[i].0..tokens[i].1];
    let next_non_flag = suffix_next(n, |i| !tok(i).starts_with('-'));
    let next_non_flag_digit = suffix_next(n, |i| {
        !tok(i).starts_with('-') && !tok(i).chars().all(|c| c.is_ascii_digit())
    });
    let next_dash_i = suffix_next(n, |i| tok(i).starts_with("-i"));
    LineIdx {
        seps,
        terms,
        eqs,
        first_call,
        has_method: METHOD_WORDS.iter().any(|w| !find_all(line, w).is_empty()),
        open_write,
        next_non_flag,
        next_non_flag_digit,
        next_dash_i,
        tokens,
    }
}

/// `line[..idx]` limited to the last [`LOCAL_WINDOW`] bytes, and whether it
/// was cut.
fn window_before(line: &str, idx: usize) -> (&str, bool) {
    let mut start = idx.saturating_sub(LOCAL_WINDOW);
    while !line.is_char_boundary(start) {
        start += 1;
    }
    (&line[start..idx], start > 0)
}

/// Whether the text just before `idx` is a `>` or `>>` redirect.
fn redirected(line: &str, idx: usize) -> bool {
    let (w, cut) = window_before(line, idx);
    let b = w.trim_end_matches(|c: char| !c.is_whitespace() && !"(,>".contains(c));
    let b = b.trim_end();
    if !b.ends_with('>') || b.ends_with("->") || b.ends_with("=>") {
        return false;
    }
    cut || !b.trim_end_matches('>').trim().is_empty()
}

fn clean_token(t: &str) -> &str {
    t.trim_matches(|c| matches!(c, '"' | '\'' | '`' | '(' | ')'))
}

/// Whether the path at `at` is the target or destination of a write in the
/// same command: a redirect, the last argument of a copy, a `tee` argument,
/// the path argument of `Set-Content` and friends, or a path passed to an
/// open-for-write or write-file call. Constant work per call: the command
/// and its argument boundaries come from the per-line token tables, so the
/// distance between command and path does not matter.
fn is_write_target(line: &str, ix: &LineIdx, at: usize) -> bool {
    if redirected(line, at)
        || ix.open_write.is_some_and(|o| o < at)
        || ix.has_method
        || ix.first_call.is_some_and(|c| c < at)
    {
        return true;
    }
    let toks = &ix.tokens;
    let Some(ti) = toks.partition_point(|&(s, _)| s <= at).checked_sub(1) else {
        return false;
    };
    let seg_start = match ix.seps.partition_point(|&p| p < at) {
        0 => 0,
        k => ix.seps[k - 1] + 1,
    };
    // First word of the command: the first token ending after the segment
    // start, skipping a few wrappers such as `sudo`.
    let mut t0 = toks.partition_point(|&(_, e)| e <= seg_start);
    for _ in 0..8 {
        let Some(&(s, e)) = toks.get(t0) else { break };
        if t0 < ti && WRAPPERS.contains(&clean_token(&line[s.max(seg_start)..e])) {
            t0 += 1;
        } else {
            break;
        }
    }
    if t0 >= ti {
        return false;
    }
    let (s, e) = toks[t0];
    let first = clean_token(&line[s.max(seg_start)..e]);
    let cmd = first.rsplit('/').next().unwrap_or(first);
    let word = |i: usize| clean_token(&line[toks[i].0..toks[i].1]);
    let no_args = t0 + 1 == ti;
    let prev = if no_args { "" } else { word(ti - 1) };
    let flags_only = ix.next_non_flag[t0 + 1] >= ti;
    let end = toks[ti].1;
    let stop = match ix.terms.partition_point(|&p| p < end) {
        k if k < ix.terms.len() => ix.terms[k],
        _ => line.len(),
    };
    let nf = ix.next_non_flag_digit[ti + 1];
    let last_arg = toks.get(nf).is_none_or(|&(s, _)| s >= stop);
    if LAST_ARG_CMDS.contains(&cmd) {
        return last_arg;
    }
    if cmd == "sed" {
        return ix.next_dash_i[t0 + 1] < ti && last_arg;
    }
    if cmd == "tee" {
        return true;
    }
    if FIRST_ARG_CMDS.contains(&cmd) {
        return PATH_FLAGS.contains(&prev) || flags_only;
    }
    if OUTPUT_FLAG_CMDS.contains(&cmd) {
        return PATH_FLAGS.contains(&prev);
    }
    (cmd == "reg" || cmd == "reg.exe") && t0 + 2 == ti && word(t0 + 1) == "add"
}

/// `git config core.hookspath` writes only when it sets or unsets a value.
/// In prose the value must look like a path, so "to see hooks" is not one.
fn git_sets(line: &str, end: usize, flags: bool, prose: bool) -> bool {
    if flags {
        return true;
    }
    line[end..].split_whitespace().next().is_some_and(|t| {
        if t.starts_with(['`', '-', ')', ';', '|', '&', '<', '>']) {
            return false;
        }
        !prose || t.starts_with(['/', '.', '~', '$', '"', '\'']) || t.contains('/')
    })
}

/// Name of the variable that `at` is assigned to on this line, if any.
fn assigned_name(line: &str, ix: &LineIdx, at: usize) -> Option<String> {
    let eq = match ix.eqs.partition_point(|&p| p < at) {
        0 => return None,
        k => ix.eqs[k - 1],
    };
    if line[..eq].ends_with(['=', '!', '<', '>']) {
        return None;
    }
    let lhs = line[..eq].trim_end_matches([' ', ':']);
    let name: String = lhs
        .chars()
        .rev()
        .take_while(|&c| is_word_char(c))
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();
    (!name.is_empty()).then_some(name)
}

/// What kind of file the text came from.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Script,
    Config,
    Prose,
}

fn normalize_line(line: &str) -> String {
    let flat: String = line
        .chars()
        .filter(|&c| !is_invisible(c))
        .flat_map(char::to_lowercase)
        .map(|c| if c == '\\' { '/' } else { c })
        .collect();
    collapse_slashes(&unwrap_join_path(&join_pieces(&flat)))
}

/// `(join-path $home ".claude/x.md")` as `".claude/x.md"`: the base is dropped
/// so the quoted path stands where the write cmdlet expects its target.
fn unwrap_join_path(line: &str) -> String {
    let mut out = line.to_string();
    for _ in 0..4 {
        let Some(at) = out.find("(join-path ") else {
            break;
        };
        let body = &out[at + "(join-path ".len()..];
        let Some(close) = body.find(')') else {
            break;
        };
        let inner = &body[..close];
        let Some(q) = inner.find(['"', '\'']) else {
            break;
        };
        let replaced = inner[q..].to_string();
        let end = at + "(join-path ".len() + close + 1;
        out.replace_range(at..end, &replaced);
    }
    out
}

/// Runs of `/` (from doubled `\` separators) as one, except in `://`.
fn collapse_slashes(line: &str) -> String {
    if !line.contains("//") {
        return line.to_string();
    }
    let mut out = String::with_capacity(line.len());
    let mut prev = '\0';
    for c in line.chars() {
        if c == '/' && prev == '/' && !out.ends_with("://") && !out.ends_with(":/") {
            continue;
        }
        out.push(c);
        prev = c;
    }
    out
}

/// Joins string pieces of a path built from parts: `"a", "b"` in a `join(`
/// or `resolve(` call, `"a" / "b"` (pathlib), `"a").joinpath("b"`,
/// `"a" + "b"` and `Join-Path $d "a" "b"`. The pieces become one string,
/// `"a/b"`.
fn join_pieces(line: &str) -> String {
    let joins = line.contains("join(")
        || line.contains("resolve(")
        || line.contains("path(")
        || line.contains("join-path");
    let ws = line.contains("join-path");
    let b: Vec<char> = line.chars().collect();
    let mut out = String::with_capacity(line.len());
    let mut quote: Option<char> = None;
    let mut i = 0;
    while i < b.len() {
        let c = b[i];
        match quote {
            None if c == '"' || c == '\'' => {
                quote = Some(c);
                out.push(c);
                i += 1;
            }
            Some(q) if c == q => match piece_joiner(&b, i + 1, joins, ws) {
                Some((next, sep)) => {
                    out.push_str(sep);
                    i = next;
                }
                None => {
                    quote = None;
                    out.push(c);
                    i += 1;
                }
            },
            _ => {
                out.push(c);
                i += 1;
            }
        }
    }
    out
}

/// After a closing quote: the text up to the next opening quote, when it only
/// joins two path pieces. Returns the index after that quote and the
/// separator to put between the pieces.
fn piece_joiner(b: &[char], start: usize, joins: bool, ws: bool) -> Option<(usize, &'static str)> {
    let skip = |mut j: usize| {
        while b.get(j) == Some(&' ') {
            j += 1;
        }
        j
    };
    let mut j = skip(start);
    let had_space = j > start;
    let sep = match *b.get(j)? {
        ',' if joins => {
            j += 1;
            "/"
        }
        '/' => {
            j += 1;
            "/"
        }
        '+' => {
            j += 1;
            ""
        }
        ')' => {
            j = skip(j + 1);
            for want in ".joinpath(".chars() {
                if b.get(j) != Some(&want) {
                    return None;
                }
                j += 1;
            }
            "/"
        }
        '"' | '\'' if ws && had_space => "/",
        _ => return None,
    };
    j = skip(j);
    matches!(b.get(j)?, '"' | '\'').then_some((j + 1, sep))
}

/// Path words that make a variable worth folding into later lines.
const PATH_WORDS: &[&str] = &[
    ".claude",
    ".codex",
    ".gemini",
    "claude",
    "agents",
    "commands",
    "skills",
    "settings",
    "hooks",
    ".mcp",
    ".bash",
    ".zsh",
    ".profile",
    "cron",
    "launchagents",
    ".git",
];

/// Whether `chars[at..]` starts with `name`.
fn starts_with_at(chars: &[char], at: usize, name: &str) -> bool {
    name.chars()
        .enumerate()
        .all(|(k, n)| chars.get(at + k) == Some(&n))
}

fn is_word(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

/// Folds `d=.claude`, `d = ".claude"` and `$d = ".claude"` (assigned once, a
/// short literal naming a configuration path) into the lines that use it as
/// `$d`, `${d}` or a bare name outside quotes, so a path built from a
/// variable is matched.
fn fold_path_variables(lines: &mut [String]) {
    let mut seen: BTreeMap<String, usize> = BTreeMap::new();
    let mut values: BTreeMap<String, String> = BTreeMap::new();
    for line in lines.iter() {
        let t = line.trim();
        let t = [
            "export ", "const ", "let ", "var ", "local ", "declare ", "set ",
        ]
        .iter()
        .find_map(|p| t.strip_prefix(p))
        .unwrap_or(t);
        let t = t.strip_prefix('$').unwrap_or(t);
        let end = t.find(|c: char| !is_word(c)).unwrap_or(t.len());
        if end == 0 {
            continue;
        }
        let (name, rest) = t.split_at(end);
        let Some(value) = rest
            .trim_start()
            .strip_prefix('=')
            .filter(|v| !v.starts_with('='))
        else {
            continue;
        };
        *seen.entry(name.to_string()).or_default() += 1;
        let value = value.trim().trim_end_matches(';').trim();
        let value = value.trim_matches(|c| c == '"' || c == '\'');
        if !value.is_empty()
            && value.len() <= 64
            && !value.contains(['$', '(', ' ', '"', '\'', '`', '{'])
            && PATH_WORDS.iter().any(|w| value.contains(w))
            && values.len() < 16
        {
            values.insert(name.to_string(), value.to_string());
        }
    }
    values.retain(|name, _| seen.get(name) == Some(&1));
    if values.is_empty() {
        return;
    }
    for line in lines.iter_mut() {
        for (name, value) in &values {
            if !line.contains(name.as_str()) {
                continue;
            }
            let chars: Vec<char> = line.chars().collect();
            let len = name.chars().count();
            let mut out = String::with_capacity(line.len());
            let mut quote: Option<char> = None;
            let mut i = 0;
            while i < chars.len() {
                let c = chars[i];
                if let Some(q) = quote {
                    if c == q {
                        quote = None;
                    }
                } else if c == '"' || c == '\'' {
                    quote = Some(c);
                }
                if c == '$' {
                    let braced = chars.get(i + 1) == Some(&'{');
                    let from = i + 1 + usize::from(braced);
                    let end = from + len;
                    if starts_with_at(&chars, from, name)
                        && if braced {
                            chars.get(end) == Some(&'}')
                        } else {
                            chars.get(end).is_none_or(|n| !is_word(*n))
                        }
                    {
                        out.push_str(value);
                        i = end + usize::from(braced);
                        continue;
                    }
                } else if quote.is_none()
                    && starts_with_at(&chars, i, name)
                    && (i == 0 || !(is_word(chars[i - 1]) || matches!(chars[i - 1], '.' | '$')))
                    && chars
                        .get(i + len)
                        .is_none_or(|n| !(is_word(*n) || matches!(n, '(' | '=' | '.')))
                {
                    out.push('"');
                    out.push_str(value);
                    out.push('"');
                    i += len;
                    continue;
                }
                out.push(c);
                i += 1;
            }
            *line = join_pieces(&out);
        }
    }
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

/// Per-file hits: (line, target) -> (context, evidence).
type Hits = BTreeMap<(u32, &'static str), (&'static str, String)>;

fn add_ctx(hits: &mut Hits, line: u32, target: &'static str, ctx: &'static str, evidence: &str) {
    hits.entry((line, target))
        .or_insert_with(|| (ctx, safe_evidence(evidence.trim())));
}

fn add(hits: &mut Hits, line: u32, target: &'static str, evidence: &str) {
    add_ctx(hits, line, target, "code", evidence);
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

/// How a write scan ended early, if it did.
#[derive(Default)]
struct Cut {
    deadline: bool,
    too_many_hits: bool,
}

/// Writes to guarded paths in any text.
///
/// Scripts and config files count only a write whose target is the guarded
/// path. Prose also counts a clear write verb on the same line. Work per line
/// is linear in its length: per-line facts are computed once and each hit is
/// a lookup, and at most [`MAX_HITS_PER_LINE`] hits per line are examined.
fn scan_writes(text: &str, kind: Kind, deadline: Instant, hits: &mut Hits) -> Cut {
    let ctx = if kind == Kind::Prose { "prose" } else { "code" };
    let mut cut = Cut::default();
    let raw: Vec<&str> = text.split('\n').collect();
    let mut lines: Vec<String> = raw
        .iter()
        .map(|l| normalize_line(l.strip_suffix('\r').unwrap_or(l)))
        .collect();
    fold_path_variables(&mut lines);
    let mut idx: Vec<Option<LineIdx>> = lines.iter().map(|_| None).collect();
    let mut vars: BTreeSet<(usize, String, &'static str)> = BTreeSet::new();
    for (i, line) in lines.iter().enumerate() {
        if (i % 64 == 0 || line.len() > 10_000) && Instant::now() > deadline {
            cut.deadline = true;
            break;
        }
        let n = i as u32 + 1;
        let shown = raw[i];
        let mut found: Vec<(&Spec, &str, usize)> = Vec::new();
        for spec in SPECS {
            if spec.commands.iter().any(|c| !find_all(line, c).is_empty()) {
                add_ctx(hits, n, spec.target, ctx, shown);
            }
            for p in spec.paths {
                for a in find_all(line, p) {
                    found.push((spec, p, a));
                }
            }
        }
        if found.is_empty() {
            continue;
        }
        if found.len() > MAX_HITS_PER_LINE {
            cut.too_many_hits = true;
            found.truncate(MAX_HITS_PER_LINE);
        }
        let ix = idx[i].insert(index_line(line));
        let mut prose_verb: Option<bool> = None;
        let git_flags = ["--unset", "--add", "--replace-all"]
            .iter()
            .any(|f| line.contains(f));
        for (spec, p, a) in found {
            let writes = if p == "core.hookspath" {
                git_sets(line, a + p.len(), git_flags, kind == Kind::Prose)
            } else {
                // Prose that merely mentions CLAUDE.md or a command folder is
                // ordinary documentation: only a write target counts there.
                is_write_target(line, ix, a)
                    || (kind == Kind::Prose
                        && spec.target != "agent_instructions"
                        && *prose_verb.get_or_insert_with(|| has_strong_prose_verb(line)))
            };
            if !writes {
                if kind == Kind::Script
                    && p != "core.hookspath"
                    && let Some(name) = assigned_name(line, ix, a)
                {
                    vars.insert((i, name, spec.target));
                }
                continue;
            }
            add_ctx(hits, n, spec.target, ctx, shown);
            if spec.target == "agent_settings" {
                for (needle, target) in [
                    ("hooks", "hooks"),
                    ("permissions", "permissions"),
                    ("mcpservers", "mcp_config"),
                ] {
                    if line.contains(&format!("\"{needle}\"")) {
                        add_ctx(hits, n, target, ctx, shown);
                    }
                }
            }
        }
    }
    for (i, name, target) in vars {
        let hi = (i + VAR_WINDOW + 1).min(lines.len());
        for j in i..hi {
            let line = &lines[j];
            let found = find_all(line, &name);
            if found.is_empty() {
                continue;
            }
            let ix = idx[j].get_or_insert_with(|| index_line(line));
            if found
                .into_iter()
                .take(MAX_HITS_PER_LINE)
                .any(|a| is_write_target(line, ix, a))
            {
                add_ctx(hits, j as u32 + 1, target, ctx, raw[j]);
                break;
            }
        }
    }
    cut
}

fn signal(target: &str, context: &str, file: &str, line: u32, evidence: String) -> Signal {
    Signal {
        kind: AGENT_CONFIG.to_string(),
        fields: BTreeMap::from([
            ("target".to_string(), target.to_string()),
            ("context".to_string(), context.to_string()),
        ]),
        locations: vec![Location {
            file: file.to_string(),
            line,
        }],
        evidence,
    }
}

impl AgentConfigAnalyzer {
    /// Scans files until `budget` (measured from the call) runs out. Files not
    /// reached, or only partly checked, each get a `parse_budget_exceeded`
    /// signal.
    pub fn run_with_deadline(&self, ctx: &ScanContext, budget: Duration) -> AnalyzerOutput {
        let deadline = Instant::now() + budget;
        let secs = budget.as_secs();
        let mut signals = Vec::new();
        for f in &ctx.inventory.files {
            if Instant::now() >= deadline {
                signals.push(budget_signal(&f.path, secs));
                continue;
            }
            let mut hits = Hits::new();
            let mut cut = Cut::default();
            let name = f.path.rsplit('/').next().unwrap_or(&f.path);
            if is_suppression_name(&name.to_ascii_lowercase()) {
                add(&mut hits, 1, "suppression_file", &f.path);
            }
            if f.content_type == ContentType::Text {
                let role = ctx.roles.get(&f.path).copied().unwrap_or(FileRole::Asset);
                let kind = match role {
                    FileRole::Script(_) => Kind::Script,
                    FileRole::Config => Kind::Config,
                    _ => Kind::Prose,
                };
                match read_lossy(ctx, &f.path) {
                    Some(text) => {
                        scan_shipped(&f.path, role, Some(&text), &mut hits);
                        cut = scan_writes(&text, kind, deadline, &mut hits);
                    }
                    None => {
                        scan_shipped(&f.path, role, None, &mut hits);
                        signals.push(unreadable_signal(&f.path));
                    }
                }
            }
            for ((line, target), (context, evidence)) in hits {
                signals.push(signal(target, context, &f.path, line, evidence));
            }
            if cut.deadline {
                signals.push(budget_signal(&f.path, secs));
            }
            if cut.too_many_hits {
                signals.push(partial_signal(
                    &f.path,
                    "more than 1000 guarded paths on one line; the rest were not checked",
                ));
            }
        }
        AnalyzerOutput {
            signals,
            coverage: Coverage::Ran,
        }
    }
}

impl Analyzer for AgentConfigAnalyzer {
    fn id(&self) -> &'static str {
        "agent_config"
    }

    fn run(&self, ctx: &ScanContext) -> AnalyzerOutput {
        self.run_with_deadline(ctx, ANALYZER_DEADLINE)
    }
}
