//! Source and sink class patterns shared by every language.
//!
//! Language rules extract string literals, environment variable names and
//! call names; the functions here decide which class, if any, they belong to.

/// Every `class` value a `Source` signal can carry.
pub const SOURCE_CLASSES: &[&str] = &[SECRET_FILE, SECRET_ENV, BROWSER_STORE, WALLET, KEYCHAIN];

/// Every `class` value a `Sink` signal can carry.
pub const SINK_CLASSES: &[&str] = &[
    NETWORK,
    EXEC,
    EVAL,
    SENSITIVE_WRITE,
    DOWNLOAD_EXEC,
    REVERSE_SHELL,
];

pub const SECRET_FILE: &str = "secret_file";
pub const SECRET_ENV: &str = "secret_env";
pub const BROWSER_STORE: &str = "browser_store";
pub const WALLET: &str = "wallet";
pub const KEYCHAIN: &str = "keychain";

pub const NETWORK: &str = "network";
pub const EXEC: &str = "exec";
pub const EVAL: &str = "eval";
pub const SENSITIVE_WRITE: &str = "sensitive_write";
pub const DOWNLOAD_EXEC: &str = "download_exec";
pub const REVERSE_SHELL: &str = "reverse_shell";

/// Shell programs, as the first word of a command vector.
pub const SHELLS: &[&str] = &[
    "sh",
    "bash",
    "dash",
    "zsh",
    "ksh",
    "/bin/sh",
    "/bin/bash",
    "/bin/dash",
    "/bin/zsh",
    "/usr/bin/sh",
    "/usr/bin/bash",
    "/usr/bin/dash",
    "/usr/bin/zsh",
    "cmd",
    "cmd.exe",
    "powershell",
    "powershell.exe",
    "pwsh",
];

/// POSIX shells, by program base name.
const POSIX_SHELLS: &[&str] = &["sh", "bash", "dash", "zsh", "ksh", "ash", "mksh", "fish"];

/// Programs that run the command given by their remaining words.
const WRAPPERS: &[&str] = &[
    "sudo", "doas", "env", "nohup", "command", "builtin", "exec", "nice", "setsid", "stdbuf",
    "busybox", "time", "timeout", "ionice",
];

/// Options of a wrapper that take the next word as a value.
fn wrapper_value_options(name: &str) -> &'static [&'static str] {
    match name {
        "sudo" | "doas" => &[
            "-u", "-g", "-p", "-C", "-D", "-r", "-t", "-U", "-T", "--user", "--group",
        ],
        "env" => &["-u", "--unset", "-C", "--chdir"],
        "nice" => &["-n", "--adjustment"],
        "ionice" => &["-c", "-n", "-p", "-t"],
        "timeout" => &["-s", "--signal", "-k", "--kill-after"],
        "stdbuf" => &["-i", "-o", "-e"],
        "exec" => &["-a"],
        _ => &[],
    }
}

/// Whether a word makes a shell run the next word as a command: a short
/// option cluster holding `c` (`-c`, `-lc`, `-ec`), cmd's `/c` or `/k`, or
/// PowerShell's `-Command` in any case or abbreviation.
pub fn is_shell_flag(word: &str) -> bool {
    let lower = word.to_ascii_lowercase();
    if matches!(lower.as_str(), "/c" | "/k") {
        return true;
    }
    let Some(rest) = lower.strip_prefix('-') else {
        return false;
    };
    if rest.is_empty() || !rest.bytes().all(|b| b.is_ascii_alphabetic()) {
        return false;
    }
    "command".starts_with(rest) || (rest.len() <= 6 && rest.contains('c'))
}

/// Program name without directories, case or an `.exe` suffix.
pub fn program_name(word: &str) -> String {
    let base = word.rsplit(['/', '\\']).next().unwrap_or(word);
    let lower = base.to_ascii_lowercase();
    lower.strip_suffix(".exe").unwrap_or(&lower).to_string()
}

/// Whether a program word names a POSIX shell (`sh`, `/bin/bash`).
pub fn is_posix_shell(word: &str) -> bool {
    POSIX_SHELLS.contains(&program_name(word).as_str())
}

/// Index of the program a command vector runs once launchers in front of
/// it are skipped: `sudo`, `env` and similar wrappers with their options,
/// option values and `NAME=value` assignments. Equals `words.len()` when no
/// program is left (`exec 3<&-`, `command -v curl` only looks a name up).
pub fn program_index<S: AsRef<str>>(words: &[S]) -> usize {
    let mut i = 0;
    while let Some(w) = words.get(i) {
        let name = program_name(w.as_ref());
        if !WRAPPERS.contains(&name.as_str()) {
            break;
        }
        i += 1;
        let mut duration_left = name == "timeout";
        while let Some(w) = words.get(i).map(AsRef::as_ref) {
            if w == "--" {
                i += 1;
                break;
            }
            let assignment = name == "env" && is_assignment(w);
            let duration = duration_left && w.starts_with(|c: char| c.is_ascii_digit());
            duration_left &= !duration;
            if !(w.starts_with('-') || assignment || duration) {
                break;
            }
            if name == "command" && matches!(w, "-v" | "-V") {
                return words.len();
            }
            if wrapper_value_options(&name).contains(&w) {
                i += 1;
            }
            i += 1;
        }
    }
    i.min(words.len())
}

/// `NAME=value` with a shell variable name.
fn is_assignment(word: &str) -> bool {
    word.split_once('=').is_some_and(|(name, _)| {
        !name.is_empty()
            && !name.starts_with(|c: char| c.is_ascii_digit())
            && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
    })
}

/// Stands for a non-literal piece when command text is folded, so that
/// pieces on either side of it never join into a word.
pub const UNKNOWN_PIECE: char = '\u{1}';

/// Credential directories, matched as a whole path segment.
const SECRET_DIRS: &[&str] = &[".ssh", ".aws", ".kube", ".docker", ".gnupg"];

const SECRET_FILE_MARKERS: &[&str] = &[
    ".aws/credentials",
    ".aws/config",
    ".npmrc",
    ".pypirc",
    ".netrc",
    ".git-credentials",
    ".docker/config.json",
    ".kube/config",
    "id_rsa",
    "id_ed25519",
];

const SECRET_ENV_MARKERS: &[&str] = &[
    "token",
    "secret",
    "password",
    "passwd",
    "apikey",
    "api_key",
    "privatekey",
    "private_key",
    "credential",
    "aws_",
    "github_",
    "openai",
    "anthropic",
];

const BROWSER_STORE_NAMES: &[&str] = &["Cookies", "Login Data", "Local State"];

const BROWSER_MARKERS: &[&str] = &[
    "chrome",
    "chromium",
    "brave",
    "edge",
    "firefox",
    "mozilla",
    "opera",
    "vivaldi",
    "user data",
    "/default/",
    "profile",
];

const WALLET_MARKERS_NOCASE: &[&str] = &["wallet.dat", "keystore", ".ethereum", "metamask"];

const KEYCHAIN_MARKERS: &[&str] = &["security find-generic-password", "login.keychain"];

const SENSITIVE_WRITE_MARKERS: &[&str] = &[
    ".bashrc",
    ".bash_profile",
    ".bash_login",
    ".profile",
    ".zshrc",
    ".zshenv",
    ".zprofile",
    ".zlogin",
    ".config/fish/config.fish",
    "/etc/profile",
    "powershell_profile.ps1",
    ".claude/",
    ".codex/",
    "crontab",
    "/etc/cron",
    "/var/spool/cron",
    "launchagents",
    "launchdaemons",
    "/startup",
    ".config/autostart",
    ".git/hooks/",
    "/currentversion/run",
];

/// Normalizes path text for matching: backslashes become `/` and runs of
/// slashes collapse.
pub fn normalize_path(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut last_slash = false;
    for c in text.chars() {
        let c = if c == '\\' { '/' } else { c };
        if c == '/' && last_slash {
            continue;
        }
        last_slash = c == '/';
        out.push(c);
    }
    out
}

/// `.env` as a file name: `.env`, `.env.local`, `/x/.env`, but not
/// `.environment` or `process.env`.
fn has_dotenv(text: &str) -> bool {
    has_segment(text, ".env", |b| {
        b.is_none_or(|b| !(b.is_ascii_alphanumeric() || b == b'_'))
    })
}

/// Whether `name` starts a path segment (after start, `/`, a quote, a space
/// or `~`) and `ends` accepts the byte after it (`None` at end of text).
fn has_segment(text: &str, name: &str, ends: impl Fn(Option<u8>) -> bool) -> bool {
    let bytes = text.as_bytes();
    let mut from = 0;
    while let Some(rel) = text[from..].find(name) {
        let at = from + rel;
        let starts = at == 0 || matches!(bytes[at - 1], b'/' | b'"' | b'\'' | b' ' | b'~');
        if starts && ends(bytes.get(at + name.len()).copied()) {
            return true;
        }
        from = at + name.len();
    }
    false
}

/// A credential directory as a whole segment: `~/.ssh`, `.aws/x`, but not
/// `.sshkeys` or `.awsome`. Expects text already normalized to `/`.
fn has_secret_dir(text: &str) -> bool {
    SECRET_DIRS.iter().any(|d| {
        has_segment(text, d, |b| {
            b.is_none_or(|b| matches!(b, b'/' | b'"' | b'\'' | b' ' | b'`'))
        })
    })
}

/// Whether a shell command fetches with `curl` or `wget` and pipes the result
/// into a POSIX shell (`curl -s u | sh`, `wget -qO- u|bash`,
/// `curl u | sudo -E /bin/bash -s --`). `||` is not a pipe.
pub fn pipes_download_to_shell(cmd: &str) -> bool {
    let lower = cmd.to_ascii_lowercase();
    let Some(fetch) = ["curl", "wget"].iter().filter_map(|f| lower.find(f)).min() else {
        return false;
    };
    let text = &lower[fetch..];
    let bytes = text.as_bytes();
    text.match_indices('|').any(|(i, _)| {
        let before = i.checked_sub(1).map(|j| bytes[j]);
        let after = bytes.get(i + 1).copied();
        if before == Some(b'|') || after == Some(b'|') {
            return false;
        }
        let rest = &text[i + 1..];
        let rest = rest.strip_prefix('&').unwrap_or(rest);
        let stage = rest.split([';', '|', '&', ')', '\n']).next().unwrap_or("");
        let words: Vec<&str> = stage
            .split_whitespace()
            .map(|w| w.trim_matches(|c| c == '"' || c == '\''))
            .collect();
        words
            .get(program_index(&words))
            .is_some_and(|p| is_posix_shell(p))
    })
}

/// Source class of a string literal (or folded path text), if any.
///
/// Only file-like classes are recognized here; environment variables go
/// through [`env_class`].
pub fn literal_source_class(text: &str) -> Option<&'static str> {
    let t = normalize_path(text);
    let lower = t.to_ascii_lowercase();
    if SECRET_FILE_MARKERS.iter().any(|m| t.contains(m)) || has_dotenv(&t) || has_secret_dir(&t) {
        return Some(SECRET_FILE);
    }
    if KEYCHAIN_MARKERS.iter().any(|m| t.contains(m)) {
        return Some(KEYCHAIN);
    }
    if WALLET_MARKERS_NOCASE.iter().any(|m| lower.contains(m)) || t.contains("Exodus") {
        return Some(WALLET);
    }
    if is_browser_store(&t, &lower) {
        return Some(BROWSER_STORE);
    }
    None
}

fn is_browser_store(t: &str, lower: &str) -> bool {
    let Some(name) = BROWSER_STORE_NAMES.iter().find(|n| t.contains(**n)) else {
        return false;
    };
    // A bare "Login Data" or "Local State" literal is specific enough; the
    // generic word "Cookies" needs a browser profile path around it.
    let bare = t.trim_matches(|c| c == '/' || c == ' ') == *name;
    (bare && *name != "Cookies") || BROWSER_MARKERS.iter().any(|m| lower.contains(m))
}

/// Whether an environment variable name looks like it holds a secret.
pub fn env_class(name: &str) -> Option<&'static str> {
    let lower = name.to_ascii_lowercase();
    SECRET_ENV_MARKERS
        .iter()
        .any(|m| lower.contains(m))
        .then_some(SECRET_ENV)
}

/// Whether path text names a shell profile, agent config, cron or autostart
/// location.
pub fn is_sensitive_write_path(text: &str) -> bool {
    let lower = normalize_path(text).to_ascii_lowercase();
    SENSITIVE_WRITE_MARKERS.iter().any(|m| lower.contains(m))
}

/// Markers of [`literal_source_class`] and [`is_sensitive_write_path`]
/// that hold none of `/`, `\`, `.`, `_` or a space.
const PLAIN_MARKERS: &[&str] = &[
    "keystore",
    "metamask",
    "exodus",
    "cookies",
    "crontab",
    "launchagents",
    "launchdaemons",
];

/// Cheap test that text may hold a source or sensitive-write marker. False
/// means neither [`literal_source_class`] nor [`is_sensitive_write_path`]
/// can match it, so callers checking many words can skip them.
pub fn may_name_path(text: &str) -> bool {
    if text.contains(['/', '\\', '.', '_', ' ']) {
        return true;
    }
    if text.len() < PLAIN_MARKERS.iter().map(|m| m.len()).min().unwrap_or(0) {
        return false;
    }
    let lower = text.to_ascii_lowercase();
    PLAIN_MARKERS.iter().any(|m| lower.contains(m))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_marker_passes_the_prefilter() {
        let lists: [&[&str]; 7] = [
            SECRET_DIRS,
            SECRET_FILE_MARKERS,
            BROWSER_STORE_NAMES,
            WALLET_MARKERS_NOCASE,
            KEYCHAIN_MARKERS,
            SENSITIVE_WRITE_MARKERS,
            &[".env", "Exodus"],
        ];
        for m in lists.iter().flat_map(|l| l.iter()) {
            assert!(may_name_path(m), "{m}");
            assert!(may_name_path(&m.to_ascii_uppercase()), "{m}");
        }
        assert!(!may_name_path("grep"));
        assert!(!may_name_path("--silent"));
    }
}
