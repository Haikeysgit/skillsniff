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

const SECRET_FILE_MARKERS: &[&str] = &[
    ".ssh/",
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
    let bytes = text.as_bytes();
    let mut from = 0;
    while let Some(rel) = text[from..].find(".env") {
        let at = from + rel;
        let before_ok = at == 0 || matches!(bytes[at - 1], b'/' | b'"' | b'\'' | b' ' | b'~');
        let after_ok = bytes
            .get(at + 4)
            .is_none_or(|b| !(b.is_ascii_alphanumeric() || *b == b'_'));
        if before_ok && after_ok {
            return true;
        }
        from = at + 4;
    }
    false
}

/// Source class of a string literal (or folded path text), if any.
///
/// Only file-like classes are recognized here; environment variables go
/// through [`env_class`].
pub fn literal_source_class(text: &str) -> Option<&'static str> {
    let t = normalize_path(text);
    let lower = t.to_ascii_lowercase();
    if SECRET_FILE_MARKERS.iter().any(|m| t.contains(m)) || has_dotenv(&t) {
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
