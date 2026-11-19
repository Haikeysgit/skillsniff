//! Hidden content: invisible characters, look-alike scripts, encoded blobs and
//! files that are not what their name says.

use std::collections::BTreeMap;

use crate::analyzers::{Analyzer, AnalyzerOutput, ScanContext};
use crate::inventory::{ContentType, FileEntry};
use crate::model::signal::HIDDEN;
use crate::model::{Coverage, Location, Signal};

/// Every `pattern` value emitted under the `Hidden` kind, including the one the
/// code analyzer emits when it runs out of parse budget or meets a script
/// that is not valid UTF-8.
pub const HIDDEN_PATTERNS: &[&str] = &[
    "zero_width",
    "bidi_control",
    "tag_chars",
    "mixed_script",
    "high_entropy",
    "binary_file",
    "minified_file",
    "oversized_file",
    "extension_mismatch",
    "parse_budget_exceeded",
    "invisible_joiner",
    "invalid_utf8_script",
    "parse_errors",
];

/// Files larger than this are flagged `oversized_file`.
const OVERSIZED_BYTES: u64 = 1024 * 1024;
/// Lines longer than this only get the invisible-character checks.
const MAX_LINE_BYTES: usize = 1024 * 1024;
const MIN_TOKEN_LEN: usize = 40;
const BASE64_ENTROPY: f64 = 4.5;
const HEX_ENTROPY: f64 = 3.5;
const EVIDENCE_TOKEN_CHARS: usize = 40;

const SCRIPT_EXTENSIONS: &[&str] = &[
    "py", "js", "mjs", "cjs", "ts", "mts", "cts", "sh", "bash", "ps1", "psm1", "md",
];

/// Detects content that is invisible or disguised.
pub struct HiddenAnalyzer;

fn is_zero_width(c: char) -> bool {
    matches!(c, '\u{200B}'..='\u{200D}' | '\u{2060}' | '\u{FEFF}')
}

fn is_bidi(c: char) -> bool {
    matches!(c, '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}')
}

fn is_joiner(c: char) -> bool {
    matches!(
        c,
        '\u{034F}'
            | '\u{00AD}'
            | '\u{FE00}'..='\u{FE0F}'
            | '\u{180B}'..='\u{180D}'
            | '\u{200E}'
            | '\u{200F}'
            | '\u{061C}'
            | '\u{2061}'..='\u{2064}'
    )
}

/// Marks and format characters that must not split a token.
fn is_token_extender(c: char) -> bool {
    matches!(
        c,
        '\u{0300}'..='\u{036F}'
            | '\u{1AB0}'..='\u{1AFF}'
            | '\u{1DC0}'..='\u{1DFF}'
            | '\u{20D0}'..='\u{20FF}'
            | '\u{FE00}'..='\u{FE0F}'
            | '\u{FE20}'..='\u{FE2F}'
            | '\u{180B}'..='\u{180D}'
            | '\u{00AD}'
            | '\u{200B}'..='\u{200F}'
            | '\u{2060}'..='\u{2064}'
            | '\u{FEFF}'
    )
}

fn is_tag(c: char) -> bool {
    matches!(c, '\u{E0000}'..='\u{E007F}')
}

fn char_name(c: char) -> &'static str {
    match c {
        '\u{200B}' => "ZERO WIDTH SPACE",
        '\u{200C}' => "ZERO WIDTH NON-JOINER",
        '\u{200D}' => "ZERO WIDTH JOINER",
        '\u{2060}' => "WORD JOINER",
        '\u{FEFF}' => "ZERO WIDTH NO-BREAK SPACE",
        '\u{202A}' => "LEFT-TO-RIGHT EMBEDDING",
        '\u{202B}' => "RIGHT-TO-LEFT EMBEDDING",
        '\u{202C}' => "POP DIRECTIONAL FORMATTING",
        '\u{202D}' => "LEFT-TO-RIGHT OVERRIDE",
        '\u{202E}' => "RIGHT-TO-LEFT OVERRIDE",
        '\u{2066}' => "LEFT-TO-RIGHT ISOLATE",
        '\u{2067}' => "RIGHT-TO-LEFT ISOLATE",
        '\u{2068}' => "FIRST STRONG ISOLATE",
        '\u{2069}' => "POP DIRECTIONAL ISOLATE",
        _ if is_tag(c) => "TAG CHARACTER",
        _ => "CHARACTER",
    }
}

fn describe(c: char) -> String {
    format!("U+{:04X} {}", c as u32, char_name(c))
}

#[derive(PartialEq, Eq, Clone, Copy)]
enum Script {
    Latin,
    Cyrillic,
    Greek,
}

fn script_of(c: char) -> Option<Script> {
    if !c.is_alphabetic() {
        return None;
    }
    match c as u32 {
        0x41..=0x5A | 0x61..=0x7A => Some(Script::Latin),
        0xD7 | 0xF7 => None,
        0xAA
        | 0xBA
        | 0xC0..=0x24F
        | 0x250..=0x2AF
        | 0x1D00..=0x1D2A
        | 0x1D2C..=0x1D77
        | 0x1D79..=0x1D7F
        | 0x2126
        | 0x212A
        | 0x212B
        | 0x1E00..=0x1EFF
        | 0x2C60..=0x2C7F
        | 0xA720..=0xA7FF => Some(Script::Latin),
        0xFF21..=0xFF3A | 0xFF41..=0xFF5A => Some(Script::Latin),
        0x1D2B | 0x1D78 => Some(Script::Cyrillic),
        0x370..=0x3FF | 0x1F00..=0x1FFF => Some(Script::Greek),
        0x400..=0x52F | 0x1C80..=0x1C8F | 0x2DE0..=0x2DFF | 0xA640..=0xA69F => {
            Some(Script::Cyrillic)
        }
        _ => None,
    }
}

fn is_mixed(token: &str) -> bool {
    let (mut latin, mut other) = (false, false);
    for c in token.chars() {
        match script_of(c) {
            Some(Script::Latin) => latin = true,
            Some(_) => other = true,
            None => {}
        }
    }
    latin && other
}

fn shannon(token: &str) -> f64 {
    let mut counts = [0usize; 256];
    for b in token.bytes() {
        counts[b as usize] += 1;
    }
    let n = token.len() as f64;
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / n;
            -p * p.log2()
        })
        .sum()
}

fn truncate_chars(s: &str, n: usize) -> String {
    s.chars().take(n).collect()
}

/// Printable stand-in for a token: anything not plain ASCII is escaped.
fn safe_token(s: &str) -> String {
    let mut out = String::new();
    for c in s.chars().take(EVIDENCE_TOKEN_CHARS) {
        if c.is_ascii_graphic() {
            out.push(c);
        } else {
            out.push_str(&format!("\\u{{{:04X}}}", c as u32));
        }
    }
    out
}

fn with_fields(mut s: Signal, extra: &[(&str, &str)]) -> Signal {
    for (k, v) in extra {
        s.fields.insert((*k).to_string(), (*v).to_string());
    }
    s
}

fn signal(pattern: &str, file: &str, line: u32, evidence: String) -> Signal {
    Signal {
        kind: HIDDEN.to_string(),
        fields: BTreeMap::from([("pattern".to_string(), pattern.to_string())]),
        locations: vec![Location {
            file: file.to_string(),
            line,
        }],
        evidence,
    }
}

/// Byte ranges of URL hosts in a line.
fn url_hosts(line: &str) -> Vec<(usize, usize)> {
    let mut hosts = Vec::new();
    let mut from = 0;
    while let Some(rel) = line[from..].find("://") {
        let at = from + rel;
        let scheme_ok = line[..at].ends_with("http") || line[..at].ends_with("https");
        let start = at + 3;
        let end = line[start..]
            .find(|c: char| c.is_whitespace() || "/?#:@<>\"'`)]}\\".contains(c))
            .map_or(line.len(), |i| start + i);
        if scheme_ok && end > start {
            hosts.push((start, end));
        }
        from = start;
    }
    hosts
}

fn scan_mixed_script(line: &str, file: &str, n: u32, out: &mut Vec<Signal>) {
    let hosts = url_hosts(line);
    for &(s, e) in &hosts {
        if line[s..e].split('.').any(is_mixed) {
            out.push(signal(
                "mixed_script",
                file,
                n,
                format!(
                    "mixed Latin and Cyrillic/Greek in host {}",
                    safe_token(&line[s..e])
                ),
            ));
        }
    }
    let mut start: Option<usize> = None;
    let flush = |s: usize, e: usize, out: &mut Vec<Signal>| {
        let idx = hosts.partition_point(|&(hs, _)| hs <= s);
        if idx > 0 && e <= hosts[idx - 1].1 {
            return;
        }
        let tok = &line[s..e];
        if is_mixed(tok) {
            out.push(signal(
                "mixed_script",
                file,
                n,
                format!(
                    "mixed Latin and Cyrillic/Greek in identifier {}",
                    safe_token(tok)
                ),
            ));
        }
    };
    for (i, c) in line.char_indices() {
        if c.is_alphanumeric() || c == '_' || (start.is_some() && is_token_extender(c)) {
            start.get_or_insert(i);
        } else if let Some(s) = start.take() {
            flush(s, i, out);
        }
    }
    if let Some(s) = start {
        flush(s, line.len(), out);
    }
}

/// Longest token that can be a path, as opposed to a payload.
const MAX_PATH_TOKEN: usize = 120;
/// Longest segment of a path-like token.
const MAX_PATH_SEGMENT: usize = 40;

/// Whether the token starting at byte `at` of the line sits in the path of a
/// URL: a `://` earlier on the line, a `/` after the host, no space, quote,
/// bracket, `?` or `#` in between, and a token short enough to be a path.
fn in_url(line: &str, at: usize, tok: &str) -> bool {
    let Some(open) = line[..at].rfind("://") else {
        return false;
    };
    let before = &line[open + 3..at];
    tok.len() <= MAX_PATH_TOKEN
        && (before.contains('/') || tok.contains('/'))
        && !before.contains(|c: char| c.is_whitespace() || "\"'`<>()[]{}?#".contains(c))
}

/// A relative file path such as `schemas/shared-types` right before `.xsd`:
/// short, with short segments and none of the `+` or `=` of base64.
fn is_file_path(tok: &str, after: &str) -> bool {
    tok.len() <= MAX_PATH_TOKEN
        && tok.contains('/')
        && !tok.contains(['+', '='])
        && tok.split('/').all(|seg| seg.len() <= MAX_PATH_SEGMENT)
        && after
            .strip_prefix('.')
            .is_some_and(|r| r.starts_with(|c: char| c.is_ascii_alphabetic()))
}

/// A subresource-integrity value: `sha256-`, `sha384-` or `sha512-` and a
/// base64 digest of exactly the right length.
fn is_integrity_hash(tok: &str) -> bool {
    [("sha256-", 44), ("sha384-", 64), ("sha512-", 88)]
        .iter()
        .any(|(p, n)| tok.strip_prefix(p).is_some_and(|d| d.len() == *n))
}

fn scan_entropy(line: &str, file: &str, n: u32, out: &mut Vec<Signal>) {
    let emit = |s: usize, tok: &str, out: &mut Vec<Signal>| {
        if tok.len() < MIN_TOKEN_LEN
            || in_url(line, s, tok)
            || is_integrity_hash(tok)
            || is_file_path(tok, &line[s + tok.len()..])
        {
            return;
        }
        let hex = tok.bytes().all(|b| b.is_ascii_hexdigit());
        let limit = if hex { HEX_ENTROPY } else { BASE64_ENTROPY };
        if shannon(tok) > limit {
            out.push(with_fields(
                signal(
                    "high_entropy",
                    file,
                    n,
                    truncate_chars(tok, EVIDENCE_TOKEN_CHARS),
                ),
                &[
                    ("alphabet", if hex { "hex" } else { "base64" }),
                    ("len", &tok.len().to_string()),
                ],
            ));
        }
    };
    let is_tok = |b: u8| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'=' | b'_' | b'-');
    let bytes = line.as_bytes();
    let mut start: Option<usize> = None;
    for (i, &b) in bytes.iter().enumerate() {
        if is_tok(b) {
            start.get_or_insert(i);
        } else if let Some(s) = start.take() {
            emit(s, &line[s..i], out);
        }
    }
    if let Some(s) = start {
        emit(s, &line[s..], out);
    }
}

/// Lines split on `\r\n`, `\n` and lone `\r`.
fn split_lines(text: &str) -> Vec<&str> {
    let b = text.as_bytes();
    let mut lines = Vec::new();
    let (mut start, mut i) = (0, 0);
    while i < b.len() {
        match b[i] {
            b'\n' => {
                lines.push(&text[start..i]);
                start = i + 1;
            }
            b'\r' => {
                lines.push(&text[start..i]);
                if b.get(i + 1) == Some(&b'\n') {
                    i += 1;
                }
                start = i + 1;
            }
            _ => {}
        }
        i += 1;
    }
    lines.push(&text[start..]);
    lines
}

/// First invisible joiner in a line. A variation selector after a symbol, an
/// emoji or a digit is ordinary emoji presentation; after a letter it hides.
fn find_joiner(line: &str) -> Option<char> {
    let mut prev: Option<char> = None;
    for c in line.chars() {
        let emoji_selector =
            matches!(c, '\u{FE0E}' | '\u{FE0F}') && prev.is_some_and(|p| !p.is_alphabetic());
        if is_joiner(c) && !emoji_selector {
            return Some(c);
        }
        prev = Some(c);
    }
    None
}

fn scan_text(file: &str, text: &str, out: &mut Vec<Signal>) {
    for (idx, line) in split_lines(text).into_iter().enumerate() {
        let n = (idx + 1) as u32;
        for (pattern, pred) in [
            ("zero_width", is_zero_width as fn(char) -> bool),
            ("bidi_control", is_bidi),
            ("tag_chars", is_tag),
        ] {
            if let Some(c) = line.chars().find(|&c| pred(c)) {
                out.push(signal(pattern, file, n, describe(c)));
            }
        }
        if let Some(c) = find_joiner(line) {
            out.push(signal("invisible_joiner", file, n, describe(c)));
        }
        if line.len() > MAX_LINE_BYTES {
            continue;
        }
        scan_mixed_script(line, file, n, out);
        scan_entropy(line, file, n, out);
    }
}

fn has_script_extension(path: &str) -> bool {
    let name = path.rsplit('/').next().unwrap_or(path);
    match name.rsplit_once('.') {
        Some((_, ext)) => SCRIPT_EXTENSIONS.contains(&ext.to_ascii_lowercase().as_str()),
        None => false,
    }
}

/// Class of a binary file judged by its first bytes, never by its name.
fn magic_class(head: &[u8]) -> &'static str {
    let starts = |p: &[u8]| head.starts_with(p);
    if starts(b"\x7fELF")
        || starts(b"MZ")
        || starts(&[0xFE, 0xED, 0xFA, 0xCE])
        || starts(&[0xFE, 0xED, 0xFA, 0xCF])
        || starts(&[0xCE, 0xFA, 0xED, 0xFE])
        || starts(&[0xCF, 0xFA, 0xED, 0xFE])
        || starts(&[0xCA, 0xFE, 0xBA, 0xBE])
        || starts(&[0xBE, 0xBA, 0xFE, 0xCA])
    {
        "exec"
    } else if starts(&[0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A])
        || starts(&[0xFF, 0xD8, 0xFF])
        || starts(b"GIF87a")
        || starts(b"GIF89a")
        || (starts(b"RIFF") && head.get(8..12) == Some(b"WEBP"))
        || starts(&[0, 0, 1, 0])
        || (starts(b"BM") && head.len() >= 10 && head[6..10] == [0, 0, 0, 0])
    {
        "image"
    } else if starts(b"wOFF") || starts(b"wOF2") || starts(&[0, 1, 0, 0]) || starts(b"OTTO") {
        "font"
    } else if starts(b"%PDF-") {
        "document"
    } else if starts(b"PK")
        || starts(&[0x1F, 0x8B])
        || starts(&[0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C])
        || starts(b"Rar!")
    {
        "archive"
    } else {
        "other"
    }
}

/// Class a file name promises, for image and font extensions.
fn expected_class(ext: &str) -> Option<&'static str> {
    match ext {
        "png" | "jpg" | "jpeg" | "gif" | "webp" | "ico" | "bmp" => Some("image"),
        "woff" | "woff2" | "ttf" | "otf" => Some("font"),
        _ => None,
    }
}

fn file_flags(ctx: &ScanContext, f: &FileEntry, out: &mut Vec<Signal>) {
    if f.content_type == ContentType::Binary {
        let ext = f
            .path
            .rsplit('/')
            .next()
            .and_then(|name| name.rsplit_once('.'))
            .map(|(_, e)| e.to_ascii_lowercase())
            .unwrap_or_default();
        let magic = ctx
            .read_bytes(&f.path)
            .map_or("other", |b| magic_class(&b[..b.len().min(16)]));
        out.push(with_fields(
            signal(
                "binary_file",
                &f.path,
                0,
                "file content is binary".to_string(),
            ),
            &[("ext", &ext), ("magic", magic)],
        ));
        if expected_class(&ext).is_some_and(|want| want != magic) {
            out.push(signal(
                "extension_mismatch",
                &f.path,
                0,
                format!("name says {ext} but the content looks like {magic}"),
            ));
        }
        if has_script_extension(&f.path) {
            out.push(signal(
                "extension_mismatch",
                &f.path,
                0,
                "script or instructions extension but binary content".to_string(),
            ));
        }
    }
    if f.minified {
        out.push(signal(
            "minified_file",
            &f.path,
            0,
            "very long average line length".to_string(),
        ));
    }
    if f.size > OVERSIZED_BYTES {
        out.push(signal(
            "oversized_file",
            &f.path,
            0,
            format!("{} bytes", f.size),
        ));
    }
}

impl Analyzer for HiddenAnalyzer {
    fn id(&self) -> &'static str {
        "hidden"
    }

    fn run(&self, ctx: &ScanContext) -> AnalyzerOutput {
        let mut signals = Vec::new();
        for f in &ctx.inventory.files {
            file_flags(ctx, f, &mut signals);
            if f.content_type == ContentType::Text
                && let Some(text) = ctx.read_text(&f.path)
            {
                scan_text(&f.path, &text, &mut signals);
            }
        }
        AnalyzerOutput {
            signals,
            coverage: Coverage::Ran,
        }
    }
}
