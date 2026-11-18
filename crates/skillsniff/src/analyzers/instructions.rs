//! Instruction text that tries to steer the agent, the user or the reviewer.
//!
//! Every Markdown file is scanned as plain text, so fenced and inline code,
//! link targets and titles, image alt text, HTML blocks and comments are all
//! covered. Text is lower-cased, whitespace-collapsed and stripped of
//! invisible characters before matching; a second pass also drops common
//! Markdown and HTML markup so emphasis or tags cannot split a phrase.

mod phrases;

use std::collections::{BTreeMap, BTreeSet};
use std::time::{Duration, Instant};

use crate::analyzers::{
    Analyzer, AnalyzerOutput, ScanContext, budget_signal, is_invisible, read_lossy, safe_evidence,
    unreadable_signal,
};
use crate::frontmatter::parse_frontmatter;
use crate::inventory::ContentType;
use crate::model::signal::INSTRUCTION;
use crate::model::{Coverage, Location, Signal};
use crate::target::FileRole;

/// Every `pattern` value this analyzer can emit.
pub const INSTRUCTION_PATTERNS: &[&str] = &[
    "prompt_injection",
    "permission_bypass",
    "remote_instructions",
    "reviewer_directed",
    "secret_request",
    "hidden_comment",
    "broad_trigger",
];

/// HTML comments longer than this many characters are flagged.
const LONG_COMMENT_CHARS: usize = 200;
/// Wall-clock budget for the whole analyzer, below the runner timeout.
pub const ANALYZER_DEADLINE: Duration = Duration::from_secs(20);
/// Longest HTML tag removed in the markup-stripped pass.
const MAX_TAG_CHARS: usize = 60;

/// Looks for steering text in Markdown files.
pub struct InstructionsAnalyzer;

enum Elem {
    Alt(Vec<Vec<char>>),
    Gap(usize),
}

struct Rule {
    pattern: &'static str,
    elems: Vec<Elem>,
    end_boundary: bool,
    firsts: [bool; 128],
}

fn compile(spec: &str) -> Vec<Elem> {
    let cs: Vec<char> = spec.chars().collect();
    let mut out = Vec::new();
    let mut lit: Vec<char> = Vec::new();
    let mut i = 0;
    let flush = |lit: &mut Vec<char>, out: &mut Vec<Elem>| {
        if !lit.is_empty() {
            out.push(Elem::Alt(vec![std::mem::take(lit)]));
        }
    };
    while i < cs.len() {
        match cs[i] {
            '\\' => {
                lit.push(cs[i + 1]);
                i += 2;
            }
            '(' => {
                flush(&mut lit, &mut out);
                let mut alts = vec![Vec::new()];
                i += 1;
                while cs[i] != ')' {
                    match cs[i] {
                        '|' => alts.push(Vec::new()),
                        '\\' => {
                            i += 1;
                            alts.last_mut().unwrap().push(cs[i]);
                        }
                        '(' | '?' => panic!("nested group or bare ? in {spec:?}"),
                        c => alts.last_mut().unwrap().push(c),
                    }
                    i += 1;
                }
                i += 1;
                out.push(Elem::Alt(alts));
            }
            '{' => {
                flush(&mut lit, &mut out);
                let end = cs[i..].iter().position(|&c| c == '}').unwrap() + i;
                let n: String = cs[i + 1..end].iter().collect();
                out.push(Elem::Gap(n.parse().unwrap()));
                i = end + 1;
            }
            '?' => panic!("unescaped ? in phrase spec {spec:?}"),
            c => {
                lit.push(c);
                i += 1;
            }
        }
    }
    flush(&mut lit, &mut out);
    out
}

fn rules_for(pattern: &'static str, specs: &[&str], end_boundary: bool, out: &mut Vec<Rule>) {
    for s in specs {
        let (s, word_end) = s.strip_suffix("$w").map_or((*s, false), |p| (p, true));
        let end_boundary = end_boundary || word_end;
        let elems = compile(s);
        let mut firsts = [false; 128];
        if let Some(Elem::Alt(alts)) = elems.first() {
            for c in alts.iter().filter_map(|a| a.first()) {
                if c.is_ascii() {
                    firsts[*c as usize] = true;
                }
            }
        }
        out.push(Rule {
            pattern,
            elems,
            end_boundary,
            firsts,
        });
    }
}

/// Rules for every family except `broad_trigger`.
fn family_rules() -> Vec<Rule> {
    let mut v = Vec::new();
    rules_for("prompt_injection", phrases::PROMPT_INJECTION, false, &mut v);
    rules_for(
        "permission_bypass",
        phrases::PERMISSION_BYPASS,
        false,
        &mut v,
    );
    rules_for(
        "remote_instructions",
        phrases::REMOTE_INSTRUCTIONS,
        false,
        &mut v,
    );
    rules_for(
        "reviewer_directed",
        phrases::REVIEWER_DIRECTED,
        false,
        &mut v,
    );
    rules_for("secret_request", phrases::SECRET_REQUEST, false, &mut v);
    v
}

fn broad_rules() -> Vec<Rule> {
    let mut v = Vec::new();
    rules_for("broad_trigger", phrases::BROAD_TRIGGER, true, &mut v);
    v
}

fn match_from(elems: &[Elem], text: &[char], pos: usize) -> Option<usize> {
    let Some((first, rest)) = elems.split_first() else {
        return Some(pos);
    };
    match first {
        Elem::Alt(alts) => alts
            .iter()
            .filter(|a| text[pos..].starts_with(a))
            .find_map(|a| match_from(rest, text, pos + a.len())),
        Elem::Gap(n) => (0..=*n)
            .take_while(|k| pos + k <= text.len())
            .find_map(|k| match_from(rest, text, pos + k)),
    }
}

/// Text prepared for matching, with the 1-based source line of every char.
struct Norm {
    chars: Vec<char>,
    lines: Vec<u32>,
}

fn fold_char(c: char) -> char {
    match c {
        '\u{2018}' | '\u{2019}' | '\u{02BC}' => '\'',
        '\u{2010}'..='\u{2015}' | '\u{2212}' => '-',
        // Cyrillic and Greek look-alikes of Latin letters.
        '\u{0430}' | '\u{03B1}' => 'a',
        '\u{0435}' | '\u{03B5}' => 'e',
        '\u{043E}' | '\u{03BF}' => 'o',
        '\u{0440}' | '\u{03C1}' => 'p',
        '\u{0441}' => 'c',
        '\u{0443}' => 'y',
        '\u{0445}' => 'x',
        '\u{0456}' | '\u{03B9}' => 'i',
        '\u{0458}' => 'j',
        '\u{0455}' => 's',
        '\u{043A}' | '\u{03BA}' => 'k',
        '\u{03BD}' => 'v',
        '\u{03C5}' => 'u',
        '\u{0501}' => 'd',
        c => c,
    }
}

fn is_markup(c: char) -> bool {
    matches!(
        c,
        '*' | '_' | '`' | '~' | '\\' | '>' | '|' | '#' | '\u{2022}' | '\u{00B7}'
    )
}

fn is_separator(c: char) -> bool {
    matches!(c, '.' | ',' | ';' | ':' | '!' | '?')
}

/// Decodes an HTML character reference at the start of `s`.
fn decode_entity(s: &str) -> Option<(char, usize)> {
    let end = s.char_indices().take(12).find(|&(_, c)| c == ';')?.0;
    let body = &s[1..end];
    let c = if let Some(num) = body.strip_prefix('#') {
        let code = match num.strip_prefix(['x', 'X']) {
            Some(hex) => u32::from_str_radix(hex, 16).ok()?,
            None => num.parse().ok()?,
        };
        char::from_u32(code)?
    } else {
        match body {
            "nbsp" => ' ',
            "amp" => '&',
            "lt" => '<',
            "gt" => '>',
            "quot" => '"',
            "apos" => '\'',
            _ => return None,
        }
    };
    Some((c, end + 1))
}

/// End offset (after `>`) of a short HTML tag at the start of `s`.
fn tag_len(s: &str) -> Option<usize> {
    let mut it = s.char_indices();
    it.next();
    if !it
        .next()
        .is_some_and(|(_, n)| n.is_ascii_alphabetic() || n == '/')
    {
        return None;
    }
    for (i, c) in it.take(MAX_TAG_CHARS) {
        match c {
            '<' => return None,
            '>' => return Some(i + 1),
            _ => {}
        }
    }
    None
}

/// One linear pass. `strip_markup` also drops Markdown and HTML markup and
/// treats sentence punctuation and list dashes as spaces.
fn normalize(text: &str, strip_markup: bool) -> Norm {
    let mut chars: Vec<char> = Vec::with_capacity(text.len());
    let mut lines: Vec<u32> = Vec::with_capacity(text.len());
    let mut line = 1u32;
    let mut i = 0;
    let space = |chars: &mut Vec<char>, lines: &mut Vec<u32>, line: u32| {
        if chars.last().is_some_and(|&c| c != ' ') {
            chars.push(' ');
            lines.push(line);
        }
    };
    while i < text.len() {
        let rest = &text[i..];
        let Some(c) = rest.chars().next() else { break };
        if strip_markup
            && c == '<'
            && let Some(n) = tag_len(rest)
        {
            line += rest[..n].matches('\n').count() as u32;
            space(&mut chars, &mut lines, line);
            i += n;
            continue;
        }
        let (ch, len, literal) = match c {
            '&' => decode_entity(rest).map_or((c, 1, true), |(d, n)| (d, n, false)),
            _ => (c, c.len_utf8(), true),
        };
        if ch == '\n' && literal {
            line += 1;
        }
        i += len;
        if is_invisible(ch) || (strip_markup && is_markup(ch)) {
            continue;
        }
        if ch == '\\'
            && chars.last().is_some_and(|p| p.is_alphabetic())
            && text[i..].chars().next().is_some_and(char::is_alphabetic)
        {
            continue;
        }
        let list_dash = strip_markup
            && ch == '-'
            && chars.last().is_none_or(|&p| p == ' ')
            && text[i..].chars().next().is_some_and(char::is_whitespace);
        if ch.is_whitespace() || (strip_markup && is_separator(ch)) || list_dash {
            space(&mut chars, &mut lines, line);
            continue;
        }
        for l in fold_char(ch).to_lowercase() {
            chars.push(fold_char(l));
            lines.push(line);
        }
    }
    Norm { chars, lines }
}

struct Hit {
    pattern: &'static str,
    line: u32,
    evidence: String,
}

/// First hit of each (pattern, line) in either normalization of `text`.
/// The flag is false when `deadline` passed before every position was tried.
fn find_hits(text: &str, rules: &[Rule], deadline: Instant) -> (Vec<Hit>, bool) {
    let mut seen: BTreeSet<(&'static str, u32)> = BTreeSet::new();
    let mut hits = Vec::new();
    for strip in [false, true] {
        let norm = normalize(text, strip);
        let t = &norm.chars;
        for start in 0..t.len() {
            if start % 4096 == 0 && Instant::now() > deadline {
                return (hits, false);
            }
            let c = t[start];
            if !c.is_ascii() || (start > 0 && t[start - 1].is_alphanumeric()) {
                continue;
            }
            for r in rules.iter().filter(|r| r.firsts[c as usize]) {
                let Some(end) = match_from(&r.elems, t, start) else {
                    continue;
                };
                if r.end_boundary && t.get(end).is_some_and(|c| c.is_alphanumeric()) {
                    continue;
                }
                let line = norm.lines[start];
                if seen.insert((r.pattern, line)) {
                    let snippet: String = t[start..end].iter().collect();
                    hits.push(Hit {
                        pattern: r.pattern,
                        line,
                        evidence: safe_evidence(&snippet),
                    });
                }
            }
        }
    }
    (hits, true)
}

/// HTML comments as (line of the opener, inner text). An unterminated
/// comment runs to the end of the file, as Markdown renders it. One pass over
/// the text; the search cursor never moves back.
fn html_comments(text: &str) -> Vec<(u32, String)> {
    let stripped: String = text.chars().filter(|&c| !is_invisible(c)).collect();
    let mut out = Vec::new();
    let (mut at, mut line_pos, mut line) = (0usize, 0usize, 1u32);
    while let Some(rel) = stripped[at..].find("<!--") {
        let s = at + rel;
        line += stripped[line_pos..s].matches('\n').count() as u32;
        line_pos = s;
        let body = s + 4;
        let (inner_end, next) = match stripped[body..].find("-->") {
            Some(e) => (body + e, body + e + 3),
            None => (stripped.len(), stripped.len()),
        };
        out.push((line, stripped[body..inner_end].to_string()));
        at = next;
    }
    out
}

fn description_line(text: &str) -> u32 {
    text.split('\n')
        .position(|l| {
            let l = l.trim_start();
            l.strip_prefix("description")
                .is_some_and(|r| r.trim_start().starts_with(':'))
        })
        .map_or(1, |i| i as u32 + 1)
}

fn signal(pattern: &str, file: &str, line: u32, evidence: String) -> Signal {
    Signal {
        kind: INSTRUCTION.to_string(),
        fields: BTreeMap::from([("pattern".to_string(), pattern.to_string())]),
        locations: vec![Location {
            file: file.to_string(),
            line,
        }],
        evidence,
    }
}

/// Returns false when the file was only partly checked.
fn scan_file(
    file: &str,
    text: &str,
    is_skill_md: bool,
    rules: &[Rule],
    deadline: Instant,
    out: &mut Vec<Signal>,
) -> bool {
    let (mut hits, mut complete) = find_hits(text, rules, deadline);
    for (line, inner) in html_comments(text) {
        let len = inner.chars().count();
        if len > LONG_COMMENT_CHARS {
            hits.push(Hit {
                pattern: "hidden_comment",
                line,
                evidence: format!("HTML comment of {len} characters"),
            });
        } else {
            let (found, done) = find_hits(&inner, rules, deadline);
            complete &= done;
            if let Some(h) = found.first() {
                hits.push(Hit {
                    pattern: "hidden_comment",
                    line,
                    evidence: format!("HTML comment containing: {}", h.evidence),
                });
            }
        }
    }
    if is_skill_md
        && let Ok((fields, _)) = parse_frontmatter(text)
        && let Some(desc) = fields.get("description")
        && let Some(h) = find_hits(desc, &broad_rules(), deadline).0.first()
    {
        hits.push(Hit {
            pattern: "broad_trigger",
            line: description_line(text),
            evidence: format!("description contains \"{}\"", h.evidence),
        });
    }
    hits.sort_by(|a, b| (a.line, a.pattern).cmp(&(b.line, b.pattern)));
    hits.dedup_by(|a, b| a.line == b.line && a.pattern == b.pattern);
    for h in hits {
        out.push(signal(h.pattern, file, h.line, safe_evidence(&h.evidence)));
    }
    complete
}

/// Extensions of plain-text documents an agent may be told to read.
const TEXT_DOC_EXTENSIONS: &[&str] = &["txt", "rst", "adoc", "org"];

/// Files to scan: Markdown, plain-text documents, and any text file a
/// `SKILL.md` names by path or file name.
fn select_files(ctx: &ScanContext, skill_mds: &[(String, String)]) -> Vec<String> {
    let mut picked = BTreeSet::new();
    for f in &ctx.inventory.files {
        let role = ctx.roles.get(&f.path).copied();
        if role == Some(FileRole::Instructions) {
            picked.insert(f.path.clone());
            continue;
        }
        if f.content_type != ContentType::Text
            || matches!(role, Some(FileRole::Script(_)) | Some(FileRole::Binary))
        {
            continue;
        }
        let name = f.path.rsplit('/').next().unwrap_or(&f.path);
        let ext = name.rsplit_once('.').map(|(_, e)| e.to_ascii_lowercase());
        let listed = ext
            .as_deref()
            .is_some_and(|e| TEXT_DOC_EXTENSIONS.contains(&e));
        let named = skill_mds.iter().any(|(dir, text)| {
            let rel = f
                .path
                .strip_prefix(dir.as_str())
                .map_or(f.path.as_str(), |r| r.trim_start_matches('/'));
            text.contains(rel) || (name.len() >= 4 && name.contains('.') && text.contains(name))
        });
        if listed || named {
            picked.insert(f.path.clone());
        }
    }
    picked.into_iter().collect()
}

impl InstructionsAnalyzer {
    /// Scans files until `budget` (measured from the call) runs out. Files not
    /// reached, or only partly checked, each get a `parse_budget_exceeded`
    /// signal.
    pub fn run_with_deadline(&self, ctx: &ScanContext, budget: Duration) -> AnalyzerOutput {
        let deadline = Instant::now() + budget;
        let secs = budget.as_secs();
        let rules = family_rules();
        let mut skill_mds = Vec::new();
        for (path, role) in &ctx.roles {
            if *role == FileRole::Instructions
                && path.rsplit('/').next() == Some("SKILL.md")
                && let Some(text) = read_lossy(ctx, path)
            {
                let dir = path.rsplit_once('/').map_or("", |(d, _)| d).to_string();
                skill_mds.push((dir, text));
            }
        }
        let mut signals = Vec::new();
        for path in select_files(ctx, &skill_mds) {
            if Instant::now() >= deadline {
                signals.push(budget_signal(&path, secs));
                continue;
            }
            let Some(text) = read_lossy(ctx, &path) else {
                signals.push(unreadable_signal(&path));
                continue;
            };
            let name = path.rsplit('/').next().unwrap_or(&path);
            if !scan_file(
                &path,
                &text,
                name == "SKILL.md",
                &rules,
                deadline,
                &mut signals,
            ) {
                signals.push(budget_signal(&path, secs));
            }
        }
        AnalyzerOutput {
            signals,
            coverage: Coverage::Ran,
        }
    }
}

impl Analyzer for InstructionsAnalyzer {
    fn id(&self) -> &'static str {
        "instructions"
    }

    fn run(&self, ctx: &ScanContext) -> AnalyzerOutput {
        self.run_with_deadline(ctx, ANALYZER_DEADLINE)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_phrase_compiles() {
        assert!(!family_rules().is_empty());
        assert!(!broad_rules().is_empty());
    }
}
