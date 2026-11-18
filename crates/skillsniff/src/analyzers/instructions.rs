//! Instruction text that tries to steer the agent, the user or the reviewer.
//!
//! Every Markdown file is scanned as plain text, so fenced and inline code,
//! link targets and titles, image alt text, HTML blocks and comments are all
//! covered. Text is lower-cased, whitespace-collapsed and stripped of
//! invisible characters before matching; a second pass also drops common
//! Markdown and HTML markup so emphasis or tags cannot split a phrase.

mod phrases;

use std::collections::{BTreeMap, BTreeSet};

use crate::analyzers::{
    Analyzer, AnalyzerOutput, ScanContext, is_invisible, read_lossy, safe_evidence,
    unreadable_signal,
};
use crate::frontmatter::parse_frontmatter;
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
        out.push(Rule {
            pattern,
            elems: compile(s),
            end_boundary,
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
        c => c,
    }
}

fn is_markup(c: char) -> bool {
    matches!(c, '*' | '_' | '`' | '~' | '\\' | '>' | '|')
}

fn normalize(text: &str, strip_markup: bool) -> Norm {
    let src: Vec<char> = text.chars().collect();
    let mut chars: Vec<char> = Vec::with_capacity(src.len());
    let mut lines: Vec<u32> = Vec::with_capacity(src.len());
    let mut line = 1u32;
    let mut i = 0;
    let space = |chars: &mut Vec<char>, lines: &mut Vec<u32>, line: u32| {
        if chars.last().is_some_and(|&c| c != ' ') {
            chars.push(' ');
            lines.push(line);
        }
    };
    while i < src.len() {
        let c = src[i];
        if strip_markup
            && c == '<'
            && src
                .get(i + 1)
                .is_some_and(|n| n.is_ascii_alphabetic() || *n == '/')
            && let Some(rel) = src[i..(i + MAX_TAG_CHARS).min(src.len())]
                .iter()
                .position(|&x| x == '>')
            && !src[i + 1..i + rel].contains(&'<')
        {
            line += src[i..=i + rel].iter().filter(|&&x| x == '\n').count() as u32;
            space(&mut chars, &mut lines, line);
            i += rel + 1;
            continue;
        }
        if c == '\n' {
            line += 1;
        }
        i += 1;
        if is_invisible(c) || (strip_markup && is_markup(c)) {
            continue;
        }
        if c.is_whitespace() {
            space(&mut chars, &mut lines, line);
            continue;
        }
        for l in fold_char(c).to_lowercase() {
            chars.push(l);
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
fn find_hits(text: &str, rules: &[Rule]) -> Vec<Hit> {
    let mut seen: BTreeSet<(&'static str, u32)> = BTreeSet::new();
    let mut hits = Vec::new();
    for strip in [false, true] {
        let norm = normalize(text, strip);
        let t = &norm.chars;
        for start in 0..t.len() {
            if start > 0 && t[start - 1].is_alphanumeric() {
                continue;
            }
            for r in rules {
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
    hits
}

/// HTML comments as (line of the opener, inner text). An unterminated
/// comment runs to the end of the file, as Markdown renders it.
fn html_comments(text: &str) -> Vec<(u32, String)> {
    let mut chars: Vec<char> = Vec::new();
    let mut lines: Vec<u32> = Vec::new();
    let mut line = 1u32;
    for c in text.chars() {
        if c == '\n' {
            line += 1;
        }
        if !is_invisible(c) {
            chars.push(c);
            lines.push(line);
        }
    }
    let find = |from: usize, pat: &[char]| {
        chars[from.min(chars.len())..]
            .windows(pat.len())
            .position(|w| w == pat)
            .map(|p| p + from)
    };
    let open: Vec<char> = "<!--".chars().collect();
    let close: Vec<char> = "-->".chars().collect();
    let mut out = Vec::new();
    let mut at = 0;
    while let Some(s) = find(at, &open) {
        let (inner_end, next) = match find(s + 4, &close) {
            Some(e) => (e, e + 3),
            None => (chars.len(), chars.len()),
        };
        let inner: String = chars[(s + 4).min(inner_end)..inner_end].iter().collect();
        out.push((lines[s], inner));
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

fn scan_file(file: &str, text: &str, is_skill_md: bool, rules: &[Rule], out: &mut Vec<Signal>) {
    let mut hits = find_hits(text, rules);
    for (line, inner) in html_comments(text) {
        let len = inner.chars().count();
        if len > LONG_COMMENT_CHARS {
            hits.push(Hit {
                pattern: "hidden_comment",
                line,
                evidence: format!("HTML comment of {len} characters"),
            });
        } else if let Some(h) = find_hits(&inner, rules).first() {
            hits.push(Hit {
                pattern: "hidden_comment",
                line,
                evidence: format!("HTML comment containing: {}", h.evidence),
            });
        }
    }
    if is_skill_md
        && let Ok((fields, _)) = parse_frontmatter(text)
        && let Some(desc) = fields.get("description")
        && let Some(h) = find_hits(desc, &broad_rules()).first()
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
}

impl Analyzer for InstructionsAnalyzer {
    fn id(&self) -> &'static str {
        "instructions"
    }

    fn run(&self, ctx: &ScanContext) -> AnalyzerOutput {
        let rules = family_rules();
        let mut signals = Vec::new();
        for (path, role) in &ctx.roles {
            if *role != FileRole::Instructions {
                continue;
            }
            let Some(text) = read_lossy(ctx, path) else {
                signals.push(unreadable_signal(path));
                continue;
            };
            let name = path.rsplit('/').next().unwrap_or(path);
            scan_file(path, &text, name == "SKILL.md", &rules, &mut signals);
        }
        AnalyzerOutput {
            signals,
            coverage: Coverage::Ran,
        }
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
