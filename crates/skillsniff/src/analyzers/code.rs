//! Code analyzer: parses scripts with tree-sitter, reports secret sources and
//! dangerous sinks, and tracks taint from one to the other within a file.

mod common;
pub mod lang_bash;
pub mod lang_js;
pub mod lang_powershell;
pub mod lang_python;
pub mod patterns;
pub mod taint;

use std::collections::{BTreeMap, BTreeSet};
use std::ops::ControlFlow;
use std::time::{Duration, Instant};

use tree_sitter::{Language, ParseOptions, ParseState, Parser, Tree};

use crate::analyzers::{Analyzer, AnalyzerOutput, ScanContext};
use crate::model::signal::{HIDDEN, SINK, SOURCE, TAINT_FLOW};
use crate::model::{Coverage, Location, Signal, sanitize_evidence};
use crate::target::{FileRole, Lang};

pub use lang_bash::BashRules;
pub use lang_js::JsRules;
pub use lang_powershell::PowerShellRules;
pub use lang_python::PythonRules;
pub use patterns::{SINK_CLASSES, SOURCE_CLASSES};
pub use taint::{Facts, Flow, Site, mark_download_exec, propagate, propagate_bounded};

/// Wall-clock budget for parsing one file, and separately for extracting its
/// facts.
pub const PARSE_BUDGET: Duration = Duration::from_secs(2);

/// Wall-clock budget for the whole analyzer, below the runner's timeout so
/// partial results survive. Files not started in time are reported as
/// `parse_budget_exceeded`.
pub const ANALYZER_DEADLINE: Duration = Duration::from_secs(20);

/// Longest piece of display text kept on each side of an evidence arrow.
const EVIDENCE_PART_CHARS: usize = 90;

/// Per-language extraction of sources, sinks and assignments.
pub trait LangRules: Send + Sync {
    fn language(&self) -> Language;
    /// Facts of one parsed file. Implementations stop early and set
    /// [`Facts::budget_exceeded`] once extraction runs past [`PARSE_BUDGET`].
    fn facts(&self, tree: &Tree, src: &str) -> Facts;
}

/// Rules and the `lang` field value for a script language, when registered.
fn rules_for(lang: Lang) -> Option<(&'static dyn LangRules, &'static str)> {
    match lang {
        Lang::Python => Some((&PythonRules, "python")),
        Lang::JavaScript => Some((&JsRules { typescript: false }, "javascript")),
        Lang::TypeScript => Some((&JsRules { typescript: true }, "typescript")),
        Lang::Bash => Some((&BashRules, "bash")),
        Lang::PowerShell => Some((&PowerShellRules, "powershell")),
    }
}

/// Shortens display text to at most `max` characters.
pub fn clip(text: &str, max: usize) -> String {
    if text.chars().count() <= max {
        return text.to_string();
    }
    let mut out: String = text.chars().take(max.saturating_sub(1)).collect();
    out.push('…');
    out
}

/// Parses `src`, giving up after `budget`. `None` means the budget ran out.
fn parse(language: &Language, src: &str, budget: Duration) -> Result<Option<Tree>, String> {
    let mut parser = Parser::new();
    parser
        .set_language(language)
        .map_err(|e| format!("grammar rejected: {e}"))?;
    let bytes = src.as_bytes();
    let start = Instant::now();
    let mut progress = |_: &ParseState| {
        if start.elapsed() > budget {
            ControlFlow::Break(())
        } else {
            ControlFlow::Continue(())
        }
    };
    let options = ParseOptions::new().progress_callback(&mut progress);
    Ok(parser.parse_with_options(
        &mut |i, _| bytes.get(i..).unwrap_or_default(),
        None,
        Some(options),
    ))
}

fn signal(kind: &str, fields: &[(&str, &str)], locations: Vec<Location>, evidence: &str) -> Signal {
    Signal {
        kind: kind.to_string(),
        fields: fields
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect(),
        locations,
        evidence: sanitize_evidence(evidence),
    }
}

fn hidden_signal(file: &str, pattern: &str, evidence: &str) -> Signal {
    signal(
        HIDDEN,
        &[("pattern", pattern)],
        vec![Location {
            file: file.to_string(),
            line: 0,
        }],
        evidence,
    )
}

fn budget_signal(file: &str) -> Signal {
    let why = format!(
        "analysis stopped after {}s; file only partly checked",
        PARSE_BUDGET.as_secs()
    );
    hidden_signal(file, "parse_budget_exceeded", &why)
}

/// Script text, decoded lossily when it is not valid UTF-8 (Python and
/// other interpreters accept declared encodings). The flag is true for lossy.
fn read_script(ctx: &ScanContext, path: &str) -> Option<(String, bool)> {
    let bytes = ctx.read_bytes(path)?;
    let bytes = bytes.strip_prefix(b"\xef\xbb\xbf").unwrap_or(&bytes);
    Some(match std::str::from_utf8(bytes) {
        Ok(text) => (text.to_string(), false),
        Err(_) => (String::from_utf8_lossy(bytes).into_owned(), true),
    })
}

/// Line of the first syntax error or missing token in a tree, if any.
fn first_error_line(tree: &Tree) -> Option<u32> {
    let mut node = tree.root_node();
    if !node.has_error() {
        return None;
    }
    let mut cursor = node.walk();
    'down: loop {
        if node.is_error() || node.is_missing() {
            break;
        }
        for child in node.children(&mut cursor) {
            if child.is_error() || child.is_missing() || child.has_error() {
                node = child;
                continue 'down;
            }
        }
        break;
    }
    Some(u32::try_from(node.start_position().row + 1).unwrap_or(u32::MAX))
}

fn at(file: &str, line: u32) -> Location {
    Location {
        file: file.to_string(),
        line,
    }
}

/// Signals for one file's facts: sinks and sources (each sorted by line, with
/// exact repeats dropped), then flows.
fn file_signals(file: &str, lang: &str, facts: &Facts, flows: &[Flow], out: &mut Vec<Signal>) {
    let mut seen = BTreeSet::new();
    let mut sites: Vec<(&str, &Site)> = facts
        .sources
        .iter()
        .map(|s| (SOURCE, s))
        .chain(facts.sinks.iter().map(|s| (SINK, s)))
        .collect();
    sites.sort_by(|a, b| {
        (a.0, a.1.line, &a.1.class, &a.1.text).cmp(&(b.0, b.1.line, &b.1.class, &b.1.text))
    });
    for (kind, s) in sites {
        if seen.insert((kind, s.line, s.class.as_str(), s.text.as_str())) {
            out.push(signal(
                kind,
                &[("class", &s.class), ("lang", lang)],
                vec![at(file, s.line)],
                &clip(&s.text, EVIDENCE_PART_CHARS),
            ));
        }
    }

    let text_of: BTreeMap<&str, &str> = facts
        .sources
        .iter()
        .chain(&facts.sinks)
        .map(|s| (s.id.as_str(), s.text.as_str()))
        .collect();
    let mut seen_flows = BTreeSet::new();
    for f in flows {
        let key = (
            f.from_class.clone(),
            f.to_class.clone(),
            f.source_line,
            f.sink_line,
        );
        if !seen_flows.insert(key) {
            continue;
        }
        let part = |id: &str| clip(text_of.get(id).copied().unwrap_or(""), EVIDENCE_PART_CHARS);
        out.push(signal(
            TAINT_FLOW,
            &[("from", &f.from_class), ("to", &f.to_class), ("lang", lang)],
            vec![at(file, f.source_line), at(file, f.sink_line)],
            &format!("{} -> {}", part(&f.source_id), part(&f.sink_id)),
        ));
    }
}

/// Static source, sink and taint analysis of script files.
pub struct CodeAnalyzer;

impl CodeAnalyzer {
    /// Analyzes script files until `deadline` (measured from the call) runs
    /// out; files not reached by then each get a `parse_budget_exceeded`
    /// signal, and everything gathered so far is returned with `Ran`.
    pub fn run_with_deadline(&self, ctx: &ScanContext, deadline: Duration) -> AnalyzerOutput {
        let started = Instant::now();
        let mut signals = Vec::new();
        for (path, role) in &ctx.roles {
            let FileRole::Script(lang) = role else {
                continue;
            };
            let Some((rules, lang_name)) = rules_for(*lang) else {
                continue;
            };
            let left = deadline.saturating_sub(started.elapsed());
            if left.is_zero() {
                signals.push(hidden_signal(
                    path,
                    "parse_budget_exceeded",
                    "not analyzed: code analysis time limit reached",
                ));
                continue;
            }
            let Some((src, lossy)) = read_script(ctx, path) else {
                continue;
            };
            if lossy {
                signals.push(hidden_signal(
                    path,
                    "invalid_utf8_script",
                    "script is not valid UTF-8; analyzed with replacement characters",
                ));
            }
            let tree = match parse(&rules.language(), &src, left.min(PARSE_BUDGET)) {
                Ok(Some(tree)) => tree,
                Ok(None) => {
                    signals.push(budget_signal(path));
                    continue;
                }
                Err(reason) => {
                    return AnalyzerOutput {
                        signals: Vec::new(),
                        coverage: Coverage::Failed { reason },
                    };
                }
            };
            if let Some(line) = first_error_line(&tree) {
                signals.push(signal(
                    HIDDEN,
                    &[("pattern", "parse_errors")],
                    vec![at(path, line)],
                    &format!("script does not parse from line {line}; code there may be misread"),
                ));
            }
            let mut facts = rules.facts(&tree, &src);
            let mut partial = facts.budget_exceeded;
            partial |= mark_download_exec(&mut facts);
            let (flows, cut) = propagate_bounded(&facts);
            if partial || cut {
                signals.push(budget_signal(path));
            }
            file_signals(path, lang_name, &facts, &flows, &mut signals);
        }
        AnalyzerOutput {
            signals,
            coverage: Coverage::Ran,
        }
    }
}

impl Analyzer for CodeAnalyzer {
    fn id(&self) -> &'static str {
        "code"
    }

    fn run(&self, ctx: &ScanContext) -> AnalyzerOutput {
        self.run_with_deadline(ctx, ANALYZER_DEADLINE)
    }
}
