//! Code analyzer: parses scripts with tree-sitter, reports secret sources and
//! dangerous sinks, and tracks taint from one to the other within a file.

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

pub use lang_python::PythonRules;
pub use patterns::{SINK_CLASSES, SOURCE_CLASSES};
pub use taint::{Facts, Flow, Site, mark_download_exec, propagate};

/// Wall-clock budget for parsing one file, and separately for extracting its
/// facts.
pub const PARSE_BUDGET: Duration = Duration::from_secs(2);

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
        Lang::JavaScript | Lang::TypeScript | Lang::Bash | Lang::PowerShell => None,
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

fn budget_signal(file: &str) -> Signal {
    signal(
        HIDDEN,
        &[("pattern", "parse_budget_exceeded")],
        vec![Location {
            file: file.to_string(),
            line: 0,
        }],
        &format!(
            "analysis stopped after {}s; file only partly checked",
            PARSE_BUDGET.as_secs()
        ),
    )
}

fn at(file: &str, line: u32) -> Location {
    Location {
        file: file.to_string(),
        line,
    }
}

/// Signals for one file's facts: sinks and sources (each sorted by line, with
/// exact repeats dropped), then flows.
fn file_signals(file: &str, lang: &str, facts: &Facts, out: &mut Vec<Signal>) {
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
    for f in propagate(facts) {
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

impl Analyzer for CodeAnalyzer {
    fn id(&self) -> &'static str {
        "code"
    }

    fn run(&self, ctx: &ScanContext) -> AnalyzerOutput {
        let mut signals = Vec::new();
        for (path, role) in &ctx.roles {
            let FileRole::Script(lang) = role else {
                continue;
            };
            let Some((rules, lang_name)) = rules_for(*lang) else {
                continue;
            };
            let Some(src) = ctx.read_text(path) else {
                continue;
            };
            let tree = match parse(&rules.language(), &src, PARSE_BUDGET) {
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
            let mut facts = rules.facts(&tree, &src);
            if facts.budget_exceeded {
                signals.push(budget_signal(path));
            }
            mark_download_exec(&mut facts);
            file_signals(path, lang_name, &facts, &mut signals);
        }
        AnalyzerOutput {
            signals,
            coverage: Coverage::Ran,
        }
    }
}
