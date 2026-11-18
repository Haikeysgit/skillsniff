//! Live progress lines on stderr.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;

use indicatif::{ProgressBar, ProgressDrawTarget, ProgressStyle};
use skillsniff::model::signal::{AGENT_CONFIG, HIDDEN, INSTRUCTION, SINK, SOURCE, TAINT_FLOW};
use skillsniff::model::{Coverage, Report, Summary};
use skillsniff::progress::{ProgressEvent, ProgressSink};
use skillsniff::rules::builtin;

use super::terminal::{counts_text, pinned};
use super::{
    AMBER, ColorDepth, GREEN, GREY, Glyphs, OutputMode, RED, Style, TEAL, clean, pad, paint,
};

/// Analyzer ids in the order they are shown.
pub(crate) const DISPLAY_ORDER: &[&str] = &["instructions", "code", "hidden", "agent_config"];

/// `Hidden` rules raised by the code analyzer rather than the hidden one.
const CODE_HIDDEN_RULES: &[&str] = &[
    "hidden.parse-budget-exceeded",
    "hidden.invalid-utf8-script",
    "hidden.parse-errors",
];

const SPINNER: &[&str] = &["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
const TICK: Duration = Duration::from_millis(80);
/// Width of the name column, so results line up.
const NAME_COL: usize = 18;

/// Human name of an analyzer id.
pub fn analyzer_name(id: &str) -> &str {
    match id {
        "instructions" => "Instructions",
        "code" => "Code + dataflow",
        "hidden" => "Hidden content",
        "agent_config" => "Agent config",
        other => other,
    }
}

/// Unsuppressed finding counts per analyzer, attributed through the signal
/// kind of each built-in rule.
fn per_analyzer(report: &Report) -> HashMap<&'static str, Summary> {
    let kinds: HashMap<String, String> = builtin()
        .rules
        .into_iter()
        .map(|r| (r.id, r.signal))
        .collect();
    let mut out: HashMap<&'static str, Summary> = HashMap::new();
    for f in report.findings.iter().filter(|f| !f.suppressed) {
        let analyzer = if CODE_HIDDEN_RULES.contains(&f.rule.as_str()) {
            Some("code")
        } else {
            match kinds.get(&f.rule).map(String::as_str) {
                Some(INSTRUCTION) => Some("instructions"),
                Some(HIDDEN) => Some("hidden"),
                Some(SOURCE | SINK | TAINT_FLOW) => Some("code"),
                Some(AGENT_CONFIG) => Some("agent_config"),
                _ => None,
            }
        };
        let Some(id) = analyzer else { continue };
        let s = out.entry(id).or_default();
        match f.severity {
            skillsniff::model::Severity::Critical => s.critical += 1,
            skillsniff::model::Severity::High => s.high += 1,
            skillsniff::model::Severity::Medium => s.medium += 1,
            skillsniff::model::Severity::Low => s.low += 1,
        }
    }
    out
}

struct Inner {
    color: ColorDepth,
    glyphs: Glyphs,
    source: String,
    spinner: ProgressBar,
    state: Mutex<State>,
}

#[derive(Default)]
struct State {
    /// Analyzers that have started, in display order.
    started: Vec<&'static str>,
    done: usize,
}

/// A spinner while the scan runs, then one line per finished stage; does
/// nothing when output is not decorated.
pub struct TerminalProgress {
    inner: Option<Inner>,
}

/// Colour of an analyzer's result by its worst finding.
fn result_style(s: &Summary) -> Style {
    if s.critical > 0 || s.high > 0 {
        Style::fg(RED)
    } else if s.medium > 0 {
        Style::fg(AMBER)
    } else {
        Style::fg(GREY)
    }
}

impl TerminalProgress {
    /// Starts the "Fetching" spinner for `source` when decorating.
    pub fn new(mode: &OutputMode, source: &str) -> TerminalProgress {
        if !mode.decorate {
            return TerminalProgress::disabled();
        }
        let color = mode.color;
        let ticks: Vec<String> = SPINNER
            .iter()
            .map(|t| paint(color, t, Style::fg(TEAL)))
            .collect();
        let refs: Vec<&str> = ticks.iter().map(String::as_str).collect();
        let style = ProgressStyle::with_template(" {spinner} {msg}")
            .expect("valid template")
            .tick_strings(&refs);
        let spinner =
            ProgressBar::with_draw_target(None, ProgressDrawTarget::stderr()).with_style(style);
        let source = clean(source);
        spinner.set_message(format!("Fetching {source}"));
        spinner.enable_steady_tick(TICK);
        TerminalProgress {
            inner: Some(Inner {
                color,
                glyphs: Glyphs::for_mode(mode),
                source,
                spinner,
                state: Mutex::new(State::default()),
            }),
        }
    }

    /// A sink that shows nothing.
    pub fn disabled() -> TerminalProgress {
        TerminalProgress { inner: None }
    }

    /// Replaces the spinner with one line per stage once the report is ready.
    pub fn finish(&self, report: &Report, files: usize) {
        let Some(inner) = &self.inner else { return };
        let g = inner.glyphs;
        let c = inner.color;
        let counts = per_analyzer(report);
        inner.spinner.finish_and_clear();

        let plural = if files == 1 { "file" } else { "files" };
        let fetched = format!(
            "{} @ {} {} {files} {plural}",
            inner.source,
            pinned(report),
            g.dot
        );
        eprintln!(
            "  {} {} {}",
            paint(c, g.ok, Style::fg(GREEN)),
            pad("Fetched", NAME_COL),
            paint(c, &fetched, Style::fg(GREY))
        );

        let state = inner.state.lock().unwrap_or_else(|e| e.into_inner());
        let mut ids: Vec<&str> = DISPLAY_ORDER.to_vec();
        ids.extend(
            state
                .started
                .iter()
                .copied()
                .filter(|i| !DISPLAY_ORDER.contains(i)),
        );
        for id in ids {
            let (mark, result) = match report.coverage.get(id) {
                Some(Coverage::Failed { .. }) => (
                    paint(c, g.failed, Style::fg(RED)),
                    paint(c, "failed", Style::fg(RED)),
                ),
                Some(Coverage::Skipped { .. }) => (
                    paint(c, g.skipped, Style::fg(GREY)),
                    paint(c, "skipped", Style::fg(GREY)),
                ),
                _ => {
                    let result = match counts.get(id) {
                        Some(s) => match counts_text(s, g.dot) {
                            Some(t) => paint(c, &t, result_style(s)),
                            None => paint(c, "clean", Style::fg(GREEN)),
                        },
                        None => paint(c, "clean", Style::fg(GREEN)),
                    };
                    (paint(c, g.ok, Style::fg(GREEN)), result)
                }
            };
            eprintln!("  {mark} {} {result}", pad(analyzer_name(id), NAME_COL));
        }
    }

    /// Marks the scan as failed before any report exists.
    pub fn fail(&self) {
        let Some(inner) = &self.inner else { return };
        inner.spinner.finish_and_clear();
        eprintln!(
            "  {} Could not read {}",
            paint(inner.color, inner.glyphs.failed, Style::fg(RED)),
            inner.source
        );
    }
}

impl ProgressSink for TerminalProgress {
    fn event(&self, e: ProgressEvent) {
        let Some(inner) = &self.inner else { return };
        let mut state = inner.state.lock().unwrap_or_else(|e| e.into_inner());
        match e {
            ProgressEvent::Started { id } => {
                if !state.started.contains(&id) {
                    state.started.push(id);
                }
            }
            ProgressEvent::Finished { .. } | ProgressEvent::Failed { .. } => {
                state.done += 1;
            }
        }
        let total = state.started.len().max(DISPLAY_ORDER.len());
        let msg = if state.started.is_empty() {
            format!("Fetching {}", inner.source)
        } else {
            format!("Checking {} of {total} stages", state.done.min(total))
        };
        inner.spinner.set_message(msg);
    }
}
