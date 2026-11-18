//! Live progress lines on stderr.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;

use indicatif::{MultiProgress, ProgressBar, ProgressDrawTarget, ProgressStyle};
use skillsniff::model::signal::{AGENT_CONFIG, HIDDEN, INSTRUCTION, SINK, SOURCE, TAINT_FLOW};
use skillsniff::model::{Coverage, Report, Summary};
use skillsniff::progress::{ProgressEvent, ProgressSink};
use skillsniff::rules::builtin;

use super::terminal::{counts_text, pinned};
use super::{
    ColorDepth, GREEN, GREY, Glyphs, OutputMode, RED, Style, TEAL, clean, pad, paint, width_of,
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
/// Narrowest label column, so results line up in one column.
const LABEL_MIN: usize = 44;

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

struct Line {
    id: &'static str,
    bar: ProgressBar,
}

struct Inner {
    multi: MultiProgress,
    color: ColorDepth,
    glyphs: Glyphs,
    source: String,
    fetch: ProgressBar,
    lines: Mutex<Vec<Line>>,
}

/// Spinner lines for fetching and each analyzer; does nothing when output
/// is not decorated.
pub struct TerminalProgress {
    inner: Option<Inner>,
}

impl TerminalProgress {
    /// Starts the "Fetching" line for `source` when decorating.
    pub fn new(mode: &OutputMode, source: &str) -> TerminalProgress {
        if !mode.decorate {
            return TerminalProgress::disabled();
        }
        let multi = MultiProgress::with_draw_target(ProgressDrawTarget::stderr());
        let inner = Inner {
            color: mode.color,
            glyphs: Glyphs::for_mode(mode),
            source: clean(source),
            fetch: ProgressBar::hidden(),
            lines: Mutex::new(Vec::new()),
            multi,
        };
        let fetch = inner.spinner(&format!("Fetching {}", inner.source));
        TerminalProgress {
            inner: Some(Inner { fetch, ..inner }),
        }
    }

    /// A sink that shows nothing.
    pub fn disabled() -> TerminalProgress {
        TerminalProgress { inner: None }
    }

    /// Settles every line with its result once the report is ready.
    pub fn finish(&self, report: &Report, files: usize) {
        let Some(inner) = &self.inner else { return };
        let g = inner.glyphs;
        let c = inner.color;
        let counts = per_analyzer(report);
        let lines = inner.lines.lock().unwrap_or_else(|e| e.into_inner());

        let fetch_label = format!("Fetched {} @ {}", inner.source, pinned(report));
        let label_w = lines
            .iter()
            .map(|l| width_of(analyzer_name(l.id)))
            .chain([width_of(&fetch_label)])
            .max()
            .unwrap_or(0)
            .max(LABEL_MIN)
            + 3;

        let plural = if files == 1 { "file" } else { "files" };
        inner.settle(
            &inner.fetch,
            g.ok,
            Style::fg(GREEN),
            &format!("{}{files} {plural}", pad(&fetch_label, label_w)),
        );
        for line in lines.iter() {
            let name = pad(analyzer_name(line.id), label_w);
            let (mark, style, result) = match report.coverage.get(line.id) {
                Some(Coverage::Failed { .. }) => {
                    (g.failed, Style::fg(RED), paint(c, "failed", Style::fg(RED)))
                }
                Some(Coverage::Skipped { .. }) => (
                    g.skipped,
                    Style::fg(GREY),
                    paint(c, "skipped", Style::fg(GREY)),
                ),
                _ => {
                    let text = counts
                        .get(line.id)
                        .and_then(|s| counts_text(s, g.dot))
                        .map(|t| paint(c, &t, Style::default().bold()))
                        .unwrap_or_else(|| paint(c, "clean", Style::fg(GREY)));
                    (g.ok, Style::fg(GREEN), text)
                }
            };
            inner.settle(&line.bar, mark, style, &format!("{name}{result}"));
        }
    }

    /// Marks the scan as failed before any report exists.
    pub fn fail(&self) {
        let Some(inner) = &self.inner else { return };
        let lines = inner.lines.lock().unwrap_or_else(|e| e.into_inner());
        if lines.is_empty() {
            let text = format!("Could not read {}", inner.source);
            inner.settle(&inner.fetch, inner.glyphs.failed, Style::fg(RED), &text);
        }
        for line in lines.iter() {
            line.bar.finish_and_clear();
        }
    }
}

impl Inner {
    fn spinner(&self, message: &str) -> ProgressBar {
        let ticks: Vec<String> = SPINNER
            .iter()
            .chain([&" "])
            .map(|t| paint(self.color, t, Style::fg(TEAL)))
            .collect();
        let refs: Vec<&str> = ticks.iter().map(String::as_str).collect();
        let style = ProgressStyle::with_template(" {spinner} {msg}")
            .expect("valid template")
            .tick_strings(&refs);
        let bar = self.multi.add(ProgressBar::new_spinner().with_style(style));
        bar.set_message(message.to_string());
        bar.enable_steady_tick(TICK);
        bar
    }

    /// Replaces the spinner with `mark` and shows `text`.
    fn settle(&self, bar: &ProgressBar, mark: &str, style: Style, text: &str) {
        bar.disable_steady_tick();
        bar.set_style(ProgressStyle::with_template(" {msg}").expect("valid template"));
        bar.finish_with_message(format!("{} {text}", paint(self.color, mark, style)));
    }

    /// A finished analyzer keeps its line until the report gives its result.
    fn mark_done(&self, bar: &ProgressBar, id: &str) {
        bar.disable_steady_tick();
        bar.set_style(ProgressStyle::with_template(" {msg}").expect("valid template"));
        bar.set_message(format!(
            "{} {}",
            paint(self.color, self.glyphs.ok, Style::fg(GREEN)),
            analyzer_name(id)
        ));
    }
}

impl ProgressSink for TerminalProgress {
    fn event(&self, e: ProgressEvent) {
        let Some(inner) = &self.inner else { return };
        let mut lines = inner.lines.lock().unwrap_or_else(|e| e.into_inner());
        match e {
            ProgressEvent::Started { id } => {
                if lines.is_empty() {
                    inner.fetch.disable_steady_tick();
                    inner
                        .fetch
                        .set_style(ProgressStyle::with_template(" {msg}").expect("valid template"));
                    inner.fetch.set_message(format!(
                        "{} Fetched {}",
                        paint(inner.color, inner.glyphs.ok, Style::fg(GREEN)),
                        inner.source
                    ));
                    for known in DISPLAY_ORDER {
                        let bar = inner.spinner(analyzer_name(known));
                        lines.push(Line { id: known, bar });
                    }
                }
                if !lines.iter().any(|l| l.id == id) {
                    let bar = inner.spinner(analyzer_name(id));
                    lines.push(Line { id, bar });
                }
            }
            ProgressEvent::Finished { id, .. } => {
                if let Some(l) = lines.iter().find(|l| l.id == id) {
                    inner.mark_done(&l.bar, id);
                }
            }
            ProgressEvent::Failed { id } => {
                if let Some(l) = lines.iter().find(|l| l.id == id) {
                    l.bar.disable_steady_tick();
                    l.bar
                        .set_style(ProgressStyle::with_template(" {msg}").expect("valid template"));
                    l.bar.set_message(format!(
                        "{} {}",
                        paint(inner.color, inner.glyphs.failed, Style::fg(RED)),
                        analyzer_name(id)
                    ));
                }
            }
        }
    }
}
