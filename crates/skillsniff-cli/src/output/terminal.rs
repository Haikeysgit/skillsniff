//! The verdict card and the JSON report.

use skillsniff::model::{Coverage, Finding, Report, Severity, Summary, Verdict};

use super::progress::{DISPLAY_ORDER, analyzer_name};
use super::{
    AMBER, Color, GREEN, GREY, Glyphs, OutputMode, RED, Style, WHITE, clean, pad, paint, width_of,
};

/// Findings listed under the card; the rest are counted.
const TOP_FINDINGS: usize = 5;
/// Locations listed per finding; the rest are counted.
const TOP_LOCATIONS: usize = 3;
/// Card width when the terminal allows it.
const CARD_MIN: usize = 58;
/// Left margin of everything below the card.
const INDENT: &str = "   ";
/// Width of the severity column.
const SEVERITY_COL: usize = 8;

/// The report as pretty, stable JSON.
pub fn render_json(report: &Report) -> String {
    serde_json::to_string_pretty(report).expect("a report always serializes")
}

pub(crate) fn verdict_color(v: Verdict) -> Color {
    match v {
        Verdict::Pass => GREEN,
        Verdict::Caution => AMBER,
        Verdict::Block => RED,
    }
}

fn severity_style(s: Severity) -> Style {
    match s {
        Severity::Critical => Style::fg(WHITE).bold().on(RED),
        Severity::High => Style::fg(RED),
        Severity::Medium => Style::fg(AMBER),
        Severity::Low => Style::fg(GREY),
    }
}

fn severity_label(s: Severity) -> &'static str {
    match s {
        Severity::Critical => "CRITICAL",
        Severity::High => "HIGH",
        Severity::Medium => "MEDIUM",
        Severity::Low => "LOW",
    }
}

/// "2 critical · 1 high", or `None` when every count is zero.
pub(crate) fn counts_text(summary: &Summary, dot: &str) -> Option<String> {
    let parts: Vec<String> = [
        (summary.critical, "critical"),
        (summary.high, "high"),
        (summary.medium, "medium"),
        (summary.low, "low"),
    ]
    .iter()
    .filter(|(n, _)| *n > 0)
    .map(|(n, word)| format!("{n} {word}"))
    .collect();
    (!parts.is_empty()).then(|| parts.join(&format!(" {dot} ")))
}

/// Short form of the checked version: the commit, else the tree hash.
pub(crate) fn pinned(report: &Report) -> String {
    match &report.target.commit {
        Some(sha) => clean(&sha.chars().take(7).collect::<String>()),
        None => format!(
            "tree {}",
            clean(
                &report
                    .target
                    .tree_sha256
                    .chars()
                    .take(7)
                    .collect::<String>()
            )
        ),
    }
}

/// Cuts `s` to `max` columns, keeping the end, which names the skill.
fn keep_tail(s: &str, max: usize, ellipsis: &str) -> String {
    if width_of(s) <= max {
        return s.to_string();
    }
    let keep = max.saturating_sub(width_of(ellipsis));
    let chars: Vec<char> = s.chars().collect();
    let tail: String = chars[chars.len().saturating_sub(keep)..].iter().collect();
    format!("{ellipsis}{tail}")
}

fn card(report: &Report, mode: &OutputMode, g: &Glyphs) -> Vec<String> {
    let c = mode.color;
    let vc = verdict_color(report.verdict);
    let suppressed = report.findings.iter().filter(|f| f.suppressed).count();

    let (word, advice) = match report.verdict {
        Verdict::Pass => ("PASS", "install this exact version"),
        Verdict::Caution => ("CAUTION", "read the findings before installing"),
        Verdict::Block => ("BLOCK", "do not install"),
    };
    let mut counts = counts_text(&report.summary, g.dot).unwrap_or_else(|| {
        if report.verdict == Verdict::Pass {
            "no known red flags".to_string()
        } else {
            "no findings, coverage incomplete".to_string()
        }
    });
    if suppressed > 0 {
        counts.push_str(&format!(" {} {suppressed} suppressed", g.dot));
    }

    let max_inner = usize::from(mode.width).saturating_sub(7).max(20);
    let source = keep_tail(&clean(&report.target.source), max_inner, g.ellipsis);
    let lines = [
        format!("{}   {counts}", paint(c, word, Style::fg(vc).bold()),),
        format!(
            "Checked {}  {}",
            paint(c, &pinned(report), Style::default().bold()),
            paint(c, advice, Style::fg(GREY))
        ),
        paint(c, &source, Style::fg(GREY)),
    ];
    let inner = lines
        .iter()
        .map(|l| width_of(l))
        .max()
        .unwrap_or(0)
        .max(CARD_MIN.min(max_inner));

    let border = |s: &str| paint(c, s, Style::fg(vc));
    let rule = g.horizontal.repeat(inner + 4);
    let mut out = vec![format!(
        " {}",
        border(&format!("{}{rule}{}", g.top_left, g.top_right))
    )];
    for line in &lines {
        out.push(format!(
            " {}  {}  {}",
            border(g.vertical),
            pad(line, inner),
            border(g.vertical)
        ));
    }
    out.push(format!(
        " {}",
        border(&format!("{}{rule}{}", g.bottom_left, g.bottom_right))
    ));
    out
}

fn finding_lines(f: &Finding, mode: &OutputMode, g: &Glyphs) -> [String; 2] {
    let c = mode.color;
    let label_col = INDENT.len() + SEVERITY_COL + 2;
    let title_max = usize::from(mode.width)
        .saturating_sub(label_col + 1)
        .max(20);
    let title = console::truncate_str(&clean(&f.title), title_max, g.ellipsis).into_owned();

    let mut locs: Vec<String> = f
        .locations
        .iter()
        .take(TOP_LOCATIONS)
        .map(|l| format!("{}:{}", clean(&l.file), l.line))
        .collect();
    let more = f.locations.len().saturating_sub(TOP_LOCATIONS);
    if more > 0 {
        locs.push(format!("+{more} more"));
    }
    let detail = format!("{} {} {}", locs.join(", "), g.dot, clean(&f.rule));
    [
        format!(
            "{INDENT}{}  {}",
            pad(
                &paint(c, severity_label(f.severity), severity_style(f.severity)),
                SEVERITY_COL
            ),
            title
        ),
        format!(
            "{}{}",
            " ".repeat(label_col),
            paint(c, &detail, Style::fg(GREY))
        ),
    ]
}

fn coverage_lines(report: &Report, mode: &OutputMode, g: &Glyphs) -> Vec<String> {
    let c = mode.color;
    let mut ids: Vec<&str> = DISPLAY_ORDER
        .iter()
        .copied()
        .filter(|id| report.coverage.contains_key(*id))
        .collect();
    ids.extend(
        report
            .coverage
            .keys()
            .map(String::as_str)
            .filter(|id| !DISPLAY_ORDER.contains(id)),
    );

    let mut items = Vec::new();
    let mut notes = Vec::new();
    for id in ids {
        let name = clean(analyzer_name(id));
        let (mark, style) = match &report.coverage[id] {
            Coverage::Ran => (g.ok, Style::fg(GREEN)),
            Coverage::Skipped { reason } => {
                notes.push(format!("{name} skipped: {}", clean(reason)));
                (g.skipped, Style::fg(GREY))
            }
            Coverage::Failed { reason } => {
                notes.push(format!("{name} failed: {}", clean(reason)));
                (g.failed, Style::fg(RED))
            }
        };
        items.push(format!("{} {name}", paint(c, mark, style)));
    }
    let mut out = vec![format!(
        "{INDENT}{}  {}",
        paint(c, "Coverage", Style::fg(GREY)),
        items.join("  ")
    )];
    out.extend(
        notes
            .iter()
            .map(|n| format!("{INDENT}{}", paint(c, n, Style::fg(AMBER)))),
    );
    out
}

/// The terminal report: verdict card, top findings and coverage.
pub fn render_report(report: &Report, mode: &OutputMode) -> String {
    let g = Glyphs::for_mode(mode);
    let c = mode.color;
    let mut lines = card(report, mode, &g);

    let active: Vec<&Finding> = report.findings.iter().filter(|f| !f.suppressed).collect();
    if !active.is_empty() {
        lines.push(String::new());
        for f in active.iter().take(TOP_FINDINGS) {
            lines.extend(finding_lines(f, mode, &g));
        }
        let hidden = active.len().saturating_sub(TOP_FINDINGS);
        if hidden > 0 {
            lines.push(format!(
                "{INDENT}{}",
                paint(
                    c,
                    &format!("+{hidden} more (use --json for the full report)"),
                    Style::fg(GREY)
                )
            ));
        }
    }

    lines.push(String::new());
    lines.extend(coverage_lines(report, mode, &g));
    if report.verdict == Verdict::Pass {
        lines.push(String::new());
        lines.push(format!(
            "{INDENT}{}",
            paint(c, "No known red flags does not mean safe.", Style::fg(GREY))
        ));
    }
    let mut out = lines.join("\n");
    out.push('\n');
    out
}
