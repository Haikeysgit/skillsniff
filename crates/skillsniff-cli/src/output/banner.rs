//! The block-letter banner.

use skillsniff::VERSION;
use skillsniff::rules::builtin;

use super::{ColorDepth, GREY, OutputMode, Style, TEAL, TEAL_DARK, paint, width_of};

const LETTERS: [&str; 6] = [
    "███████╗██╗  ██╗██╗██╗     ██╗     ███████╗███╗   ██╗██╗███████╗███████╗",
    "██╔════╝██║ ██╔╝██║██║     ██║     ██╔════╝████╗  ██║██║██╔════╝██╔════╝",
    "███████╗█████╔╝ ██║██║     ██║     ███████╗██╔██╗ ██║██║█████╗  █████╗",
    "╚════██║██╔═██╗ ██║██║     ██║     ╚════██║██║╚██╗██║██║██╔══╝  ██╔══╝",
    "███████║██║  ██╗██║███████╗███████╗███████║██║ ╚████║██║██║     ██║",
    "╚══════╝╚═╝  ╚═╝╚═╝╚══════╝╚══════╝╚══════╝╚═╝  ╚═══╝╚═╝╚═╝     ╚═╝",
];

const TAGLINE: &str = "If a skill smells off, you'll know.";

/// Narrowest terminal that shows the block letters.
const MIN_WIDTH: u16 = 80;

fn lerp(a: u8, b: u8, t: f64) -> u8 {
    (f64::from(a) + (f64::from(b) - f64::from(a)) * t).round() as u8
}

fn gradient_line(line: &str, columns: usize) -> String {
    let mut out = String::new();
    for (i, ch) in line.chars().enumerate() {
        if ch == ' ' {
            out.push(ch);
            continue;
        }
        let t = if columns > 1 {
            i as f64 / (columns - 1) as f64
        } else {
            0.0
        };
        let (a, b) = (TEAL.rgb, TEAL_DARK.rgb);
        let (r, g, bl) = (lerp(a.0, b.0, t), lerp(a.1, b.1, t), lerp(a.2, b.2, t));
        out.push_str(&format!("\u{1b}[38;2;{r};{g};{bl}m{ch}"));
    }
    out.push_str("\u{1b}[0m");
    out
}

/// The version and rule pack shown beside the banner.
fn status(dot: &str) -> String {
    format!("v{VERSION} {dot} rules {}", builtin().version)
}

/// The §7.9 banner: block letters in a teal gradient over a status line, or
/// a one-line title when the terminal is narrow or not UTF-8.
pub fn render_banner(mode: &OutputMode) -> String {
    let c = mode.color;
    if mode.width < MIN_WIDTH || !mode.utf8 {
        let dot = if mode.utf8 { "·" } else { "-" };
        return format!(
            "{}  {}\n",
            paint(c, "skillsniff", Style::fg(TEAL).bold()),
            paint(c, &status(dot), Style::fg(GREY))
        );
    }
    let columns = LETTERS.iter().map(|l| width_of(l)).max().unwrap_or(0);
    let mut out = String::new();
    for line in LETTERS {
        let shown = match c {
            ColorDepth::TrueColor => gradient_line(line, columns),
            _ => paint(c, line, Style::fg(TEAL)),
        };
        out.push_str(&shown);
        out.push('\n');
    }
    let left = format!(" {TAGLINE}");
    let right = status("·");
    let gap = columns
        .saturating_sub(width_of(&left) + width_of(&right))
        .max(2);
    out.push_str(&format!(
        "{left}{}{}\n",
        " ".repeat(gap),
        paint(c, &right, Style::fg(GREY))
    ));
    out
}
