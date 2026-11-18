//! Report rendering and terminal decoration.
//!
//! Decoration (banner, colour, spinners) appears only on an interactive
//! terminal. It never changes content: every mode lists the same findings in
//! the same order.

use std::io::IsTerminal;

use skillsniff::model::sanitize_evidence;

mod banner;
mod console_guard;
mod progress;
mod terminal;

pub use banner::render_banner;
pub use console_guard::ConsoleGuard;
pub use progress::{TerminalProgress, analyzer_name};
pub use terminal::{render_json, render_report};

/// How many colours the terminal can show.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ColorDepth {
    None,
    Ansi16,
    TrueColor,
}

/// Where and how output is shown.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OutputMode {
    pub json: bool,
    /// Banner, colour and spinners are allowed.
    pub decorate: bool,
    pub color: ColorDepth,
    /// Terminal width in columns.
    pub width: u16,
    /// Output can show UTF-8 box and block characters.
    pub utf8: bool,
}

/// Width assumed when the terminal size is unknown.
const DEFAULT_WIDTH: u16 = 80;

/// Detects the output mode from stdout and the environment.
pub fn detect(json: bool, quiet: bool) -> OutputMode {
    let tty = std::io::stdout().is_terminal();
    let width = console::Term::stdout().size_checked().map(|(_, w)| w);
    detect_from(json, quiet, tty, &|k| std::env::var(k).ok(), width)
}

/// [`detect`] with the terminal state and environment passed in.
pub fn detect_from(
    json: bool,
    quiet: bool,
    stdout_tty: bool,
    env: &dyn Fn(&str) -> Option<String>,
    width: Option<u16>,
) -> OutputMode {
    let set = |k: &str| env(k).is_some_and(|v| !v.is_empty());
    let decorate = !json && !quiet && stdout_tty && !set("CI") && !set("NO_COLOR");
    let color = if !decorate || env("TERM").as_deref() == Some("dumb") {
        ColorDepth::None
    } else if truecolor(env) {
        ColorDepth::TrueColor
    } else {
        ColorDepth::Ansi16
    };
    OutputMode {
        json,
        decorate,
        color,
        width: width.filter(|w| *w > 0).unwrap_or(DEFAULT_WIDTH),
        utf8: utf8_output(env),
    }
}

fn truecolor(env: &dyn Fn(&str) -> Option<String>) -> bool {
    let colorterm = env("COLORTERM").unwrap_or_default().to_ascii_lowercase();
    colorterm == "truecolor" || colorterm == "24bit" || env("WT_SESSION").is_some() || cfg!(windows)
}

/// Windows writes to the console as UTF-16 and switches the code page when
/// decorating; elsewhere the locale decides.
fn utf8_output(env: &dyn Fn(&str) -> Option<String>) -> bool {
    if cfg!(windows) {
        return true;
    }
    for key in ["LC_ALL", "LC_CTYPE", "LANG"] {
        if let Some(v) = env(key).filter(|v| !v.is_empty()) {
            let v = v.to_ascii_lowercase();
            return v.contains("utf-8") || v.contains("utf8");
        }
    }
    false
}

/// A foreground colour: 24-bit value and its 16-colour SGR code.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Color {
    pub rgb: (u8, u8, u8),
    pub ansi: u8,
}

pub(crate) const TEAL: Color = Color {
    rgb: (0x3C, 0xC9, 0xBD),
    ansi: 36,
};
pub(crate) const TEAL_DARK: Color = Color {
    rgb: (0x0B, 0x6E, 0x69),
    ansi: 36,
};
pub(crate) const GREEN: Color = Color {
    rgb: (0x3F, 0xB9, 0x50),
    ansi: 32,
};
pub(crate) const AMBER: Color = Color {
    rgb: (0xE3, 0xB3, 0x41),
    ansi: 33,
};
pub(crate) const RED: Color = Color {
    rgb: (0xF8, 0x51, 0x49),
    ansi: 31,
};
pub(crate) const ORANGE: Color = Color {
    rgb: (0xF0, 0x88, 0x3E),
    ansi: 31,
};
pub(crate) const GREY: Color = Color {
    rgb: (0x8B, 0x94, 0x9E),
    ansi: 90,
};

/// Text style; the default leaves text unchanged.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct Style {
    pub fg: Option<Color>,
    pub bold: bool,
}

impl Style {
    pub fn fg(c: Color) -> Style {
        Style {
            fg: Some(c),
            bold: false,
        }
    }

    pub fn bold(self) -> Style {
        Style { bold: true, ..self }
    }
}

/// Wraps `text` in SGR codes for `depth`; plain text when there is no colour.
pub(crate) fn paint(depth: ColorDepth, text: &str, style: Style) -> String {
    if text.is_empty() || depth == ColorDepth::None || (style.fg.is_none() && !style.bold) {
        return text.to_string();
    }
    let mut codes = Vec::new();
    if style.bold {
        codes.push("1".to_string());
    }
    if let Some(c) = style.fg {
        codes.push(match depth {
            ColorDepth::TrueColor => format!("38;2;{};{};{}", c.rgb.0, c.rgb.1, c.rgb.2),
            _ => c.ansi.to_string(),
        });
    }
    format!("\u{1b}[{}m{text}\u{1b}[0m", codes.join(";"))
}

/// Report text made safe to print: control, zero-width and bidi characters
/// are escaped and the length is capped.
pub(crate) fn clean(s: &str) -> String {
    sanitize_evidence(s)
}

/// Visible width of `s`, ignoring SGR codes.
pub(crate) fn width_of(s: &str) -> usize {
    console::measure_text_width(s)
}

/// Pads `painted` with spaces until its visible width is `to`.
pub(crate) fn pad(painted: &str, to: usize) -> String {
    let w = width_of(painted);
    format!("{painted}{}", " ".repeat(to.saturating_sub(w)))
}

/// Characters that differ between UTF-8 and ASCII output.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Glyphs {
    pub top_left: &'static str,
    pub top_right: &'static str,
    pub bottom_left: &'static str,
    pub bottom_right: &'static str,
    pub horizontal: &'static str,
    pub vertical: &'static str,
    pub ok: &'static str,
    pub failed: &'static str,
    pub skipped: &'static str,
    pub dot: &'static str,
    pub ellipsis: &'static str,
}

impl Glyphs {
    pub fn for_mode(mode: &OutputMode) -> Glyphs {
        if mode.utf8 {
            Glyphs {
                top_left: "╭",
                top_right: "╮",
                bottom_left: "╰",
                bottom_right: "╯",
                horizontal: "─",
                vertical: "│",
                ok: "✔",
                failed: "✖",
                skipped: "–",
                dot: "·",
                ellipsis: "…",
            }
        } else {
            Glyphs {
                top_left: "+",
                top_right: "+",
                bottom_left: "+",
                bottom_right: "+",
                horizontal: "-",
                vertical: "|",
                ok: "+",
                failed: "x",
                skipped: "-",
                dot: "-",
                ellipsis: "...",
            }
        }
    }
}
