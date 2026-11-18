//! The block-letter banner and the welcome screen.

use skillsniff::VERSION;
use skillsniff::rules::builtin;

use super::{
    Color, ColorDepth, GREY, Glyphs, OutputMode, Style, TEAL, WHITE, pad, paint, width_of,
};

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

/// Gradient stops for the solid blocks, light to deep.
const STOPS: [(u8, u8, u8); 4] = [
    (110, 255, 236),
    (60, 201, 189),
    (20, 140, 200),
    (90, 90, 230),
];
/// Colour of the box-drawing shadow.
const SHADOW: Color = Color {
    rgb: (30, 94, 90),
    ansi: 36,
};
/// Plain bright cyan for the 16-colour fallback.
const BLOCK_ANSI16: Color = Color {
    rgb: (110, 255, 236),
    ansi: 96,
};

/// Narrowest welcome box content, in columns.
const BOX_MIN_INNER: usize = 54;

fn lerp(a: u8, b: u8, t: f64) -> u8 {
    (f64::from(a) + (f64::from(b) - f64::from(a)) * t).round() as u8
}

/// The gradient colour at `t` in 0..=1.
fn gradient(t: f64) -> (u8, u8, u8) {
    let t = t.clamp(0.0, 1.0) * (STOPS.len() - 1) as f64;
    let i = (t.floor() as usize).min(STOPS.len() - 2);
    let f = t - i as f64;
    let (a, b) = (STOPS[i], STOPS[i + 1]);
    (lerp(a.0, b.0, f), lerp(a.1, b.1, f), lerp(a.2, b.2, f))
}

fn is_shadow(ch: char) -> bool {
    matches!(ch, '╗' | '║' | '═' | '╝' | '╔' | '╚')
}

/// One banner row coloured per character.
fn colour_row(line: &str, y: usize, columns: usize, depth: ColorDepth) -> String {
    let mut out = String::new();
    for (x, ch) in line.chars().enumerate() {
        if ch == ' ' || depth == ColorDepth::None {
            out.push(ch);
            continue;
        }
        let shadow = is_shadow(ch);
        match depth {
            ColorDepth::TrueColor => {
                let (r, g, b) = if shadow {
                    SHADOW.rgb
                } else {
                    gradient((x + 2 * y) as f64 / (columns + 12) as f64)
                };
                out.push_str(&format!("\u{1b}[38;2;{r};{g};{b}m{ch}"));
            }
            _ => {
                let c = if shadow { SHADOW } else { BLOCK_ANSI16 };
                out.push_str(&format!("\u{1b}[{}m{ch}", c.ansi));
            }
        }
    }
    if depth != ColorDepth::None {
        out.push_str("\u{1b}[0m");
    }
    out
}

/// The version and rule pack shown beside the banner.
fn status(dot: &str) -> String {
    format!("v{VERSION} {dot} rules {}", builtin().version)
}

/// The banner: chrome block letters with a shadow, a rule, the tagline and
/// the version, or a one-line title when the terminal is narrow or not UTF-8.
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
    for (y, line) in LETTERS.iter().enumerate() {
        out.push_str(&colour_row(line, y, columns, c));
        out.push('\n');
    }
    out.push_str(&paint(c, &"─".repeat(columns), Style::fg(GREY)));
    out.push('\n');
    let right = status("·");
    let gap = columns
        .saturating_sub(width_of(TAGLINE) + width_of(&right))
        .max(2);
    out.push_str(&format!(
        "{TAGLINE}{}{}\n",
        " ".repeat(gap),
        paint(c, &right, Style::fg(GREY))
    ));
    out
}

/// The welcome screen: banner, a rounded box, tips and example commands.
pub fn render_welcome(mode: &OutputMode) -> String {
    let c = mode.color;
    let g = Glyphs::for_mode(mode);
    let banner_mode = if mode.decorate {
        *mode
    } else {
        OutputMode { width: 0, ..*mode }
    };
    let mut out = render_banner(&banner_mode);
    out.push('\n');

    let title = format!(
        "{} {} {}",
        paint(c, ">_", Style::fg(TEAL)),
        paint(c, "skillsniff", Style::fg(WHITE).bold()),
        paint(c, &format!("v{VERSION}"), Style::fg(GREY))
    );
    let rows = [
        title,
        String::new(),
        "Welcome. I check AI agent skills before your agent".to_string(),
        "installs them. I never run their code.".to_string(),
    ];
    let inner = rows
        .iter()
        .map(|r| width_of(r) + 2)
        .max()
        .unwrap_or(0)
        .max(BOX_MIN_INNER);
    let dim = |s: &str| paint(c, s, Style::fg(GREY));
    let rule = g.horizontal.repeat(inner);
    out.push_str(&dim(&format!("{}{rule}{}", g.top_left, g.top_right)));
    out.push('\n');
    for row in &rows {
        out.push_str(&format!(
            "{} {} {}\n",
            dim(g.vertical),
            pad(row, inner - 2),
            dim(g.vertical)
        ));
    }
    out.push_str(&dim(&format!("{}{rule}{}", g.bottom_left, g.bottom_right)));
    out.push_str("\n\n");

    out.push_str(&format!(
        "  {} scan a GitHub skill, a folder, or a .zip file.\n\n",
        dim("Tips:")
    ));
    let arrow = if mode.utf8 { "›" } else { ">" };
    for example in [
        "skillsniff scan github.com/owner/repo",
        "skillsniff scan ./my-skill",
        "skillsniff scan skill.zip --json",
    ] {
        out.push_str(&format!(
            "  {} {example}\n",
            paint(c, arrow, Style::fg(TEAL))
        ));
    }
    out.push_str(&format!(
        "\n{}\n",
        dim("  Run skillsniff --help for every option.")
    ));
    out
}
