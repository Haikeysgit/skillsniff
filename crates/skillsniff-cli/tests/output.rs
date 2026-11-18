use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use skillsniff::model::Report;
use skillsniff::progress::NoopProgress;
use skillsniff::scan::{ScanOptions, scan};
use skillsniff_cli::output::{
    ColorDepth, OutputMode, detect_from, render_banner, render_json, render_report,
};

fn fixture(rel: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures")
        .join(rel)
}

fn empty_suppressions() -> PathBuf {
    let p = Path::new(env!("CARGO_TARGET_TMPDIR")).join("cli-output-empty-suppressions.yaml");
    fs::write(&p, "suppressions: []\n").unwrap();
    p
}

/// Scans a fixture and pins the fields that differ between machines.
fn report_for(rel: &str) -> Report {
    let opts = ScanOptions {
        suppressions: Some(empty_suppressions()),
        ..ScanOptions::default()
    };
    let path = fixture(rel);
    let mut report = scan(path.to_str().unwrap(), &opts, &NoopProgress)
        .unwrap_or_else(|e| panic!("scan failed: {e}"))
        .report;
    report.target.source = format!("tests/fixtures/{rel}");
    report.target.tree_sha256 =
        "3f2a9c10d4e5b6a7980112233445566778899aabbccddeeff00112233445566".into();
    report
}

fn env_of(pairs: &'static [(&'static str, &'static str)]) -> impl Fn(&str) -> Option<String> {
    move |k: &str| {
        pairs
            .iter()
            .find(|(name, _)| *name == k)
            .map(|(_, v)| v.to_string())
    }
}

fn plain(width: u16) -> OutputMode {
    OutputMode {
        json: false,
        decorate: false,
        color: ColorDepth::None,
        width,
        utf8: true,
    }
}

#[test]
fn json_mode_has_no_ansi_and_no_banner() {
    let mode = detect_from(true, false, true, &env_of(&[]), Some(120));
    assert!(mode.json);
    assert!(!mode.decorate);
    assert_eq!(mode.color, ColorDepth::None);
    let json = render_json(&report_for("malicious/exfil-aws"));
    assert!(!json.contains('\u{1b}'));
    assert!(!json.contains('█'));
    let parsed: Report = serde_json::from_str(&json).unwrap();
    assert_eq!(
        parsed.findings.len(),
        report_for("malicious/exfil-aws").findings.len()
    );
}

#[test]
fn ci_env_disables_decoration() {
    let tty = detect_from(false, false, true, &env_of(&[]), Some(120));
    assert!(tty.decorate, "an interactive terminal is decorated");
    let ci = detect_from(false, false, true, &env_of(&[("CI", "true")]), Some(120));
    assert!(!ci.decorate);
    assert_eq!(ci.color, ColorDepth::None);
    let piped = detect_from(false, false, false, &env_of(&[]), None);
    assert!(!piped.decorate);
    let quiet = detect_from(false, true, true, &env_of(&[]), Some(120));
    assert!(!quiet.decorate);
}

#[test]
fn no_color_disables_colour() {
    let mode = detect_from(false, false, true, &env_of(&[("NO_COLOR", "1")]), Some(120));
    assert_eq!(mode.color, ColorDepth::None);
    assert!(!mode.decorate);
    let out = render_report(&report_for("malicious/exfil-aws"), &mode);
    assert!(!out.contains('\u{1b}'));
    let truecolor = detect_from(
        false,
        false,
        true,
        &env_of(&[("COLORTERM", "truecolor")]),
        Some(120),
    );
    assert_eq!(truecolor.color, ColorDepth::TrueColor);
}

#[test]
fn narrow_terminal_uses_one_line_banner() {
    let mut mode = plain(60);
    let narrow = render_banner(&mode);
    assert_eq!(narrow.trim_end().lines().count(), 1, "{narrow}");
    assert!(narrow.contains("skillsniff"));
    assert!(!narrow.contains('█'));

    mode.width = 100;
    let wide = render_banner(&mode);
    assert!(wide.contains("███████╗██╗  ██╗██╗██╗     ██╗     ███████╗"));
    assert!(wide.contains("If a skill smells off, you'll know."));

    mode.utf8 = false;
    assert!(!render_banner(&mode).contains('█'));
}

#[test]
fn banner_gradient_runs_from_light_to_dark_teal() {
    let mode = OutputMode {
        color: ColorDepth::TrueColor,
        decorate: true,
        ..plain(100)
    };
    let banner = render_banner(&mode);
    assert!(
        banner.contains("\u{1b}[38;2;60;201;189m"),
        "starts at #3CC9BD"
    );
    assert!(
        banner.contains("\u{1b}[38;2;11;110;105m"),
        "ends at #0B6E69"
    );
    let ansi16 = render_banner(&OutputMode {
        color: ColorDepth::Ansi16,
        ..mode
    });
    assert!(ansi16.contains("\u{1b}[36m"));
}

#[test]
fn banner_snapshot() {
    insta::assert_snapshot!(render_banner(&plain(100)));
}

#[test]
fn terminal_report_snapshot_block() {
    insta::assert_snapshot!(render_report(
        &report_for("malicious/exfil-aws"),
        &plain(100)
    ));
}

#[test]
fn terminal_report_snapshot_pass() {
    insta::assert_snapshot!(render_report(
        &report_for("clean/minimal-skill"),
        &plain(100)
    ));
}

/// Rule ids and `file:line` locations listed in plain terminal output.
fn listed(out: &str) -> BTreeSet<(String, String)> {
    let mut set = BTreeSet::new();
    for line in out.lines() {
        let Some((locs, rule)) = line.trim().rsplit_once(" · ") else {
            continue;
        };
        if !rule.contains('.') || rule.contains(' ') {
            continue;
        }
        for loc in locs.split(", ") {
            set.insert((rule.to_string(), loc.to_string()));
        }
    }
    set
}

#[test]
fn content_is_identical_across_modes() {
    let report = report_for("malicious/exfil-aws");
    assert!(!report.findings.is_empty());
    let plain_out = render_report(&report, &plain(100));
    let json: Report = serde_json::from_str(&render_json(&report)).unwrap();
    let expected: BTreeSet<(String, String)> = json
        .findings
        .iter()
        .filter(|f| !f.suppressed)
        .flat_map(|f| {
            f.locations
                .iter()
                .map(|l| (f.rule.clone(), format!("{}:{}", l.file, l.line)))
        })
        .collect();
    assert_eq!(listed(&plain_out), expected);

    for color in [ColorDepth::Ansi16, ColorDepth::TrueColor] {
        let coloured = render_report(
            &report,
            &OutputMode {
                color,
                decorate: true,
                ..plain(100)
            },
        );
        assert_eq!(console::strip_ansi_codes(&coloured), plain_out);
    }
}

#[test]
fn control_characters_never_reach_the_terminal() {
    let mut report = report_for("malicious/exfil-aws");
    report.findings[0].title = "evil\u{1b}[2Jtitle\u{202E}".into();
    report.findings[0].locations[0].file = "a\u{7}b.py".into();
    report.target.source = "src\u{1b}]0;x\u{7}".into();
    let out = render_report(&report, &plain(100));
    assert!(!out.contains('\u{1b}'));
    assert!(!out.contains('\u{7}'));
    assert!(!out.contains('\u{202E}'));
}
