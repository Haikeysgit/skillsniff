//! Command surface and exit codes.
//!
//! Exit codes: 0 PASS, 1 CAUTION, 2 BLOCK, 3 usage error, 4 fetch failed,
//! 5 internal error.

use std::ffi::OsString;
use std::fs;
use std::io::Read as _;
use std::path::{Path, PathBuf};

use clap::{Parser, Subcommand, ValueEnum};
use skillsniff::VERSION;
use skillsniff::export::{ExportError, export};
use skillsniff::inventory::build_inventory;
use skillsniff::model::{Report, Verdict, sanitize_evidence};
use skillsniff::review::apply_review;
use skillsniff::scan::{ScanError, ScanOptions, scan};
use skillsniff::target::TargetError;

use crate::output::{
    ConsoleGuard, OutputMode, TerminalProgress, detect, render_banner, render_json, render_report,
    render_welcome,
};

pub const EXIT_USAGE: i32 = 3;
pub const EXIT_FETCH: i32 = 4;
pub const EXIT_INTERNAL: i32 = 5;

/// Largest report or review file read by `review apply`.
const MAX_INPUT_BYTES: u64 = 16 * 1024 * 1024;

/// Statically inspects AI agent skills for red flags, without running them.
#[derive(Parser)]
#[command(name = "skillsniff", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Scan a skill from GitHub, a local folder or an archive.
    Scan(ScanArgs),
    /// Set up skillsniff in Claude Code and Codex (also: `skillsniff setup`).
    #[command(visible_alias = "setup")]
    InstallSkill(crate::install_skill::InstallSkillArgs),
    /// Work with external reviews of a report.
    Review {
        #[command(subcommand)]
        action: ReviewAction,
    },
}

#[derive(clap::Args)]
struct ScanArgs {
    /// github.com/owner/repo[/path][@ref], a local folder, or a .zip/.tar.gz.
    source: String,
    /// Print the full report as JSON.
    #[arg(long)]
    json: bool,
    /// No banner, colour or progress.
    #[arg(long)]
    quiet: bool,
    /// Refuse remote sources.
    #[arg(long)]
    offline: bool,
    /// Keep the scanned files on disk and print where they are.
    #[arg(long)]
    keep: bool,
    /// Copy the exact scanned files to this new folder (PASS only by default).
    #[arg(long, value_name = "DIR")]
    export: Option<PathBuf>,
    /// Allow --export when the verdict is CAUTION.
    #[arg(long)]
    allow_caution: bool,
    /// Folder of extra rule files.
    #[arg(long, value_name = "DIR")]
    rules: Option<PathBuf>,
    /// Suppressions file (default: the user configuration).
    #[arg(long, value_name = "FILE")]
    suppressions: Option<PathBuf>,
    /// Exit 1 at this verdict or worse, 0 otherwise.
    #[arg(long, value_enum, value_name = "VERDICT")]
    fail_on: Option<FailOn>,
}

#[derive(Clone, Copy, ValueEnum)]
enum FailOn {
    Caution,
    Block,
}

#[derive(Subcommand)]
enum ReviewAction {
    /// Merge a review into a report; it can only add or raise findings.
    Apply {
        /// Report JSON from `skillsniff scan --json`.
        report: PathBuf,
        /// Review JSON.
        review: PathBuf,
        /// Print the merged report as JSON.
        #[arg(long)]
        json: bool,
    },
}

/// Runs the command line and returns the exit code.
pub fn run<I: IntoIterator<Item = OsString>>(args: I) -> i32 {
    #[cfg(debug_assertions)]
    if std::env::var("SKILLSNIFF_TEST_PANIC").as_deref() == Ok("1") {
        panic!("forced test panic");
    }
    let cli = match Cli::try_parse_from(args) {
        Ok(cli) => cli,
        Err(e) => {
            use clap::error::ErrorKind;
            let _ = e.print();
            return match e.kind() {
                ErrorKind::DisplayHelp | ErrorKind::DisplayVersion => 0,
                _ => EXIT_USAGE,
            };
        }
    };
    match cli.command {
        None => welcome(),
        Some(Command::Scan(args)) => scan_command(&args),
        Some(Command::InstallSkill(args)) => crate::install_skill::install_skill_command(&args),
        Some(Command::Review {
            action:
                ReviewAction::Apply {
                    report,
                    review,
                    json,
                },
        }) => review_apply(&report, &review, json),
    }
}

fn shown(s: &str) -> String {
    sanitize_evidence(s)
}

fn shown_path(p: &Path) -> String {
    shown(&p.to_string_lossy())
}

fn error(msg: &str) {
    eprintln!("error: {msg}");
}

fn welcome() -> i32 {
    let mode = detect(false, false);
    let _guard = ConsoleGuard::prepare(mode.decorate);
    print!("{}", render_welcome(&mode));
    0
}

fn target_message(e: &TargetError, source: &str) -> String {
    match e {
        TargetError::NoSkill => format!("no skill found: {source} has no SKILL.md"),
        TargetError::MultipleSkills(dirs) => {
            let dirs: Vec<String> = dirs.iter().map(|d| shown(d)).collect();
            format!(
                "multiple skills found: {} \u{2014} pass one path",
                dirs.join(", ")
            )
        }
        other => shown(&other.to_string()),
    }
}

/// Message and exit code for a scan that produced no report.
fn scan_failure(e: &ScanError, source: &str) -> (String, i32) {
    match e {
        ScanError::Usage(m) => (shown(m), EXIT_USAGE),
        ScanError::Target(t) => (target_message(t, source), EXIT_USAGE),
        ScanError::Fetch(f) => (
            format!("could not read {source}: {}", shown(&f.to_string())),
            EXIT_FETCH,
        ),
        ScanError::Internal(m) => (
            format!("internal error (skillsniff {VERSION}): {}", shown(m)),
            EXIT_INTERNAL,
        ),
    }
}

fn verdict_code(verdict: Verdict, fail_on: Option<FailOn>) -> i32 {
    match fail_on {
        None => verdict.exit_code(),
        Some(FailOn::Caution) => i32::from(verdict != Verdict::Pass),
        Some(FailOn::Block) => i32::from(verdict == Verdict::Block),
    }
}

fn print_report(report: &Report, mode: &OutputMode) {
    if mode.json {
        println!("{}", render_json(report));
    } else {
        if mode.decorate {
            println!();
        }
        print!("{}", render_report(report, mode));
    }
}

fn scan_command(args: &ScanArgs) -> i32 {
    let mode = detect(args.json, args.quiet);
    let _guard = ConsoleGuard::prepare(mode.decorate);
    let source = shown(&args.source);
    if mode.decorate {
        println!("{}", render_banner(&mode));
    }

    let mut opts = ScanOptions {
        offline: args.offline,
        keep: args.keep,
        extra_rules: args.rules.clone(),
        ..ScanOptions::default()
    };
    if args.suppressions.is_some() {
        opts.suppressions = args.suppressions.clone();
    }

    let progress = TerminalProgress::new(&mode, &source);
    let mut outcome = match scan(&args.source, &opts, &progress) {
        Ok(o) => o,
        Err(e) => {
            progress.fail();
            let (msg, code) = scan_failure(&e, &source);
            error(&msg);
            return code;
        }
    };
    if mode.decorate {
        let files = outcome
            .quarantine
            .as_ref()
            .and_then(|q| build_inventory(q.root()).ok())
            .map_or(0, |i| i.files.len());
        progress.finish(&outcome.report, files);
    }

    print_report(&outcome.report, &mode);
    let mut code = verdict_code(outcome.report.verdict, args.fail_on);

    if let Some(dest) = &args.export {
        match export(&outcome, dest, args.allow_caution) {
            Ok(()) => eprintln!("Exported the scanned files to {}", shown_path(dest)),
            Err(e) => {
                error(&shown(&e.to_string()));
                code = match e {
                    ExportError::Blocked => 2,
                    ExportError::CautionNotAllowed => 1,
                    _ => EXIT_USAGE,
                };
            }
        }
    }

    if let Some(q) = outcome.quarantine.take() {
        if args.keep {
            let kept = q.keep();
            eprintln!("Kept the scanned files at {}", shown_path(&kept));
        } else {
            drop(q);
        }
    }
    code
}

fn read_limited(path: &Path, what: &str) -> Result<String, String> {
    let file = fs::File::open(path)
        .map_err(|e| format!("cannot read {what} {}: {e}", shown_path(path)))?;
    let mut text = String::new();
    file.take(MAX_INPUT_BYTES + 1)
        .read_to_string(&mut text)
        .map_err(|e| format!("cannot read {what} {}: {e}", shown_path(path)))?;
    if text.len() as u64 > MAX_INPUT_BYTES {
        return Err(format!(
            "{what} {} is larger than {MAX_INPUT_BYTES} bytes",
            shown_path(path)
        ));
    }
    Ok(text)
}

fn review_apply(report_path: &Path, review_path: &Path, json: bool) -> i32 {
    let mode = detect(json, false);
    let _guard = ConsoleGuard::prepare(mode.decorate);
    let merged = read_limited(report_path, "report")
        .and_then(|text| {
            serde_json::from_str::<Report>(&text)
                .map_err(|e| format!("invalid report {}: {e}", shown_path(report_path)))
        })
        .and_then(|report| {
            let review = read_limited(review_path, "review")?;
            apply_review(report, &review)
        });
    match merged {
        Ok(report) => {
            print_report(&report, &mode);
            report.verdict.exit_code()
        }
        Err(msg) => {
            error(&shown(&msg));
            EXIT_USAGE
        }
    }
}
