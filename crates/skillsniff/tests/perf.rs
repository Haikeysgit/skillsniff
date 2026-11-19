//! Release-mode time limit on a large skill. Run with
//! `cargo test --release -- --ignored`.

use std::fmt::Write as _;
use std::fs;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use skillsniff::progress::NoopProgress;
use skillsniff::scan::{ScanOptions, scan};

const LIMIT: Duration = Duration::from_secs(10);

/// One module of ordinary-looking code, about `bytes` long.
fn python_module(bytes: usize, seed: usize) -> String {
    let mut s = String::from(
        "\"\"\"Helpers for report formatting.\"\"\"\n\nimport json\nimport os\nimport re\n\n",
    );
    let mut i = 0;
    while s.len() < bytes {
        let _ = write!(
            s,
            "def format_row_{seed}_{i}(row, width=20):\n    \"\"\"Pads each cell of a row.\"\"\"\n    cells = [str(c).ljust(width) for c in row]\n    # Join the cells and trim the end of the line.\n    text = \" | \".join(cells).rstrip()\n    if re.search(r\"\\s{{3,}}\", text):\n        text = re.sub(r\"\\s+\", \" \", text)\n    return text\n\n\n"
        );
        i += 1;
    }
    s
}

fn largest_fixture_dir() -> PathBuf {
    let dir = tempfile::tempdir().unwrap().keep();
    fs::write(
        dir.join("SKILL.md"),
        "---\nname: large-report-tools\ndescription: Formats report tables. Use when the user asks to format a report table.\n---\n\nRun the helpers in scripts/ to format tables.\n",
    )
    .unwrap();
    fs::create_dir_all(dir.join("scripts")).unwrap();
    // Five megabytes in all: forty scripts and a long reference page.
    for n in 0..40 {
        fs::write(
            dir.join(format!("scripts/fmt_{n}.py")),
            python_module(100_000, n),
        )
        .unwrap();
    }
    let page = "Tables are aligned on the pipe character. Keep cells short.\n\n".repeat(16_000);
    fs::write(dir.join("reference.md"), page).unwrap();
    dir
}

#[test]
#[ignore = "slow: run with --release -- --ignored"]
fn large_skill_scans_within_the_limit() {
    let dir = largest_fixture_dir();
    // Kept outside the skill so the scan does not see it.
    let empty_outside = std::env::temp_dir().join("skillsniff-perf-suppressions.yaml");
    fs::write(&empty_outside, "suppressions: []\n").unwrap();
    let opts = ScanOptions {
        offline: true,
        suppressions: Some(empty_outside),
        ..ScanOptions::default()
    };
    let started = Instant::now();
    let out = scan(dir.to_str().unwrap(), &opts, &NoopProgress).expect("scan");
    let took = started.elapsed();
    let _ = fs::remove_dir_all(&dir);
    assert!(took < LIMIT, "scan took {took:?}");
    assert_eq!(out.report.verdict, skillsniff::model::Verdict::Pass);
}
