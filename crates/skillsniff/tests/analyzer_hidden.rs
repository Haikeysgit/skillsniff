use std::fs;

use skillsniff::analyzers::hidden::{HIDDEN_PATTERNS, HiddenAnalyzer};
use skillsniff::analyzers::{Analyzer, ScanContext};
use skillsniff::inventory::build_inventory;
use skillsniff::model::signal::HIDDEN;
use skillsniff::model::{Coverage, Signal};
use skillsniff::target::{Target, detect_skill};

fn run(files: &[(&str, Vec<u8>)]) -> Vec<Signal> {
    let dir = tempfile::tempdir().unwrap();
    fs::write(
        dir.path().join("SKILL.md"),
        "---\nname: demo\ndescription: a demo\n---\nbody\n",
    )
    .unwrap();
    for (name, data) in files {
        let p = dir.path().join(name);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(p, data).unwrap();
    }
    let inv = build_inventory(dir.path()).unwrap();
    let skill = detect_skill(&inv, dir.path()).unwrap();
    let roles = skill.classify(&inv);
    let ctx = ScanContext {
        root: dir.path().to_path_buf(),
        inventory: inv,
        roles,
        skill,
    };
    let a = HiddenAnalyzer;
    assert_eq!(a.id(), "hidden");
    let out = a.run(&ctx);
    assert_eq!(out.coverage, Coverage::Ran);
    out.signals
}

fn pat(s: &Signal) -> &str {
    s.fields.get("pattern").unwrap()
}

fn with<'a>(sigs: &'a [Signal], p: &str) -> Vec<&'a Signal> {
    sigs.iter().filter(|s| pat(s) == p).collect()
}

#[test]
fn clean_file_emits_nothing() {
    let sigs = run(&[("notes.md", b"# Hello\nplain text only\n".to_vec())]);
    assert!(sigs.is_empty(), "{sigs:?}");
}

#[test]
fn zero_width_flagged_with_line_and_safe_evidence() {
    let sigs = run(&[("a.md", "ok\nhid\u{200B}den\n".as_bytes().to_vec())]);
    let z = with(&sigs, "zero_width");
    assert_eq!(z.len(), 1);
    assert_eq!(z[0].kind, HIDDEN);
    assert_eq!(z[0].locations[0].file, "a.md");
    assert_eq!(z[0].locations[0].line, 2);
    assert!(z[0].evidence.contains("U+200B"));
    assert!(!z[0].evidence.contains('\u{200B}'));
}

#[test]
fn bom_at_start_not_flagged_but_later_feff_is() {
    let sigs = run(&[("bom.md", b"\xef\xbb\xbfhello\n".to_vec())]);
    assert!(with(&sigs, "zero_width").is_empty());
    let sigs = run(&[("b.md", "he\u{FEFF}llo\n".as_bytes().to_vec())]);
    assert_eq!(with(&sigs, "zero_width").len(), 1);
}

#[test]
fn one_signal_per_line_per_pattern() {
    let sigs = run(&[(
        "a.md",
        "a\u{200B}b\u{200C}c\nd\u{2060}\n".as_bytes().to_vec(),
    )]);
    assert_eq!(with(&sigs, "zero_width").len(), 2);
}

#[test]
fn bidi_control_flagged() {
    let sigs = run(&[("a.md", "x \u{202E}evil\n".as_bytes().to_vec())]);
    let b = with(&sigs, "bidi_control");
    assert_eq!(b.len(), 1);
    assert!(b[0].evidence.contains("U+202E"));
    let sigs = run(&[("a.md", "x \u{2066}y\u{2069}\n".as_bytes().to_vec())]);
    assert_eq!(with(&sigs, "bidi_control").len(), 1);
}

#[test]
fn tag_chars_flagged() {
    let sigs = run(&[("a.md", "x\u{E0041}y\n".as_bytes().to_vec())]);
    let t = with(&sigs, "tag_chars");
    assert_eq!(t.len(), 1);
    assert!(t[0].evidence.contains("U+E0041"));
}

#[test]
fn mixed_script_identifier_flagged() {
    // Cyrillic small a inside a Latin word.
    let sigs = run(&[("s.py", "p\u{0430}ssword = 1\n".as_bytes().to_vec())]);
    assert_eq!(with(&sigs, "mixed_script").len(), 1);
    // Greek.
    let sigs = run(&[("s.py", "v\u{03B1}lue = 1\n".as_bytes().to_vec())]);
    assert_eq!(with(&sigs, "mixed_script").len(), 1);
}

#[test]
fn mixed_script_url_host_flagged() {
    let sigs = run(&[(
        "a.md",
        "see https://ex\u{0430}mple.invalid/x\n".as_bytes().to_vec(),
    )]);
    assert_eq!(with(&sigs, "mixed_script").len(), 1);
}

#[test]
fn pure_cyrillic_not_flagged() {
    let sigs = run(&[("a.md", "привет мир\n".as_bytes().to_vec())]);
    assert!(with(&sigs, "mixed_script").is_empty());
}

#[test]
fn high_entropy_base64_flagged() {
    let tok = "aB3dE5gH7jK9mN1pQ3sT5vW7yZ9bC2eF4hJ6kL8nP0rS";
    let sigs = run(&[("a.md", format!("key {tok}\n").into_bytes())]);
    let h = with(&sigs, "high_entropy");
    assert_eq!(h.len(), 1);
    assert_eq!(h[0].evidence, &tok[..40]);
}

#[test]
fn high_entropy_hex_flagged_and_low_entropy_not() {
    let hex = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";
    let sigs = run(&[("a.md", format!("h {hex}\n").into_bytes())]);
    assert_eq!(with(&sigs, "high_entropy").len(), 1);
    let low = "a".repeat(64);
    let sigs = run(&[("a.md", format!("h {low}\n").into_bytes())]);
    assert!(with(&sigs, "high_entropy").is_empty());
    let short = "aB3dE5gH7jK9mN1pQ3sT5vW7yZ9bC2e";
    let sigs = run(&[("a.md", format!("h {short}\n").into_bytes())]);
    assert!(with(&sigs, "high_entropy").is_empty());
}

#[test]
fn binary_file_flagged() {
    let sigs = run(&[("data.bin", vec![0u8, 1, 2, 3, 0xff])]);
    let b = with(&sigs, "binary_file");
    assert_eq!(b.len(), 1);
    assert_eq!(b[0].locations[0].file, "data.bin");
    assert_eq!(b[0].locations[0].line, 0);
}

#[test]
fn minified_file_flagged() {
    let line = "x=1;".repeat(300);
    let sigs = run(&[("m.js", line.into_bytes())]);
    assert_eq!(with(&sigs, "minified_file").len(), 1);
}

#[test]
fn oversized_file_flagged() {
    let data = "line of text\n".repeat(100_000);
    let sigs = run(&[("big.txt", data.into_bytes())]);
    let o = with(&sigs, "oversized_file");
    assert_eq!(o.len(), 1);
    assert_eq!(o[0].locations[0].line, 0);
}

#[test]
fn non_utf8_py_is_binary_with_extension_mismatch_and_no_panic() {
    let sigs = run(&[("tool.py", vec![0xffu8, 0xfe, 0x00, 0x80, 0x00])]);
    assert_eq!(with(&sigs, "binary_file").len(), 1);
    assert_eq!(with(&sigs, "extension_mismatch").len(), 1);
}

#[test]
fn binary_asset_without_script_extension_has_no_mismatch() {
    let sigs = run(&[("logo.png", png())]);
    assert!(with(&sigs, "extension_mismatch").is_empty());
}

#[test]
fn pattern_list_is_complete() {
    assert_eq!(
        HIDDEN_PATTERNS,
        &[
            "zero_width",
            "bidi_control",
            "tag_chars",
            "mixed_script",
            "high_entropy",
            "binary_file",
            "minified_file",
            "oversized_file",
            "extension_mismatch",
            "parse_budget_exceeded",
            "invisible_joiner",
            "invalid_utf8_script",
            "parse_errors",
        ]
    );
}

#[test]
fn combining_joiner_does_not_split_mixed_script_token() {
    let sigs = run(&[("s.py", "p\u{034F}\u{0430}ssword = 1\n".as_bytes().to_vec())]);
    assert_eq!(with(&sigs, "mixed_script").len(), 1);
    let sigs = run(&[("s.py", "p\u{00AD}\u{0430}ssword = 1\n".as_bytes().to_vec())]);
    assert_eq!(with(&sigs, "mixed_script").len(), 1);
}

#[test]
fn invisible_joiner_is_flagged() {
    for c in [
        '\u{034F}', '\u{00AD}', '\u{FE0F}', '\u{180B}', '\u{200E}', '\u{061C}', '\u{2062}',
    ] {
        let sigs = run(&[("a.md", format!("a{c}b\n").into_bytes())]);
        let j = with(&sigs, "invisible_joiner");
        assert_eq!(j.len(), 1, "{c:?}");
        assert!(j[0].evidence.contains("U+"));
        assert!(!j[0].evidence.contains(c));
    }
}

#[test]
fn many_urls_on_one_line_is_fast() {
    let line = "http://a ".repeat(100_000);
    let start = std::time::Instant::now();
    let sigs = run(&[("a.md", line.into_bytes())]);
    assert!(start.elapsed() < std::time::Duration::from_secs(10));
    assert!(with(&sigs, "mixed_script").is_empty());
}

#[test]
fn cyrillic_label_with_latin_tld_is_not_mixed() {
    let sigs = run(&[(
        "a.md",
        "https://\u{043F}\u{0440}\u{0438}\u{043C}\u{0435}\u{0440}.com/x\n"
            .as_bytes()
            .to_vec(),
    )]);
    assert!(with(&sigs, "mixed_script").is_empty());
    let sigs = run(&[("a.md", "https://p\u{0430}ypal.com/x\n".as_bytes().to_vec())]);
    assert_eq!(with(&sigs, "mixed_script").len(), 1);
}

#[test]
fn lone_cr_line_numbers() {
    let sigs = run(&[("a.md", "a\rb\rc\u{200B}\r\nd\u{200B}\n".as_bytes().to_vec())]);
    let lines: Vec<u32> = with(&sigs, "zero_width")
        .iter()
        .map(|s| s.locations[0].line)
        .collect();
    assert_eq!(lines, vec![3, 4]);
}

#[test]
fn high_entropy_carries_alphabet_and_length() {
    let hex = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";
    let sigs = run(&[("a.md", format!("h {hex}\n").into_bytes())]);
    let h = with(&sigs, "high_entropy");
    assert_eq!(h[0].fields["alphabet"], "hex");
    assert_eq!(h[0].fields["len"], "64");
    let tok = "aB3dE5gH7jK9mN1pQ3sT5vW7yZ9bC2eF4hJ6kL8nP0rS";
    let sigs = run(&[("a.md", format!("key {tok}\n").into_bytes())]);
    let h = with(&sigs, "high_entropy");
    assert_eq!(h[0].fields["alphabet"], "base64");
    assert_eq!(h[0].fields["len"], tok.len().to_string());
}

#[test]
fn binary_file_carries_lowercase_extension() {
    let sigs = run(&[("Logo.PNG", png()), ("blob", vec![0u8, 1, 2])]);
    let b = with(&sigs, "binary_file");
    let ext = |f: &str| b.iter().find(|s| s.locations[0].file == f).unwrap().fields["ext"].clone();
    assert_eq!(ext("Logo.PNG"), "png");
    assert_eq!(ext("blob"), "");
}

fn png() -> Vec<u8> {
    let mut v = vec![0x89u8, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];
    v.extend_from_slice(&[0, 0, 0, 13, b'I', b'H', b'D', b'R', 0, 0]);
    v
}

fn magic_of(sigs: &[Signal], file: &str) -> String {
    with(sigs, "binary_file")
        .iter()
        .find(|s| s.locations[0].file == file)
        .unwrap_or_else(|| panic!("no binary_file for {file}"))
        .fields["magic"]
        .clone()
}

#[test]
fn magic_classes_are_detected_from_content() {
    let mut elf = vec![0x7fu8, b'E', b'L', b'F'];
    elf.extend_from_slice(&[2, 1, 1, 0, 0, 0]);
    let mut webp = b"RIFF".to_vec();
    webp.extend_from_slice(&[0x10, 0, 0, 0]);
    webp.extend_from_slice(b"WEBPVP8 ");
    let cases: Vec<(&str, Vec<u8>, &str)> = vec![
        ("a.png", png(), "image"),
        ("a.jpg", vec![0xff, 0xd8, 0xff, 0xe0, 0, 0], "image"),
        ("a.gif", b"GIF89a\0\0\0".to_vec(), "image"),
        ("a.webp", webp, "image"),
        ("a.ico", vec![0, 0, 1, 0, 1, 0, 0], "image"),
        ("a.woff", b"wOFF\0\0\0\0".to_vec(), "font"),
        ("a.woff2", b"wOF2\0\0\0\0".to_vec(), "font"),
        ("a.ttf", vec![0, 1, 0, 0, 0, 1, 0, 0], "font"),
        ("a.otf", b"OTTO\0\0\0\0".to_vec(), "font"),
        ("elf.bin", elf, "exec"),
        ("pe.bin", b"MZ\x90\0\x03\0\0\0".to_vec(), "exec"),
        (
            "macho.bin",
            vec![0xcf, 0xfa, 0xed, 0xfe, 7, 0, 0, 1],
            "exec",
        ),
        ("fat.bin", vec![0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 2], "exec"),
        ("z.bin", b"PK\x03\x04\0\0\0\0".to_vec(), "archive"),
        ("g.bin", vec![0x1f, 0x8b, 8, 0, 0, 0], "archive"),
        ("r.bin", vec![0u8, 1, 2, 3, 4], "other"),
    ];
    for (name, bytes, want) in cases {
        let sigs = run(&[(name, bytes)]);
        assert_eq!(magic_of(&sigs, name), want, "{name}");
    }
}

#[test]
fn executable_disguised_as_image_or_font_is_a_mismatch() {
    let sigs = run(&[
        ("assets/logo.png", vec![0x7f, b'E', b'L', b'F', 2, 1, 1, 0]),
        ("assets/font.woff2", b"MZ\x90\0\x03\0\0\0".to_vec()),
        ("assets/real.png", png()),
    ]);
    assert_eq!(magic_of(&sigs, "assets/logo.png"), "exec");
    assert_eq!(magic_of(&sigs, "assets/font.woff2"), "exec");
    let mism: Vec<&str> = with(&sigs, "extension_mismatch")
        .iter()
        .map(|s| s.locations[0].file.as_str())
        .collect();
    assert!(mism.contains(&"assets/logo.png"));
    assert!(mism.contains(&"assets/font.woff2"));
    assert!(!mism.contains(&"assets/real.png"));
}
