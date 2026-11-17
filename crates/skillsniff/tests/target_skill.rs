use std::fs;
use std::path::Path;

use skillsniff::frontmatter::parse_frontmatter;
use skillsniff::inventory::build_inventory;
use skillsniff::target::{FileRole, Lang, Target, TargetError, detect_skill};

fn write(root: &Path, rel: &str, bytes: &[u8]) {
    let p = root.join(rel);
    fs::create_dir_all(p.parent().unwrap()).unwrap();
    fs::write(p, bytes).unwrap();
}

const GOOD: &[u8] = b"---\nname: demo\ndescription: Does a thing\n---\n# Body\n";

#[test]
fn detects_skill_and_reads_name_description() {
    let dir = tempfile::tempdir().unwrap();
    write(dir.path(), "pkg/SKILL.md", GOOD);
    write(dir.path(), "pkg/run.py", b"print(1)\n");
    let inv = build_inventory(dir.path()).unwrap();
    let t = detect_skill(&inv, dir.path()).unwrap();
    assert_eq!(t.kind(), "skill");
    assert_eq!(t.skill_md, "pkg/SKILL.md");
    assert_eq!(t.name, "demo");
    assert_eq!(t.description, "Does a thing");
}

#[test]
fn crlf_and_bom_frontmatter_parses_with_correct_lines() {
    let text = "\u{feff}---\r\nname: demo\r\ndescription: x\r\n---\r\nbody\r\n";
    let (map, body_line) = parse_frontmatter(text).unwrap();
    assert_eq!(map["name"], "demo");
    assert_eq!(map["description"], "x");
    // Lines: 1 ---, 2 name, 3 description, 4 ---, 5 body.
    assert_eq!(body_line, 5);
    let lf = "---\nname: a\ndescription: b\n---\nbody\n";
    assert_eq!(parse_frontmatter(lf).unwrap().1, 5);
    let long = "---\nname: a\ndescription: b\nextra: c\n---\n\nbody\n";
    assert_eq!(parse_frontmatter(long).unwrap().1, 6);
}

#[test]
fn frontmatter_errors() {
    assert!(parse_frontmatter("no frontmatter\n").is_err());
    assert!(parse_frontmatter("---\nname: a\n").is_err());
    assert!(parse_frontmatter("---\nname: [unclosed\n---\n").is_err());
    assert!(parse_frontmatter("---\n- a\n- b\n---\n").is_err());
}

#[test]
fn non_string_values_are_rendered() {
    let (m, _) = parse_frontmatter("---\nn: 3\ntools: [a, b]\nflag: true\n---\n").unwrap();
    assert_eq!(m["n"], "3");
    assert_eq!(m["tools"], "a, b");
    assert_eq!(m["flag"], "true");
}

#[test]
fn no_skill_md_is_an_error() {
    let dir = tempfile::tempdir().unwrap();
    write(dir.path(), "README.md", b"hi\n");
    let inv = build_inventory(dir.path()).unwrap();
    assert!(matches!(
        detect_skill(&inv, dir.path()),
        Err(TargetError::NoSkill)
    ));
}

#[test]
fn two_skill_dirs_lists_both() {
    let dir = tempfile::tempdir().unwrap();
    write(dir.path(), "b/SKILL.md", GOOD);
    write(dir.path(), "a/x/SKILL.md", GOOD);
    write(dir.path(), "SKILL.md", GOOD);
    let inv = build_inventory(dir.path()).unwrap();
    match detect_skill(&inv, dir.path()) {
        Err(TargetError::MultipleSkills(dirs)) => assert_eq!(dirs, [".", "a/x", "b"]),
        other => panic!("unexpected {other:?}"),
    }
}

#[test]
fn missing_description_is_bad_frontmatter() {
    for body in [
        "---\nname: demo\n---\nbody\n",
        "---\nname: demo\ndescription: \"\"\n---\n",
        "---\nname: demo\ndescription: [a]\n---\n",
        "---\ndescription: d\n---\n",
    ] {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "SKILL.md", body.as_bytes());
        let inv = build_inventory(dir.path()).unwrap();
        let r = detect_skill(&inv, dir.path());
        assert!(matches!(r, Err(TargetError::BadFrontmatter(_))), "{body}");
    }
}

#[test]
fn classification_table() {
    let dir = tempfile::tempdir().unwrap();
    let files: &[(&str, &[u8])] = &[
        ("SKILL.md", GOOD),
        ("docs/notes.md", b"n\n"),
        ("a.py", b"x\n"),
        ("a.js", b"x\n"),
        ("a.mjs", b"x\n"),
        ("a.cjs", b"x\n"),
        ("a.ts", b"x\n"),
        ("a.mts", b"x\n"),
        ("a.cts", b"x\n"),
        ("a.sh", b"x\n"),
        ("a.bash", b"x\n"),
        ("noext", b"#!/bin/bash\necho hi\n"),
        ("noext2", b"#!/usr/bin/env sh\necho hi\n"),
        ("plain", b"#!/usr/bin/env python3\nx\n"),
        ("a.ps1", b"x\n"),
        ("a.psm1", b"x\n"),
        ("package.json", b"{}\n"),
        ("requirements.txt", b"x\n"),
        ("requirements-dev.txt", b"x\n"),
        ("pyproject.toml", b"x\n"),
        ("Cargo.toml", b"x\n"),
        ("settings.json", b"{}\n"),
        (".claude/other.json", b"{}\n"),
        (".codex/c.json", b"{}\n"),
        ("hooks/h.json", b"{}\n"),
        ("data.json", b"{}\n"),
        ("blob.dat", b"a\0b"),
        ("pic.py", b"\0\0\0"),
        ("notes.txt", b"hello\n"),
    ];
    for (p, b) in files {
        write(dir.path(), p, b);
    }
    let inv = build_inventory(dir.path()).unwrap();
    let t = detect_skill(&inv, dir.path()).unwrap();
    let c = t.classify(&inv);
    use FileRole::*;
    let want: &[(&str, FileRole)] = &[
        ("SKILL.md", Instructions),
        ("docs/notes.md", Instructions),
        ("a.py", Script(Lang::Python)),
        ("a.js", Script(Lang::JavaScript)),
        ("a.mjs", Script(Lang::JavaScript)),
        ("a.cjs", Script(Lang::JavaScript)),
        ("a.ts", Script(Lang::TypeScript)),
        ("a.mts", Script(Lang::TypeScript)),
        ("a.cts", Script(Lang::TypeScript)),
        ("a.sh", Script(Lang::Bash)),
        ("a.bash", Script(Lang::Bash)),
        ("noext", Script(Lang::Bash)),
        ("noext2", Script(Lang::Bash)),
        ("plain", Asset),
        ("a.ps1", Script(Lang::PowerShell)),
        ("a.psm1", Script(Lang::PowerShell)),
        ("package.json", Manifest),
        ("requirements.txt", Manifest),
        ("requirements-dev.txt", Manifest),
        ("pyproject.toml", Manifest),
        ("Cargo.toml", Manifest),
        ("settings.json", Config),
        (".claude/other.json", Config),
        (".codex/c.json", Config),
        ("hooks/h.json", Config),
        ("data.json", Asset),
        ("blob.dat", Binary),
        ("pic.py", Binary),
        ("notes.txt", Asset),
    ];
    assert_eq!(c.len(), want.len());
    for (p, r) in want {
        assert_eq!(c[*p], *r, "{p}");
    }
}
