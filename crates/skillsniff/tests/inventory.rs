use std::fs;
use std::path::Path;

use skillsniff::inventory::{ContentType, build_inventory};

fn write(root: &Path, rel: &str, bytes: &[u8]) {
    let p = root.join(rel);
    fs::create_dir_all(p.parent().unwrap()).unwrap();
    fs::write(p, bytes).unwrap();
}

#[test]
fn tree_hash_is_stable_across_line_ending_checkouts() {
    let dir = tempfile::tempdir().unwrap();
    write(dir.path(), "sub/b.txt", b"a\r\nb\r\n");
    write(dir.path(), "a.txt", b"hello\n");
    let inv = build_inventory(dir.path()).unwrap();
    assert_eq!(
        inv.tree_sha256,
        "fc619bee4380342cb67ce00c6d4d32ebde45456458ed346bd5de4fadf50ff9d4"
    );
    let paths: Vec<_> = inv.files.iter().map(|f| f.path.as_str()).collect();
    assert_eq!(paths, ["a.txt", "sub/b.txt"]);
    assert_eq!(
        inv.files[0].sha256,
        "5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03"
    );
    assert!(inv.files[1].crlf);
    assert!(!inv.files[0].crlf);
    assert_eq!(inv.files[0].size, 6);
}

#[test]
fn tree_hash_changes_when_one_byte_changes() {
    let dir = tempfile::tempdir().unwrap();
    write(dir.path(), "a.txt", b"hello\n");
    let before = build_inventory(dir.path()).unwrap().tree_sha256;
    write(dir.path(), "a.txt", b"hellp\n");
    let after = build_inventory(dir.path()).unwrap().tree_sha256;
    assert_ne!(before, after);
}

#[test]
fn binary_detection() {
    let dir = tempfile::tempdir().unwrap();
    write(dir.path(), "nul.bin", b"ab\0cd");
    write(dir.path(), "bad.txt", &[0x66, 0xff, 0xfe, 0x67]);
    write(dir.path(), "bom.txt", b"\xef\xbb\xbfhello");
    write(dir.path(), "ok.txt", "caf\u{e9}\n".as_bytes());
    let inv = build_inventory(dir.path()).unwrap();
    let ty = |p: &str| inv.files.iter().find(|f| f.path == p).unwrap().content_type;
    assert_eq!(ty("nul.bin"), ContentType::Binary);
    assert_eq!(ty("bad.txt"), ContentType::Binary);
    assert_eq!(ty("bom.txt"), ContentType::Text);
    assert_eq!(ty("ok.txt"), ContentType::Text);
}

#[test]
fn minified_detection() {
    let dir = tempfile::tempdir().unwrap();
    write(dir.path(), "min.js", "x".repeat(600).as_bytes());
    write(dir.path(), "normal.js", b"let a = 1;\nlet b = 2;\n");
    write(dir.path(), "blob.bin", &[0u8; 2000]);
    let inv = build_inventory(dir.path()).unwrap();
    let m = |p: &str| inv.files.iter().find(|f| f.path == p).unwrap().minified;
    assert!(m("min.js"));
    assert!(!m("normal.js"));
    assert!(!m("blob.bin"));
}

#[test]
fn empty_root_has_empty_hash_of_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let inv = build_inventory(dir.path()).unwrap();
    assert!(inv.files.is_empty());
    assert_eq!(
        inv.tree_sha256,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
}
