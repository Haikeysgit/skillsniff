//! Acquisition of local folders and archives into a quarantine.
//!
//! Every archive is built in memory with the `tar`/`zip` writers; no binary
//! fixtures are committed.

use std::fs;
use std::io::{Cursor, Write};
use std::path::{Path, PathBuf};

use flate2::Compression;
use flate2::write::GzEncoder;
use skillsniff::acquire::{
    AcquireError, Acquired, INVENTORY_PATTERNS, Limits, Quarantine, acquire_archive,
    acquire_local_dir,
};
use skillsniff::model::Signal;
use skillsniff::model::signal::INVENTORY;
use tempfile::TempDir;
use zip::write::SimpleFileOptions;

// ---------------------------------------------------------------- helpers

/// Kind of a raw tar entry written without the builder's path checks.
enum Raw<'a> {
    File(&'a [u8], u32),
    Dir,
    Symlink(&'a str),
    Hardlink(&'a str),
}

/// Builds a `.tar.gz` from raw entries. Names are written straight into the
/// header bytes so hostile names (`../x`, `/etc/passwd`) survive unchanged.
fn tar_gz(entries: &[(&str, Raw<'_>)]) -> Vec<u8> {
    let enc = GzEncoder::new(Vec::new(), Compression::best());
    let mut b = tar::Builder::new(enc);
    for (name, kind) in entries {
        let mut h = tar::Header::new_gnu();
        let bytes = name.as_bytes();
        assert!(bytes.len() < 100, "test names must fit the old header");
        h.as_old_mut().name[..bytes.len()].copy_from_slice(bytes);
        let data: &[u8] = match kind {
            Raw::File(data, mode) => {
                h.set_entry_type(tar::EntryType::Regular);
                h.set_mode(*mode);
                data
            }
            Raw::Dir => {
                h.set_entry_type(tar::EntryType::Directory);
                h.set_mode(0o755);
                &[]
            }
            Raw::Symlink(target) => {
                h.set_entry_type(tar::EntryType::Symlink);
                h.set_link_name_literal(target.as_bytes()).unwrap();
                h.set_mode(0o777);
                &[]
            }
            Raw::Hardlink(target) => {
                h.set_entry_type(tar::EntryType::Link);
                h.set_link_name_literal(target.as_bytes()).unwrap();
                h.set_mode(0o644);
                &[]
            }
        };
        h.set_size(data.len() as u64);
        h.set_cksum();
        b.append(&h, data).unwrap();
    }
    b.into_inner().unwrap().finish().unwrap()
}

/// Kind of a zip entry.
enum ZipRaw<'a> {
    File(&'a [u8]),
    Symlink(&'a str),
}

fn zip_bytes(entries: &[(&str, ZipRaw<'_>)]) -> Vec<u8> {
    let mut w = zip::ZipWriter::new(Cursor::new(Vec::new()));
    let opts = SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated)
        .unix_permissions(0o755);
    for (name, kind) in entries {
        match kind {
            ZipRaw::File(data) => {
                w.start_file(*name, opts).unwrap();
                w.write_all(data).unwrap();
            }
            ZipRaw::Symlink(target) => {
                w.add_symlink(*name, *target, opts).unwrap();
            }
        }
    }
    w.finish().unwrap().into_inner()
}

/// Writes `bytes` to `<new temp dir>/<file_name>` and returns both.
fn write_archive(file_name: &str, bytes: &[u8]) -> (TempDir, PathBuf) {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join(file_name);
    fs::write(&path, bytes).unwrap();
    (dir, path)
}

fn inventory<'a>(acq: &'a Acquired, pattern: &str) -> Vec<&'a Signal> {
    acq.signals
        .iter()
        .filter(|s| {
            s.kind == INVENTORY && s.fields.get("pattern").map(String::as_str) == Some(pattern)
        })
        .collect()
}

fn files(signal: &Signal) -> Vec<&str> {
    signal.locations.iter().map(|l| l.file.as_str()).collect()
}

fn assert_rejected(err: AcquireError) {
    assert!(
        matches!(
            err,
            AcquireError::LimitExceeded(_) | AcquireError::Unsupported(_)
        ),
        "expected LimitExceeded or Unsupported, got {err:?}"
    );
}

/// A file name unique to this test run, so checks for stray writes cannot be
/// fooled by leftovers.
fn unique(stem: &str) -> String {
    let t = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    format!("skillsniff-{stem}-{}-{t}.sh", std::process::id())
}

/// Lists every path under `root`, relative and `/`-separated, sorted.
fn tree(root: &Path) -> Vec<String> {
    fn walk(root: &Path, dir: &Path, out: &mut Vec<String>) {
        for e in fs::read_dir(dir).unwrap() {
            let e = e.unwrap();
            let p = e.path();
            let rel = p
                .strip_prefix(root)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/");
            let ft = fs::symlink_metadata(&p).unwrap().file_type();
            if ft.is_dir() {
                out.push(format!("{rel}/"));
                walk(root, &p, out);
            } else {
                out.push(rel);
            }
        }
    }
    let mut out = Vec::new();
    walk(root, root, &mut out);
    out.sort();
    out
}

// ---------------------------------------------------------- brief tests

#[test]
fn zip_with_parent_traversal_is_rejected() {
    let name = unique("zip-parent");
    let bytes = zip_bytes(&[
        ("SKILL.md", ZipRaw::File(b"ok")),
        (&format!("../{name}"), ZipRaw::File(b"echo pwned")),
    ]);
    let (dir, path) = write_archive("evil.zip", &bytes);

    let err = acquire_archive(&path, &Limits::default()).unwrap_err();
    assert_rejected(err);

    // `..` relative to the quarantine lands in the OS temp dir; relative to
    // the archive it lands in the archive's parent.
    assert!(!std::env::temp_dir().join(&name).exists());
    assert!(!dir.path().parent().unwrap().join(&name).exists());
    assert!(!dir.path().join(&name).exists());
}

#[test]
fn tar_with_absolute_path_is_rejected() {
    let bytes = tar_gz(&[
        ("SKILL.md", Raw::File(b"ok", 0o644)),
        ("/etc/passwd", Raw::File(b"root::0:0::/:/bin/sh", 0o644)),
    ]);
    let (_dir, path) = write_archive("evil.tar.gz", &bytes);

    let before = fs::read("/etc/passwd").ok();
    let err = acquire_archive(&path, &Limits::default()).unwrap_err();
    assert_rejected(err);
    assert_eq!(fs::read("/etc/passwd").ok(), before);
}

#[test]
fn symlink_entry_is_recorded_not_followed() {
    let bytes = tar_gz(&[
        ("SKILL.md", Raw::File(b"ok", 0o644)),
        ("link", Raw::Symlink("/home")),
    ]);
    let (_dir, path) = write_archive("skill.tar.gz", &bytes);

    let acq = acquire_archive(&path, &Limits::default()).unwrap();
    let sigs = inventory(&acq, "symlink");
    assert_eq!(sigs.len(), 1, "signals: {:?}", acq.signals);
    assert_eq!(files(sigs[0]), ["link"]);
    assert_eq!(sigs[0].locations[0].line, 0);
    assert_eq!(
        sigs[0].fields.get("target").map(String::as_str),
        Some("/home")
    );

    let link = acq.quarantine.root().join("link");
    assert!(
        fs::symlink_metadata(&link).is_err(),
        "nothing may exist at `link`"
    );
    assert_eq!(tree(acq.quarantine.root()), ["SKILL.md"]);
}

#[test]
fn case_colliding_entries_are_reported() {
    let tar = tar_gz(&[
        ("SKILL.md", Raw::File(b"ok", 0o644)),
        ("Run.sh", Raw::File(b"echo one", 0o644)),
        ("run.sh", Raw::File(b"echo two", 0o644)),
    ]);
    let zip = zip_bytes(&[
        ("SKILL.md", ZipRaw::File(b"ok")),
        ("Run.sh", ZipRaw::File(b"echo one")),
        ("run.sh", ZipRaw::File(b"echo two")),
    ]);
    for (name, bytes) in [("c.tar.gz", tar), ("c.zip", zip)] {
        let (_dir, path) = write_archive(name, &bytes);
        let acq = acquire_archive(&path, &Limits::default()).unwrap();
        let sigs = inventory(&acq, "case_collision");
        assert_eq!(sigs.len(), 1, "{name}: {:?}", acq.signals);
        assert_eq!(files(sigs[0]), ["Run.sh", "run.sh"], "{name}");
        assert_eq!(tree(acq.quarantine.root()), ["SKILL.md"], "{name}");
    }
}

#[test]
fn decompression_ratio_over_100_is_rejected() {
    // 4 MiB of zeros gzips to a few KB: far beyond 100:1, yet under the
    // 10 MB per-file and 50 MB total limits, so only the ratio can trip.
    let zeros = vec![0u8; 4 << 20];
    let bytes = tar_gz(&[("bomb.bin", Raw::File(&zeros, 0o644))]);
    assert!(bytes.len() < 10 * 1024, "gzip is {} bytes", bytes.len());
    let (_dir, path) = write_archive("bomb.tar.gz", &bytes);

    match acquire_archive(&path, &Limits::default()).unwrap_err() {
        AcquireError::LimitExceeded(msg) => assert!(msg.contains("ratio"), "{msg}"),
        other => panic!("expected LimitExceeded, got {other:?}"),
    }
}

#[test]
fn file_count_over_limit_is_rejected() {
    let limits = Limits {
        max_files: 3,
        ..Limits::default()
    };
    let names = ["a.md", "b.md", "c.md", "d.md"];

    let tar_entries: Vec<_> = names.iter().map(|n| (*n, Raw::File(b"x", 0o644))).collect();
    let (_t, tar_path) = write_archive("many.tgz", &tar_gz(&tar_entries));
    match acquire_archive(&tar_path, &limits).unwrap_err() {
        AcquireError::LimitExceeded(msg) => assert!(msg.contains("files"), "{msg}"),
        other => panic!("expected LimitExceeded, got {other:?}"),
    }

    let zip_entries: Vec<_> = names.iter().map(|n| (*n, ZipRaw::File(b"x"))).collect();
    let (_z, zip_path) = write_archive("many.zip", &zip_bytes(&zip_entries));
    assert!(matches!(
        acquire_archive(&zip_path, &limits).unwrap_err(),
        AcquireError::LimitExceeded(_)
    ));

    let src = TempDir::new().unwrap();
    for n in names {
        fs::write(src.path().join(n), "x").unwrap();
    }
    assert!(matches!(
        acquire_local_dir(src.path(), &limits).unwrap_err(),
        AcquireError::LimitExceeded(_)
    ));

    // Exactly at the limit is fine.
    let (_e, ok_path) = write_archive("three.tgz", &tar_gz(&tar_entries[..3]));
    acquire_archive(&ok_path, &limits).unwrap();
}

#[cfg(unix)]
#[test]
fn executable_bits_are_stripped() {
    use std::os::unix::fs::PermissionsExt;

    let mode = |p: &Path| fs::metadata(p).unwrap().permissions().mode();

    let bytes = tar_gz(&[("run.sh", Raw::File(b"echo hi", 0o755))]);
    let (_t, tar_path) = write_archive("x.tar.gz", &bytes);
    let acq = acquire_archive(&tar_path, &Limits::default()).unwrap();
    assert_eq!(mode(&acq.quarantine.root().join("run.sh")) & 0o111, 0);

    let zbytes = zip_bytes(&[("run.sh", ZipRaw::File(b"echo hi"))]);
    let (_z, zip_path) = write_archive("x.zip", &zbytes);
    let acq = acquire_archive(&zip_path, &Limits::default()).unwrap();
    assert_eq!(mode(&acq.quarantine.root().join("run.sh")) & 0o111, 0);

    let src = TempDir::new().unwrap();
    let f = src.path().join("run.sh");
    fs::write(&f, "echo hi").unwrap();
    fs::set_permissions(&f, fs::Permissions::from_mode(0o755)).unwrap();
    let acq = acquire_local_dir(src.path(), &Limits::default()).unwrap();
    assert_eq!(mode(&acq.quarantine.root().join("run.sh")) & 0o111, 0);
}

#[test]
fn quarantine_is_deleted_on_drop() {
    let q = Quarantine::new().unwrap();
    let root = q.root().to_path_buf();
    assert!(root.is_dir());
    assert!(
        root.starts_with(std::env::temp_dir())
            || root.starts_with(fs::canonicalize(std::env::temp_dir()).unwrap())
    );
    drop(q);
    assert!(!root.exists());

    let bytes = tar_gz(&[("SKILL.md", Raw::File(b"ok", 0o644))]);
    let (_d, path) = write_archive("s.tgz", &bytes);
    let acq = acquire_archive(&path, &Limits::default()).unwrap();
    let root = acq.quarantine.root().to_path_buf();
    assert!(root.join("SKILL.md").is_file());
    drop(acq);
    assert!(!root.exists());

    // `keep` hands the directory over instead of deleting it.
    let q = Quarantine::new().unwrap();
    let kept = q.keep();
    assert!(kept.is_dir());
    fs::remove_dir_all(&kept).unwrap();
}

// ---------------------------------------------------------- more coverage

#[test]
fn limits_default_to_spec_values() {
    let l = Limits::default();
    assert_eq!(l.max_total_bytes, 50 * 1024 * 1024);
    assert_eq!(l.max_files, 5_000);
    assert_eq!(l.max_file_bytes, 10 * 1024 * 1024);
    assert_eq!(l.max_ratio, 100);
    assert_eq!(l.fetch_timeout, std::time::Duration::from_secs(60));
}

#[test]
fn inventory_patterns_constant_lists_every_pattern() {
    assert_eq!(
        INVENTORY_PATTERNS,
        ["symlink", "hardlink", "case_collision"]
    );
}

#[test]
fn tar_gz_regular_files_are_extracted() {
    let bytes = tar_gz(&[
        ("./", Raw::Dir),
        ("./SKILL.md", Raw::File(b"---\nname: x\n---\n", 0o644)),
        ("./scripts/", Raw::Dir),
        ("./scripts/run.py", Raw::File(b"print(1)", 0o644)),
        ("docs/empty/", Raw::Dir),
    ]);
    for name in ["s.tar.gz", "s.tgz", "S.TGZ"] {
        let (_d, path) = write_archive(name, &bytes);
        let acq = acquire_archive(&path, &Limits::default()).unwrap();
        assert!(acq.signals.is_empty(), "{:?}", acq.signals);
        assert_eq!(acq.commit, None);
        assert_eq!(
            tree(acq.quarantine.root()),
            [
                "SKILL.md",
                "docs/",
                "docs/empty/",
                "scripts/",
                "scripts/run.py"
            ]
        );
        assert_eq!(
            fs::read(acq.quarantine.root().join("scripts/run.py")).unwrap(),
            b"print(1)"
        );
    }
}

#[test]
fn zip_regular_files_are_extracted() {
    let bytes = zip_bytes(&[
        ("SKILL.md", ZipRaw::File(b"hello")),
        ("scripts/run.py", ZipRaw::File(b"print(1)")),
    ]);
    let (_d, path) = write_archive("s.zip", &bytes);
    let acq = acquire_archive(&path, &Limits::default()).unwrap();
    assert!(acq.signals.is_empty(), "{:?}", acq.signals);
    assert_eq!(
        tree(acq.quarantine.root()),
        ["SKILL.md", "scripts/", "scripts/run.py"]
    );
    assert_eq!(
        fs::read(acq.quarantine.root().join("SKILL.md")).unwrap(),
        b"hello"
    );
    assert!(acq.source.ends_with("s.zip"), "{}", acq.source);
}

#[test]
fn hostile_entry_names_are_rejected() {
    let hostile = [
        "..\\evil.sh",
        "a\\..\\..\\evil.sh",
        "C:\\evil.sh",
        "C:evil.sh",
        "\\\\server\\share\\evil.sh",
        "//server/share/evil.sh",
        "\\evil.sh",
        "a/../../evil.sh",
        "a/..",
        "file.txt:stream",
        "nul\0.sh",
        ".. /evil.sh",
        "../",
    ];
    for name in hostile {
        let (_z, zp) = write_archive("h.zip", &zip_bytes(&[(name, ZipRaw::File(b"x"))]));
        match acquire_archive(&zp, &Limits::default()) {
            Err(e) => assert_rejected(e),
            Ok(a) => panic!("zip {name:?} accepted: {:?}", tree(a.quarantine.root())),
        }
        if !name.contains('\0') {
            let (_t, tp) = write_archive("h.tgz", &tar_gz(&[(name, Raw::File(b"x", 0o644))]));
            match acquire_archive(&tp, &Limits::default()) {
                Err(e) => assert_rejected(e),
                Ok(a) => panic!("tar {name:?} accepted: {:?}", tree(a.quarantine.root())),
            }
        }
    }
}

#[test]
fn hostile_symlink_and_hardlink_names_are_rejected_too() {
    let (_t, tp) = write_archive("h.tgz", &tar_gz(&[("../link", Raw::Symlink("/etc"))]));
    assert_rejected(acquire_archive(&tp, &Limits::default()).unwrap_err());
}

#[test]
fn hardlink_entry_is_recorded_not_extracted() {
    let bytes = tar_gz(&[
        ("SKILL.md", Raw::File(b"ok", 0o644)),
        ("copy.md", Raw::Hardlink("SKILL.md")),
    ]);
    let (_d, path) = write_archive("h.tar.gz", &bytes);
    let acq = acquire_archive(&path, &Limits::default()).unwrap();
    let sigs = inventory(&acq, "hardlink");
    assert_eq!(sigs.len(), 1, "{:?}", acq.signals);
    assert_eq!(files(sigs[0]), ["copy.md"]);
    assert_eq!(tree(acq.quarantine.root()), ["SKILL.md"]);
}

#[test]
fn zip_symlink_entry_is_recorded_not_followed() {
    let bytes = zip_bytes(&[
        ("SKILL.md", ZipRaw::File(b"ok")),
        ("keys", ZipRaw::Symlink("/home/user/.ssh")),
    ]);
    let (_d, path) = write_archive("l.zip", &bytes);
    let acq = acquire_archive(&path, &Limits::default()).unwrap();
    let sigs = inventory(&acq, "symlink");
    assert_eq!(sigs.len(), 1, "{:?}", acq.signals);
    assert_eq!(files(sigs[0]), ["keys"]);
    assert_eq!(
        sigs[0].fields.get("target").map(String::as_str),
        Some("/home/user/.ssh")
    );
    assert_eq!(tree(acq.quarantine.root()), ["SKILL.md"]);
}

#[test]
fn directory_case_collision_skips_both_subtrees() {
    let bytes = tar_gz(&[
        ("SKILL.md", Raw::File(b"ok", 0o644)),
        ("Lib/a.py", Raw::File(b"a", 0o644)),
        ("lib/b.py", Raw::File(b"b", 0o644)),
    ]);
    let (_d, path) = write_archive("d.tgz", &bytes);
    let acq = acquire_archive(&path, &Limits::default()).unwrap();
    let sigs = inventory(&acq, "case_collision");
    assert_eq!(sigs.len(), 1, "{:?}", acq.signals);
    assert_eq!(files(sigs[0]), ["Lib", "lib"]);
    assert_eq!(tree(acq.quarantine.root()), ["SKILL.md"]);
}

#[test]
fn duplicate_and_file_versus_directory_entries_collide() {
    let bytes = tar_gz(&[
        ("SKILL.md", Raw::File(b"one", 0o644)),
        ("SKILL.md", Raw::File(b"two", 0o644)),
        ("x", Raw::File(b"file", 0o644)),
        ("x/y", Raw::File(b"nested", 0o644)),
        ("keep.md", Raw::File(b"k", 0o644)),
    ]);
    let (_d, path) = write_archive("dup.tgz", &bytes);
    let acq = acquire_archive(&path, &Limits::default()).unwrap();
    let mut got: Vec<Vec<&str>> = inventory(&acq, "case_collision")
        .iter()
        .map(|s| files(s))
        .collect();
    got.sort();
    assert_eq!(got, [vec!["SKILL.md"], vec!["x"]]);
    assert_eq!(tree(acq.quarantine.root()), ["keep.md"]);
}

#[test]
fn per_file_and_total_limits_trip_while_streaming() {
    // Random-ish bytes so the ratio limit stays out of the way.
    let data: Vec<u8> = (0..64 * 1024u32)
        .map(|i| (i.wrapping_mul(2_654_435_761) >> 13) as u8)
        .collect();

    let per_file = Limits {
        max_file_bytes: 1024,
        ..Limits::default()
    };
    let (_t, tp) = write_archive("big.tgz", &tar_gz(&[("big.bin", Raw::File(&data, 0o644))]));
    match acquire_archive(&tp, &per_file).unwrap_err() {
        AcquireError::LimitExceeded(msg) => assert!(msg.contains("file"), "{msg}"),
        other => panic!("{other:?}"),
    }
    let (_z, zp) = write_archive("big.zip", &zip_bytes(&[("big.bin", ZipRaw::File(&data))]));
    assert!(matches!(
        acquire_archive(&zp, &per_file).unwrap_err(),
        AcquireError::LimitExceeded(_)
    ));

    let total = Limits {
        max_total_bytes: 100 * 1024,
        ..Limits::default()
    };
    let (_t2, tp2) = write_archive(
        "two.tgz",
        &tar_gz(&[
            ("a.bin", Raw::File(&data, 0o644)),
            ("b.bin", Raw::File(&data, 0o644)),
        ]),
    );
    match acquire_archive(&tp2, &total).unwrap_err() {
        AcquireError::LimitExceeded(msg) => assert!(msg.contains("total"), "{msg}"),
        other => panic!("{other:?}"),
    }

    let src = TempDir::new().unwrap();
    fs::write(src.path().join("big.bin"), &data).unwrap();
    assert!(matches!(
        acquire_local_dir(src.path(), &per_file).unwrap_err(),
        AcquireError::LimitExceeded(_)
    ));
}

#[test]
fn zip_bomb_is_rejected_by_ratio() {
    let zeros = vec![0u8; 4 << 20];
    let bytes = zip_bytes(&[("bomb.bin", ZipRaw::File(&zeros))]);
    let (_d, path) = write_archive("bomb.zip", &bytes);
    match acquire_archive(&path, &Limits::default()).unwrap_err() {
        AcquireError::LimitExceeded(msg) => assert!(msg.contains("ratio"), "{msg}"),
        other => panic!("expected LimitExceeded, got {other:?}"),
    }
}

#[test]
fn unknown_extension_and_missing_paths_are_errors() {
    let (_d, path) = write_archive("skill.rar", b"Rar!");
    assert!(matches!(
        acquire_archive(&path, &Limits::default()).unwrap_err(),
        AcquireError::Unsupported(_)
    ));

    let missing = Path::new("definitely-missing-skillsniff-input.zip");
    assert!(matches!(
        acquire_archive(missing, &Limits::default()).unwrap_err(),
        AcquireError::NotFound(_)
    ));
    assert!(matches!(
        acquire_local_dir(
            Path::new("definitely-missing-skillsniff-dir"),
            &Limits::default()
        )
        .unwrap_err(),
        AcquireError::NotFound(_)
    ));

    let (_g, garbage) = write_archive("junk.zip", b"not a zip at all");
    assert!(acquire_archive(&garbage, &Limits::default()).is_err());
    let (_h, garbage) = write_archive("junk.tar.gz", b"not gzip");
    assert!(acquire_archive(&garbage, &Limits::default()).is_err());
}

#[test]
fn local_dir_copies_regular_files() {
    let src = TempDir::new().unwrap();
    fs::write(src.path().join("SKILL.md"), "hello").unwrap();
    fs::create_dir_all(src.path().join("scripts/deep")).unwrap();
    fs::write(src.path().join("scripts/deep/run.py"), "print(1)").unwrap();
    let acq = acquire_local_dir(src.path(), &Limits::default()).unwrap();
    assert!(acq.signals.is_empty(), "{:?}", acq.signals);
    assert_eq!(acq.commit, None);
    assert_eq!(
        tree(acq.quarantine.root()),
        [
            "SKILL.md",
            "scripts/",
            "scripts/deep/",
            "scripts/deep/run.py"
        ]
    );
    assert_eq!(
        fs::read(acq.quarantine.root().join("scripts/deep/run.py")).unwrap(),
        b"print(1)"
    );
    // The source is untouched.
    assert!(src.path().join("SKILL.md").is_file());
}

#[test]
fn local_dir_file_argument_is_rejected() {
    let src = TempDir::new().unwrap();
    let f = src.path().join("SKILL.md");
    fs::write(&f, "x").unwrap();
    assert!(acquire_local_dir(&f, &Limits::default()).is_err());
}

/// Creates a link to a directory; `None` when the OS refuses (Windows
/// without the symlink privilege).
fn dir_link(target: &Path, link: &Path) -> Option<()> {
    #[cfg(unix)]
    let r = std::os::unix::fs::symlink(target, link);
    #[cfg(windows)]
    let r = std::os::windows::fs::symlink_dir(target, link);
    match r {
        Ok(()) => Some(()),
        Err(e) => {
            eprintln!("note: skipping, cannot create symlink here: {e}");
            None
        }
    }
}

fn file_link(target: &Path, link: &Path) -> Option<()> {
    #[cfg(unix)]
    let r = std::os::unix::fs::symlink(target, link);
    #[cfg(windows)]
    let r = std::os::windows::fs::symlink_file(target, link);
    match r {
        Ok(()) => Some(()),
        Err(e) => {
            eprintln!("note: skipping, cannot create symlink here: {e}");
            None
        }
    }
}

#[test]
fn local_dir_symlinks_are_recorded_not_followed() {
    let outside = TempDir::new().unwrap();
    fs::write(outside.path().join("secret.txt"), "top secret").unwrap();

    let src = TempDir::new().unwrap();
    fs::write(src.path().join("SKILL.md"), "ok").unwrap();
    if dir_link(outside.path(), &src.path().join("outside")).is_none() {
        return;
    }
    if file_link(
        &outside.path().join("secret.txt"),
        &src.path().join("secret.md"),
    )
    .is_none()
    {
        return;
    }

    let acq = acquire_local_dir(src.path(), &Limits::default()).unwrap();
    let mut got: Vec<&str> = inventory(&acq, "symlink")
        .iter()
        .flat_map(|s| files(s))
        .collect();
    got.sort();
    assert_eq!(got, ["outside", "secret.md"], "{:?}", acq.signals);
    for s in inventory(&acq, "symlink") {
        assert!(s.fields.contains_key("target"), "{s:?}");
    }
    assert_eq!(tree(acq.quarantine.root()), ["SKILL.md"]);
}

#[cfg(unix)]
#[test]
fn local_dir_hardlinks_are_recorded_not_copied() {
    let src = TempDir::new().unwrap();
    fs::write(src.path().join("SKILL.md"), "ok").unwrap();
    fs::write(src.path().join("a.txt"), "shared").unwrap();
    fs::hard_link(src.path().join("a.txt"), src.path().join("b.txt")).unwrap();
    let acq = acquire_local_dir(src.path(), &Limits::default()).unwrap();
    let mut got: Vec<&str> = inventory(&acq, "hardlink")
        .iter()
        .flat_map(|s| files(s))
        .collect();
    got.sort();
    assert_eq!(got, ["a.txt", "b.txt"]);
    assert_eq!(tree(acq.quarantine.root()), ["SKILL.md"]);
}

#[cfg(target_os = "linux")]
#[test]
fn local_dir_case_collision_is_reported() {
    let src = TempDir::new().unwrap();
    fs::write(src.path().join("Run.sh"), "1").unwrap();
    fs::write(src.path().join("run.sh"), "2").unwrap();
    fs::write(src.path().join("SKILL.md"), "ok").unwrap();
    let acq = acquire_local_dir(src.path(), &Limits::default()).unwrap();
    let sigs = inventory(&acq, "case_collision");
    assert_eq!(sigs.len(), 1);
    assert_eq!(files(sigs[0]), ["Run.sh", "run.sh"]);
    assert_eq!(tree(acq.quarantine.root()), ["SKILL.md"]);
}
