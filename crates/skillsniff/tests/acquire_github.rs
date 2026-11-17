//! GitHub acquisition against a local HTTP test server. Nothing here touches
//! the real network.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use flate2::Compression;
use flate2::write::GzEncoder;
use skillsniff::acquire::{AcquireError, Limits, acquire_github, acquire_github_with_token};
use skillsniff::source::{Source, parse_source};

const SHA: &str = "a41f9c2d7e0b35681c4f9a2e7d3b0c5816f4a9e2";

// ---------------------------------------------------------------- server

type Handler = Box<dyn Fn(&str) -> Option<(u16, Vec<u8>)> + Send + Sync>;

struct Server {
    base: String,
    connections: Arc<AtomicUsize>,
    requests: Arc<Mutex<Vec<String>>>,
}

/// Serves canned responses; `None` from the handler means accept and never
/// reply. Each request is the raw header block.
fn serve(handler: Handler) -> Server {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let connections = Arc::new(AtomicUsize::new(0));
    let requests = Arc::new(Mutex::new(Vec::new()));
    let (c, r) = (connections.clone(), requests.clone());
    let handler = Arc::new(handler);
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { continue };
            c.fetch_add(1, Ordering::SeqCst);
            let (h, r) = (handler.clone(), r.clone());
            thread::spawn(move || handle(stream, &h, &r));
        }
    });
    Server {
        base,
        connections,
        requests,
    }
}

fn handle(mut stream: TcpStream, handler: &Handler, requests: &Mutex<Vec<String>>) {
    let mut head = Vec::new();
    let mut buf = [0u8; 1024];
    while !head.windows(4).any(|w| w == b"\r\n\r\n") {
        match stream.read(&mut buf) {
            Ok(0) | Err(_) => return,
            Ok(n) => head.extend_from_slice(&buf[..n]),
        }
    }
    let head = String::from_utf8_lossy(&head).into_owned();
    requests.lock().unwrap().push(head.clone());
    let target = head.split_whitespace().nth(1).unwrap_or("").to_string();
    match handler(&target) {
        Some((status, body)) => {
            let _ = write!(
                stream,
                "HTTP/1.1 {status} X\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = stream.write_all(&body);
        }
        None => thread::sleep(Duration::from_secs(10)),
    }
}

fn tarball(entries: &[(&str, &str)]) -> Vec<u8> {
    let mut b = tar::Builder::new(Vec::new());
    for (path, data) in entries {
        let mut h = tar::Header::new_gnu();
        h.set_size(data.len() as u64);
        h.set_mode(0o644);
        h.set_cksum();
        b.append_data(&mut h, path, data.as_bytes()).unwrap();
    }
    let raw = b.into_inner().unwrap();
    let mut enc = GzEncoder::new(Vec::new(), Compression::default());
    enc.write_all(&raw).unwrap();
    enc.finish().unwrap()
}

fn repo_server() -> Server {
    let tgz = tarball(&[
        ("repo-abc/README.md", "readme"),
        ("repo-abc/skills/demo/SKILL.md", "# demo"),
        ("repo-abc/skills/demo/run.sh", "echo hi"),
        ("repo-abc/other/x.txt", "x"),
    ]);
    serve(Box::new(move |target| {
        if target.starts_with("/repos/o/r/commits/") {
            Some((200, SHA.as_bytes().to_vec()))
        } else if target == format!("/o/r/tar.gz/{SHA}") {
            Some((200, tgz.clone()))
        } else {
            Some((404, b"{}".to_vec()))
        }
    }))
}

fn gh(path: Option<&str>) -> Source {
    Source::GitHub {
        owner: "o".into(),
        repo: "r".into(),
        path: path.map(str::to_string),
        git_ref: None,
    }
}

// ----------------------------------------------------------------- tests

#[test]
fn parse_source_forms() {
    let g = |o: &str, r: &str, p: Option<&str>, f: Option<&str>| Source::GitHub {
        owner: o.into(),
        repo: r.into(),
        path: p.map(str::to_string),
        git_ref: f.map(str::to_string),
    };
    let cases = [
        ("https://github.com/o/r", g("o", "r", None, None)),
        ("https://github.com/o/r/", g("o", "r", None, None)),
        (
            "github.com/o/r/tree/main/a/b",
            g("o", "r", Some("a/b"), Some("main")),
        ),
        ("github.com/o/r/tree/v1", g("o", "r", None, Some("v1"))),
        ("o/r", g("o", "r", None, None)),
        ("o/r/skills/x", g("o", "r", Some("skills/x"), None)),
        ("o/r@v2", g("o", "r", None, Some("v2"))),
        ("o/r/skills/x@v2", g("o", "r", Some("skills/x"), Some("v2"))),
    ];
    for (input, want) in cases {
        assert_eq!(parse_source(input).unwrap(), want, "{input}");
    }
    for bad in [
        "ftp://x",
        "o/",
        "o",
        "../r",
        "o/r/../x",
        "o/r/C:/x",
        "o/r@",
        "o/r@a b",
        "github.com/o/r/blob/main/x",
    ] {
        assert!(parse_source(bad).is_err(), "{bad} was accepted");
    }
}

#[test]
fn local_paths_win_over_shorthand() {
    let dir = tempfile::tempdir().unwrap();
    let sub = dir.path().join("o");
    std::fs::create_dir_all(sub.join("r")).unwrap();
    let s = sub.join("r");
    assert_eq!(
        parse_source(s.to_str().unwrap()).unwrap(),
        Source::LocalDir(s.clone())
    );
    let zip = dir.path().join("a.zip");
    std::fs::write(&zip, b"x").unwrap();
    assert_eq!(
        parse_source(zip.to_str().unwrap()).unwrap(),
        Source::Archive(zip)
    );
}

#[test]
fn resolves_ref_then_downloads_tarball_at_sha() {
    let srv = repo_server();
    let got = acquire_github_with_token(
        &gh(Some("skills/demo")),
        &Limits::default(),
        &srv.base,
        &srv.base,
        false,
        None,
    )
    .unwrap();
    assert_eq!(got.commit.as_deref(), Some(SHA));
    let root = got.quarantine.root();
    assert_eq!(
        std::fs::read_to_string(root.join("SKILL.md")).unwrap(),
        "# demo"
    );
    assert!(root.join("run.sh").is_file());
    assert!(!root.join("README.md").exists());
    assert!(!root.join("other").exists());
    let reqs = srv.requests.lock().unwrap();
    assert!(reqs[0].starts_with("GET /repos/o/r/commits/HEAD "));
    assert!(
        reqs[0]
            .to_ascii_lowercase()
            .contains("application/vnd.github.sha")
    );
    assert!(
        reqs[0]
            .to_ascii_lowercase()
            .contains("user-agent: skillsniff/")
    );
}

#[test]
fn whole_repo_strips_top_level_directory() {
    let srv = repo_server();
    let got = acquire_github_with_token(
        &gh(None),
        &Limits::default(),
        &srv.base,
        &srv.base,
        false,
        None,
    )
    .unwrap();
    assert!(got.quarantine.root().join("README.md").is_file());
    assert!(got.quarantine.root().join("skills/demo/SKILL.md").is_file());
}

#[test]
fn explicit_ref_is_used_in_the_api_request() {
    let srv = repo_server();
    let src = Source::GitHub {
        owner: "o".into(),
        repo: "r".into(),
        path: None,
        git_ref: Some("feature/x".into()),
    };
    acquire_github_with_token(&src, &Limits::default(), &srv.base, &srv.base, false, None).unwrap();
    assert!(srv.requests.lock().unwrap()[0].starts_with("GET /repos/o/r/commits/feature/x "));
}

#[test]
fn missing_path_in_tarball_is_not_found() {
    let srv = repo_server();
    let err = acquire_github_with_token(
        &gh(Some("nope")),
        &Limits::default(),
        &srv.base,
        &srv.base,
        false,
        None,
    )
    .unwrap_err();
    assert!(matches!(err, AcquireError::NotFound(_)), "{err}");
}

#[test]
fn missing_repo_maps_to_not_found() {
    let srv = serve(Box::new(|_| Some((404, b"{}".to_vec()))));
    let err = acquire_github_with_token(
        &gh(None),
        &Limits::default(),
        &srv.base,
        &srv.base,
        false,
        None,
    )
    .unwrap_err();
    assert!(matches!(err, AcquireError::NotFound(_)), "{err}");
}

#[test]
fn non_sha_answer_is_a_network_error() {
    let srv = serve(Box::new(|_| Some((200, b"not-a-sha".to_vec()))));
    let err = acquire_github_with_token(
        &gh(None),
        &Limits::default(),
        &srv.base,
        &srv.base,
        false,
        None,
    )
    .unwrap_err();
    assert!(matches!(err, AcquireError::Network(_)), "{err}");
}

#[test]
fn oversized_download_is_a_limit_error() {
    let tgz = tarball(&[("repo-abc/a.txt", &"x".repeat(5000))]);
    let srv = serve(Box::new(move |t| {
        if t.starts_with("/repos/") {
            Some((200, SHA.as_bytes().to_vec()))
        } else {
            Some((200, tgz.clone()))
        }
    }));
    let limits = Limits {
        max_total_bytes: 100,
        ..Limits::default()
    };
    let err = acquire_github_with_token(&gh(None), &limits, &srv.base, &srv.base, false, None)
        .unwrap_err();
    assert!(matches!(err, AcquireError::LimitExceeded(_)), "{err}");
}

#[test]
fn offline_refuses_without_network() {
    let srv = repo_server();
    let err =
        acquire_github(&gh(None), &Limits::default(), &srv.base, &srv.base, true).unwrap_err();
    assert_eq!(
        err.to_string(),
        "network error: offline: remote sources are disabled"
    );
    assert_eq!(srv.connections.load(Ordering::SeqCst), 0);
}

#[test]
fn token_is_sent_but_never_appears_in_error_text() {
    let srv = serve(Box::new(|_| Some((500, b"boom secret123".to_vec()))));
    let err = acquire_github_with_token(
        &gh(None),
        &Limits::default(),
        &srv.base,
        &srv.base,
        false,
        Some("secret123"),
    )
    .unwrap_err();
    assert!(matches!(err, AcquireError::Network(_)));
    assert!(!format!("{err}").contains("secret123"));
    assert!(!format!("{err:?}").contains("secret123"));
    let reqs = srv.requests.lock().unwrap();
    assert!(
        reqs[0]
            .to_ascii_lowercase()
            .contains("authorization: bearer secret123")
    );
}

#[test]
fn fetch_times_out() {
    let srv = serve(Box::new(|_| None));
    let limits = Limits {
        fetch_timeout: Duration::from_secs(1),
        ..Limits::default()
    };
    let start = Instant::now();
    let err = acquire_github_with_token(&gh(None), &limits, &srv.base, &srv.base, false, None)
        .unwrap_err();
    assert!(matches!(err, AcquireError::Network(_)), "{err}");
    assert!(start.elapsed() < Duration::from_secs(3));
}
