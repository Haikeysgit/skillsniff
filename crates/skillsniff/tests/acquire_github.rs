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
/// Returns the complete raw HTTP response; `None` means never reply.
type RawHandler = Box<dyn Fn(&str) -> Option<Vec<u8>> + Send + Sync>;

fn response(status: u16, headers: &[(&str, &str)], body: &[u8]) -> Vec<u8> {
    let mut out = format!("HTTP/1.1 {status} X\r\nConnection: close\r\n").into_bytes();
    for (k, v) in headers {
        out.extend_from_slice(format!("{k}: {v}\r\n").as_bytes());
    }
    out.extend_from_slice(b"\r\n");
    out.extend_from_slice(body);
    out
}

struct Server {
    base: String,
    connections: Arc<AtomicUsize>,
    requests: Arc<Mutex<Vec<String>>>,
}

/// Serves canned responses; `None` from the handler means accept and never
/// reply. Each request is the raw header block.
fn serve(handler: Handler) -> Server {
    serve_raw(Box::new(move |t| {
        handler(t).map(|(status, body)| {
            let len = body.len().to_string();
            response(status, &[("Content-Length", &len)], &body)
        })
    }))
}

fn serve_raw(handler: RawHandler) -> Server {
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

fn handle(mut stream: TcpStream, handler: &RawHandler, requests: &Mutex<Vec<String>>) {
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
        Some(bytes) => {
            let _ = stream.write_all(&bytes);
        }
        None => thread::sleep(Duration::from_secs(10)),
    }
}

fn tarball(entries: &[(&str, &str)]) -> Vec<u8> {
    tarball_with(entries, false)
}

fn tarball_with(entries: &[(&str, &str)], pax_global: bool) -> Vec<u8> {
    let mut b = tar::Builder::new(Vec::new());
    if pax_global {
        let rec = format!("52 comment={SHA}\n");
        let mut h = tar::Header::new_ustar();
        h.set_entry_type(tar::EntryType::XGlobalHeader);
        h.set_size(rec.len() as u64);
        h.set_path("pax_global_header").unwrap();
        h.set_cksum();
        b.append(&h, rec.as_bytes()).unwrap();
    }
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

/// Incompressible bytes, so the gzip stream is about as large as its input.
fn noise(n: usize) -> Vec<u8> {
    let mut x: u64 = 0x9E37_79B9_7F4A_7C15;
    (0..n)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            (x >> 24) as u8
        })
        .collect()
}

fn noisy_tarball() -> Vec<u8> {
    let raw = noise(20_000);
    let mut b = tar::Builder::new(Vec::new());
    let mut h = tar::Header::new_gnu();
    h.set_size(raw.len() as u64);
    h.set_mode(0o644);
    h.set_cksum();
    b.append_data(&mut h, "repo-abc/a.bin", raw.as_slice())
        .unwrap();
    let raw = b.into_inner().unwrap();
    let mut enc = GzEncoder::new(Vec::new(), Compression::default());
    enc.write_all(&raw).unwrap();
    enc.finish().unwrap()
}

const CAP: u64 = 1000;

fn assert_cap_error(err: &AcquireError) {
    assert!(
        matches!(err, AcquireError::LimitExceeded(m) if m.starts_with("download is larger than")),
        "{err}"
    );
}

#[test]
fn oversized_download_is_a_limit_error() {
    let tgz = noisy_tarball();
    assert!(tgz.len() as u64 > CAP * 5);
    let srv = serve(Box::new(move |t| {
        if t.starts_with("/repos/") {
            Some((200, SHA.as_bytes().to_vec()))
        } else {
            Some((200, tgz.clone()))
        }
    }));
    let limits = Limits {
        max_total_bytes: CAP,
        ..Limits::default()
    };
    let err = acquire_github_with_token(&gh(None), &limits, &srv.base, &srv.base, false, None)
        .unwrap_err();
    assert_cap_error(&err);
}

#[test]
fn content_length_is_not_trusted() {
    // No Content-Length at all: the body runs until the connection closes.
    let tgz = noisy_tarball();
    let srv = serve_raw(Box::new(move |t| {
        if t.starts_with("/repos/") {
            Some(response(200, &[], SHA.as_bytes()))
        } else {
            Some(response(200, &[], &tgz))
        }
    }));
    let limits = Limits {
        max_total_bytes: CAP,
        ..Limits::default()
    };
    let err = acquire_github_with_token(&gh(None), &limits, &srv.base, &srv.base, false, None)
        .unwrap_err();
    assert_cap_error(&err);
}

#[test]
fn api_redirect_within_allowed_host_is_followed() {
    let tgz = tarball(&[("repo-abc/SKILL.md", "# s")]);
    let srv = serve_raw(Box::new(move |t| {
        if t == "/repos/o/r/commits/HEAD" {
            Some(response(301, &[("Location", "/moved/commit")], b""))
        } else if t == "/moved/commit" {
            Some(response(200, &[], SHA.as_bytes()))
        } else if t == format!("/o/r/tar.gz/{SHA}") {
            Some(response(200, &[], &tgz))
        } else {
            Some(response(404, &[], b""))
        }
    }));
    let got = acquire_github_with_token(
        &gh(None),
        &Limits::default(),
        &srv.base,
        &srv.base,
        false,
        None,
    )
    .unwrap();
    assert_eq!(got.commit.as_deref(), Some(SHA));
}

#[test]
fn redirect_to_foreign_host_is_refused() {
    let other = serve(Box::new(|_| Some((200, SHA.as_bytes().to_vec()))));
    let target = format!("{}/x", other.base);
    let srv = serve_raw(Box::new(move |_| {
        Some(response(302, &[("Location", &target)], b""))
    }));
    let err = acquire_github_with_token(
        &gh(None),
        &Limits::default(),
        &srv.base,
        &srv.base,
        false,
        Some("tok-xyz"),
    )
    .unwrap_err();
    assert!(matches!(err, AcquireError::Network(_)), "{err}");
    assert!(!format!("{err}").contains("tok-xyz"));
    assert_eq!(other.connections.load(Ordering::SeqCst), 0);
}

#[test]
fn authorization_not_sent_after_host_change() {
    // The API host redirects to the codeload host. Both are allowed, but the
    // token must not travel with the redirect.
    let code = serve(Box::new(|_| Some((200, SHA.as_bytes().to_vec()))));
    let target = format!("{}/sha", code.base);
    let api = serve_raw(Box::new(move |_| {
        Some(response(302, &[("Location", &target)], b""))
    }));
    let _ = acquire_github_with_token(
        &gh(None),
        &Limits::default(),
        &api.base,
        &code.base,
        false,
        Some("tok-xyz"),
    );
    assert!(
        api.requests.lock().unwrap()[0]
            .to_ascii_lowercase()
            .contains("authorization: bearer tok-xyz")
    );
    let seen = code.requests.lock().unwrap();
    let redirected = seen
        .iter()
        .find(|r| r.starts_with("GET /sha "))
        .expect("redirect was followed");
    assert!(!redirected.contains("tok-xyz"));
}

#[test]
fn redirect_loop_stops_after_three_hops() {
    let srv = serve_raw(Box::new(|_| {
        Some(response(302, &[("Location", "/again")], b""))
    }));
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
    assert_eq!(srv.requests.lock().unwrap().len(), 4);
}

#[test]
fn redirect_without_location_is_a_network_error() {
    let srv = serve_raw(Box::new(|_| Some(response(302, &[], b""))));
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
fn pax_global_header_is_ignored_when_stripping_top() {
    let tgz = tarball_with(&[("repo-abc/SKILL.md", "# s")], true);
    let srv = serve(Box::new(move |t| {
        if t.starts_with("/repos/") {
            Some((200, SHA.as_bytes().to_vec()))
        } else {
            Some((200, tgz.clone()))
        }
    }));
    let got = acquire_github_with_token(
        &gh(None),
        &Limits::default(),
        &srv.base,
        &srv.base,
        false,
        None,
    )
    .unwrap();
    assert!(got.quarantine.root().join("SKILL.md").is_file());
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
