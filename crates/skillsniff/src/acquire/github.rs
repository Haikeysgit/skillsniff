//! GitHub acquisition: resolve a ref to a commit, download that commit's
//! tarball, extract it into a quarantine.
//!
//! Only the two configured hosts are contacted. Redirects are followed by
//! hand, a few hops at most and only between those hosts, so neither the
//! token nor a request can be steered elsewhere.

use std::io::Read;
use std::time::Duration;

use ureq::Agent;
use ureq::http::StatusCode;

use super::archive::{Selection, extract_tar_gz_selected};
use super::{AcquireError, Acquired, Limits, Quarantine};
use crate::model::sanitize_evidence;
use crate::source::Source;

/// Longest accepted body of the ref-resolution response, in bytes.
const MAX_SHA_BODY: u64 = 256;

/// Downloads a GitHub source at its resolved commit into a new quarantine.
///
/// `api_base` and `codeload_base` are `https://api.github.com` and
/// `https://codeload.github.com` in production. A `GITHUB_TOKEN` in the
/// environment is sent to those hosts only and never appears in errors.
pub fn acquire_github(
    src: &Source,
    limits: &Limits,
    api_base: &str,
    codeload_base: &str,
    offline: bool,
) -> Result<Acquired, AcquireError> {
    let token = std::env::var("GITHUB_TOKEN").ok().filter(|t| !t.is_empty());
    acquire_github_with_token(
        src,
        limits,
        api_base,
        codeload_base,
        offline,
        token.as_deref(),
    )
}

/// [`acquire_github`] with the token passed explicitly instead of read from
/// the environment.
#[doc(hidden)]
pub fn acquire_github_with_token(
    src: &Source,
    limits: &Limits,
    api_base: &str,
    codeload_base: &str,
    offline: bool,
    token: Option<&str>,
) -> Result<Acquired, AcquireError> {
    if offline {
        return Err(AcquireError::Network(
            "offline: remote sources are disabled".into(),
        ));
    }
    let Source::GitHub {
        owner,
        repo,
        path,
        git_ref,
    } = src
    else {
        return Err(AcquireError::Unsupported("not a GitHub source".to_string()));
    };
    let agent = agent(limits.fetch_timeout);
    let allowed: Vec<(String, String)> = [api_base, codeload_base]
        .iter()
        .filter_map(|b| split_url(b))
        .map(|(s, a, _)| (s.to_string(), a.to_string()))
        .collect();
    let what = format!("{owner}/{repo}");

    let ref_name = git_ref.as_deref().unwrap_or("HEAD");
    // A full commit SHA needs no lookup: skipping it saves an API request
    // (unauthenticated callers get only 60 an hour), and the download
    // answers 404 when the commit does not exist.
    let pinned = (ref_name.len() == 40 && ref_name.bytes().all(|b| b.is_ascii_hexdigit()))
        .then(|| ref_name.to_ascii_lowercase());
    let sha = match pinned {
        Some(sha) => sha,
        None => {
            let url = format!(
                "{}/repos/{owner}/{repo}/commits/{ref_name}",
                api_base.trim_end_matches('/')
            );
            let mut body = get(
                &agent,
                &url,
                Some("application/vnd.github.sha"),
                token,
                &what,
                &allowed,
            )?;
            let mut text = Vec::new();
            body.by_ref()
                .take(MAX_SHA_BODY + 1)
                .read_to_end(&mut text)
                .map_err(|e| network(&format!("reading commit response failed: {e}")))?;
            std::str::from_utf8(&text)
                .ok()
                .map(str::trim)
                .filter(|t| t.len() == 40 && t.bytes().all(|b| b.is_ascii_hexdigit()))
                .map(str::to_ascii_lowercase)
                .ok_or_else(|| network("GitHub did not return a 40-character commit SHA"))?
        }
    };

    let url = format!(
        "{}/{owner}/{repo}/tar.gz/{sha}",
        codeload_base.trim_end_matches('/')
    );
    let mut body = get(&agent, &url, None, token, &what, &allowed)?;
    let cap = limits.max_total_bytes;
    let mut bytes = Vec::new();
    body.by_ref()
        .take(cap.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|e| network(&format!("download failed: {e}")))?;
    if bytes.len() as u64 > cap {
        return Err(AcquireError::LimitExceeded(format!(
            "download is larger than the total limit of {cap} bytes"
        )));
    }

    let quarantine = Quarantine::new()?;
    let selection = Selection {
        strip_top: true,
        subpath: path.clone(),
    };
    let signals = extract_tar_gz_selected(&bytes, limits, quarantine.root(), &selection)?;

    let mut source = format!("https://github.com/{owner}/{repo}");
    if let Some(p) = path {
        source.push_str(&format!("/tree/{sha}/{p}"));
    }
    Ok(Acquired {
        quarantine,
        source,
        commit: Some(sha),
        signals,
    })
}

fn agent(timeout: Duration) -> Agent {
    Agent::config_builder()
        .timeout_global(Some(timeout))
        .max_redirects(0)
        .max_redirects_will_error(false)
        .http_status_as_error(false)
        .user_agent(format!("skillsniff/{}", crate::VERSION))
        .build()
        .into()
}

fn network(msg: &str) -> AcquireError {
    AcquireError::Network(msg.to_string())
}

/// Redirects followed per request.
const MAX_REDIRECTS: usize = 3;

/// Splits `scheme://authority/path` into its parts.
fn split_url(url: &str) -> Option<(&str, &str, &str)> {
    let (scheme, rest) = url.split_once("://")?;
    let end = rest.find('/').unwrap_or(rest.len());
    let (authority, path) = rest.split_at(end);
    if scheme.is_empty() || authority.is_empty() || authority.contains('@') {
        return None;
    }
    Some((scheme, authority, path))
}

/// Resolves a `Location` value against the URL it answered.
fn resolve_location(current: &str, location: &str) -> Option<String> {
    if location.starts_with('/') && !location.starts_with("//") {
        let (scheme, authority, _) = split_url(current)?;
        return Some(format!("{scheme}://{authority}{location}"));
    }
    split_url(location)?;
    Some(location.to_string())
}

/// Sends one GET and returns the body reader of a 2xx response.
///
/// Up to [`MAX_REDIRECTS`] redirects are followed by hand, and only to the
/// scheme and authority of `api_base` or `codeload_base`. The token is sent
/// only to the authority of the first request.
fn get(
    agent: &Agent,
    url: &str,
    accept: Option<&str>,
    token: Option<&str>,
    what: &str,
    allowed: &[(String, String)],
) -> Result<impl Read + use<>, AcquireError> {
    let first_authority = split_url(url)
        .map(|(_, a, _)| a.to_string())
        .ok_or_else(|| network("invalid GitHub base URL"))?;
    let mut url = url.to_string();
    let mut hops = 0;
    loop {
        let same_host = split_url(&url).is_some_and(|(_, a, _)| a == first_authority);
        let mut req = agent.get(&url);
        if let Some(a) = accept {
            req = req.header("Accept", a);
        }
        if let (Some(t), true) = (token, same_host) {
            req = req.header("Authorization", format!("Bearer {t}"));
        }
        let resp = req
            .call()
            .map_err(|e| network(&sanitize_evidence(&format!("request failed: {e}"))))?;
        let status = resp.status();
        if matches!(status.as_u16(), 301 | 302 | 303 | 307 | 308) {
            if hops == MAX_REDIRECTS {
                return Err(network("too many redirects from GitHub"));
            }
            hops += 1;
            let next = resp
                .headers()
                .get("location")
                .and_then(|v| v.to_str().ok())
                .and_then(|l| resolve_location(&url, l))
                .ok_or_else(|| network("GitHub sent a redirect without a usable Location"))?;
            let permitted = split_url(&next)
                .is_some_and(|(s, a, _)| allowed.iter().any(|(as_, aa)| as_ == s && aa == a));
            if !permitted {
                return Err(network("refused a redirect to a host that is not allowed"));
            }
            url = next;
            continue;
        }
        if status == StatusCode::NOT_FOUND {
            return Err(AcquireError::NotFound(format!(
                "{what} (or the requested ref) was not found on GitHub"
            )));
        }
        if !status.is_success() {
            return Err(network(&format!(
                "GitHub answered HTTP {}",
                status.as_u16()
            )));
        }
        return Ok(resp.into_body().into_reader());
    }
}
