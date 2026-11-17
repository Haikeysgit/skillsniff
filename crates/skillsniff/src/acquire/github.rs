//! GitHub acquisition: resolve a ref to a commit, download that commit's
//! tarball, extract it into a quarantine.
//!
//! Only the two configured hosts are contacted and redirects are not
//! followed, so neither the token nor a request can be steered elsewhere.

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
    let what = format!("{owner}/{repo}");

    let ref_name = git_ref.as_deref().unwrap_or("HEAD");
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
    )?;
    let mut text = Vec::new();
    body.by_ref()
        .take(MAX_SHA_BODY + 1)
        .read_to_end(&mut text)
        .map_err(|e| network(&format!("reading commit response failed: {e}")))?;
    let sha = std::str::from_utf8(&text)
        .ok()
        .map(str::trim)
        .filter(|t| t.len() == 40 && t.bytes().all(|b| b.is_ascii_hexdigit()))
        .map(str::to_ascii_lowercase)
        .ok_or_else(|| network("GitHub did not return a 40-character commit SHA"))?;

    let url = format!(
        "{}/{owner}/{repo}/tar.gz/{sha}",
        codeload_base.trim_end_matches('/')
    );
    let mut body = get(&agent, &url, None, token, &what)?;
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
        .http_status_as_error(false)
        .user_agent(format!("skillsniff/{}", crate::VERSION))
        .build()
        .into()
}

fn network(msg: &str) -> AcquireError {
    AcquireError::Network(msg.to_string())
}

/// Sends one GET and returns the body reader of a 2xx response.
fn get(
    agent: &Agent,
    url: &str,
    accept: Option<&str>,
    token: Option<&str>,
    what: &str,
) -> Result<impl Read + use<>, AcquireError> {
    let mut req = agent.get(url);
    if let Some(a) = accept {
        req = req.header("Accept", a);
    }
    if let Some(t) = token {
        req = req.header("Authorization", format!("Bearer {t}"));
    }
    let resp = req
        .call()
        .map_err(|e| network(&sanitize_evidence(&format!("request failed: {e}"))))?;
    let status = resp.status();
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
    Ok(resp.into_body().into_reader())
}
