//! Report model, evidence sanitizing and finding order.

use std::collections::BTreeMap;
use std::fmt;

use serde::de::{self, Deserializer};
use serde::ser::Serializer;
use serde::{Deserialize, Serialize};

pub mod signal;

/// Maximum number of characters kept in an evidence string.
pub const EVIDENCE_MAX_CHARS: usize = 200;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Verdict {
    Pass,
    Caution,
    Block,
}

impl Verdict {
    /// Process exit code for this verdict.
    pub fn exit_code(self) -> i32 {
        match self {
            Verdict::Pass => 0,
            Verdict::Caution => 1,
            Verdict::Block => 2,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Location {
    pub file: String,
    pub line: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Signal {
    pub kind: String,
    pub fields: BTreeMap<String, String>,
    pub locations: Vec<Location>,
    pub evidence: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Coverage {
    Ran,
    Skipped { reason: String },
    Failed { reason: String },
}

impl fmt::Display for Coverage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Coverage::Ran => f.write_str("ran"),
            Coverage::Skipped { reason } => write!(f, "skipped: {reason}"),
            Coverage::Failed { reason } => write!(f, "failed: {reason}"),
        }
    }
}

impl Serialize for Coverage {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for Coverage {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let text = String::deserialize(d)?;
        if text == "ran" {
            Ok(Coverage::Ran)
        } else if let Some(reason) = text.strip_prefix("skipped: ") {
            Ok(Coverage::Skipped {
                reason: reason.to_string(),
            })
        } else if let Some(reason) = text.strip_prefix("failed: ") {
            Ok(Coverage::Failed {
                reason: reason.to_string(),
            })
        } else {
            Err(de::Error::custom(format!(
                "invalid coverage value: {text:?}"
            )))
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FindingSource {
    Engine,
    Review,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
    pub rule: String,
    pub severity: Severity,
    pub title: String,
    pub locations: Vec<Location>,
    pub evidence: String,
    pub explain: String,
    pub advice: String,
    pub source: FindingSource,
    pub suppressed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolInfo {
    pub name: String,
    pub version: String,
    pub rules: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TargetInfo {
    pub source: String,
    #[serde(rename = "type")]
    pub kind: String,
    pub commit: Option<String>,
    pub tree_sha256: String,
}

/// Counts of unsuppressed findings per severity.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Summary {
    pub critical: u32,
    pub high: u32,
    pub medium: u32,
    pub low: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReviewInfo {
    pub applied: bool,
    pub rejected_changes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Report {
    pub schema_version: String,
    pub tool: ToolInfo,
    pub target: TargetInfo,
    pub verdict: Verdict,
    pub summary: Summary,
    pub findings: Vec<Finding>,
    pub coverage: BTreeMap<String, Coverage>,
    pub review: ReviewInfo,
}

fn needs_escape(c: char) -> bool {
    c.is_control()
        || matches!(
            c,
            '\u{200B}'..='\u{200F}'
                | '\u{202A}'..='\u{202E}'
                | '\u{2060}'..='\u{2064}'
                | '\u{2066}'..='\u{2069}'
                | '\u{FEFF}'
                | '\u{00AD}'
                | '\u{061C}'
        )
}

/// Escapes control, zero-width and bidi characters as `\u{XXXX}` and caps the
/// result at 200 characters, appending `…` when truncated.
pub fn sanitize_evidence(s: &str) -> String {
    let mut out = String::new();
    let mut count = 0usize;
    for c in s.chars() {
        let piece = if needs_escape(c) {
            format!("\\u{{{:04X}}}", c as u32)
        } else {
            c.to_string()
        };
        let len = piece.chars().count();
        if count + len > EVIDENCE_MAX_CHARS {
            out.push('…');
            return out;
        }
        out.push_str(&piece);
        count += len;
    }
    out
}

/// Sorts findings by severity (descending), then first location path, line,
/// and rule id, so output never depends on analyzer scheduling.
pub fn sort_findings(f: &mut [Finding]) {
    f.sort_by(|a, b| {
        let key = |x: &Finding| {
            let (file, line) = x
                .locations
                .first()
                .map(|l| (l.file.replace('\\', "/"), l.line))
                .unwrap_or_default();
            (std::cmp::Reverse(x.severity), file, line, x.rule.clone())
        };
        key(a).cmp(&key(b))
    });
}
