//! Rule engine: turns analyzer signals into findings.
//!
//! A rule matches a signal when the kinds are equal and every `where` entry
//! equals the signal field of the same name. A `where` value may list
//! alternatives separated by `|`. When several rules match one signal, only
//! the most specific one (most `where` entries, then highest severity, then
//! pack order) produces a finding, so each signal yields exactly one finding.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

use yaml_rust2::{Yaml, YamlLoader};

use crate::model::{Finding, FindingSource, Location, Severity, Signal, sanitize_evidence};

/// Largest accepted rule file, in bytes.
const MAX_RULE_FILE_BYTES: u64 = 512 * 1024;
/// Most rule files read from one directory.
const MAX_RULE_FILES: usize = 64;

const CORE_PACK: &str = include_str!("../../../rules/core.yaml");

/// One detection rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rule {
    pub id: String,
    pub severity: Severity,
    pub title: String,
    /// Signal kind this rule applies to, such as `TaintFlow`.
    pub signal: String,
    /// Signal fields that must all match; a value may be `a|b|c`.
    pub r#where: BTreeMap<String, String>,
    pub explain: String,
    pub advice: String,
}

/// A versioned list of rules.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RulePack {
    pub version: String,
    pub rules: Vec<Rule>,
}

fn str_of<'a>(map: &'a Yaml, key: &str) -> Option<&'a str> {
    map[key].as_str()
}

fn parse_severity(s: &str) -> Result<Severity, String> {
    match s {
        "low" => Ok(Severity::Low),
        "medium" => Ok(Severity::Medium),
        "high" => Ok(Severity::High),
        "critical" => Ok(Severity::Critical),
        other => Err(format!("unknown severity \"{other}\"")),
    }
}

fn parse_rule(node: &Yaml) -> Result<Rule, String> {
    let field = |key: &str| {
        str_of(node, key)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .ok_or_else(|| format!("rule is missing a text field `{key}`"))
    };
    let id = field("id")?;
    let ctx = |e: String| format!("rule {id}: {e}");
    let severity = parse_severity(&field("severity").map_err(ctx)?).map_err(ctx)?;
    let mut wh = BTreeMap::new();
    match &node["where"] {
        Yaml::BadValue | Yaml::Null => {}
        Yaml::Hash(h) => {
            for (k, v) in h {
                let (Some(k), Some(v)) = (k.as_str(), v.as_str()) else {
                    return Err(format!("rule {id}: `where` entries must be text"));
                };
                wh.insert(k.to_string(), v.to_string());
            }
        }
        _ => return Err(format!("rule {id}: `where` must be a mapping")),
    }
    Ok(Rule {
        severity,
        title: field("title").map_err(ctx)?,
        signal: field("signal").map_err(ctx)?,
        r#where: wh,
        explain: field("explain").map_err(ctx)?,
        advice: field("advice").map_err(ctx)?,
        id,
    })
}

fn parse_pack(text: &str, need_version: bool) -> Result<RulePack, String> {
    let docs = YamlLoader::load_from_str(text).map_err(|e| format!("invalid YAML: {e}"))?;
    let [doc] = docs.as_slice() else {
        return Err("rule file must hold exactly one YAML document".to_string());
    };
    let version = match doc["version"].as_str() {
        Some(v) => v.to_string(),
        None if need_version => return Err("rule file needs a text `version`".to_string()),
        None => String::new(),
    };
    let Some(list) = doc["rules"].as_vec() else {
        return Err("rule file needs a `rules` list".to_string());
    };
    let rules = list.iter().map(parse_rule).collect::<Result<Vec<_>, _>>()?;
    let mut seen = BTreeSet::new();
    for r in &rules {
        if !seen.insert(r.id.as_str()) {
            return Err(format!("duplicate rule id {}", r.id));
        }
    }
    Ok(RulePack { version, rules })
}

/// The rule pack shipped with the tool.
pub fn builtin() -> RulePack {
    parse_pack(CORE_PACK, true).expect("built-in rule pack is valid")
}

/// Reads every `*.yaml` and `*.yml` file directly inside `dir`, in name order.
pub fn load_extra(dir: &Path) -> Result<Vec<Rule>, String> {
    let shown = dir.display();
    let entries =
        fs::read_dir(dir).map_err(|e| format!("cannot read rules folder {shown}: {e}"))?;
    let mut files = Vec::new();
    for entry in entries {
        let path = entry
            .map_err(|e| format!("cannot read rules folder {shown}: {e}"))?
            .path();
        let is_yaml = path
            .extension()
            .and_then(|e| e.to_str())
            .is_some_and(|e| e.eq_ignore_ascii_case("yaml") || e.eq_ignore_ascii_case("yml"));
        if is_yaml && path.is_file() {
            files.push(path);
        }
    }
    files.sort();
    if files.len() > MAX_RULE_FILES {
        return Err(format!("more than {MAX_RULE_FILES} rule files in {shown}"));
    }
    let mut rules = Vec::new();
    let mut seen = BTreeSet::new();
    for path in files {
        let name = path.display();
        let meta = fs::metadata(&path).map_err(|e| format!("{name}: {e}"))?;
        if meta.len() > MAX_RULE_FILE_BYTES {
            return Err(format!("{name}: rule file is larger than 512 KiB"));
        }
        let text = fs::read_to_string(&path).map_err(|e| format!("{name}: {e}"))?;
        for r in parse_pack(&text, false)
            .map_err(|e| format!("{name}: {e}"))?
            .rules
        {
            if !seen.insert(r.id.clone()) {
                return Err(format!("{name}: duplicate rule id {}", r.id));
            }
            rules.push(r);
        }
    }
    Ok(rules)
}

/// Adds `extra` rules to `builtin`. An extra rule that reuses an existing id
/// is an error: extras add, they never replace.
pub fn merge(mut builtin: RulePack, extra: Vec<Rule>) -> Result<RulePack, String> {
    let mut ids: BTreeSet<String> = builtin.rules.iter().map(|r| r.id.clone()).collect();
    for r in extra {
        if !ids.insert(r.id.clone()) {
            return Err(format!("rule id {} is already defined", r.id));
        }
        builtin.rules.push(r);
    }
    Ok(builtin)
}

fn matches(rule: &Rule, s: &Signal) -> bool {
    rule.signal == s.kind
        && rule.r#where.iter().all(|(k, want)| {
            s.fields
                .get(k)
                .is_some_and(|have| want.split('|').any(|alt| alt == have))
        })
}

/// One finding per signal, from the most specific matching rule. Signals no
/// rule matches produce nothing. Evidence and file names are sanitized.
pub fn apply(pack: &RulePack, signals: &[Signal]) -> Vec<Finding> {
    let mut out = Vec::new();
    for s in signals {
        let best = pack
            .rules
            .iter()
            .enumerate()
            .filter(|(_, r)| matches(r, s))
            .max_by_key(|(i, r)| (r.r#where.len(), r.severity, std::cmp::Reverse(*i)));
        let Some((_, r)) = best else {
            continue;
        };
        out.push(Finding {
            rule: r.id.clone(),
            severity: r.severity,
            title: r.title.clone(),
            locations: s
                .locations
                .iter()
                .map(|l| Location {
                    file: sanitize_evidence(&l.file),
                    line: l.line,
                })
                .collect(),
            evidence: sanitize_evidence(&s.evidence),
            explain: r.explain.clone(),
            advice: r.advice.clone(),
            source: FindingSource::Engine,
            suppressed: false,
        });
    }
    out
}
