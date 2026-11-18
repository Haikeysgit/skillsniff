use std::collections::{BTreeMap, BTreeSet};
use std::fs;

use skillsniff::acquire::INVENTORY_PATTERNS;
use skillsniff::analyzers::agent_config::AGENT_CONFIG_TARGETS;
use skillsniff::analyzers::code::patterns::{SINK_CLASSES, SOURCE_CLASSES};
use skillsniff::analyzers::hidden::HIDDEN_PATTERNS;
use skillsniff::analyzers::instructions::INSTRUCTION_PATTERNS;
use skillsniff::model::signal::{
    AGENT_CONFIG, HIDDEN, INSTRUCTION, INVENTORY, SINK, SOURCE, TAINT_FLOW,
};
use skillsniff::model::{Finding, Location, Severity, Signal};
use skillsniff::rules::{Rule, RulePack, apply, builtin, load_extra, merge};

fn sig(kind: &str, fields: &[(&str, &str)]) -> Signal {
    Signal {
        kind: kind.to_string(),
        fields: fields
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect::<BTreeMap<_, _>>(),
        locations: vec![Location {
            file: "a.md".to_string(),
            line: 3,
        }],
        evidence: "ev".to_string(),
    }
}

fn one(s: Signal) -> Finding {
    let pack = builtin();
    let mut f = apply(&pack, &[s]);
    assert_eq!(f.len(), 1, "expected exactly one finding");
    f.remove(0)
}

fn sev(kind: &str, fields: &[(&str, &str)]) -> Severity {
    one(sig(kind, fields)).severity
}

fn rule(id: &str, signal: &str, wh: &[(&str, &str)], severity: Severity) -> Rule {
    Rule {
        id: id.to_string(),
        severity,
        title: format!("title {id}"),
        signal: signal.to_string(),
        r#where: wh
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect(),
        explain: "explain".to_string(),
        advice: "advice".to_string(),
    }
}

fn pack_of(rules: Vec<Rule>) -> RulePack {
    RulePack {
        version: "t".to_string(),
        rules,
    }
}

#[test]
fn builtin_pack_loads_and_ids_are_unique() {
    let pack = builtin();
    assert!(!pack.version.is_empty());
    assert!(pack.rules.len() >= 50, "{} rules", pack.rules.len());
    let ids: BTreeSet<&str> = pack.rules.iter().map(|r| r.id.as_str()).collect();
    assert_eq!(ids.len(), pack.rules.len(), "duplicate rule id");
    for r in &pack.rules {
        let (area, name) = r.id.split_once('.').expect("area.name");
        assert!(!area.is_empty() && !name.is_empty(), "{}", r.id);
        assert!(!r.title.is_empty() && !r.explain.is_empty() && !r.advice.is_empty());
    }
}

#[test]
fn every_signal_pattern_has_a_rule() {
    let mut signals = Vec::new();
    for p in INVENTORY_PATTERNS {
        signals.push(sig(INVENTORY, &[("pattern", p)]));
    }
    for p in HIDDEN_PATTERNS {
        signals.push(sig(HIDDEN, &[("pattern", p)]));
    }
    for c in SOURCE_CLASSES {
        signals.push(sig(SOURCE, &[("class", c), ("lang", "python")]));
    }
    for c in SINK_CLASSES {
        signals.push(sig(SINK, &[("class", c), ("lang", "python")]));
    }
    for from in SOURCE_CLASSES {
        for to in SINK_CLASSES {
            signals.push(sig(
                TAINT_FLOW,
                &[("from", from), ("to", to), ("lang", "bash")],
            ));
        }
    }
    for p in INSTRUCTION_PATTERNS {
        signals.push(sig(INSTRUCTION, &[("pattern", p)]));
    }
    for t in AGENT_CONFIG_TARGETS {
        for ctx in ["code", "prose"] {
            signals.push(sig(AGENT_CONFIG, &[("target", t), ("context", ctx)]));
        }
    }
    let pack = builtin();
    for s in signals {
        let f = apply(&pack, std::slice::from_ref(&s));
        assert_eq!(f.len(), 1, "no single rule for {} {:?}", s.kind, s.fields);
    }
}

#[test]
fn where_requires_all_fields() {
    let pack = pack_of(vec![rule(
        "t.both",
        "Source",
        &[("class", "wallet"), ("lang", "python")],
        Severity::High,
    )]);
    let hit = sig("Source", &[("class", "wallet"), ("lang", "python")]);
    let half = sig("Source", &[("class", "wallet"), ("lang", "bash")]);
    let missing = sig("Source", &[("class", "wallet")]);
    let other_kind = sig("Sink", &[("class", "wallet"), ("lang", "python")]);
    assert_eq!(apply(&pack, &[hit]).len(), 1);
    assert!(apply(&pack, &[half]).is_empty());
    assert!(apply(&pack, &[missing]).is_empty());
    assert!(apply(&pack, &[other_kind]).is_empty());
}

#[test]
fn where_accepts_alternatives() {
    let pack = pack_of(vec![rule(
        "t.alt",
        "Hidden",
        &[("ext", "png|jpg|gif")],
        Severity::Low,
    )]);
    for e in ["png", "jpg", "gif"] {
        assert_eq!(apply(&pack, &[sig("Hidden", &[("ext", e)])]).len(), 1);
    }
    assert!(apply(&pack, &[sig("Hidden", &[("ext", "pn")])]).is_empty());
    assert!(apply(&pack, &[sig("Hidden", &[("ext", "")])]).is_empty());
}

#[test]
fn most_specific_rule_wins_then_higher_severity() {
    let pack = pack_of(vec![
        rule("t.generic", "Hidden", &[("pattern", "x")], Severity::High),
        rule(
            "t.specific",
            "Hidden",
            &[("pattern", "x"), ("ext", "png")],
            Severity::Low,
        ),
        rule("t.tie-low", "Sink", &[("class", "a")], Severity::Low),
        rule("t.tie-high", "Sink", &[("class", "a")], Severity::Critical),
    ]);
    let f = apply(&pack, &[sig("Hidden", &[("pattern", "x"), ("ext", "png")])]);
    assert_eq!(f.len(), 1);
    assert_eq!(f[0].rule, "t.specific");
    let f = apply(&pack, &[sig("Hidden", &[("pattern", "x"), ("ext", "bin")])]);
    assert_eq!(f[0].rule, "t.generic");
    let f = apply(&pack, &[sig("Sink", &[("class", "a")])]);
    assert_eq!(f[0].rule, "t.tie-high");
}

#[test]
fn extra_rule_cannot_replace_builtin() {
    let base = builtin();
    let dup = rule(&base.rules[0].id, "Hidden", &[], Severity::Low);
    assert!(merge(builtin(), vec![dup]).is_err());
    let new = rule(
        "custom.thing",
        "Hidden",
        &[("pattern", "zz")],
        Severity::Low,
    );
    let merged = merge(builtin(), vec![new.clone()]).unwrap();
    assert_eq!(merged.rules.len(), base.rules.len() + 1);
    assert!(merge(builtin(), vec![new.clone(), new]).is_err());
}

#[test]
fn extra_rules_load_from_a_directory() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(
        dir.path().join("mine.yaml"),
        "version: \"1\"\nrules:\n  - id: custom.thing\n    severity: medium\n    title: T\n    signal: Hidden\n    where:\n      pattern: zz\n    explain: E\n    advice: A\n",
    )
    .unwrap();
    let rules = load_extra(dir.path()).unwrap();
    assert_eq!(rules.len(), 1);
    assert_eq!(rules[0].severity, Severity::Medium);
    assert_eq!(rules[0].r#where["pattern"], "zz");

    fs::write(dir.path().join("bad.yaml"), "rules:\n  - id: x\n").unwrap();
    assert!(load_extra(dir.path()).is_err());
    assert!(load_extra(&dir.path().join("missing")).is_err());
}

#[test]
fn evidence_is_sanitized() {
    let mut s = sig("Hidden", &[("pattern", "zero_width")]);
    s.evidence = format!("a\u{202E}b\u{200B}{}", "x".repeat(400));
    s.locations[0].file = "dir/ev\u{202E}il.md".to_string();
    let f = one(s);
    assert!(f.evidence.contains("\\u{202E}"));
    assert!(f.evidence.contains("\\u{200B}"));
    assert!(!f.evidence.contains('\u{202E}'));
    assert!(f.evidence.chars().count() <= 201);
    assert_eq!(f.locations[0].file, "dir/ev\\u{202E}il.md");
}

#[test]
fn finding_copies_rule_text_and_signal_locations() {
    let f = one(sig("Instruction", &[("pattern", "permission_bypass")]));
    assert_eq!(f.rule, "instructions.permission-bypass");
    assert_eq!(f.severity, Severity::High);
    assert_eq!(f.locations.len(), 1);
    assert!(!f.suppressed);
    assert!(!f.explain.is_empty() && !f.advice.is_empty());
}

#[test]
fn taint_severities_follow_the_rulings() {
    let flow = |from: &str, to: &str| sev("TaintFlow", &[("from", from), ("to", to)]);
    assert_eq!(flow("secret_env", "network"), Severity::Medium);
    for from in ["secret_file", "browser_store", "wallet", "keychain"] {
        for to in ["network", "download_exec", "reverse_shell"] {
            assert_eq!(flow(from, to), Severity::Critical, "{from}->{to}");
        }
    }
    assert_eq!(flow("secret_env", "download_exec"), Severity::Critical);
    assert_eq!(flow("secret_env", "reverse_shell"), Severity::Critical);
}

#[test]
fn sink_and_source_severities() {
    let sink = |c: &str| sev("Sink", &[("class", c)]);
    assert_eq!(sink("download_exec"), Severity::Critical);
    assert_eq!(sink("reverse_shell"), Severity::Critical);
    assert_eq!(sink("eval"), Severity::High);
    assert_eq!(sink("sensitive_write"), Severity::High);
    assert_eq!(sink("exec"), Severity::Medium);
    assert_eq!(sink("network"), Severity::Low);
    let source = |c: &str| sev("Source", &[("class", c)]);
    assert_eq!(source("secret_env"), Severity::Low);
    for c in ["secret_file", "browser_store", "wallet", "keychain"] {
        assert_eq!(source(c), Severity::Medium, "{c}");
    }
}

#[test]
fn agent_config_severity_depends_on_context() {
    let cfg = |t: &str, c: &str| sev("AgentConfig", &[("target", t), ("context", c)]);
    for t in ["hooks", "permissions", "mcp_config", "agent_settings"] {
        assert_eq!(cfg(t, "code"), Severity::Critical, "{t}");
        assert_eq!(cfg(t, "prose"), Severity::Medium, "{t}");
    }
    for t in [
        "shell_profile",
        "cron",
        "launch_agent",
        "windows_run_key",
        "git_hooks",
    ] {
        assert_eq!(cfg(t, "code"), Severity::High, "{t}");
        assert_eq!(cfg(t, "prose"), Severity::Medium, "{t}");
    }
    assert_eq!(cfg("suppression_file", "code"), Severity::Medium);
    assert_eq!(cfg("suppression_file", "prose"), Severity::Medium);
}

#[test]
fn hidden_false_positive_tuning() {
    let h = |fields: &[(&str, &str)]| sev("Hidden", fields);
    let entropy = |alphabet: &str, len: &str| {
        h(&[
            ("pattern", "high_entropy"),
            ("alphabet", alphabet),
            ("len", len),
        ])
    };
    assert_eq!(entropy("hex", "40"), Severity::Low);
    assert_eq!(entropy("hex", "64"), Severity::Low);
    assert_eq!(entropy("hex", "48"), Severity::Medium);
    assert_eq!(entropy("base64", "40"), Severity::Medium);
    assert_eq!(h(&[("pattern", "high_entropy")]), Severity::Medium);
    for ext in [
        "png", "jpg", "jpeg", "gif", "webp", "ico", "svg", "woff", "woff2", "ttf", "otf",
    ] {
        assert_eq!(
            h(&[("pattern", "binary_file"), ("ext", ext)]),
            Severity::Low,
            "{ext}"
        );
    }
    assert_eq!(
        h(&[("pattern", "binary_file"), ("ext", "exe")]),
        Severity::Medium
    );
    assert_eq!(
        h(&[("pattern", "binary_file"), ("ext", "")]),
        Severity::Medium
    );
    assert_eq!(h(&[("pattern", "minified_file")]), Severity::Low);
    assert_eq!(h(&[("pattern", "oversized_file")]), Severity::Low);
    assert_eq!(h(&[("pattern", "parse_errors")]), Severity::Low);
    assert_eq!(h(&[("pattern", "parse_budget_exceeded")]), Severity::Medium);
    assert_eq!(h(&[("pattern", "bidi_control")]), Severity::High);
    assert_eq!(h(&[("pattern", "tag_chars")]), Severity::High);
    assert_eq!(h(&[("pattern", "zero_width")]), Severity::Medium);
}

#[test]
fn inventory_and_instruction_severities() {
    for p in ["symlink", "hardlink", "case_collision"] {
        assert_eq!(sev("Inventory", &[("pattern", p)]), Severity::High, "{p}");
    }
    for p in [
        "prompt_injection",
        "permission_bypass",
        "remote_instructions",
        "reviewer_directed",
        "secret_request",
    ] {
        assert_eq!(sev("Instruction", &[("pattern", p)]), Severity::High, "{p}");
    }
    for p in ["hidden_comment", "broad_trigger"] {
        assert_eq!(
            sev("Instruction", &[("pattern", p)]),
            Severity::Medium,
            "{p}"
        );
    }
}
