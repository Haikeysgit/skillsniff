# skillsniff — Design Spec

- **Status:** Draft for review
- **Date:** 2026-11-17
- **Tagline:** If a skill smells off, you'll know.

## 1. Summary

skillsniff is an open-source security scanner for AI coding-agent skills. Before an agent installs a skill, the user (or the agent) runs `skillsniff scan <source>`. skillsniff fetches the skill into a quarantine folder, analyzes it statically without executing anything, and returns one of three verdicts — **PASS**, **CAUTION**, **BLOCK** — with evidence at `file:line` and the exact commit SHA that was checked.

It ships as a single Rust binary per platform. Thin adapters (a `SKILL.md` per agent) let Claude Code, Codex, and later other agents call it. The host agent adds a semantic review that can only escalate the verdict, never lower it, and that rule is enforced in code.

## 2. Goals and non-goals

### Goals

1. Catch malicious or dangerous skills before installation, with evidence a security engineer can verify.
2. Give casual users a one-word answer they can act on.
3. Work on macOS, Windows, and Linux with no runtime dependencies.
4. Work with any agent through thin adapters; launch with Claude Code and Codex.
5. Resist manipulation by the content being scanned.
6. Be deterministic: same input and rule version always produce the same deterministic verdict.

### Non-goals (v1)

- Executing or sandboxing the target (reserved for Phase 4).
- Scanning plugins or MCP servers (Phase 3; the target layer is designed for them).
- A hosted service, accounts, or a registry.
- Calling an LLM API directly. Semantic review comes from the host agent.
- Claiming a skill is "safe". Output says "no known red flags".

## 3. Users and success criteria

| User | Needs | Success looks like |
|---|---|---|
| Casual developer | "Can I install this?" | One command, one word, under 10 seconds for a typical skill |
| Security-minded dev / team | Proof and control | Findings with `file:line`, JSON/SARIF output, CI gating, suppression with written reasons |

Measurable targets for Phase 1 exit:

- 100% detection on the malicious fixture corpus (every fixture has an expected finding).
- At most 5% of benign corpus skills get CAUTION or BLOCK from false positives.
- Scan time under 10 s for a skill under 5 MB on a mid-range laptop, network excluded.
- Identical JSON output (minus timestamps) on macOS, Windows, and Linux for the same fixture.

## 4. Locked decisions

| Topic | Decision |
|---|---|
| Audience | Casual devs and security teams: simple verdict on top, evidence underneath |
| Scope | Skills in v1. Target layer is pluggable for plugins and MCP servers later |
| Analysis | Static only in v1. Sandbox is a reserved seam |
| LLM review | Host agent performs it. Escalate-only, enforced by the engine |
| Network | Online by default. `--offline` skips network checks and reports them as skipped |
| Engine | Rust, tree-sitter parsers, one signed static binary per platform |
| Distribution | Open source, local-first, no telemetry |

## 5. Threat model

### 5.1 Assets the attacker wants

Credentials (`~/.ssh`, `~/.aws`, `.env`, git and cloud tokens, browser cookie stores, crypto wallets, OS keychains), source code, agent permissions and configuration, persistence on the machine.

### 5.2 Attack surfaces in a skill

| Surface | Example attacks |
|---|---|
| `SKILL.md` instructions | Prompt injection, "skip permission prompts", hidden instructions to exfiltrate, fetching more instructions from a URL at runtime, text addressed to AI reviewers |
| Frontmatter `description` | Over-broad triggers so the skill loads on every task |
| Bundled scripts (py, js/ts, sh, ps1) | Secret reads flowing to network calls, download-and-execute, reverse shells, `eval` of decoded strings |
| Obfuscation | Base64/hex blobs, char-code building, string concatenation, minified code, high-entropy strings |
| Hidden content | Zero-width and bidi Unicode, homoglyphs, HTML comments in Markdown, binaries |
| Dependencies | Typosquatted packages, install hooks (`postinstall`), dependencies with known CVEs, installs from raw URLs |
| Agent configuration | Writing hooks, permission rules, MCP server entries, shell rc files, cron, startup items |
| Provenance | Recently transferred repo, new owner, sudden large rewrite, force-pushed history |
| Time-of-check vs time-of-use | Skill changes between scan and install |

### 5.3 Attacks against skillsniff itself

| Attack | Defense |
|---|---|
| Content tells the reviewer it is safe | Escalate-only merge enforced in code. Reviewer-directed text is itself a HIGH finding |
| Archive bombs, huge files | Size, file-count, and decompression-ratio limits |
| Path traversal, symlink and junction escapes | Never follow links out of quarantine. Reject `..` and absolute paths in archives |
| Parser crashes and hangs | Per-file timeouts, fuzzed parsers, failure becomes CAUTION, never PASS |
| Swap after scan | `skillsniff scan --export <dir>` copies the exact scanned tree out of quarantine after PASS (or user-approved CAUTION). Adapters install that copy and never re-fetch. Report pins commit SHA (git sources) and tree hash (all sources) |
| Scanned skill ships its own suppression file | Suppressions are never read from the target tree. A `.skillsniff.yaml` inside the target is a MEDIUM finding |
| Injection aimed at the host agent during review | Evidence snippets in JSON are capped at 200 chars with control, zero-width and bidi characters escaped. The adapter's review step may only read the report and flagged lines and write `review.json` |
| Agent misreports the verdict to the user | Adapter must quote the engine's verdict line verbatim. Residual risk: an agent already compromised by injection can still lie in chat. Phase 3 adds a pre-install hook that blocks installs of unscanned trees in the agent itself |
| Compromised skillsniff release | Signed releases, SLSA provenance, reproducible builds, minimal pinned dependencies |
| Adapter used as an installer of the binary | `SKILL.md` never downloads the binary. It prints the install command if missing |
| Git client attack surface | No shelling out to system `git`. Phase 1 fetches GitHub sources as HTTPS tarballs at a resolved SHA. No submodules, LFS or hooks are ever fetched or run |

## 6. Architecture

### 6.1 Components

Phase 1 is two crates: a library and a thin binary. Modules inside the library keep the same boundaries; a module is split into its own crate only when a second consumer (for example the Phase 3 MCP server) needs it.

```text
skillsniff/
  crates/
    skillsniff/         library
      src/acquire/      fetch into quarantine, limits, SHA pinning, export
      src/inventory/    file walk, hashing, content-type detection
      src/targets/      Target trait; skill target (v1)
      src/analyzers/    one module per analyzer, Analyzer trait
      src/rules/        YAML rule loader and matcher
      src/score/        verdict computation, review merge
      src/report/       terminal, JSON (Markdown, SARIF later)
    skillsniff-cli/     binary: argument parsing, exit codes, output selection
  rules/          *.yaml rule packs, versioned
  adapters/
    claude-code/SKILL.md
    codex/SKILL.md
  tests/
    fixtures/malicious/   inert attack samples
    fixtures/benign/      real-world skills, pinned
    golden/               expected reports
  docs/
```

Each module has one job and a narrow interface. Analyzers do not know about each other. Reporters only read a finished `Report`.

### 6.2 Data flow

```text
source ─▶ acquire ─▶ inventory ─▶ target.classify ─▶ analyzers (parallel) ─▶ rules ─▶ score ─▶ Report
                                                                                                │
                              agent review JSON ─▶ score.merge_review (escalate-only) ◀─────────┘
                                                                                                │
                                                                                     reporters ─▶ terminal / JSON / Markdown / SARIF
```

### 6.3 Key interfaces

```rust
pub trait Target {
    fn detect(inv: &Inventory) -> Option<Self> where Self: Sized;
    fn classify(&self, inv: &Inventory) -> Vec<FileRole>; // Instructions, Script(Lang), Manifest, Config, Asset, Binary
}

pub trait Analyzer: Send + Sync {
    fn id(&self) -> &'static str;
    fn needs_network(&self) -> bool;
    fn run(&self, ctx: &ScanContext) -> AnalyzerOutput; // signals + coverage status
}

pub enum Coverage { Ran, Skipped { reason: String }, Failed { reason: String } }
```

`Signal` is raw evidence: rule-matchable facts with locations, for example `SecretRead { path, loc }`, `NetworkSend { loc }`, `TaintFlow { from, to, steps }`, `DecodedPayload { loc, decoded }`. Rules turn signals into `Finding`s with severity.

## 7. Pipeline detail

### 7.1 Acquire

- **Sources (Phase 1):** GitHub URL or shorthand `owner/repo[/path][@ref]`, local directory, `.zip` or `.tar.gz`. Generic git hosts come in Phase 3.
- **GitHub:** resolve the ref to a commit SHA through the API, then download the tarball for that SHA over HTTPS. No system `git` is used. Record the SHA.
- **Identity:** every report carries `tree_sha256`. Git sources also carry `commit`. Local directories and archives have no commit; the tree hash is their identity.
- **Export:** `--export <dir>` copies the scanned tree, byte for byte, to a new directory after the scan. The command refuses on BLOCK, and refuses on CAUTION unless `--allow-caution` is passed.
- **Limits (defaults, configurable):** 50 MB total, 5,000 files, 10 MB per file, decompression ratio 100:1, 60 s fetch timeout.
- Strip executable bits on extraction. Never follow symlinks or junctions that resolve outside quarantine; record them as findings.
- Delete the quarantine on exit unless `--keep` is passed.

### 7.2 Inventory

- SHA-256 per file and a content hash for the whole tree.
- Detect type by content (shebang, magic bytes, parse attempt), not by extension. A mismatch between extension and content is a signal.
- Flag binaries, minified files (average line length above 500), and files over 1 MB.

### 7.3 Target: skill (v1)

Detects a skill by `SKILL.md` with valid frontmatter (`name`, `description`). It assigns roles: `SKILL.md` and referenced Markdown are Instructions, scripts are `Script(lang)`, `package.json`, `requirements.txt`, `pyproject.toml` and `Cargo.toml` are Manifest, and agent settings are Config. Plugins and MCP servers become new `Target` implementations later, with no engine change.

### 7.4 Analyzers

| Analyzer | Phase | What it does |
|---|---|---|
| `instructions` | 1 | Parses Markdown. Detects injection phrasing, permission-bypass requests, remote instruction fetching, reviewer-directed text, over-broad description triggers, hidden HTML comments |
| `code` | 1 (intra-file), 2 (cross-file) | tree-sitter ASTs for Python, JS/TS, Bash, PowerShell. Sources: secret paths, env vars, keychains. Sinks: network, process execution, `eval`, file writes to sensitive paths. Taint tracking from source to sink |
| `hidden` | 1 | Zero-width and bidi characters, homoglyphs in identifiers and URLs, binaries, minified blobs, high-entropy strings |
| `agent_config` | 1 | Writes to agent settings, hooks, permission rules, MCP config, shell rc, cron, launch agents, Windows Run keys, git hooks |
| `deobfuscate` | 2 | Decodes base64, hex, char codes and folded concatenations, up to depth 3. Total decoded output is capped at 4x the input size and 10 MB; hitting the cap is a HIGH finding. Feeds decoded content back through `code` and `instructions` |
| `supply_chain` | 2 | Parses manifests and lockfiles. OSV lookups, typosquat distance against top package lists, install hooks, URL installs |
| `provenance` | 2 | GitHub API: repo age, owner changes, recent large rewrites, force pushes, default-branch protection |
| `sandbox` | 4 | Reserved seam. Not implemented in v1 |

### 7.5 Rules

Rules are data, versioned as a pack (`2026.11.1`). Each rule matches signals and emits findings.

```yaml
id: exfil.secret-to-network
severity: critical
title: Secret sent to the network
matches:
  signal: TaintFlow
  where: { from.kind: secret, to.kind: network }
explain: Code reads a credential file and sends its contents to a remote host.
advice: Do not install. Report the skill to its registry.
```

Phase 1 matching is deliberately simple: a rule names one signal type and lists field equality checks. No expressions, regex over signals, or cross-signal joins. Combinations are expressed as dedicated signals produced by analyzers (for example `TaintFlow`).

The rule pack is compiled into the binary and only changes with a release. `--rules <dir>` adds rules but cannot remove built-in ones.

### 7.6 Scoring

Severity levels: LOW, MEDIUM, HIGH, CRITICAL.

Verdict, evaluated in order:

1. Any CRITICAL produces BLOCK.
2. Two or more HIGH findings from different rules produce BLOCK.
3. Any HIGH or MEDIUM produces CAUTION.
4. Any analyzer with `Coverage::Failed`, or a required analyzer `Skipped`, produces CAUTION. Every analyzer shipped in the current phase is required. Network analyzers skipped by `--offline` count as required unless `--offline-ok` is passed.
5. Otherwise the verdict is PASS.

**Suppressions:** a `suppressions.yaml` in the user config directory (`$XDG_CONFIG_HOME/skillsniff/` or `~/.config/skillsniff/`, `%APPDATA%\skillsniff\` on Windows), or a file passed with `--suppressions <file>`, can suppress a rule for a specific SHA. A suppression requires a written `reason`. Suppressed findings still appear in every report, marked as suppressed. A suppression can never apply to a CRITICAL finding.

### 7.7 Agent review and the escalate-only merge

1. The adapter runs `skillsniff scan <src> --json > report.json`.
2. The agent reads the report and the flagged code. It writes `review.json` with added findings, or severity raises on existing findings, each with a reason.
3. The adapter runs `skillsniff review apply report.json review.json`.
4. The engine accepts only additions and raises. Any attempt to lower or remove is rejected and recorded in the report. The verdict is recomputed with the same scoring.

This makes escalate-only a property of the code, not a request to the agent. The final verdict is the more severe of the engine verdict and the merged verdict.

During review the agent sees only the report (with sanitized, length-capped evidence) and the flagged line ranges. It may not run commands or open other files from the target.

### 7.8 Reporters

| Format | Audience | Notes |
|---|---|---|
| Terminal | People | Colour with `NO_COLOR` support, verdict first, then findings, coverage, pinned SHA |
| JSON | Agents, scripts | Versioned schema (`schema_version`), stable field order. Findings sorted by severity (desc), then file path (normalized `/`), line, rule id. Analyzers run in parallel; output order never depends on scheduling |
| Markdown | Docs, PR comments | Same content as terminal |
| SARIF 2.1.0 | CI, GitHub code scanning | Phase 3 |

JSON report shape:

```json
{
  "schema_version": "1",
  "tool": { "name": "skillsniff", "version": "0.1.0", "rules": "2026.11.1" },
  "target": { "source": "github.com/example/pdf-tools", "type": "skill", "commit": "a41f9c2…", "tree_sha256": "…" },
  "verdict": "BLOCK",
  "summary": { "critical": 2, "high": 1, "medium": 0, "low": 0 },
  "findings": [
    { "rule": "exfil.secret-to-network", "severity": "critical", "title": "Secret sent to the network",
      "locations": [ { "file": "scripts/convert.py", "line": 41 }, { "file": "scripts/convert.py", "line": 58 } ],
      "evidence": "open('~/.aws/credentials') -> buf -> requests.post(data=buf)", "source": "engine", "suppressed": false }
  ],
  "coverage": { "instructions": "ran", "code": "ran", "hidden": "ran", "supply_chain": "skipped: offline" },
  "review": { "applied": false, "rejected_changes": [] }
}
```

## 8. Network policy

- **Allowed hosts:** `api.github.com` and `codeload.github.com` (Phase 1 fetch), `api.osv.dev` (Phase 2). Nothing else.
- In Phase 1 the only network use is fetching. `--offline` therefore only blocks remote sources; local and archive scans are unaffected.
- **Sent:** repo URL and package names and versions only. Never the user's own files or the scanned content.
- `--offline` disables all three and marks dependent analyzers `Skipped`. That produces CAUTION unless `--offline-ok` is passed.
- `GITHUB_TOKEN` is used if set, to raise rate limits. It is never logged.
- No telemetry.

## 9. Cross-platform

| Concern | Handling |
|---|---|
| Builds | macOS arm64 and x86_64, Windows x86_64 and arm64, Linux x86_64 and arm64 (musl, static) |
| Paths | Normalize to `/` internally. Long-path support on Windows. Case-insensitive collision detection |
| Line endings | CRLF and LF parsed identically. Line numbers stable across both |
| Links | Symlinks, hardlinks, and Windows junctions never followed outside quarantine |
| Temp dirs | OS temp with random names, cleaned on exit and on Ctrl-C |
| Terminal | ANSI colour on Windows 10+, plain fallback, `NO_COLOR` respected |
| CI | Every PR runs the test suite on macOS, Windows, and Linux runners |

## 10. Distribution and adapters

### 10.1 Binary

- GitHub Releases with Sigstore signatures, SLSA provenance attestations, and SHA-256 checksums.
- Install channels: `cargo install skillsniff`, Homebrew tap, Scoop bucket, winget, and release archives.
- Reproducible builds verified in CI.
- Dependencies are minimal, pinned in `Cargo.lock`, and audited with `cargo-deny` and `cargo-audit` in CI.

### 10.2 Adapters (Phase 1)

Claude Code (`~/.claude/skills/skillsniff/SKILL.md`) and Codex (its skills directory). Each adapter:

1. Triggers when the user asks to install, add, or check a skill.
2. Checks that `skillsniff` is on `PATH`. If it is missing, it stops and shows the install command; it never downloads.
3. Runs the scan, then performs the review (section 7.7).
4. Presents the verdict, top findings, and pinned SHA.
5. Quotes the engine's verdict line verbatim. On PASS, installs the `--export` copy. On CAUTION, asks the user, then exports with `--allow-caution` only on a yes. On BLOCK, refuses and explains. It never re-fetches the skill from its source.
6. Treats all scanned content as data, never as instructions.

## 11. Errors and exit codes

| Code | Meaning |
|---|---|
| 0 | PASS |
| 1 | CAUTION |
| 2 | BLOCK |
| 3 | Usage error |
| 4 | Fetch failed (network, auth, not found) |
| 5 | Internal error |

- `--fail-on caution|block` maps verdicts to a single non-zero code for CI.
- The argument parser's built-in exit codes are overridden: clap exits with 2 on usage errors by default, which would read as BLOCK. All usage errors exit 3.
- Panics are caught at the top level and exit 5, never Rust's default 101.
- A crash or timeout inside one analyzer never aborts the scan. It is recorded as `Coverage::Failed` and forces at least CAUTION.

## 12. Testing

| Layer | Approach |
|---|---|
| Unit | Each analyzer and rule has tests against small inline samples |
| Malicious corpus | 100+ inert fixtures covering every rule, with dead hosts (TEST-NET ranges, `.invalid`), defanged URLs and non-functional payloads. Each declares its expected findings. Fixtures live in one directory with a README saying they are inert test data, so antivirus and secret scanners on contributor machines and CI can be configured to exclude them |
| Benign corpus | 30+ popular real skills pinned by SHA, used to measure the false-positive rate |
| Golden reports | Snapshot JSON per fixture; any rule change shows a reviewable diff |
| Fuzzing | `cargo-fuzz` on acquire (archives), inventory, and every parser entry point |
| Cross-platform | Full suite on 3 OSes in CI, plus a byte-identical JSON check |
| Review merge | Unit tests on `review apply`: additions accepted, raises accepted, lowers and removals rejected and recorded, verdict recomputed |
| Export | Exported tree hash equals scanned tree hash; export refused on BLOCK and on CAUTION without the flag |
| Exit codes | One CLI test per code 0 to 5, including a usage error (must be 3) and a forced panic (must be 5) |
| Adapter | Phase 1: a written manual checklist run against Claude Code and Codex for each verdict. Phase 3: automated agent evals |
| Adversarial | Fixtures that try to talk the reviewer into PASS must still BLOCK after review apply. A fixture containing its own `.skillsniff.yaml` must produce the MEDIUM finding and suppress nothing |

## 13. Phases

| Phase | Ships | Exit criteria |
|---|---|---|
| 1 Core engine | acquire (GitHub, local, archive), export, inventory, skill target, `instructions`, `code` (intra-file), `hidden`, `agent_config`, about 60 rules, scoring, review apply, terminal + JSON, Claude Code + Codex adapters, signed releases for 6 targets | Section 3 targets met |
| 2 Depth | `deobfuscate`, cross-file taint, `supply_chain`, `provenance`, Markdown reporter | Corpus grows to cover new analyzers; FP rate still at most 5% |
| 3 Reach | Plugin and MCP targets, generic git hosts, Cursor/Gemini/Copilot adapters, MCP server mode, pre-install hook, `diff` mode, SARIF, GitHub Action | Each new target has its own fixture corpus |
| 4 Live testing | Optional sandbox analyzer, static/runtime correlation | Sandbox escape tests pass on all supported OSes |

## 14. Positioning

Existing tools include Cisco skill-scanner, NVIDIA SkillSpector, Snyk agent-scan, JFrog, Mondoo, and Litmus. Public research reports that existing skill scanners were bypassed with little effort. skillsniff differentiates on:

1. Real parsers and dataflow across five languages, not pattern lists.
2. Escalate-only review enforced in code.
3. A pinned SHA and tree hash, so users install exactly what was checked.
4. Local-first, offline-capable, one binary.

## 15. Resolved questions

1. **License:** `MIT OR Apache-2.0`, the Rust ecosystem convention.
2. **Rule updates:** compiled into the binary; new rules ship as releases. A signed rule-pack download is reconsidered only if release cadence is too slow to answer a live attack.
3. **Typosquat lists (Phase 2):** embed the top 5,000 package names each from npm, PyPI and crates.io, regenerated by a script at each release. Flag names within Damerau-Levenshtein distance 2 of a listed name (names of 5+ characters only) that are not themselves on the list.

## 16. Design review record (2026-11-17)

Each finding below was resolved and the fix applied in this document.

| # | Severity | Finding | Resolution |
|---|---|---|---|
| 1 | P1 | Install could re-fetch a different tree than the one scanned | `--export` of the scanned tree; adapters install that copy (sections 5.3, 7.1, 10.2) |
| 2 | P1 | A scanned skill could ship `.skillsniff.yaml` and suppress its own findings when scanned from its own directory | Suppressions only from user config or `--suppressions`; target copy is a finding (5.3, 7.6, 12) |
| 3 | P1 | Host agent reads attacker text during review | Sanitized, capped evidence; review step limited to report and flagged lines (5.3, 7.7) |
| 4 | P1 | clap's default usage-error exit code 2 collides with BLOCK | Override to 3; panics to 5 (11) |
| 5 | P2 | Shelling out to `git` on untrusted repos adds attack surface and a system dependency | Phase 1 uses GitHub HTTPS tarballs at a resolved SHA; generic git deferred to Phase 3 (7.1) |
| 6 | P2 | Local and archive sources have no commit SHA | Tree hash is the identity for all sources (7.1) |
| 7 | P2 | Nine crates in Phase 1 is premature structure | Two crates, same module boundaries (6.1) |
| 8 | P2 | Scoring rule 2 mixed finding counts with raw signals | Two HIGHs from different rules produce BLOCK (7.6) |
| 9 | P2 | Parallel analyzers make output order unstable, breaking cross-OS identical JSON | Defined sort order (7.8) |
| 10 | P2 | Rule matching language unbounded | Field equality on one signal type in Phase 1 (7.5) |
| 11 | P2 | Deobfuscation can expand without bound | Output cap with a HIGH finding on overflow (7.4) |
| 12 | P3 | Agent can still misreport the verdict in chat | Verbatim verdict line now; pre-install hook in Phase 3; residual risk documented (5.3) |
| 13 | P3 | Inert fixtures may trip antivirus or secret scanning | Defanged, isolated directory with README (12) |

This review covered the written design only; there is no code yet.
