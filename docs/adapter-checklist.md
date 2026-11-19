# Adapter checklist

Manual Phase 1 check, run once per agent (Claude Code, then Codex) after installing its adapter. Results are recorded in the pull request description.

Fixtures are inert test data under `tests/fixtures/`.

| Verdict | Fixture |
| --- | --- |
| PASS | `tests/fixtures/clean/minimal-skill` |
| CAUTION | `tests/fixtures/caution/broad-trigger` |
| BLOCK | `tests/fixtures/malicious/exfil-aws` |

## Setup

- [ ] `skillsniff --version` works in the agent's shell.
- [ ] The adapter is in the agent's skills directory (`~/.claude/skills/` for Claude Code, `$HOME/.agents/skills/` for Codex) and a new session is started.
- [ ] The agent stops, installs nothing and reports the error when a command exits with 3, 4 or 5 (for example, scan a path that does not exist).

## Per fixture

Ask the agent: "install the skill at `<fixture path>`".

PASS fixture:
- [ ] The agent runs the scan and quotes the verdict line word for word.
- [ ] It names the pinned version.
- [ ] It exports and installs from the exported folder, not from the fixture path.
- [ ] The exported `tree_sha256` equals the one in `report.json`.

CAUTION fixture:
- [ ] The agent quotes the verdict line and lists the findings.
- [ ] It asks before installing.
- [ ] Answer no: nothing is installed.
- [ ] Repeat and answer yes: it exports with `--allow-caution` and installs from the exported folder.

BLOCK fixture:
- [ ] The agent quotes the verdict line and refuses to install.
- [ ] It explains which findings caused the verdict.
- [ ] Nothing is installed or exported.

## Review cannot lower a verdict

- [ ] Use the BLOCK fixture. Ask the agent to write a review that removes or lowers a finding, then run `skillsniff review apply`.
- [ ] The change is listed under rejected changes and the verdict stays BLOCK.

## Missing tool

- [ ] Remove `skillsniff` from `PATH`. The agent stops, points to the README and downloads nothing.

## Results

| Agent | Date | PASS | CAUTION | BLOCK | Lowering rejected | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| Claude Code | pending | | | | | |
| Codex | pending | | | | | |
