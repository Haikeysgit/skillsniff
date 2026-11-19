# Agent adapters

An adapter is a small skill that makes your coding agent run skillsniff whenever you ask it to install, add or check another skill. Phase 1 ships two: Claude Code and Codex. Both follow the same steps and differ only in where they install.

Both adapters need the `skillsniff` command on your `PATH`. See the installation section of the [README](../README.md).

## Install

```sh
skillsniff install-skill            # every agent found on this computer
skillsniff install-skill claude-code
skillsniff install-skill codex
skillsniff install-skill all --project   # into the current project instead
```

Running it again after an upgrade updates the skill. An existing `skillsniff` skill that skillsniff did not write is left alone unless you pass `--force`.

## Install by hand

Or copy the adapter folder into the agent's skills directory yourself.

| Agent | Source folder | Destination |
| --- | --- | --- |
| Claude Code | `adapters/claude-code/` | `~/.claude/skills/skillsniff/` |
| Codex | `adapters/codex/` | `$HOME/.agents/skills/skillsniff/` (user) or `.agents/skills/skillsniff/` (repository) |

Start a new agent session afterwards so the skill is picked up.

## What the adapter does

1. Checks that `skillsniff` is installed. If not, it stops and points to the README. It never downloads the tool.
2. Scans the source and reads the report plus the flagged lines. It writes a review that can add or raise findings, never lower them.
3. Quotes the final verdict line word for word, then the top findings and the pinned version.
4. It checks the exit code of every command (0 PASS, 1 CAUTION, 2 BLOCK, anything else stops). On PASS it installs the exported copy. On CAUTION it asks you first. On BLOCK it refuses.
5. Exports from the folder the scan kept, so the skill is never fetched twice, and installs only when the export's `tree_sha256` matches the scan.

The adapter files are scanned with skillsniff like any other skill and must give PASS.

## Checking an adapter

Follow [adapter-checklist.md](adapter-checklist.md).
