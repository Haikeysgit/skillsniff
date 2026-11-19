# Agent adapters

An adapter is a small skill that makes your coding agent run skillsniff whenever you ask it to install, add or check another skill. Phase 1 ships two: Claude Code and Codex. Both follow the same steps and differ only in where they install.

Both adapters need the `skillsniff` command on your `PATH`. See the installation section of the [README](../README.md).

## Install by hand

Copy the adapter folder into the agent's skills directory.

| Agent | Source folder | Destination |
| --- | --- | --- |
| Claude Code | `adapters/claude-code/` | `~/.claude/skills/skillsniff/` |
| Codex | `adapters/codex/` | `~/.codex/skills/skillsniff/` |

Start a new agent session afterwards so the skill is picked up.

## What the adapter does

1. Checks that `skillsniff` is installed. If not, it stops and points to the README. It never downloads the tool.
2. Scans the source and reads the report plus the flagged lines. It writes a review that can add or raise findings, never lower them.
3. Quotes the final verdict line word for word, then the top findings and the pinned version.
4. On PASS it installs the exported copy. On CAUTION it asks you first. On BLOCK it refuses.
5. Installs only from the exported copy, and only when its `tree_sha256` matches the scan.

The adapter files are scanned with skillsniff like any other skill and must give PASS.

## Checking an adapter

Follow [adapter-checklist.md](adapter-checklist.md).
