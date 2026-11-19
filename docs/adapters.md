# The skillsniff skill

The skillsniff skill makes your coding agent run skillsniff whenever you ask it to install, add or check another skill. One skill file, [`skills/skillsniff/SKILL.md`](../skills/skillsniff/SKILL.md), works in both Claude Code and Codex.

The skill needs the `skillsniff` program. If it is missing, the skill's **Setup** section has the agent install it after asking you once: with brew, Scoop or winget when available, otherwise from the release archive with its checksum checked.

## Install by asking your agent

> Install the skillsniff skill from https://github.com/Haikeysgit/skillsniff

In Claude Code you can also run `/plugin marketplace add Haikeysgit/skillsniff` and then `/plugin install skillsniff@skillsniff`.

## Install with the command

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
| Claude Code | `skills/skillsniff/` | `~/.claude/skills/skillsniff/` |
| Codex | `skills/skillsniff/` | `$HOME/.agents/skills/skillsniff/` (user) or `.agents/skills/skillsniff/` (repository) |

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
