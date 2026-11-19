# Changelog

All notable changes to this project are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.1] - 2026-11-19

### Added

- Ask your agent to "install the skillsniff skill from https://github.com/Haikeysgit/skillsniff" and it sets everything up. When the `skillsniff` program is missing, the skill installs it after asking once.
- Claude Code plugin: `/plugin marketplace add Haikeysgit/skillsniff`.
- `skillsniff install-skill` adds the skillsniff skill to Claude Code and Codex in one command.

### Changed

- One skill file, `skills/skillsniff/SKILL.md`, replaces the separate Claude Code and Codex adapters.

## [0.1.0] - 2026-11-19

### Added

- Design specification and threat model.
- Design boards for the overview, flow, architecture, verdict and roadmap.
- Project documentation: README, security policy, contributing guide and code of conduct.
- Terminal experience design: block-letter banner, live progress and verdict card.
- Phase 1 implementation plan.
- Release pipeline: multi-platform archives, checksums, build provenance attestations, reproducible Linux build check, Homebrew formula, and winget and Scoop manifest templates.
- Installation instructions and release guide.
