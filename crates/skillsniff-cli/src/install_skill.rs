//! `skillsniff install-skill`: puts the skillsniff adapter skill where an
//! agent looks for skills, so `/skillsniff` works without copying files.

use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use clap::ValueEnum;

use crate::commands::{EXIT_INTERNAL, EXIT_USAGE};
use crate::output::{ConsoleGuard, detect, render_banner};

/// The one skill file shipped for every agent (`skills/skillsniff/SKILL.md`).
const SKILL: &str = include_str!("../../../skills/skillsniff/SKILL.md");

/// Agents that `install-skill` knows how to set up.
#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum Agent {
    /// Claude Code (~/.claude/skills).
    ClaudeCode,
    /// Codex (~/.agents/skills).
    Codex,
    /// Every agent above.
    All,
}

impl Agent {
    fn label(self) -> &'static str {
        match self {
            Agent::ClaudeCode => "Claude Code",
            Agent::Codex => "Codex",
            Agent::All => "all agents",
        }
    }

    /// Folder (under home or the project) that holds the agent's skills.
    fn skills_dir(self, base: &Path) -> PathBuf {
        match self {
            Agent::ClaudeCode => base.join(".claude").join("skills"),
            Agent::Codex | Agent::All => base.join(".agents").join("skills"),
        }
    }

    /// True when the agent looks installed for this user.
    fn detected(self, home: &Path) -> bool {
        match self {
            Agent::ClaudeCode => home.join(".claude").is_dir(),
            Agent::Codex | Agent::All => {
                home.join(".codex").is_dir() || home.join(".agents").is_dir()
            }
        }
    }
}

#[derive(clap::Args)]
pub struct InstallSkillArgs {
    /// Agent to set up. Without it, every agent found on this computer is set up.
    #[arg(value_enum)]
    agent: Option<Agent>,
    /// Install into the current project instead of your user folder.
    #[arg(long)]
    project: bool,
    /// Replace an existing skill named skillsniff that skillsniff did not write.
    #[arg(long)]
    force: bool,
}

fn home_dir() -> Option<PathBuf> {
    let from = |k: &str| {
        std::env::var_os(k)
            .filter(|v| !v.is_empty())
            .map(PathBuf::from)
    };
    if cfg!(windows) {
        from("USERPROFILE").or_else(|| from("HOME"))
    } else {
        from("HOME").or_else(|| from("USERPROFILE"))
    }
}

/// Our own adapter files start with this frontmatter line; any other
/// `skillsniff` skill is someone else's and is only replaced with --force.
fn written_by_us(existing: &str) -> bool {
    existing
        .lines()
        .take(5)
        .any(|l| l.trim() == "name: skillsniff")
        && existing.contains("skillsniff scan")
}

enum Outcome {
    Installed(PathBuf),
    Updated(PathBuf),
    UpToDate(PathBuf),
}

fn install_one(agent: Agent, base: &Path, force: bool) -> Result<Outcome, String> {
    let dir = agent.skills_dir(base).join("skillsniff");
    let file = dir.join("SKILL.md");
    let content = SKILL;
    let existed = match fs::read_to_string(&file) {
        Ok(existing) if existing == content => return Ok(Outcome::UpToDate(file)),
        Ok(existing) if !force && !written_by_us(&existing) => {
            return Err(format!(
                "{} already has a different skill at {}; rerun with --force to replace it",
                agent.label(),
                file.display()
            ));
        }
        Ok(_) => true,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
        Err(e) => return Err(format!("cannot read {}: {e}", file.display())),
    };
    fs::create_dir_all(&dir).map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
    let tmp = dir.join(".SKILL.md.skillsniff-tmp");
    let write = || -> std::io::Result<()> {
        let mut f = fs::File::create(&tmp)?;
        f.write_all(content.as_bytes())?;
        f.sync_all()?;
        drop(f);
        fs::rename(&tmp, &file)
    };
    if let Err(e) = write() {
        let _ = fs::remove_file(&tmp);
        return Err(format!("cannot write {}: {e}", file.display()));
    }
    Ok(if existed {
        Outcome::Updated(file)
    } else {
        Outcome::Installed(file)
    })
}

pub fn install_skill_command(args: &InstallSkillArgs) -> i32 {
    // A person in a terminal gets the banner; an agent or a pipe gets plain lines.
    let mode = detect(false, false);
    let _guard = ConsoleGuard::prepare(mode.decorate);
    if mode.decorate {
        println!("{}", render_banner(&mode));
    }
    let ok = if mode.decorate {
        console::style("✔").green().bold().to_string()
    } else {
        String::new()
    };
    let mark = |line: String| {
        if ok.is_empty() {
            line
        } else {
            format!("  {ok} {line}")
        }
    };
    let base = if args.project {
        match std::env::current_dir() {
            Ok(d) => d,
            Err(e) => {
                eprintln!("error: cannot read the current folder: {e}");
                return EXIT_INTERNAL;
            }
        }
    } else {
        match home_dir() {
            Some(h) => h,
            None => {
                eprintln!("error: cannot find your home folder; use --project inside a project");
                return EXIT_USAGE;
            }
        }
    };

    let agents: Vec<Agent> = match args.agent {
        Some(Agent::All) => vec![Agent::ClaudeCode, Agent::Codex],
        Some(a) => vec![a],
        None => {
            let found: Vec<Agent> = [Agent::ClaudeCode, Agent::Codex]
                .into_iter()
                .filter(|a| a.detected(&base))
                .collect();
            if found.is_empty() {
                eprintln!(
                    "error: no Claude Code or Codex folder found in {}\n  \
                     choose one: skillsniff install-skill claude-code | codex | all",
                    base.display()
                );
                return EXIT_USAGE;
            }
            found
        }
    };

    let mut failed = false;
    for agent in agents {
        match install_one(agent, &base, args.force) {
            Ok(Outcome::Installed(p)) => {
                println!(
                    "{}",
                    mark(format!(
                        "Installed the skillsniff skill for {} at {}",
                        agent.label(),
                        p.display()
                    ))
                );
            }
            Ok(Outcome::Updated(p)) => {
                println!(
                    "{}",
                    mark(format!(
                        "Updated the skillsniff skill for {} at {}",
                        agent.label(),
                        p.display()
                    ))
                );
            }
            Ok(Outcome::UpToDate(p)) => {
                println!(
                    "{}",
                    mark(format!(
                        "The skillsniff skill for {} is already up to date at {}",
                        agent.label(),
                        p.display()
                    ))
                );
            }
            Err(msg) => {
                eprintln!("error: {msg}");
                failed = true;
            }
        }
    }
    if failed {
        return EXIT_USAGE;
    }
    if mode.decorate {
        println!();
        println!("  You're set up. Start a new agent session: your agent now checks every");
        println!("  skill before installing it, and you can type /skillsniff to check one.");
        println!();
        println!(
            "  {} Try it yourself: {}",
            console::style("Tip:").dim(),
            console::style("skillsniff scan github.com/owner/repo").cyan()
        );
    } else {
        println!("Start a new agent session, then ask it to install a skill or type /skillsniff.");
    }
    0
}
