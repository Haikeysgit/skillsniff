use clap::Parser;

/// Security scanner for AI agent skills.
#[derive(Parser)]
#[command(name = "skillsniff", version)]
struct Cli {}

fn main() {
    Cli::parse();
}
