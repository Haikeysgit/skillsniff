use std::panic;

use skillsniff::VERSION;
use skillsniff_cli::commands::{EXIT_INTERNAL, run};

fn main() {
    // Panics, including ones on analyzer threads, must never print into
    // stdout or stderr; the top level reports them once below.
    panic::set_hook(Box::new(|_| {}));
    let code = match panic::catch_unwind(|| run(std::env::args_os())) {
        Ok(code) => code,
        Err(_) => {
            eprintln!("internal error (skillsniff {VERSION})");
            EXIT_INTERNAL
        }
    };
    std::process::exit(code);
}
