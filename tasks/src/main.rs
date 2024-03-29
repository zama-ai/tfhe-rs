use clap::{Arg, Command};
use lazy_static::lazy_static;
use log::LevelFilter;
use simplelog::{ColorChoice, CombinedLogger, Config, TermLogger, TerminalMode};
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering::Relaxed;

mod format_latex_doc;
mod utils;

// -------------------------------------------------------------------------------------------------
// CONSTANTS
// -------------------------------------------------------------------------------------------------
lazy_static! {
    static ref DRY_RUN: AtomicBool = AtomicBool::new(false);
}

// -------------------------------------------------------------------------------------------------
// MAIN
// -------------------------------------------------------------------------------------------------

fn main() -> Result<(), std::io::Error> {
    // We parse the input args
    let matches = Command::new("tasks")
        .about("Rust scripts runner")
        .arg(
            Arg::new("verbose")
                .short('v')
                .long("verbose")
                .help("Prints debug messages"),
        )
        .arg(
            Arg::new("dry-run")
                .long("dry-run")
                .help("Do not execute the commands"),
        )
        .subcommand(Command::new("format_latex_doc").about("Escape underscores in latex equations"))
        .arg_required_else_help(true)
        .get_matches();

    // We initialize the logger with proper verbosity
    let verb = if matches.contains_id("verbose") {
        LevelFilter::Debug
    } else {
        LevelFilter::Info
    };
    CombinedLogger::init(vec![TermLogger::new(
        verb,
        Config::default(),
        TerminalMode::Mixed,
        ColorChoice::Auto,
    )])
    .unwrap();

    // We set the dry-run mode if present
    if matches.contains_id("dry-run") {
        DRY_RUN.store(true, Relaxed);
    }

    if matches.subcommand_matches("format_latex_doc").is_some() {
        format_latex_doc::escape_underscore_in_latex_doc()?;
    }

    Ok(())
}
