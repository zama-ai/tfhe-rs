use clap::{Arg, Command};
use log::LevelFilter;
use simplelog::{ColorChoice, CombinedLogger, Config, TermLogger, TerminalMode};
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering::Relaxed;

mod check_tfhe_docs_are_tested;
mod format_latex_doc;
mod utils;

// -------------------------------------------------------------------------------------------------
// CONSTANTS
// -------------------------------------------------------------------------------------------------

static DRY_RUN: AtomicBool = AtomicBool::new(false);

// -------------------------------------------------------------------------------------------------
// MAIN
// -------------------------------------------------------------------------------------------------

const FORMAT_LATEX_DOC: &str = "format_latext_doc";
const CHECK_TFHE_DOCS_ARE_TESTED: &str = "check_tfhe_docs_are_tested";

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
        .subcommand(Command::new(FORMAT_LATEX_DOC).about("Escape underscores in latex equations"))
        .subcommand(
            Command::new(CHECK_TFHE_DOCS_ARE_TESTED)
                .about("Check that doc files with rust code blocks are tested"),
        )
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

    if matches.subcommand_matches(FORMAT_LATEX_DOC).is_some() {
        format_latex_doc::escape_underscore_in_latex_doc()?;
    } else if matches
        .subcommand_matches(CHECK_TFHE_DOCS_ARE_TESTED)
        .is_some()
    {
        check_tfhe_docs_are_tested::check_tfhe_docs_are_tested()?;
    }

    Ok(())
}
