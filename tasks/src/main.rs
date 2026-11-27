use clap::{Parser, Subcommand};
use log::LevelFilter;
use simplelog::{ColorChoice, CombinedLogger, Config, TermLogger, TerminalMode};
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering::Relaxed;

mod check_local_workspace_version;
mod check_tfhe_docs_are_tested;
mod format_latex_doc;
mod release_status;
mod utils;

// -------------------------------------------------------------------------------------------------
// CONSTANTS
// -------------------------------------------------------------------------------------------------

static DRY_RUN: AtomicBool = AtomicBool::new(false);

// -------------------------------------------------------------------------------------------------
// CLI
// -------------------------------------------------------------------------------------------------

#[derive(Parser)]
#[command(about = "Rust scripts runner", arg_required_else_help = true)]
struct Cli {
    #[arg(short, long, help = "Prints debug messages")]
    verbose: bool,

    #[arg(long, help = "Do not execute the commands")]
    dry_run: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Escape underscores in latex equations
    FormatLatexDoc,
    /// Check that doc files with rust code blocks are tested
    CheckTfheDocsAreTested,
    /// Check that local workspace dependency versions are consistent
    CheckLocalWorkspaceVersion,
    /// Show which released crates need a version bump, a tag or a publish
    ReleaseStatus(release_status::Args),
}

// -------------------------------------------------------------------------------------------------
// MAIN
// -------------------------------------------------------------------------------------------------

fn main() -> Result<(), std::io::Error> {
    let cli = Cli::parse();

    // We initialize the logger with proper verbosity
    let verb = if cli.verbose {
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
    if cli.dry_run {
        DRY_RUN.store(true, Relaxed);
    }

    match cli.command {
        Commands::FormatLatexDoc => format_latex_doc::escape_underscore_in_latex_doc()?,
        Commands::CheckTfheDocsAreTested => {
            check_tfhe_docs_are_tested::check_tfhe_docs_are_tested()?
        }
        Commands::CheckLocalWorkspaceVersion => {
            check_local_workspace_version::check_local_workspace_version()
        }
        Commands::ReleaseStatus(args) => {
            let exit_code = release_status::run(&args);
            if exit_code != 0 {
                std::process::exit(exit_code);
            }
        }
    }

    Ok(())
}
