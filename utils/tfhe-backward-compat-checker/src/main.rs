mod diff;
mod report;
mod snapshot;

use clap::Parser;
use diff::{DiffEntry, Registry};
use report::build_diff_report;
use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Parser)]
#[command(name = "backward-compat-checker")]
#[command(about = "Check backward compatibility between two versions of tfhe-rs")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(clap::Subcommand)]
enum Command {
    /// Check backward compatibility between base and head snapshots
    Check(CheckArgs),
    /// Generate a markdown diff report between two snapshot directories
    DiffReport(DiffReportArgs),
}

#[derive(clap::Args)]
struct CheckArgs {
    /// Directory containing base (origin) JSON snapshot files
    #[arg(long)]
    base_dir: PathBuf,

    /// Directory containing head (target) JSON snapshot files
    #[arg(long)]
    head_dir: PathBuf,

    #[arg(long, default_value_t = false)]
    allow_additional_enums: bool,
}

#[derive(clap::Args)]
struct DiffReportArgs {
    /// Directory containing old snapshot JSON files
    #[arg(long)]
    base_dir: PathBuf,

    /// Directory containing new snapshot JSON files
    #[arg(long)]
    head_dir: PathBuf,

    /// Output file for the markdown report
    #[arg(long, short)]
    output: PathBuf,
}

fn run_check(args: CheckArgs) -> ExitCode {
    let base = match Registry::load_registry(&args.base_dir) {
        Ok(r) => r,
        Err(code) => return code,
    };
    let head = match Registry::load_registry(&args.head_dir) {
        Ok(r) => r,
        Err(code) => return code,
    };

    let entries = base.diff(&head);

    let (errors, warnings, additions) = DiffEntry::split_by_severity(&entries);

    if !additions.is_empty() {
        eprintln!("\nAdditions:");
        for a in &additions {
            eprintln!("   + {a}");
        }
    }

    if !warnings.is_empty() {
        eprintln!("\nWarnings:");
        for w in &warnings {
            eprintln!("   ~ {w}");
        }
    }

    if !errors.is_empty() {
        eprintln!("\nErrors:");
        for e in &errors {
            eprintln!("   ! {e}");
        }
        eprintln!(
            "\nFound {} error(s) — variant removals break backward compatibility",
            errors.len()
        );
        return ExitCode::from(1);
    }

    if !warnings.is_empty() {
        eprintln!(
            "\nFound {} warning(s) — please review carefully",
            warnings.len()
        );
    }

    if !args.allow_additional_enums && !additions.is_empty() {
        eprintln!("\nNew enums/variants/upgrades are not allowed");
        eprintln!("To fix it please regenerate the base snapshot");
        return ExitCode::from(2);
    }

    eprintln!("\nBackward compatibility check passed!");
    println!("OK");
    ExitCode::SUCCESS
}

fn run_diff_report(args: DiffReportArgs) -> ExitCode {
    let old = match Registry::load_registry(&args.base_dir) {
        Ok(r) => r,
        Err(code) => return code,
    };
    let new = match Registry::load_registry(&args.head_dir) {
        Ok(r) => r,
        Err(code) => return code,
    };

    let entries = old.diff(&new);

    let report = build_diff_report(&entries);

    if let Err(err) = fs::write(&args.output, &report) {
        eprintln!("Cannot write report to {}: {}", args.output.display(), err);
        return ExitCode::from(1);
    }

    if report.is_empty() {
        eprintln!("No changes detected");
    } else {
        eprintln!("Report written to {}", args.output.display());
    }

    ExitCode::SUCCESS
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    match cli.command {
        Command::Check(args) => run_check(args),
        Command::DiffReport(args) => run_diff_report(args),
    }
}
