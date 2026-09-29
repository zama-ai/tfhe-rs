use benchmark_spec::Backend;
use clap::Parser;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
    about = "Parse criterion benchmark or keys size results.",
    long_about = None,
)]
pub struct Cli {
    /// Location of criterion benchmark results directory.
    /// If --csv is used, this must point to a CSV file.
    #[arg(short = 'i', long)]
    pub input_results_file: PathBuf,

    /// File storing parsed results.
    #[arg(short = 'o', long)]
    pub output_file: PathBuf,

    /// Name of the database used to store results.
    #[arg(short = 'd', long, required_unless_present = "append_results")]
    pub database: Option<String>,

    /// Hardware reference used to perform benchmark.
    #[arg(short = 'w', long, required_unless_present = "append_results")]
    pub hardware: Option<String>,

    /// Commit hash reference.
    #[arg(
        short = 'V',
        long = "project-version",
        required_unless_present = "append_results"
    )]
    pub project_version: Option<String>,

    /// Git branch name on which benchmark was performed.
    #[arg(short = 'b', long, required_unless_present = "append_results")]
    pub branch: Option<String>,

    /// Timestamp of commit hash used in project_version.
    #[arg(long = "commit-date", required_unless_present = "append_results")]
    pub commit_date: Option<String>,

    /// Timestamp when benchmark was run.
    #[arg(long = "bench-date", required_unless_present = "append_results")]
    pub bench_date: Option<String>,

    /// Suffix to append to each of the result test names.
    #[arg(long = "name-suffix", default_value = "")]
    pub name_suffix: String,

    /// Additional directory in which to look for a `benchmarks_parameters` records directory,
    /// on top of the built-in candidates. Can be given multiple times.
    #[arg(long = "params-dir")]
    pub params_dirs: Vec<PathBuf>,

    /// Append parsed results to an existing file.
    #[arg(long = "append-results")]
    pub append_results: bool,

    /// Check for results in subdirectories.
    #[arg(long = "walk-subdirs")]
    pub walk_subdirs: bool,

    /// Parse a CSV of `id,value` rows instead of a criterion directory.
    #[arg(long = "csv")]
    pub csv: bool,

    /// Backend on which benchmarks have run.
    /// Required even with --append-results, as it is stamped on every parsed point.
    #[arg(long, value_parser = parse_cli_backend)]
    pub backend: Backend,
}

fn parse_cli_backend(s: &str) -> Result<Backend, String> {
    s.parse().map_err(|_| format!("unknown backend: {s}"))
}
