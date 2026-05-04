use benchmark_spec::{Backend, BenchmarkMetric};
use clap::Parser;
use std::path::PathBuf;
use std::str::FromStr;

#[derive(Parser, Debug)]
#[command(
    about = "Parse criterion benchmark or keys size results.",
    long_about = None,
)]
pub struct Cli {
    /// Location of criterion benchmark results directory.
    /// If --object-sizes or --key-gen is used, this must point to a CSV file.
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

    /// Append parsed results to an existing file.
    #[arg(long = "append-results")]
    pub append_results: bool,

    /// Check for results in subdirectories.
    #[arg(long = "walk-subdirs")]
    pub walk_subdirs: bool,

    /// Parse only the results regarding keys size measurements.
    #[arg(long = "object-sizes", conflicts_with = "key_gen")]
    pub object_sizes: bool,

    /// Parse only the results regarding keys generation time measurements.
    #[arg(long = "key-gen")]
    pub key_gen: bool,

    /// Fetch results for latency or throughput benchmarks.
    #[arg(long = "bench-type",value_parser = parse_cli_bench_metric,default_value = "latency")]
    pub bench_type: BenchmarkMetric,

    /// Backend on which benchmarks have run.
    /// Required even with --append-results, as it is stamped on every parsed point.
    #[arg(long, value_parser = parse_cli_backend)]
    pub backend: Backend,
}

fn parse_cli_bench_metric(s: &str) -> Result<BenchmarkMetric, String> {
    let m = BenchmarkMetric::from_str(s)?;
    match m {
        BenchmarkMetric::Latency | BenchmarkMetric::Throughput => Ok(m),
        _ => Err(format!("--bench-type does not support {m:?}")),
    }
}

fn parse_cli_backend(s: &str) -> Result<Backend, String> {
    Backend::from_str(s)
}
