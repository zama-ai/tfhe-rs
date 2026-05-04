use clap::{Parser, ValueEnum};
use std::path::PathBuf;
use tfhe_benchmark_parser::model::{Backend, PointType};

#[derive(Parser, Debug)]
#[command(
    about = "Parse criterion benchmark or keys size results.",
    long_about = None,
)]
pub struct Cli {
    /// Location of criterion benchmark results directory.
    /// If --object-sizes or --key-gen is used, this must point to a CSV file.
    pub results: PathBuf,

    /// File storing parsed results.
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
    #[arg(long = "bench-type", value_enum, default_value_t = BenchType::Latency)]
    pub bench_type: BenchType,

    /// Backend on which benchmarks have run.
    #[arg(long, value_enum, default_value_t = Backend::Cpu)]
    pub backend: Backend,

    /// Crate for which benchmarks have run.
    /// Kept for CLI parity: passed by `.github/workflows/benchmark_gpu_coprocessor.yml`,
    /// but unused, the Python original also accepted it without ever consulting it,
    /// since `get_parameters` always iterates the hardcoded `BENCHMARK_DIRS` list.
    #[arg(long = "crate", default_value = "tfhe")]
    pub crate_name: String,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
pub enum BenchType {
    Latency,
    Throughput,
}

impl From<BenchType> for PointType {
    fn from(value: BenchType) -> Self {
        match value {
            BenchType::Latency => PointType::Latency,
            BenchType::Throughput => PointType::Throughput,
        }
    }
}
