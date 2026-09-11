//! The command line: the vocabulary its flags accept, the arguments themselves,
//! and what the two of them say the run should produce.

use std::path::PathBuf;

use benchmark_spec::tfhe::TfheLayerKind;
use chrono::NaiveDateTime;
use clap::{ArgGroup, Parser, ValueEnum};

use crate::archive;
use crate::db::{self, PbsKind};

/// Layer of the tfhe-rs library to filter against.
#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
pub enum Layer {
    #[value(name = "hlapi")]
    HlApi,
    Integer,
    Shortint,
    #[value(name = "core_crypto")]
    CoreCrypto,
    Wasm,
}

impl Layer {
    /// Maps the CLI layer onto the spec's own layer token, so the id prefix used in
    /// the SQL `LIKE` pattern always follows the spec grammar.
    pub fn layer_kind(&self) -> anyhow::Result<TfheLayerKind> {
        Ok(match self {
            Layer::HlApi => TfheLayerKind::Hlapi,
            Layer::Integer => TfheLayerKind::Integer,
            Layer::Shortint => TfheLayerKind::Shortint,
            Layer::CoreCrypto => TfheLayerKind::CoreCrypto,
            // Wasm benches never migrated to the spec grammar: their ids carry no
            // crate prefix, so there is nothing the parser could match.
            Layer::Wasm => anyhow::bail!("the `wasm` layer is not part of the benchmark spec"),
        })
    }
}

/// Type of benchmark to filter against.
#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
pub enum BenchType {
    Latency,
    Throughput,
    Both,
}

/// Subset of benchmarks to filter against, dedicated formatting will be applied.
#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
pub enum BenchSubset {
    All,
    Erc7984,
    Zk,
    #[value(name = "kv_store")]
    KvStore,
}

impl BenchSubset {
    /// The bench path segment that follows the layer, so that a subset narrows
    /// the query instead of being filtered out once every row of the layer has
    /// been fetched. Already `LIKE`-escaped, and terminated by `::` so it can be
    /// concatenated straight onto the layer prefix.
    ///
    /// ```text
    /// all -> tfhe::integer::%_mean_avx512
    /// zk  -> tfhe::integer::zk::%_mean_avx512
    /// ```
    pub fn path_segment(self) -> String {
        let segment = match self {
            // No segment: the whole layer is in scope.
            Self::All => return String::new(),
            Self::Erc7984 => "erc7984",
            Self::Zk => "zk",
            Self::KvStore => "kv_store",
        };
        format!("{}::", db::like_escape(segment))
    }
}

impl BenchType {
    /// Maps the CLI filter onto the spec metric. `None` means no metric filter
    /// (i.e. both latency and throughput).
    pub fn as_metric(self) -> Option<benchmark_spec::BenchmarkMetric> {
        match self {
            BenchType::Latency => Some(benchmark_spec::BenchmarkMetric::Latency),
            BenchType::Throughput => Some(benchmark_spec::BenchmarkMetric::Throughput),
            BenchType::Both => None,
        }
    }
}

/// Parses the `--backend` argument straight into the spec's `Backend` type.
fn parse_backend(s: &str) -> Result<benchmark_spec::Backend, String> {
    s.parse().map_err(|e| format!("invalid backend: {e}"))
}

/// Exit code for a selection that matched nothing. Writing the `N/A` grid anyway
/// would let a broken selection reach the documentation through a green job, so
/// an empty report is a failure. Distinct from the 1 any other error exits with,
/// so a caller can tell a bad filter from a broken run.
pub const EXIT_NO_RESULTS: i32 = 2;

/// The timestamp format `--bench-date` accepts and the query sends back out.
pub const BENCH_DATE_FORMAT: &str = "%Y-%m-%dT%H:%M:%S";

/// Rejects a malformed `--bench-date` here rather than leaving it to PostgreSQL
/// once the connection is open.
fn parse_bench_date(s: &str) -> Result<NaiveDateTime, String> {
    NaiveDateTime::parse_from_str(s, BENCH_DATE_FORMAT)
        .map_err(|e| format!("expected an ISO 8601 YYYY-MM-DDThh:mm:ss timestamp: {e}"))
}

/// Same reason as [`parse_bench_date`]: a malformed quarter is caught before
/// the connection is open, not after a full fetch.
fn parse_quarter(s: &str) -> Result<archive::Quarter, String> {
    s.parse()
}

/// What no single flag description can say: where the credentials come from,
/// what a run writes, and how a selection is built. Shown by `--help` only, so
/// `-h` stays a flag list.
const AFTER_LONG_HELP: &str = r#"CREDENTIALS:
  --config-file takes a TOML file holding [database] host, user and password;
  see config.example.toml next to this crate. The environment variables
  DATA_EXTRACTOR_DATABASE_HOST, _USER and _PASSWORD override any value that
  file holds, and are enough on their own.

OUTPUTS:
  The --generate-* flags are mutually exclusive, and the CSV comes out
  alongside whichever one is picked: there is no --generate-csv. Files are
  named `<output-file><suffix>.<ext>`, the suffix being the operand type.

  With no --generate-* flag, nothing is written: the row count and the first
  ten rows are printed instead, which is the quickest way to eyeball a filter.

  --generate-archive-csv is the exception: it writes `<output-file>-archive.csv`
  and nothing else. Its rows hold raw nanoseconds and rates, one per published
  operation, for the archive repository to merge into its own cells.csv.

  It also ignores every selection flag but the window and --param. Machine,
  parameter set and PBS kind are elected on the figures: the query keeps the
  most recent value of each id, then the best one wins per operation, and the
  machine that won is what the `hardware` column reports.

SELECTION:
  Without a profile, the report is one broad pattern for the whole layer, minus
  the `unchecked_` variants.

  --regression-profiles and --regression-selected-profile go together and, when
  given, pin the report to exactly the bench paths that profile lists. Profile
  entries are spec path fragments rather than bare operation names, for example
  `target.hlapi-dex = ["swap_request::whitepaper"]`.

  --dry-run prints the id patterns the selection expands to and exits, without
  reading the config file or opening a connection.

EXAMPLES:
  Check what a profile selects, no database needed:
    tfhe-data-extractor out --dry-run \
      --regression-profiles ci/regression.toml \
      --regression-selected-profile default

  SVG and CSV for the integer tables of the last 30 days:
    tfhe-data-extractor bench-results --config-file config.toml \
      --generate-svg --tfhe-rs-layer integer --hardware hpc8a.96xlarge

  The archive rows of one quarter, nothing to pick but the window:
    tfhe-data-extractor out --config-file config.toml \
      --generate-archive-csv --quarter 2026Q3 \
      --bench-date 2026-09-30T23:59:59 --time-span-days 30
"#;

// Several fields are parsed but not consumed yet.
#[allow(dead_code)]
#[derive(Parser, Debug)]
#[command(
    about = "Extract benchmarks results from Zama PostgreSQL instance, filtered and formatted as CSV.",
    after_long_help = AFTER_LONG_HELP,
    // `-V` is taken by --project-version, so free clap's automatic version flag.
    disable_version_flag = true,
    // `-w/--hardware` and `--hardware-comp` are mutually exclusive.
    group(ArgGroup::new("hardware_selection").args(["hardware", "hardware_comp"])),
    // The four `--generate-*` options are mutually exclusive. The CSV has no
    // flag: it is emitted alongside whichever of these is picked.
    group(ArgGroup::new("generation").args([
        "generate_markdown",
        "generate_svg",
        "generate_svg_from_file",
        "generate_regression_json",
        "generate_archive_csv",
    ])),
)]
pub struct Args {
    /// File storing parsed results (with no extension).
    pub output_file: String,

    /// Location of configuration file containing credentials to connect to
    /// PostgreSQL instance.
    #[arg(short = 'c', long = "config-file")]
    pub config_file: Option<PathBuf>,

    /// Last insertion date to look for in the database, formatted as ISO 8601
    /// timestamp YYYY-MM-DDThh:mm:ss. Defaults to now when omitted.
    #[arg(long = "bench-date", value_parser = parse_bench_date)]
    pub bench_date: Option<NaiveDateTime>,

    /// Name of the database used to store results.
    #[arg(short, long, default_value = "tfhe_rs")]
    pub database: String,

    /// Hardware reference used to perform benchmark. Not needed by
    /// --generate-archive-csv, which elects a machine per operation.
    #[arg(short = 'w', long, required_unless_present = "generate_archive_csv")]
    pub hardware: Option<String>,

    /// Comma separated values of hardware to compare. The first value would be
    /// chosen as baseline.
    #[arg(long = "hardware-comp")]
    pub hardware_comp: Option<String>,

    /// Commit hash reference.
    #[arg(short = 'V', long = "project-version")]
    pub project_version: Option<String>,

    /// Git branch name on which benchmark was performed.
    #[arg(short, long, default_value = "main")]
    pub branch: String,

    /// Git base branch name on which benchmark history can be fetched.
    #[arg(long = "base-branch", default_value = "main")]
    pub base_branch: String,

    /// Backend on which benchmarks have run.
    #[arg(long, default_value = "cpu", value_parser = parse_backend)]
    pub backend: benchmark_spec::Backend,

    /// Produce a comparison between backends on 64 bits ciphertext/ciphertext
    /// integer operations.
    #[arg(long = "backends-comparison")]
    pub backends_comparison: bool,

    /// Layer of the tfhe-rs library to filter against.
    #[arg(long = "tfhe-rs-layer", value_enum, default_value_t = Layer::Integer)]
    pub layer: Layer,

    /// Kind of PBS to look for.
    #[arg(long = "pbs-kind", value_enum, default_value_t = PbsKind::Classical)]
    pub pbs_kind: PbsKind,

    /// Grouping factor used in multi-bit parameters set.
    #[arg(long = "grouping-factor", value_parser = clap::value_parser!(u8).range(2..=4))]
    pub grouping_factor: Option<u8>,

    /// Numbers of days prior of `bench_date` we search for results in the
    /// database.
    #[arg(long = "time-span-days", default_value_t = 30, value_parser = clap::value_parser!(i64).range(1..))]
    pub time_span_days: i64,

    /// Type of benchmark to filter against.
    #[arg(long = "bench-type", value_enum, default_value_t = BenchType::Latency)]
    pub bench_type: BenchType,

    /// Subset of benchmarks to filter against, dedicated formatting will be
    /// applied.
    #[arg(long = "bench-subset", value_enum, default_value_t = BenchSubset::All)]
    pub bench_subset: BenchSubset,

    /// Suffix to match the test names.
    #[arg(long = "name-suffix", default_value = "_mean_avx512")]
    pub name_suffix: String,

    /// Path to file containing regression profiles formatted as TOML.
    #[arg(long = "regression-profiles")]
    pub regression_profiles: Option<PathBuf>,

    /// Regression profile to select from the regression profiles file to filter
    /// out database results.
    #[arg(long = "regression-selected-profile")]
    pub regression_selected_profile: Option<String>,

    /// Generate Markdown array.
    #[arg(long = "generate-markdown")]
    pub generate_markdown: bool,

    /// Generate SVG table formatted like ones in tfhe-rs documentation.
    #[arg(long = "generate-svg")]
    pub generate_svg: bool,

    /// Generate SVG table formatted like ones in tfhe-rs documentation from a
    /// Markdown table.
    #[arg(long = "generate-svg-from-markdown")]
    pub generate_svg_from_file: Option<String>,

    /// Generate JSON file with regression data with all the results from base
    /// branch and the latest results of the development branch.
    #[arg(long = "generate-regression-json")]
    pub generate_regression_json: bool,

    /// Generate the merge input of the benchmark archive: one row per published
    /// operation, latency and throughput side by side, figures unformatted.
    /// Takes no selection flag beyond the window and the quarter: the machine,
    /// the parameter set and the PBS kind are elected on the figures.
    ///
    /// The flags it would ignore are refused rather than dropped, so that a
    /// command copied from a table run fails instead of quietly meaning
    /// something else.
    #[arg(
        long = "generate-archive-csv",
        requires = "quarter",
        conflicts_with_all = [
            "hardware",
            "hardware_comp",
            "backend",
            "backends_comparison",
            "pbs_kind",
            "bench_type",
            "layer",
            "bench_subset",
            "regression_profiles",
            "regression_selected_profile",
        ],
    )]
    pub generate_archive_csv: bool,

    /// Quarter the archive rows are published under, `2026Q2`. A label only:
    /// which results land in it is decided by --project-version or the
    /// --bench-date window.
    #[arg(long = "quarter", value_parser = parse_quarter)]
    pub quarter: Option<archive::Quarter>,

    /// Restrict the report to one parameter set, matched as a substring of the
    /// alias. Overrides the profile's `parameters_filter`.
    #[arg(long = "param")]
    pub param: Option<String>,

    /// Print the id patterns the selection expands to, then exit without
    /// touching the database.
    #[arg(long = "dry-run")]
    pub dry_run: bool,
}
/// What the run produces.
///
/// The two reports share a connection and little else: the archive elects its
/// own machine, parameter set and metric, so every selection flag but the
/// window is meaningless to it. Resolved once, so that no later step has to
/// ask again which report it is serving.
pub enum Mode {
    /// The published tables, one per operand type or parameter family.
    Tables,
    /// The archive's merge input, tagged with the quarter it publishes under.
    Archive(archive::Quarter),
}

impl Mode {
    pub fn from_args(args: &Args) -> Self {
        if args.generate_archive_csv {
            // `requires = "quarter"` has already rejected the flag without it.
            Mode::Archive(
                args.quarter
                    .expect("--generate-archive-csv requires --quarter"),
            )
        } else {
            Mode::Tables
        }
    }
}
