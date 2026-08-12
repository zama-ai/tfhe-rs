//! Extracts benchmark results from the Zama PostgreSQL instance and writes the
//! filtered tables as CSV, Markdown or SVG.
//!
//! Connection settings come from a configuration file, from these environment
//! variables, or from both:
//!  * DATA_EXTRACTOR_DATABASE_HOST
//!  * DATA_EXTRACTOR_DATABASE_USER
//!  * DATA_EXTRACTOR_DATABASE_PASSWORD
//!
//! Environment variables take precedence over the configuration file.

use std::path::PathBuf;

use benchmark_spec::tfhe::TfheLayerKind;
use benchmark_spec::{BenchCrateKind, OperandType};
use chrono::NaiveDateTime;
use clap::{ArgGroup, Parser, ValueEnum};

mod db;
mod format;
mod profile;

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

/// Kind of parameter set used for the Programmable Bootstrapping operation.
#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
pub enum PbsKind {
    Classical,
    #[value(name = "multi_bit")]
    MultiBit,
    /// Special variant used when the user doesn't care about the PBS kind.
    Any,
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

impl BenchType {
    /// Maps the CLI filter onto the spec metric. `None` means no metric filter
    /// (i.e. both latency and throughput).
    fn as_metric(self) -> Option<benchmark_spec::BenchmarkMetric> {
        match self {
            BenchType::Latency => Some(benchmark_spec::BenchmarkMetric::Latency),
            BenchType::Throughput => Some(benchmark_spec::BenchmarkMetric::Throughput),
            BenchType::Both => None,
        }
    }
}

/// Parses the `--backend` argument straight into the spec's `Backend` type.
fn parse_backend(s: &str) -> Result<benchmark_spec::Backend, String> {
    s.parse()
}

/// The timestamp format `--bench-date` accepts and the query sends back out.
const BENCH_DATE_FORMAT: &str = "%Y-%m-%dT%H:%M:%S";

/// Rejects a malformed `--bench-date` here rather than leaving it to PostgreSQL
/// once the connection is open.
fn parse_bench_date(s: &str) -> Result<NaiveDateTime, String> {
    NaiveDateTime::parse_from_str(s, BENCH_DATE_FORMAT)
        .map_err(|e| format!("expected an ISO 8601 YYYY-MM-DDThh:mm:ss timestamp: {e}"))
}

// Several fields are parsed but not consumed yet.
#[allow(dead_code)]
#[derive(Parser, Debug)]
#[command(
    about = "Extract benchmarks results from Zama PostgreSQL instance, filtered and formatted as CSV.",
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
    ])),
)]
struct Args {
    /// File storing parsed results (with no extension).
    output_file: String,

    /// Location of configuration file containing credentials to connect to
    /// PostgreSQL instance.
    #[arg(short = 'c', long = "config-file")]
    config_file: Option<PathBuf>,

    /// Last insertion date to look for in the database, formatted as ISO 8601
    /// timestamp YYYY-MM-DDThh:mm:ss. Defaults to now when omitted.
    #[arg(long = "bench-date", value_parser = parse_bench_date)]
    bench_date: Option<NaiveDateTime>,

    /// Name of the database used to store results.
    #[arg(short, long, default_value = "tfhe_rs")]
    database: String,

    /// Hardware reference used to perform benchmark.
    #[arg(short = 'w', long, default_value = "hpc8a.96xlarge")]
    hardware: String,

    /// Comma separated values of hardware to compare. The first value would be
    /// chosen as baseline.
    #[arg(long = "hardware-comp")]
    hardware_comp: Option<String>,

    /// Commit hash reference.
    #[arg(short = 'V', long = "project-version")]
    project_version: Option<String>,

    /// Git branch name on which benchmark was performed.
    #[arg(short, long, default_value = "main")]
    branch: String,

    /// Git base branch name on which benchmark history can be fetched.
    #[arg(long = "base-branch", default_value = "main")]
    base_branch: String,

    /// Backend on which benchmarks have run.
    #[arg(long, default_value = "cpu", value_parser = parse_backend)]
    backend: benchmark_spec::Backend,

    /// Produce a comparison between backends on 64 bits ciphertext/ciphertext
    /// integer operations.
    #[arg(long = "backends-comparison")]
    backends_comparison: bool,

    /// Layer of the tfhe-rs library to filter against.
    #[arg(long = "tfhe-rs-layer", value_enum, default_value_t = Layer::Integer)]
    layer: Layer,

    /// Kind of PBS to look for.
    #[arg(long = "pbs-kind", value_enum, default_value_t = PbsKind::Classical)]
    pbs_kind: PbsKind,

    /// Grouping factor used in multi-bit parameters set.
    #[arg(long = "grouping-factor", value_parser = clap::value_parser!(u8).range(2..=4))]
    grouping_factor: Option<u8>,

    /// Numbers of days prior of `bench_date` we search for results in the
    /// database.
    #[arg(long = "time-span-days", default_value_t = 30, value_parser = clap::value_parser!(i64).range(1..))]
    time_span_days: i64,

    /// Type of benchmark to filter against.
    #[arg(long = "bench-type", value_enum, default_value_t = BenchType::Latency)]
    bench_type: BenchType,

    /// Subset of benchmarks to filter against, dedicated formatting will be
    /// applied.
    #[arg(long = "bench-subset", value_enum, default_value_t = BenchSubset::All)]
    bench_subset: BenchSubset,

    /// Suffix to match the test names.
    #[arg(long = "name-suffix", default_value = "_mean_avx512")]
    name_suffix: String,

    /// Path to file containing regression profiles formatted as TOML.
    #[arg(long = "regression-profiles")]
    regression_profiles: Option<PathBuf>,

    /// Regression profile to select from the regression profiles file to filter
    /// out database results.
    #[arg(long = "regression-selected-profile")]
    regression_selected_profile: Option<String>,

    /// Generate Markdown array.
    #[arg(long = "generate-markdown")]
    generate_markdown: bool,

    /// Generate SVG table formatted like ones in tfhe-rs documentation.
    #[arg(long = "generate-svg")]
    generate_svg: bool,

    /// Generate SVG table formatted like ones in tfhe-rs documentation from a
    /// Markdown table.
    #[arg(long = "generate-svg-from-markdown")]
    generate_svg_from_file: Option<String>,

    /// Generate JSON file with regression data with all the results from base
    /// branch and the latest results of the development branch.
    #[arg(long = "generate-regression-json")]
    generate_regression_json: bool,

    /// Restrict the report to one parameter set, matched as a substring of the
    /// alias. Overrides the profile's `parameters_filter`.
    #[arg(long = "param")]
    param: Option<String>,

    /// Print the id patterns the selection expands to, then exit without
    /// touching the database.
    #[arg(long = "dry-run")]
    dry_run: bool,
}

/// Maps the CLI layer onto the spec's own layer token, so the id prefix used in
/// the SQL `LIKE` pattern always follows the spec grammar.
fn layer_kind(layer: Layer) -> anyhow::Result<TfheLayerKind> {
    Ok(match layer {
        Layer::HlApi => TfheLayerKind::Hlapi,
        Layer::Integer => TfheLayerKind::Integer,
        Layer::Shortint => TfheLayerKind::Shortint,
        Layer::CoreCrypto => TfheLayerKind::CoreCrypto,
        // Wasm benches never migrated to the spec grammar: their ids carry no
        // crate prefix, so there is nothing the parser could match.
        Layer::Wasm => anyhow::bail!("the `wasm` layer is not part of the benchmark spec"),
    })
}

/// How a built table is serialized.
#[derive(Copy, Clone, Debug)]
enum OutputFormat {
    Markdown,
    Csv,
    Svg,
    RegressionJson,
}

impl OutputFormat {
    /// Every artefact a run produces: at most one from the exclusive
    /// `generation` group, plus the CSV, which is always emitted alongside it.
    /// No flag at all writes nothing.
    fn from_args(args: &Args) -> Vec<Self> {
        let mut outputs = Vec::new();
        if args.generate_markdown {
            outputs.push(Self::Markdown);
        } else if args.generate_svg {
            outputs.push(Self::Svg);
        } else if args.generate_regression_json {
            outputs.push(Self::RegressionJson);
        }
        if !outputs.is_empty() {
            outputs.push(Self::Csv);
        }
        outputs
    }

    fn extension(self) -> &'static str {
        match self {
            Self::Markdown => "md",
            Self::Csv => "csv",
            Self::Svg => "svg",
            Self::RegressionJson => "json",
        }
    }

    fn render(self, grid: &format::Grid) -> anyhow::Result<String> {
        Ok(match self {
            Self::Markdown => format::render::markdown::table(grid),
            Self::Csv => format::render::csv::table(grid),
            Self::Svg => format::render::svg::table(grid),
            // Two branches compared over a longer window.
            Self::RegressionJson => {
                anyhow::bail!("output format {self:?} is not implemented yet")
            }
        })
    }
}

/// Which benchmarks the report is about, as SQL-ready patterns.
struct Selection {
    /// One exact prefix per bench path (profile), or one broad layer pattern.
    like_patterns: Vec<String>,
    /// `LIKE` pattern pinning the parameter set, if any.
    param_pattern: Option<String>,
    /// Drop the `unchecked_` variants by name. Only needed for the broad
    /// pattern: a profile already spells out the operations it wants.
    exclude_non_default: bool,
}

impl Selection {
    /// A regression profile gives an explicit allow-list of bench paths;
    /// without one, fall back to a broad per-layer pattern. Both are anchored on
    /// the crate prefix, so legacy ids are excluded.
    fn from_args(args: &Args) -> anyhow::Result<Self> {
        let (like_patterns, param_filter, exclude_non_default) = match (
            args.regression_profiles.as_deref(),
            args.regression_selected_profile.as_deref(),
        ) {
            (Some(path), Some(name)) => {
                let profiles = profile::Profiles::load(path)?;
                let selected = profiles.get(args.backend, name)?;
                let resolved = selected.resolve();
                if !resolved.unresolved.is_empty() {
                    eprintln!(
                        "warning: {} profile entries not in the spec: {}",
                        resolved.unresolved.len(),
                        resolved.unresolved.join(", "),
                    );
                }
                (
                    resolved.like_patterns(&args.name_suffix),
                    // `--param` wins over the profile's own filter.
                    args.param
                        .clone()
                        .or_else(|| selected.parameters_filter.clone()),
                    false,
                )
            }
            (Some(_), None) | (None, Some(_)) => {
                anyhow::bail!("--regression-profiles and --regression-selected-profile go together")
            }
            (None, None) => (
                vec![format!(
                    "{}::{}::%{}",
                    BenchCrateKind::Tfhe,
                    db::like_escape(&layer_kind(args.layer)?.to_string()),
                    db::like_escape(&args.name_suffix),
                )],
                args.param.clone(),
                true,
            ),
        };

        Ok(Self {
            like_patterns,
            param_pattern: param_filter
                .as_deref()
                .map(|p| format!("%{}%", db::like_escape(p))),
            exclude_non_default,
        })
    }

    /// Human-readable lines, shared by `--dry-run` and the no-result report.
    fn describe(&self) -> Vec<String> {
        let mut lines = Vec::new();
        if let Some(pattern) = &self.param_pattern {
            lines.push(format!("parameter set: {pattern}"));
        }
        lines.push(format!("{} id pattern(s):", self.like_patterns.len()));
        lines.extend(self.like_patterns.iter().map(|p| format!("  {p}")));
        lines
    }
}

/// Lists every filter the query applied, so that a run without a single result
/// says why rather than just how many.
fn report_no_rows(args: &Args, backend: &str, selection: &Selection) {
    eprintln!("no result matched. Filters applied:");
    eprintln!("  hardware: {}", args.hardware);
    eprintln!("  backend:  {backend}");
    eprintln!("  branch:   {}", args.branch);
    eprintln!("  metric:   {:?}", args.bench_type);
    eprintln!("  pbs kind: {:?}", args.pbs_kind);
    match args.project_version.as_deref() {
        Some(version) => eprintln!("  version:  {version}"),
        None => eprintln!(
            "  window:   {} days back from {}",
            args.time_span_days,
            args.bench_date.map_or_else(
                || "now".to_string(),
                |date| date.format(BENCH_DATE_FORMAT).to_string()
            ),
        ),
    }
    for line in selection.describe() {
        eprintln!("  {line}");
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let selection = Selection::from_args(&args)?;

    if args.dry_run {
        for line in selection.describe() {
            println!("{line}");
        }
        return Ok(());
    }

    let db_config = db::DbConfig::load(args.config_file.as_deref())?;
    let pool = db_config.connect(&args.database).await?;
    let backend = args.backend.to_string();
    // Sent as text: the `insert_time` column may be `timestamp` or `timestamptz`,
    // and a SQL cast copes with either, where a typed bind would have to pick one.
    let bench_date = args
        .bench_date
        .map(|date| date.format(BENCH_DATE_FORMAT).to_string());

    let query = db::FetchQuery {
        hardware: &args.hardware,
        backend: &backend,
        branch: &args.branch,
        like_patterns: &selection.like_patterns,
        exclude_non_default: selection.exclude_non_default,
        param_pattern: selection.param_pattern.as_deref(),
        metric: args.bench_type.as_metric(),
        pbs_kind: match args.pbs_kind {
            PbsKind::Classical => db::PbsKind::Classical,
            PbsKind::MultiBit => db::PbsKind::MultiBit,
            PbsKind::Any => db::PbsKind::Any,
        },
        project_version: args.project_version.as_deref(),
        bench_date: bench_date.as_deref(),
        time_span_days: args.time_span_days as i32,
    };

    let rows = db::fetch_bench_rows(&pool, &query).await?;

    if rows.is_empty() {
        report_no_rows(&args, &backend, &selection);
    }

    let outputs = OutputFormat::from_args(&args);
    if !outputs.is_empty() {
        // Files are named after the operand type for every layer but
        // core_crypto; integer publishes both.
        let tables: Vec<(String, format::Table)> = match (args.layer, args.bench_subset) {
            (Layer::Integer, BenchSubset::All) => vec![
                (
                    "-ciphertext".to_string(),
                    format::integer::table(&rows, OperandType::CipherText),
                ),
                (
                    "-plaintext".to_string(),
                    format::integer::table(&rows, OperandType::PlainText),
                ),
            ],
            (Layer::HlApi, BenchSubset::Erc7984) => {
                vec![("-ciphertext".to_string(), format::erc7984::table(&rows))]
            }
            // One table per operation, all ciphertext.
            (Layer::HlApi, BenchSubset::KvStore) => format::kv_store::tables(&rows)
                .into_iter()
                .map(|(suffix, table)| (format!("-ciphertext{suffix}"), table))
                .collect(),
            (layer, subset) => {
                anyhow::bail!("no table implemented for layer {layer:?} / subset {subset:?}")
            }
        };
        println!("{} rows fetched", rows.len());
        for (suffix, table) in &tables {
            for output in &outputs {
                let path = format!("{}{suffix}.{}", args.output_file, output.extension());
                std::fs::write(&path, output.render(&table.grid)?)?;
                println!("  wrote {path}");
            }
            table.report();
        }
    } else {
        println!("fetched {} rows (layer: {:?})", rows.len(), args.layer);
        for row in rows.iter().take(10) {
            println!("{row:?}");
        }
    }

    Ok(())
}
