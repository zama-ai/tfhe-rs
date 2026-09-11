//! What a run does with the rows it fetched: the tables, the archive, and the
//! formats each is serialized in.

use benchmark_spec::OperandType;

use crate::cli::{Args, BenchSubset, Layer};
use crate::{archive, db, format};

/// How a built table is serialized.
#[derive(Copy, Clone, Debug)]
pub enum OutputFormat {
    Markdown,
    Csv,
    Svg,
    RegressionJson,
}

impl OutputFormat {
    /// Every artefact a run produces: at most one from the exclusive
    /// `generation` group, plus the CSV, which is always emitted alongside it.
    /// No flag at all writes nothing.
    pub fn from_args(args: &Args) -> Vec<Self> {
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

    pub fn extension(self) -> &'static str {
        match self {
            Self::Markdown => "md",
            Self::Csv => "csv",
            Self::Svg => "svg",
            Self::RegressionJson => "json",
        }
    }

    pub fn render(self, grid: &format::Grid) -> anyhow::Result<String> {
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

/// Parses the fetched ids against the spec, reporting how many the current
/// grammar does not cover.
pub fn parse_and_warn(rows: &[db::BenchRow]) -> Vec<format::Measured> {
    let (measured, unparsed) = format::parse_rows(rows);
    if unparsed > 0 {
        eprintln!("warning: {unparsed} ids skipped, not in the current spec grammar");
    }
    measured
}

/// Writes the archive's merge input, and says what it could not fill in.
pub fn write_archive(
    output_file: &str,
    quarter: archive::Quarter,
    measured: &[format::Measured],
) -> anyhow::Result<()> {
    let archive = archive::build(measured);
    let path = format!("{output_file}-archive.csv");
    std::fs::write(&path, archive::render(&archive, quarter))?;

    println!(
        "  wrote {path}: {} of the {} published operations",
        archive.rows.len(),
        archive::published_rows(),
    );
    archive.report();

    Ok(())
}

/// The tables a run publishes, each with the suffix its file is named after.
///
/// Named after the operand type for every layer but core_crypto; integer
/// publishes both.
pub fn build_tables(
    args: &Args,
    measured: &[format::Measured],
) -> anyhow::Result<Vec<(String, format::Table)>> {
    Ok(match (args.layer, args.bench_subset) {
        (Layer::Integer, BenchSubset::All) => vec![
            (
                "-ciphertext".to_string(),
                format::integer::table(measured, args.backend, OperandType::CipherText),
            ),
            (
                "-plaintext".to_string(),
                format::integer::table(measured, args.backend, OperandType::PlainText),
            ),
        ],
        (Layer::HlApi, BenchSubset::Erc7984) => vec![(
            "-ciphertext".to_string(),
            format::erc7984::table(measured, args.backend),
        )],
        // One table per compute load, all ciphertext.
        (Layer::Integer, BenchSubset::Zk) => format::zk::tables(measured)
            .into_iter()
            .map(|(suffix, table)| (format!("-ciphertext{suffix}"), table))
            .collect(),
        // One table per parameter set family, and no operand type in the name:
        // core_crypto has no scalar operation.
        (Layer::CoreCrypto, BenchSubset::All) => {
            format::core_crypto::tables(measured, args.grouping_factor.map(u32::from))
        }
        // One table per operation, all ciphertext.
        (Layer::HlApi, BenchSubset::KvStore) => format::kv_store::tables(measured)
            .into_iter()
            .map(|(suffix, table)| (format!("-ciphertext{suffix}"), table))
            .collect(),
        (layer, subset) => {
            anyhow::bail!("no table implemented for layer {layer:?} / subset {subset:?}")
        }
    })
}

/// Serializes every table in every requested format, and reports what each one
/// could not account for.
pub fn write_tables(
    args: &Args,
    outputs: &[OutputFormat],
    tables: &[(String, format::Table)],
) -> anyhow::Result<()> {
    for (suffix, table) in tables {
        for output in outputs {
            let path = format!("{}{suffix}.{}", args.output_file, output.extension());
            std::fs::write(&path, output.render(&table.grid)?)?;
            println!("  wrote {path}");
        }
        table.report();
    }

    Ok(())
}
