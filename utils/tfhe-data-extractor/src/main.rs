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

use clap::Parser;

use tfhe_data_extractor::cli::{Args, EXIT_NO_RESULTS, Mode};
use tfhe_data_extractor::db;
use tfhe_data_extractor::output::{
    OutputFormat, build_tables, parse_and_warn, write_archive, write_tables,
};
use tfhe_data_extractor::query::{QueryInputs, Selection, report_no_rows};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let mode = Mode::from_args(&args);
    let selection = Selection::from_args(&args, &mode)?;

    if args.dry_run {
        for line in selection.describe() {
            println!("{line}");
        }
        return Ok(());
    }

    let db_config = db::DbConfig::load(args.config_file.as_deref())?;
    let pool = db_config.connect(&args.database).await?;

    let inputs = QueryInputs::from_args(&args, &mode);
    let query = inputs.query(&args, &selection);

    let rows = db::fetch_bench_rows(&pool, &query).await?;

    if rows.is_empty() {
        report_no_rows(&query, &selection);
        std::process::exit(EXIT_NO_RESULTS);
    }

    match mode {
        Mode::Archive(quarter) => {
            println!("{} rows fetched", rows.len());
            write_archive(&args.output_file, quarter, &parse_and_warn(&rows))
        }
        Mode::Tables => {
            // No --generate-* flag: nothing is written, the first rows are printed
            // instead, which is the quickest way to eyeball a filter.
            let outputs = OutputFormat::from_args(&args);
            if outputs.is_empty() {
                println!("fetched {} rows (layer: {:?})", rows.len(), args.layer);
                for row in rows.iter().take(10) {
                    println!("{row:?}");
                }
                return Ok(());
            }
            let tables = build_tables(&args, &parse_and_warn(&rows))?;
            println!("{} rows fetched", rows.len());
            write_tables(&args, &outputs, &tables)
        }
    }
}
