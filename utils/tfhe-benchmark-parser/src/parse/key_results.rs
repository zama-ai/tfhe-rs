use super::ParseOutcome;
use super::metric::declared_metric;
use super::parameters::get_parameters;
use anyhow::{Context, Result};
use benchmark_spec::Backend;
use serde::Deserialize;
use serde_json::Number;
use std::path::{Path, PathBuf};
use tfhe_benchmark_parser::model::{ParsingFailure, Point, PointClass};

#[derive(Deserialize)]
struct CsvResultRow {
    test_name: String,
    value: i64,
}

pub fn parse_csv_results(
    result_file: &Path,
    extra_params_dirs: &[PathBuf],
    backend: Backend,
) -> Result<ParseOutcome> {
    // Note: matching the Python parser, both CSV modes use `class = "keygen"`. Only `type` differs.
    parse_key_results(result_file, extra_params_dirs, backend)
}

fn parse_key_results(
    result_file: &Path,
    extra_params_dirs: &[PathBuf],
    backend: Backend,
) -> Result<ParseOutcome> {
    let mut points = Vec::new();
    let mut failures = Vec::new();

    let mut reader = csv::ReaderBuilder::new()
        .has_headers(false)
        .from_path(result_file)
        .with_context(|| format!("opening {}", result_file.display()))?;

    for (line_idx, row) in reader.deserialize::<CsvResultRow>().enumerate() {
        let row = match row {
            Ok(r) => r,
            Err(err) => {
                failures.push(ParsingFailure {
                    source: format!("{}:{}", result_file.display(), line_idx + 1),
                    error: format!("malformed CSV row: {err}"),
                });
                continue;
            }
        };

        let point_type = match declared_metric(&row.test_name) {
            Ok(metric) => metric,
            Err(failure) => {
                failures.push(failure);
                continue;
            }
        };

        let (params, display_name, operator) =
            match get_parameters(&row.test_name, extra_params_dirs) {
                Ok(triple) => triple,
                Err(err) => {
                    failures.push(ParsingFailure {
                        source: row.test_name,
                        error: format!("failed to get parameters: {err:#}"),
                    });
                    continue;
                }
            };

        points.push(Point {
            value: Number::from(row.value),
            test: row.test_name,
            name: display_name,
            // Matching the Python parser.
            class: PointClass::KeyGen,
            point_type,
            operator,
            params,
            backend,
        });
    }

    Ok(ParseOutcome { points, failures })
}
