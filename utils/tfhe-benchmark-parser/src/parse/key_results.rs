use super::ParseOutcome;
use super::parameters::get_parameters;
use anyhow::{Context, Result};
use serde::Deserialize;
use serde_json::Number;
use std::path::Path;
use tfhe_benchmark_parser::model::{Backend, ParsingFailure, Point, PointClass, PointType};

#[derive(Deserialize)]
struct KeyResultRow {
    test_name: String,
    value: i64,
}

pub fn parse_object_sizes(result_file: &Path, backend: Backend) -> Result<ParseOutcome> {
    // Note: matching the Python parser, both CSV modes use `class = "keygen"`. Only `type` differs.
    parse_key_results(result_file, PointClass::Keygen, PointType::Keysize, backend)
}

pub fn parse_key_gen_time(result_file: &Path, backend: Backend) -> Result<ParseOutcome> {
    parse_key_results(result_file, PointClass::Keygen, PointType::Latency, backend)
}

fn parse_key_results(
    result_file: &Path,
    class: PointClass,
    point_type: PointType,
    backend: Backend,
) -> Result<ParseOutcome> {
    let mut points = Vec::new();
    let mut failures = Vec::new();

    let mut reader = csv::ReaderBuilder::new()
        .has_headers(false)
        .from_path(result_file)
        .with_context(|| format!("opening {}", result_file.display()))?;

    for row in reader.deserialize::<KeyResultRow>() {
        let row = match row {
            Ok(r) => r,
            Err(err) => {
                failures.push(ParsingFailure {
                    source: result_file.display().to_string(),
                    error: format!("malformed CSV row: {err}"),
                });
                continue;
            }
        };

        let (params, display_name, operator) = match get_parameters(&row.test_name) {
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
            class,
            point_type,
            operator,
            params,
            backend,
        });
    }

    Ok(ParseOutcome { points, failures })
}
