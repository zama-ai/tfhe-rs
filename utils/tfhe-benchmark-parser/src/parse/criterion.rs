use super::ParseOutcome;
use super::parameters::get_parameters;
use crate::cli::BenchType;
use anyhow::{Context, Result};
use serde::de::DeserializeOwned;
use serde_json::Number;
use std::fs;
use std::path::Path;
use tfhe_benchmark_parser::model::{
    Backend, CriterionBenchmark, CriterionEstimates, ParsingFailure, Point, PointClass,
};

const ONE_SECOND_IN_NANOSECONDS: f64 = 1e9;
/// Subdirectories ignored during a criterion results walk.
const EXCLUDED_DIRECTORIES: &[&str] = &["child_generate", "fork", "parent_generate", "report"];

pub fn recursive_parse(
    directory: &Path,
    bench_type: BenchType,
    walk_subdirs: bool,
    name_suffix: &str,
    backend: Backend,
) -> Result<ParseOutcome> {
    let mut points = Vec::new();
    let mut failures = Vec::new();

    let entries =
        fs::read_dir(directory).with_context(|| format!("reading {}", directory.display()))?;

    for entry in entries {
        let entry = entry?;
        let dir = entry.path();
        let dir_name = entry.file_name();
        let dir_name = dir_name.to_string_lossy();

        if EXCLUDED_DIRECTORIES.contains(&dir_name.as_ref()) {
            continue;
        }
        if !dir.is_dir() {
            continue;
        }

        let inner = match fs::read_dir(&dir) {
            Ok(it) => it,
            Err(err) => {
                eprintln!("warning: skipping {}: {err}", dir.display());
                continue;
            }
        };

        for sub in inner {
            let sub = sub?;
            let mut subdir = sub.path();
            let sub_name = sub.file_name();
            let sub_name = sub_name.to_string_lossy();

            if walk_subdirs {
                if sub_name != "new" {
                    subdir = subdir.join("new");
                    if !subdir.exists() {
                        continue;
                    }
                }
            } else if sub_name != "new" {
                continue;
            }

            process_leaf(
                &subdir,
                bench_type,
                name_suffix,
                backend,
                &mut points,
                &mut failures,
            );
        }
    }

    Ok(ParseOutcome { points, failures })
}

fn process_leaf(
    subdir: &Path,
    bench_type: BenchType,
    name_suffix: &str,
    backend: Backend,
    points: &mut Vec<Point>,
    failures: &mut Vec<ParsingFailure>,
) {
    let benchmark = match parse_benchmark_file(subdir) {
        Ok(b) => b,
        Err(err) => {
            failures.push(ParsingFailure {
                source: subdir.display().to_string(),
                error: format!("failed to read benchmark.json: {err:#}"),
            });
            return;
        }
    };

    // For throughput benches we need the `Elements` count from criterion to convert
    // ns/op -> ops/s. For latency benches it is irrelevant.
    let throughput_elements = benchmark.throughput.as_ref().and_then(|t| t.elements);
    let throughput_elements = match (bench_type, throughput_elements) {
        (BenchType::Throughput, None) => return, // latency-only subdir, skip
        (BenchType::Throughput, Some(n)) => Some(n),
        (BenchType::Latency, _) => None,
    };

    let test_name = match benchmark.function_id {
        Some(name) => name,
        None => {
            failures.push(ParsingFailure {
                source: benchmark.full_id,
                error: "'function_id' field is null in report".to_string(),
            });
            return;
        }
    };

    let (params, display_name, operator) = match get_parameters(&test_name) {
        Ok(triple) => triple,
        Err(err) => {
            failures.push(ParsingFailure {
                source: benchmark.full_id,
                error: format!("failed to get parameters: {err:#}"),
            });
            return;
        }
    };

    let estimates = match parse_estimate_file(subdir) {
        Ok(e) => e,
        Err(err) => {
            failures.push(ParsingFailure {
                source: benchmark.full_id,
                error: format!("failed to read estimates.json: {err:#}"),
            });
            return;
        }
    };

    let mean_value = match throughput_elements {
        Some(n) => (n as f64 * ONE_SECOND_IN_NANOSECONDS) / estimates.mean.point_estimate,
        None => estimates.mean.point_estimate,
    };

    for (raw_value, stat) in [
        (mean_value, "mean"),
        (estimates.std_dev.point_estimate, "std_dev"),
    ] {
        let Some(number) = Number::from_f64(raw_value) else {
            failures.push(ParsingFailure {
                source: test_name.clone(),
                error: format!("non-finite {stat} value"),
            });
            continue;
        };
        points.push(Point {
            value: number,
            test: join_test_name_parts(&[&test_name, stat, name_suffix]),
            name: display_name.clone(),
            class: PointClass::Evaluate,
            point_type: bench_type.into(),
            operator: operator.clone(),
            params: params.clone(),
            backend,
        });
    }
}

fn parse_benchmark_file(directory: &Path) -> Result<CriterionBenchmark> {
    read_json(directory, "benchmark.json")
}

fn parse_estimate_file(directory: &Path) -> Result<CriterionEstimates> {
    read_json(directory, "estimates.json")
}

fn read_json<T: DeserializeOwned>(directory: &Path, filename: &str) -> Result<T> {
    let path = directory.join(filename);
    let content =
        fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;
    let parsed =
        serde_json::from_str(&content).with_context(|| format!("parsing {}", path.display()))?;
    Ok(parsed)
}

fn join_test_name_parts(parts: &[&str]) -> String {
    parts
        .iter()
        .filter(|s| !s.is_empty())
        .copied()
        .collect::<Vec<_>>()
        .join("_")
}
