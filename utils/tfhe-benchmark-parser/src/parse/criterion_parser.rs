use super::ParseOutcome;
use super::parameters::get_parameters;
use anyhow::{Context, Result};
use benchmark_spec::{Backend, BenchmarkMetric};
use serde::de::DeserializeOwned;
use serde_json::Number;
use std::fs;
use std::path::Path;
use tfhe_benchmark_parser::model::{
    CriterionBenchmark, CriterionEstimates, ParsingFailure, Point, PointClass,
};

const ONE_SECOND_IN_NANOSECONDS: f64 = 1e9;
/// Subdirectories ignored during a criterion results walk.
const EXCLUDED_DIRECTORIES: [&str; 4] = ["child_generate", "fork", "parent_generate", "report"];

pub fn recursive_parse(
    directory: &Path,
    bench_type: BenchmarkMetric,
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

        if !dir.is_dir()
            || EXCLUDED_DIRECTORIES
                .iter()
                .any(|excluded| *excluded == dir_name)
        {
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

            if sub.file_name() != "new" {
                if !walk_subdirs {
                    continue;
                }
                subdir = subdir.join("new");
                if !subdir.exists() {
                    continue;
                }
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
    bench_type: BenchmarkMetric,
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

    // For throughput benchmarks we need the `Elements` count from criterion to convert
    // ns/op -> ops/s. For latency benchmarks it is irrelevant.
    let throughput_elements = benchmark.throughput.as_ref().and_then(|t| t.elements);
    let throughput_elements = match (bench_type, throughput_elements) {
        (BenchmarkMetric::Throughput, None) => return, // latency-only subdir, skip
        (BenchmarkMetric::Throughput, Some(n)) => Some(n),
        _ => None,
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
        // Throughput benchmark: convert ns/op to ops/s.
        Some(n) => (n as f64 * ONE_SECOND_IN_NANOSECONDS) / estimates.mean.point_estimate,
        // Latency benchmark.
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
            point_type: bench_type,
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
