//! Locks the JSON format written by the noise and pfail tests: slab parses these
//! files, so any change here must be mirrored on its side.

use super::*;
use serde_json::{json, Value};

const NAME: &str = "some_check";
const LAYER: &str = "shortint";
const PARAM_NAME: &str = "TEST_META_PARAM";
const NO_BOUNDS_REASON: &str = "Unable to compute bounds, 0 fails measured";

fn output(
    kind: TestKind,
    pass: bool,
    warning: Option<&str>,
    results: TestResult,
) -> TestJsonOutput<Value> {
    TestJsonOutput {
        name: NAME.to_string(),
        kind,
        layer: LAYER.to_string(),
        backend: Backend::Cpu,
        param_name: PARAM_NAME.to_string(),
        pass,
        warning: warning.map(str::to_string),
        run: None,
        parameters: json!({ "message_modulus": 4 }),
        results,
    }
}

fn expected(kind: &str, pass: bool, warning: Option<&str>, results: &Value) -> Value {
    json!({
        "name": NAME,
        "kind": kind,
        "layer": LAYER,
        "backend": "cpu",
        "param_name": PARAM_NAME,
        "pass": pass,
        "warning": warning,
        "parameters": { "message_modulus": 4 },
        "results": results,
    })
}

fn assert_format(output: &TestJsonOutput<Value>, expected: &Value) {
    let written = serde_json::to_value(output).unwrap();
    assert_eq!(&written, expected, "written JSON changed");
}

fn bounded(measured: &str, expected: &str, lower: &str, upper: &str) -> BoundedMeasurement<String> {
    let interval = Interval::new(lower.to_string(), upper.to_string());
    BoundedMeasurement::new(
        measured.to_string(),
        expected.to_string(),
        ConfidenceInterval::Bounded(interval),
    )
}

fn with_log2(raw: &str, log2: &str) -> ValueWithLog2 {
    ValueWithLog2::new(raw.to_string(), log2.to_string())
}

fn noise_results() -> (
    BoundedMeasurement<String>,
    BoundedMeasurement<String>,
    Value,
) {
    let variance = bounded("2.1e-12", "2.0e-12", "1.9e-12", "2.3e-12");
    let mean = bounded("1.0e-8", "0", "-2.0e-8", "4.0e-8");
    let json = json!({
        "after_ms_variance": {
            "value": { "measured": "2.1e-12", "expected": "2.0e-12" },
            "confidence_interval": { "lower": "1.9e-12", "upper": "2.3e-12" },
        },
        "after_ms_mean": {
            "value": { "measured": "1.0e-8", "expected": "0" },
            "confidence_interval": { "lower": "-2.0e-8", "upper": "4.0e-8" },
        },
    });
    (variance, mean, json)
}

fn pfail_metadata() -> (PfailMetadata, Value) {
    let metadata = PfailMetadata::new(
        with_log2("2.9e-39", "-128"),
        with_log2("1.5e-5", "-16"),
        "15".to_string(),
        "1000000".to_string(),
    );
    let json = json!({
        "pfail_with_original_precision": { "raw": "2.9e-39", "log2": "-128" },
        "pfail_with_test_precision": { "raw": "1.5e-5", "log2": "-16" },
        "expected_fails_with_test_precision": "15",
        "total_runs": "1000000",
    });
    (metadata, json)
}

#[test]
fn test_sanity_ci_run_filter() {
    let output = output(TestKind::Sanity, true, None, TestResult::Empty {});
    let expected = expected("sanity", true, None, &json!({}));
    assert_format(&output, &expected);
}

#[test]
fn test_crash_before_measurements_ci_run_filter() {
    let output = output(TestKind::Pfail, false, None, TestResult::Empty {});
    let expected = expected("pfail", false, None, &json!({}));
    assert_format(&output, &expected);
}

#[test]
fn test_noise_with_normality_check_ci_run_filter() {
    let (variance, mean, mut results_json) = noise_results();
    results_json["before_ms_normality_check"] = json!(true);
    let results = NoiseCheckResult::new(variance, mean, Some(true)).into();

    let output = output(TestKind::Noise, true, None, results);
    let expected = expected("noise", true, None, &results_json);
    assert_format(&output, &expected);
}

#[test]
fn test_noise_without_normality_check_ci_run_filter() {
    let (variance, mean, results_json) = noise_results();
    let results = NoiseCheckResult::new(variance, mean, None).into();

    let output = output(TestKind::Noise, false, None, results);
    let expected = expected("noise", false, None, &results_json);
    assert_format(&output, &expected);
}

#[test]
fn test_pfail_with_bounds_ci_run_filter() {
    let (metadata, metadata_json) = pfail_metadata();
    let equivalent_interval = Interval::new(
        with_log2("9.8e-40", "-129.6"),
        with_log2("4.7e-39", "-127.3"),
    );
    let results = PfailTestResultJson::new(
        metadata,
        Measurement::new("12".to_string(), "15".to_string()),
        bounded("1.2e-5", "1.5e-5", "5.1e-6", "2.4e-5"),
        BoundedMeasurement::new(
            with_log2("2.3e-39", "-128.3"),
            with_log2("2.9e-39", "-128"),
            ConfidenceInterval::Bounded(equivalent_interval),
        ),
    )
    .into();
    let warning = Some("measured pfail is smaller than expected pfail");

    let output = output(TestKind::Pfail, true, warning, results);
    let expected = expected(
        "pfail",
        true,
        warning,
        &json!({
            "pfail_parameters": metadata_json,
            "fails": { "measured": "12", "expected": "15" },
            "pfail_with_test_precision": {
                "value": { "measured": "1.2e-5", "expected": "1.5e-5" },
                "confidence_interval": { "lower": "5.1e-6", "upper": "2.4e-5" },
            },
            "equivalent_pfail_with_original_precision": {
                "value": {
                    "measured": { "raw": "2.3e-39", "log2": "-128.3" },
                    "expected": { "raw": "2.9e-39", "log2": "-128" },
                },
                "confidence_interval": {
                    "lower": { "raw": "9.8e-40", "log2": "-129.6" },
                    "upper": { "raw": "4.7e-39", "log2": "-127.3" },
                },
            },
        }),
    );
    assert_format(&output, &expected);
}

#[test]
fn test_pfail_with_zero_fails_ci_run_filter() {
    let (metadata, metadata_json) = pfail_metadata();
    let results = PfailTestResultJson::new(
        metadata,
        Measurement::new("0".to_string(), "15".to_string()),
        BoundedMeasurement::new(
            "0".to_string(),
            "1.5e-5".to_string(),
            ConfidenceInterval::NoBounds(NoBounds::new(NO_BOUNDS_REASON)),
        ),
        BoundedMeasurement::new(
            with_log2("0", "-inf"),
            with_log2("2.9e-39", "-128"),
            ConfidenceInterval::NoBounds(NoBounds::new(NO_BOUNDS_REASON)),
        ),
    )
    .into();

    let output = output(TestKind::Pfail, true, None, results);
    let expected = expected(
        "pfail",
        true,
        None,
        &json!({
            "pfail_parameters": metadata_json,
            "fails": { "measured": "0", "expected": "15" },
            "pfail_with_test_precision": {
                "value": { "measured": "0", "expected": "1.5e-5" },
                "confidence_interval": { "reason": NO_BOUNDS_REASON },
            },
            "equivalent_pfail_with_original_precision": {
                "value": {
                    "measured": { "raw": "0", "log2": "-inf" },
                    "expected": { "raw": "2.9e-39", "log2": "-128" },
                },
                "confidence_interval": { "reason": NO_BOUNDS_REASON },
            },
        }),
    );
    assert_format(&output, &expected);
}

#[test]
fn test_with_run_context_ci_run_filter() {
    let mut output = output(TestKind::Sanity, true, None, TestResult::Empty {});
    output.run = Some(RunContext {
        commit_sha: "0123abcd".to_string(),
        commit_date: "2026-11-27T10:00:00+01:00".to_string(),
        branch: "main".to_string(),
        gh_run_id: "9001".to_string(),
        gh_run_attempt: "1".to_string(),
        machine: "hpc7a.96xlarge".to_string(),
    });

    let mut expected = expected("sanity", true, None, &json!({}));
    expected["run"] = json!({
        "commit_sha": "0123abcd",
        "commit_date": "2026-11-27T10:00:00+01:00",
        "branch": "main",
        "gh_run_id": "9001",
        "gh_run_attempt": "1",
        "machine": "hpc7a.96xlarge",
    });
    assert_format(&output, &expected);
}
