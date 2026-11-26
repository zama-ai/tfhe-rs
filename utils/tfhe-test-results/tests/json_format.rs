//! Locks the JSON format written by the noise and pfail tests.
//!
//! Each case builds a value with the contract types and checks that it serializes
//! exactly to the expected JSON (catches a silent format change), and that the
//! expected JSON reads back to the same value (catches a wrong `untagged` match).

use serde_json::{Value, json};
use tfhe_test_results::{
    Backend, BoundedLog2Measurement, BoundedMeasurement, ConfidenceInterval,
    ConfidenceIntervalWithLog2, Measurement, NoBounds, NoiseCheckWithNormalityCheck,
    NoiseCheckWithoutNormalityCheck, PfailMetadata, PfailTestResultJson, StringConfidenceInterval,
    StringConfidenceIntervalWithLog2, TestJsonOutput, TestKind, TestResult, ValueWithLog2,
};

const TEST: &str = "shortint::some_check::test_meta_param";
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
        test: TEST.to_string(),
        name: NAME.to_string(),
        kind,
        layer: LAYER.to_string(),
        backend: Backend::Cpu,
        param_name: PARAM_NAME.to_string(),
        pass,
        warning: warning.map(str::to_string),
        parameters: json!({ "message_modulus": 4 }),
        results,
    }
}

fn expected(kind: &str, pass: bool, warning: Option<&str>, results: Value) -> Value {
    json!({
        "test": TEST,
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

    let read: TestJsonOutput<Value> = serde_json::from_value(expected.clone()).unwrap();
    let rewritten = serde_json::to_value(&read).unwrap();
    assert_eq!(
        &rewritten, expected,
        "JSON does not read back to the same value"
    );
}

fn bounded(measured: &str, expected: &str, lower: &str, upper: &str) -> BoundedMeasurement {
    let interval = StringConfidenceInterval::builder()
        .lower(lower.to_string())
        .upper(upper.to_string())
        .build()
        .unwrap();
    BoundedMeasurement::new(
        measured.to_string(),
        expected.to_string(),
        ConfidenceInterval::Bounded(interval),
    )
}

fn with_log2(raw: &str, log2: &str) -> ValueWithLog2 {
    ValueWithLog2::new(raw.to_string(), log2.to_string())
}

fn noise_results() -> (BoundedMeasurement, BoundedMeasurement, Value) {
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
fn sanity() {
    let output = output(TestKind::Sanity, true, None, TestResult::Empty {});
    let expected = expected("sanity", true, None, json!({}));
    assert_format(&output, &expected);
}

#[test]
fn crash_before_measurements() {
    let output = output(TestKind::Pfail, false, None, TestResult::Empty {});
    let expected = expected("pfail", false, None, json!({}));
    assert_format(&output, &expected);
}

#[test]
fn noise_with_normality_check() {
    let (variance, mean, mut results_json) = noise_results();
    results_json["before_ms_normality_check"] = json!(true);
    let results = TestResult::NoiseCheckWithNormalityCheck(Box::new(
        NoiseCheckWithNormalityCheck::new(variance, mean, true),
    ));

    let output = output(TestKind::Noise, true, None, results);
    let expected = expected("noise", true, None, results_json);
    assert_format(&output, &expected);
}

#[test]
fn noise_without_normality_check() {
    let (variance, mean, results_json) = noise_results();
    let results = TestResult::NoiseCheckWithoutNormalityCheck(Box::new(
        NoiseCheckWithoutNormalityCheck::new(variance, mean),
    ));

    let output = output(TestKind::Noise, false, None, results);
    let expected = expected("noise", false, None, results_json);
    assert_format(&output, &expected);
}

#[test]
fn pfail_with_bounds() {
    let (metadata, metadata_json) = pfail_metadata();
    let equivalent_interval = StringConfidenceIntervalWithLog2::builder()
        .lower(with_log2("9.8e-40", "-129.6"))
        .upper(with_log2("4.7e-39", "-127.3"))
        .build()
        .unwrap();
    let results = PfailTestResultJson::new(
        metadata,
        Measurement::new("12".to_string(), "15".to_string()),
        bounded("1.2e-5", "1.5e-5", "5.1e-6", "2.4e-5"),
        BoundedLog2Measurement::new(
            with_log2("2.3e-39", "-128.3"),
            with_log2("2.9e-39", "-128"),
            ConfidenceIntervalWithLog2::Bounded(equivalent_interval),
        ),
    )
    .into_test_result();
    let warning = Some("measured pfail is smaller than expected pfail");

    let output = output(TestKind::Pfail, true, warning, results);
    let expected = expected(
        "pfail",
        true,
        warning,
        json!({
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
fn pfail_with_zero_fails() {
    let (metadata, metadata_json) = pfail_metadata();
    let results = PfailTestResultJson::new(
        metadata,
        Measurement::new("0".to_string(), "15".to_string()),
        BoundedMeasurement::new(
            "0".to_string(),
            "1.5e-5".to_string(),
            ConfidenceInterval::NoBounds(NoBounds::new(NO_BOUNDS_REASON)),
        ),
        BoundedLog2Measurement::new(
            with_log2("0", "-inf"),
            with_log2("2.9e-39", "-128"),
            ConfidenceIntervalWithLog2::NoBounds(NoBounds::new(NO_BOUNDS_REASON)),
        ),
    )
    .into_test_result();

    let output = output(TestKind::Pfail, true, None, results);
    let expected = expected(
        "pfail",
        true,
        None,
        json!({
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
