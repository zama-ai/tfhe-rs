use crate::shortint::parameters::MetaParameters;
use serde::Serialize;
use std::fs;
use std::path::PathBuf;

#[derive(Serialize)]
#[serde(untagged)] // untagged removed useless precision of the enum in the json file
pub enum TestResult {
    DpKsMsNoiseCheckResult(Box<DpKsMsNoiseCheckResult>),
    DpKsPackingNoiseCheckResult(Box<DpKsPackingNoiseCheckResult>),
    PfailTestResultJson(Box<PfailTestResultJson>),
    Empty {},
}

/// String is used to make it easier to parse from other languages like js
#[derive(Serialize, Clone)]
pub struct Measurement {
    measured: String,
    expected: String,
}

impl Measurement {
    pub fn new(measured: String, expected: String) -> Self {
        Self { measured, expected }
    }
}

#[derive(Serialize, Clone)]
pub struct Log2Measurement {
    measured: ValueWithLog2,
    expected: ValueWithLog2,
}

impl Log2Measurement {
    pub fn new(measured: ValueWithLog2, expected: ValueWithLog2) -> Self {
        Self { measured, expected }
    }
}

#[derive(Serialize, Clone)]
#[serde(untagged)] // untagged removed useless precision of the enum in the json file
pub enum ConfidenceInterval {
    Bounded(StringConfidenceInterval),
    NoBounds(NoBounds),
}

#[derive(Serialize, Clone)]
pub struct StringConfidenceInterval {
    lower: String,
    upper: String,
}

pub struct StringConfidenceIntervalBuilder {
    lower: Option<String>,
    upper: Option<String>,
}

impl StringConfidenceInterval {
    pub fn builder() -> StringConfidenceIntervalBuilder {
        StringConfidenceIntervalBuilder {
            lower: None,
            upper: None,
        }
    }
}

impl StringConfidenceIntervalBuilder {
    pub fn lower(mut self, lower: String) -> Self {
        self.lower = Some(lower);
        self
    }

    pub fn upper(mut self, upper: String) -> Self {
        self.upper = Some(upper);
        self
    }

    pub fn build(self) -> Result<StringConfidenceInterval, &'static str> {
        match (self.lower, self.upper) {
            (Some(lower), Some(upper)) => Ok(StringConfidenceInterval { lower, upper }),
            _ => Err("Both lower and upper bounds must be set"),
        }
    }
}

#[derive(Serialize, Clone)]
pub struct NoBounds {
    reason: String,
}

impl NoBounds {
    pub fn new(reason: &str) -> Self {
        Self {
            reason: reason.to_string(),
        }
    }
}

/// String is used to make it easier to parse from other languages like js
#[derive(Serialize, Clone)]
pub struct BoundedMeasurement {
    value: Measurement,
    confidence_interval: ConfidenceInterval,
}

impl BoundedMeasurement {
    pub fn new(
        measured: String,
        expected: String,
        confidence_interval: ConfidenceInterval,
    ) -> Self {
        Self {
            value: Measurement::new(measured, expected),
            confidence_interval,
        }
    }
}

#[derive(Serialize, Clone)]
#[serde(untagged)] // untagged removed useless precision of the enum in the json file
pub enum ConfidenceIntervalWithLog2 {
    Bounded(StringConfidenceIntervalWithLog2),
    NoBounds(NoBounds),
}

#[derive(Serialize, Clone)]
pub struct StringConfidenceIntervalWithLog2 {
    lower: ValueWithLog2,
    upper: ValueWithLog2,
}

#[derive(Serialize)]
pub struct StringConfidenceIntervalWithLog2Builder {
    lower: Option<ValueWithLog2>,
    upper: Option<ValueWithLog2>,
}

impl StringConfidenceIntervalWithLog2 {
    pub fn builder() -> StringConfidenceIntervalWithLog2Builder {
        StringConfidenceIntervalWithLog2Builder {
            lower: None,
            upper: None,
        }
    }
}

impl StringConfidenceIntervalWithLog2Builder {
    pub fn lower(mut self, lower: ValueWithLog2) -> Self {
        self.lower = Some(lower);
        self
    }

    pub fn upper(mut self, upper: ValueWithLog2) -> Self {
        self.upper = Some(upper);
        self
    }

    pub fn build(self) -> Result<StringConfidenceIntervalWithLog2, &'static str> {
        match (self.lower, self.upper) {
            (Some(lower), Some(upper)) => Ok(StringConfidenceIntervalWithLog2 { lower, upper }),
            _ => Err("Both lower and upper bounds must be set"),
        }
    }
}

#[derive(Serialize, Clone)]
pub struct BoundedLog2Measurement {
    value: Log2Measurement,
    confidence_interval: ConfidenceIntervalWithLog2,
}

impl BoundedLog2Measurement {
    pub fn new(
        measured: ValueWithLog2,
        expected: ValueWithLog2,
        confidence_interval: ConfidenceIntervalWithLog2,
    ) -> Self {
        Self {
            value: Log2Measurement::new(measured, expected),
            confidence_interval,
        }
    }
}

/// String is used to make it easier to parse from other languages like js
#[derive(Serialize, Clone)]
pub struct ValueWithLog2 {
    raw: String,
    log2: String,
}

impl ValueWithLog2 {
    pub fn new(raw: String, log2: String) -> Self {
        Self { raw, log2 }
    }
}

#[derive(Serialize)]
pub struct DpKsMsNoiseCheckResult {
    after_ms_variance: BoundedMeasurement,
    after_ms_mean: BoundedMeasurement,
    before_ms_normality_check: bool,
}

impl DpKsMsNoiseCheckResult {
    pub fn new(
        variance: BoundedMeasurement,
        mean: BoundedMeasurement,
        normality_check: bool,
    ) -> Self {
        Self {
            after_ms_variance: variance,
            after_ms_mean: mean,
            before_ms_normality_check: normality_check,
        }
    }
}

#[derive(Serialize)]
pub struct DpKsPackingNoiseCheckResult {
    after_ms_variance: BoundedMeasurement,
    after_ms_mean: BoundedMeasurement,
}

impl DpKsPackingNoiseCheckResult {
    pub fn new(variance: BoundedMeasurement, mean: BoundedMeasurement) -> Self {
        Self {
            after_ms_variance: variance,
            after_ms_mean: mean,
        }
    }
}

#[derive(Serialize, Clone)]
pub struct PfailMetadata {
    pfail_with_original_precision: ValueWithLog2,
    pfail_with_test_precision: ValueWithLog2,
    expected_fails_with_test_precision: String,
    total_runs: String,
}

impl PfailMetadata {
    pub fn new(
        pfail_with_original_precision: ValueWithLog2,
        pfail_with_test_precision: ValueWithLog2,
        expected_fails_with_test_precision: String,
        total_runs: String,
    ) -> Self {
        Self {
            pfail_with_original_precision,
            pfail_with_test_precision,
            expected_fails_with_test_precision,
            total_runs,
        }
    }
}

#[derive(Serialize)]
pub struct PfailTestResultJson {
    pfail_parameters: PfailMetadata,
    fails: Measurement,
    pfail_with_test_precision: BoundedMeasurement,
    equivalent_pfail_with_original_precision: BoundedLog2Measurement,
}

impl PfailTestResultJson {
    pub fn new(
        pfail_parameters: PfailMetadata,
        fails: Measurement,
        pfail_with_test_precision: BoundedMeasurement,
        equivalent_pfail_with_original_precision: BoundedLog2Measurement,
    ) -> Self {
        Self {
            pfail_parameters,
            fails,
            pfail_with_test_precision,
            equivalent_pfail_with_original_precision,
        }
    }

    pub fn into_test_result(self) -> TestResult {
        TestResult::PfailTestResultJson(Box::new(self))
    }
}

#[derive(Serialize)]
struct TestJsonOutput<'a> {
    test: &'a str,
    name: &'a str,
    pass: bool,
    warning: Option<String>,
    parameters: &'a MetaParameters,
    results: TestResult,
}

impl<'a> TestJsonOutput<'a> {
    pub fn new(
        test: &'a str,
        name: &'a str,
        pass: bool,
        warning: Option<String>,
        parameters: &'a MetaParameters,
        results: TestResult,
    ) -> Self {
        Self {
            test,
            name,
            pass,
            warning,
            parameters,
            results,
        }
    }
}

/// Returns the name of the function from which it is called.
#[macro_export]
macro_rules! this_function_name {
    () => {{
        struct Local;
        let name = std::any::type_name::<Local>();
        let first = name.split("::").nth(1).unwrap_or(name);
        let before_last = name.rsplit("::").nth(1).unwrap_or(name);
        format!("{}::{}", first, before_last)
    }};
}

pub fn write_empty_json_file(
    meta_param: &MetaParameters,
    test_name: &str,
    test_module_path: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    write_to_json_file(
        meta_param,
        test_name,
        test_module_path,
        false,
        None,
        TestResult::Empty {},
    )
}

pub fn write_to_json_file(
    meta_param: &MetaParameters,
    test_name: &str,
    test_module_path: &str,
    pass: bool,
    warning: Option<String>,
    results: TestResult,
) -> Result<(), Box<dyn std::error::Error>> {
    let test_id = format!("{test_module_path}::{test_name}").to_lowercase();
    let short_name = test_module_path
        .rsplit_once("::")
        .map_or(test_module_path, |(_, p)| p);
    let output_data = TestJsonOutput::new(&test_id, short_name, pass, warning, meta_param, results);
    let serialized_output = serde_json::to_string_pretty(&output_data)?;
    let mut path = PathBuf::new();
    path.push("tests_results");
    fs::create_dir_all(&path)?;
    path.push(format!("{test_id}.json"));
    fs::write(&path, serialized_output)?;
    Ok(())
}
