use crate::shortint::parameters::MetaParameters;
use serde::Serialize;
use std::fs;
use std::path::PathBuf;

#[derive(Serialize)]
#[serde(untagged)]
pub enum TestResult {
    DpKsMsNoiseCheckResult(Box<DpKsMsNoiseCheckResult>),
    DpKsPackingNoiseCheckResult(Box<DpKsPackingNoiseCheckResult>),
    PfailTestResultJson(Box<PfailTestResultJson>),
    Empty {},
}

/// String is used to make it easier to parse from other languages like js
#[derive(Serialize)]
pub struct Measurement {
    pub measured: String,
    pub expected: String,
}

#[derive(Serialize)]
pub struct Log2Measurement {
    pub measured: ValueWithLog2,
    pub expected: ValueWithLog2,
}

/// String is used to make it easier to parse from other languages like js
#[derive(Serialize)]
pub struct BoundedMeasurement {
    pub value: Measurement,
    pub upper_bound: String,
    pub lower_bound: String,
}

impl BoundedMeasurement {
    pub fn new(
        measured: String,
        expected: String,
        upper_bound: String,
        lower_bound: String,
    ) -> Self {
        Self {
            value: Measurement { measured, expected },
            upper_bound,
            lower_bound,
        }
    }

    pub fn new_no_bounds(measured: String, expected: String) -> Self {
        Self {
            value: Measurement { measured, expected },
            upper_bound: "Not specified".to_string(),
            lower_bound: "Not specified".to_string(),
        }
    }

    pub fn set_bounds(&mut self, upper_bound: String, lower_bound: String) {
        self.upper_bound = upper_bound;
        self.lower_bound = lower_bound;
    }
}

#[derive(Serialize)]
pub struct BoundedLog2Measurement {
    pub value: Log2Measurement,
    pub upper_bound: ValueWithLog2,
    pub lower_bound: ValueWithLog2,
}

impl BoundedLog2Measurement {
    pub fn new_no_bounds(measured: ValueWithLog2, expected: ValueWithLog2) -> Self {
        Self {
            value: Log2Measurement { measured, expected },
            upper_bound: ValueWithLog2 {
                raw: "Not specified".to_string(),
                log2: None,
            },
            lower_bound: ValueWithLog2 {
                raw: "Not specified".to_string(),
                log2: None,
            },
        }
    }

    pub fn set_bounds(&mut self, upper_bound: ValueWithLog2, lower_bound: ValueWithLog2) {
        self.upper_bound = upper_bound;
        self.lower_bound = lower_bound;
    }
}

/// String is used to make it easier to parse from other languages like js
#[derive(Serialize)]
pub struct ValueWithLog2 {
    pub raw: String,
    pub log2: Option<String>,
}

impl ValueWithLog2 {
    pub fn new(raw: String, log2: Option<String>) -> Self {
        Self { raw, log2 }
    }
}

#[derive(Serialize)]
pub struct DpKsMsNoiseCheckResult {
    pub after_ms_variance: BoundedMeasurement,
    pub after_ms_mean: BoundedMeasurement,
    pub before_ms_normality_check: bool,
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
    pub after_ms_variance: BoundedMeasurement,
    pub after_ms_mean: BoundedMeasurement,
}

impl DpKsPackingNoiseCheckResult {
    pub fn new(variance: BoundedMeasurement, mean: BoundedMeasurement) -> Self {
        Self {
            after_ms_variance: variance,
            after_ms_mean: mean,
        }
    }
}

#[derive(Serialize)]
pub struct PfailMetadata {
    pub pfail_with_original_precision: ValueWithLog2,
    pub pfail_with_test_precision: ValueWithLog2,
    pub expected_fails_with_test_precision: String,
    pub total_runs: String,
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
    pub pfail_parameters: PfailMetadata,
    pub fails: Measurement,
    pub pfail_with_test_precision: BoundedMeasurement,
    pub equivalent_pfail_with_original_precision: BoundedLog2Measurement,
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
    pub test: &'a str,
    pub name: &'a str,
    pub pass: bool,
    pub warning: Option<String>,
    pub parameters: &'a MetaParameters,
    pub results: TestResult,
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
    let output_data = TestJsonOutput {
        test: &test_id,
        name: short_name,
        pass,
        warning,
        parameters: meta_param,
        results,
    };
    let serialized_output = serde_json::to_string_pretty(&output_data)?;
    let mut path = PathBuf::new();
    path.push("tests_results");
    fs::create_dir_all(&path)?;
    path.push(format!("{test_id}.json"));
    fs::write(&path, serialized_output)?;
    Ok(())
}
