use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
#[serde(untagged)] // https://serde.rs/enum-representations.html#untagged
pub enum TestResult {
    NoiseCheckWithNormalityCheck(Box<NoiseCheckWithNormalityCheck>),
    NoiseCheckWithoutNormalityCheck(Box<NoiseCheckWithoutNormalityCheck>),
    PfailTestResultJson(Box<PfailTestResultJson>),
    Empty {},
}

/// String is used to make it easier to parse from other languages like js
#[derive(Serialize, Deserialize, Clone)]
pub struct Measurement {
    pub measured: String,
    pub expected: String,
}

impl Measurement {
    pub fn new(measured: String, expected: String) -> Self {
        Self { measured, expected }
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Log2Measurement {
    pub measured: ValueWithLog2,
    pub expected: ValueWithLog2,
}

impl Log2Measurement {
    pub fn new(measured: ValueWithLog2, expected: ValueWithLog2) -> Self {
        Self { measured, expected }
    }
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(untagged)] // https://serde.rs/enum-representations.html#untagged
pub enum ConfidenceInterval {
    Bounded(StringConfidenceInterval),
    NoBounds(NoBounds),
}

#[derive(Serialize, Deserialize, Clone)]
pub struct StringConfidenceInterval {
    pub lower: String,
    pub upper: String,
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

#[derive(Serialize, Deserialize, Clone)]
pub struct NoBounds {
    pub reason: String,
}

impl NoBounds {
    pub fn new(reason: &str) -> Self {
        Self {
            reason: reason.to_string(),
        }
    }
}

/// String is used to make it easier to parse from other languages like js
#[derive(Serialize, Deserialize, Clone)]
pub struct BoundedMeasurement {
    pub value: Measurement,
    pub confidence_interval: ConfidenceInterval,
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

#[derive(Serialize, Deserialize, Clone)]
#[serde(untagged)] // untagged removed useless precision of the enum in the json file
pub enum ConfidenceIntervalWithLog2 {
    Bounded(StringConfidenceIntervalWithLog2),
    NoBounds(NoBounds),
}

#[derive(Serialize, Deserialize, Clone)]
pub struct StringConfidenceIntervalWithLog2 {
    pub lower: ValueWithLog2,
    pub upper: ValueWithLog2,
}

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

#[derive(Serialize, Deserialize, Clone)]
pub struct BoundedLog2Measurement {
    pub value: Log2Measurement,
    pub confidence_interval: ConfidenceIntervalWithLog2,
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
#[derive(Serialize, Deserialize, Clone)]
pub struct ValueWithLog2 {
    pub raw: String,
    pub log2: String,
}

impl ValueWithLog2 {
    pub fn new(raw: String, log2: String) -> Self {
        Self { raw, log2 }
    }
}

#[derive(Serialize, Deserialize)]
pub struct NoiseCheckWithNormalityCheck {
    pub after_ms_variance: BoundedMeasurement,
    pub after_ms_mean: BoundedMeasurement,
    pub before_ms_normality_check: bool,
}

impl NoiseCheckWithNormalityCheck {
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

#[derive(Serialize, Deserialize)]
pub struct NoiseCheckWithoutNormalityCheck {
    pub after_ms_variance: BoundedMeasurement,
    pub after_ms_mean: BoundedMeasurement,
}

impl NoiseCheckWithoutNormalityCheck {
    pub fn new(variance: BoundedMeasurement, mean: BoundedMeasurement) -> Self {
        Self {
            after_ms_variance: variance,
            after_ms_mean: mean,
        }
    }
}

#[derive(Serialize, Deserialize, Clone)]
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

#[derive(Serialize, Deserialize)]
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

#[derive(Serialize, Deserialize)]
pub struct TestJsonOutput<P> {
    pub test: String,
    pub name: String,
    pub pass: bool,
    pub warning: Option<String>,
    pub parameters: P,
    pub results: TestResult,
}

impl<P> TestJsonOutput<P> {
    pub fn new(
        test: String,
        name: String,
        pass: bool,
        warning: Option<String>,
        parameters: P,
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
