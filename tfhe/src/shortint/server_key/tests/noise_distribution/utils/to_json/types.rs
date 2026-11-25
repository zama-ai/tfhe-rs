//! Measured values are written as strings: it keeps their full precision and allows `-inf`
//! (log2 of a zero pfail), which a JSON number cannot represent.

use serde::Serialize;

#[derive(Serialize, Clone, Copy)]
#[serde(rename_all = "lowercase")]
pub enum TestKind {
    Sanity,
    Noise,
    Pfail,
}

#[derive(Serialize, Clone, Copy)]
#[serde(rename_all = "lowercase")]
pub enum Backend {
    Cpu,
    #[cfg(feature = "gpu")]
    Gpu,
}

#[derive(Serialize)]
#[serde(untagged)] // https://serde.rs/enum-representations.html#untagged
pub enum TestResult {
    NoiseCheck(Box<NoiseCheckResult>),
    Pfail(Box<PfailTestResultJson>),
    Empty {},
}

#[derive(Serialize, Clone)]
pub struct Measurement<T> {
    measured: T,
    expected: T,
}

impl<T> Measurement<T> {
    pub fn new(measured: T, expected: T) -> Self {
        Self { measured, expected }
    }
}

#[derive(Serialize, Clone)]
pub struct Interval<T> {
    lower: T,
    upper: T,
}

impl<T> Interval<T> {
    pub fn new(lower: T, upper: T) -> Self {
        Self { lower, upper }
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

#[derive(Serialize, Clone)]
#[serde(untagged)]
pub enum ConfidenceInterval<T> {
    Bounded(Interval<T>),
    NoBounds(NoBounds),
}

#[derive(Serialize, Clone)]
pub struct BoundedMeasurement<T> {
    value: Measurement<T>,
    confidence_interval: ConfidenceInterval<T>,
}

impl<T> BoundedMeasurement<T> {
    pub fn new(measured: T, expected: T, confidence_interval: ConfidenceInterval<T>) -> Self {
        Self {
            value: Measurement::new(measured, expected),
            confidence_interval,
        }
    }
}

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

impl From<f64> for ValueWithLog2 {
    fn from(value: f64) -> Self {
        Self::new(value.to_string(), value.log2().to_string())
    }
}

#[derive(Serialize)]
pub struct NoiseCheckResult {
    after_ms_variance: BoundedMeasurement<String>,
    after_ms_mean: BoundedMeasurement<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    before_ms_normality_check: Option<bool>,
}

impl NoiseCheckResult {
    pub fn new(
        variance: BoundedMeasurement<String>,
        mean: BoundedMeasurement<String>,
        normality_check: Option<bool>,
    ) -> Self {
        Self {
            after_ms_variance: variance,
            after_ms_mean: mean,
            before_ms_normality_check: normality_check,
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
    fails: Measurement<String>,
    pfail_with_test_precision: BoundedMeasurement<String>,
    equivalent_pfail_with_original_precision: BoundedMeasurement<ValueWithLog2>,
}

impl PfailTestResultJson {
    pub fn new(
        pfail_parameters: PfailMetadata,
        fails: Measurement<String>,
        pfail_with_test_precision: BoundedMeasurement<String>,
        equivalent_pfail_with_original_precision: BoundedMeasurement<ValueWithLog2>,
    ) -> Self {
        Self {
            pfail_parameters,
            fails,
            pfail_with_test_precision,
            equivalent_pfail_with_original_precision,
        }
    }
}

impl From<NoiseCheckResult> for TestResult {
    fn from(result: NoiseCheckResult) -> Self {
        Self::NoiseCheck(Box::new(result))
    }
}

impl From<PfailTestResultJson> for TestResult {
    fn from(result: PfailTestResultJson) -> Self {
        Self::Pfail(Box::new(result))
    }
}

#[derive(Serialize)]
pub struct TestJsonOutput<P> {
    pub(super) name: String,
    pub(super) kind: TestKind,
    pub(super) layer: String,
    pub(super) backend: Backend,
    pub(super) param_name: String,
    pub(super) pass: bool,
    pub(super) warning: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) run: Option<RunContext>,
    pub(super) parameters: P,
    pub(super) results: TestResult,
}

/// Where the test ran, only known in CI.
#[derive(Serialize, Clone)]
pub struct RunContext {
    pub(super) commit_sha: String,
    pub(super) commit_date: String,
    pub(super) branch: String,
    pub(super) gh_run_id: String,
    pub(super) gh_run_attempt: String,
    pub(super) machine: String,
}
