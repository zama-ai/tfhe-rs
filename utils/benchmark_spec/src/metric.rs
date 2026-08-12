//! What a benchmark measures, and the operand it measures it on.

use serde::{Deserialize, Serialize};
use std::env;
use std::str::FromStr;
use std::sync::OnceLock;

#[derive(Debug, Serialize, Clone, Copy)]
pub enum OperandType {
    CipherText,
    PlainText,
}

impl OperandType {
    pub fn is_scalar(&self) -> bool {
        matches!(self, OperandType::PlainText)
    }
}

/// Benchmark type driven by the `__TFHE_RS_BENCH_TYPE` environment variable.
///
/// Only `Latency` and `Throughput` can come from the environment; `PbsCount`
/// is hard-coded at specific call sites.
#[derive(Debug, Clone, Copy, Serialize)]
pub enum BenchmarkType {
    Latency,
    Throughput,
}

/// The metric being recorded by a benchmark, used in [`BenchmarkSpec`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum BenchmarkMetric {
    Latency,
    Throughput,
    PbsCount,
    KeySize,
}

impl From<BenchmarkType> for BenchmarkMetric {
    fn from(ct: BenchmarkType) -> Self {
        match ct {
            BenchmarkType::Latency => BenchmarkMetric::Latency,
            BenchmarkType::Throughput => BenchmarkMetric::Throughput,
        }
    }
}

impl FromStr for BenchmarkMetric {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "latency" => Ok(Self::Latency),
            "throughput" => Ok(Self::Throughput),
            "pbscount" => Ok(Self::PbsCount),
            "keysize" => Ok(Self::KeySize),
            _ => Err(format!("unknown benchmark metric: {s}")),
        }
    }
}

impl FromStr for BenchmarkType {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "latency" => Ok(Self::Latency),
            "throughput" => Ok(Self::Throughput),
            _ => Err(format!("benchmark type '{s}' is not supported")),
        }
    }
}

static BENCH_TYPE: OnceLock<BenchmarkType> = OnceLock::new();

/// Retrieves the benchmark type from the environment variable `__TFHE_RS_BENCH_TYPE`.
/// Panics if the variable is set to anything other than `latency` or `throughput`.
pub fn get_bench_type() -> BenchmarkType {
    *BENCH_TYPE.get_or_init(|| {
        env::var("__TFHE_RS_BENCH_TYPE")
            .as_deref()
            .unwrap_or("latency")
            .parse()
            .unwrap()
    })
}
