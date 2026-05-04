pub mod criterion_model;
pub mod point;
pub mod record;

#[cfg(feature = "boolean")]
mod boolean;
#[cfg(feature = "shortint")]
mod shortint;

pub use criterion_model::{CriterionBenchmark, CriterionEstimates};
pub use point::{Backend, Point, PointClass, PointType, Series};
pub use record::{CryptoParametersRecord, OperatorType};

/// Failure record for a single benchmark or CSV row that could not be parsed.
pub struct ParsingFailure {
    pub source: String,
    pub error: String,
}
