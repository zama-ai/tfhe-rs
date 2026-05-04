pub mod criterion_model;
pub mod point;
pub mod record;

pub use criterion_model::{CriterionBenchmark, CriterionEstimates};
pub use point::{Backend, Point, PointClass, Series};
pub use record::OperatorType;

/// Failure record for a single benchmark or CSV row that could not be parsed.
pub struct ParsingFailure {
    pub source: String,
    pub error: String,
}
