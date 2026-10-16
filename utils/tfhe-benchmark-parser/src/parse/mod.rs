mod criterion_parser;
mod key_results;
mod metric;
mod parameters;

pub use criterion_parser::recursive_parse;
pub use key_results::parse_csv_results;

use tfhe_benchmark_parser::model::{ParsingFailure, Point};

pub struct ParseOutcome {
    pub points: Vec<Point>,
    pub failures: Vec<ParsingFailure>,
}
