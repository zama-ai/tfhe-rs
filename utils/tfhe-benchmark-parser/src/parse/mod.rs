mod criterion;
mod key_results;
mod parameters;

pub use criterion::recursive_parse;
pub use key_results::{parse_key_gen_time, parse_object_sizes};

use tfhe_benchmark_parser::model::{ParsingFailure, Point};

pub struct ParseOutcome {
    pub points: Vec<Point>,
    pub failures: Vec<ParsingFailure>,
}
