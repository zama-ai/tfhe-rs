pub mod model;
mod writer;

pub use model::OperatorType;
pub use writer::{write_to_json, write_to_json_unchecked};
