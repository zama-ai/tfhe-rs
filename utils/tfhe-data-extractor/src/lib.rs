//! The extractor as a library, so that the binary is not the only thing that
//! can fetch and shape benchmark results.
//!
//! The command line stays in `main.rs`; everything it drives lives here.

pub mod archive;
pub mod cli;
pub mod db;
pub mod format;
pub mod output;
pub mod params;
pub mod profile;
pub mod query;
