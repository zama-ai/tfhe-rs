//! Plumbing shared by the forward compatibility matrix crates.
//!
//! One binary per tfhe version produces artifacts, then loads back the ones
//! produced by newer versions and reports the result on stdout (`outcome`). The
//! orchestrator collects those lines into a [`Matrix`] (`matrix`), which it both
//! renders for humans (`markdown`) and reduces to the reviewed state committed
//! in the repository (`baseline`).
//!
//! Version-agnostic on purpose: no `tfhe` dependency, so every isolated
//! per-version crate can share it without pinning a version.

mod artifacts;
mod baseline;
mod markdown;
mod matrix;
mod outcome;

#[cfg(test)]
mod test_fixtures;

pub use artifacts::{
    ARTIFACTS, Artifact, CLEAR_BOOL, CLEAR_U8, CLEAR_U32, LIMIT, PROVEN_LEN, ZK_METADATA, file_of,
};
pub use baseline::{
    BASELINE_FILE, Baseline, BaselineDiff, BaselineKey, CellState, describe_key, diff_baseline,
    parse_baseline, render_baseline,
};
pub use matrix::{Matrix, NIGHTLY};
pub use outcome::{Outcome, Report, parse_report, report};
