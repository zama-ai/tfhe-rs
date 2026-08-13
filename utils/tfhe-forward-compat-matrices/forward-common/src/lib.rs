//! Plumbing shared by the forward compatibility matrix crates: the artifacts
//! every per-version binary writes (`artifacts`) and the stdout line format it
//! reports them with (`outcome`). Turning those lines into a matrix is the
//! orchestrator's job.
//!
//! No dependency at all, on purpose: every isolated per-version crate shares it
//! without pinning anything.

mod artifacts;
mod outcome;

pub use artifacts::{
    ARTIFACTS, Artifact, CLEAR_BOOL, CLEAR_U8, CLEAR_U32, LIMIT, PROVEN_LEN, ZK_METADATA, file_of,
};
pub use outcome::{Outcome, Report, parse_report, report, single_line};
