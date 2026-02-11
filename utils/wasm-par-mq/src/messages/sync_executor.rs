//! Messages for sync executor communication.

use serde::{Deserialize, Serialize};

use crate::registry::FunctionId;

/// Messages from main thread to sync executor
#[derive(Debug, Serialize, Deserialize)]
pub(crate) enum MainToSyncExecutor {
    /// Request to start a new job
    Job {
        job_id: u64,
        fn_id: FunctionId,
        data: Vec<u8>,
    },
}

/// Messages from sync executor to main thread
#[derive(Debug, Serialize, Deserialize)]
pub(crate) enum SyncExecutorToMain {
    Ready,
    Done(JobOutcome),
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct JobOutcome {
    pub(crate) job_id: u64,
    pub(crate) result: Result<Vec<u8>, String>,
}
