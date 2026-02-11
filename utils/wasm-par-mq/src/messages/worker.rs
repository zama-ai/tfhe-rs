//! Messages for compute worker communication.

use serde::{Deserialize, Serialize};

use crate::registry::FunctionId;

/// Messages from pool owner (main thread or SyncExecutor) to worker
#[derive(Debug, Serialize, Deserialize)]
pub(crate) enum MainToWorker {
    Chunk {
        chunk_id: u64,
        fn_id: FunctionId,
        data: Vec<u8>,
        // In sync mode, we also need to register the task this chunk belongs to
        #[cfg(feature = "sync-api")]
        task_id: Option<u64>,
    },
}

/// Messages from worker to main thread
#[derive(Debug, Serialize, Deserialize)]
pub(crate) enum WorkerToMain {
    Ready,
    Done(ChunkOutcome),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct ChunkOutcome {
    pub chunk_id: u64,
    pub result: Result<Vec<u8>, String>,
}
