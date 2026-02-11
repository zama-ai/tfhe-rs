//! Messages for coordinator (Service Worker) communication.

use serde::{Deserialize, Serialize};

use super::ChunkOutcome;

/// Sent by the coordinator the the Sync Executor when all the chunks in a task are done
#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct CoordinatorToSyncExecutor {
    pub results: Vec<ChunkOutcome>,
}

/// Sent by the workers to the coordinator when a chunk is done
#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct WorkerToCoordinator {
    pub task_id: u64,
    #[serde(flatten)]
    pub outcome: ChunkOutcome,
}
