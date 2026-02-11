//! Message types and serialization helpers for worker communication.

mod worker;
pub(crate) use worker::{ChunkOutcome, MainToWorker, WorkerToMain};

#[cfg(feature = "sync-api")]
mod coordinator;
#[cfg(feature = "sync-api")]
pub(crate) use coordinator::{CoordinatorToSyncExecutor, WorkerToCoordinator};

#[cfg(feature = "sync-api")]
mod sync_executor;
#[cfg(feature = "sync-api")]
pub(crate) use sync_executor::{JobOutcome, MainToSyncExecutor, SyncExecutorToMain};

use serde::{Deserialize, Serialize};

/// Deserialize a JsValue into a message type
pub(crate) fn from_js<T: for<'de> Deserialize<'de>>(
    value: wasm_bindgen::JsValue,
) -> Result<T, String> {
    serde_wasm_bindgen::from_value(value).map_err(|e| e.to_string())
}

/// Serialize a message to JsValue
pub(crate) fn to_js<T: Serialize>(value: &T) -> Result<wasm_bindgen::JsValue, String> {
    let ser = serde_wasm_bindgen::Serializer::new().serialize_large_number_types_as_bigints(true);
    value.serialize(&ser).map_err(|e| e.to_string())
}
