use strum::Display;

use crate::traits::SpecNode;

/// KV store benchmark operations for the HLAPI layer.
#[derive(Debug, Clone, Copy, Display)]
#[strum(serialize_all = "snake_case")]
pub enum KvStoreOp {
    ContainsKey,
    ContainsValue,
    ContainsClearValue,
    Get,
    Update,
    Map,
}

impl SpecNode for KvStoreOp {}
