use strum::Display;

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
