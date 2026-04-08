use strum::Display;

/// KV store benchmark operations for the HLAPI layer.
#[derive(Clone, Copy, Display)]
#[strum(serialize_all = "snake_case")]
pub enum KvStoreOp {
    Get,
    Update,
    Map,
}
