use strum::{Display, EnumString};

use crate::traits::SpecLeafNode;

/// KV store benchmark operations for the HLAPI layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Display, EnumString, enum_iterator::Sequence)]
#[strum(serialize_all = "snake_case")]
pub enum KvStoreOp {
    ContainsKey,
    ContainsValue,
    ContainsClearValue,
    Get,
    Update,
    Map,
}

impl SpecLeafNode for KvStoreOp {}
