use strum::{Display, EnumString};

use crate::traits::SpecLeafNode;

/// What a proven compact ciphertext list benchmark measures: a step of the
/// zero-knowledge flow, or one of the objects that flow produces.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Display, EnumString, enum_iterator::Sequence)]
#[strum(serialize_all = "snake_case")]
pub enum ZkPkeBench {
    /// Building a proven list.
    Proof,
    Verify,
    VerifyAndExpand,
    /// Expanding a list without verifying it first.
    OnlyExpand,
    /// The common reference string.
    Crs,
    /// The serialized proven list.
    ProvenList,
}

impl SpecLeafNode for ZkPkeBench {}
