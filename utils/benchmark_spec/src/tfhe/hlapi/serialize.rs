use strum::{Display, EnumString};

use crate::traits::SpecLeafNode;

/// An object whose serialization is timed, key or ciphertext.
#[derive(Debug, Clone, Copy, Display, EnumString, enum_iterator::Sequence)]
#[strum(serialize_all = "snake_case")]
pub enum Serializable {
    CompactList,
    ServerKeyCompressed,
}

impl SpecLeafNode for Serializable {}
