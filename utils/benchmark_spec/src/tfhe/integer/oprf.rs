use strum::{Display, EnumString};

use crate::traits::SpecLeafNode;

/// Oblivious PRF flavors (integer layer).
#[derive(Debug, Clone, Copy, Display, EnumString, enum_iterator::Sequence)]
#[strum(serialize_all = "snake_case")]
pub enum IntegerOprf {
    Unsigned,
    UnsignedBounded,
}

impl SpecLeafNode for IntegerOprf {}
