use strum::{Display, EnumString};

use crate::traits::SpecLeafNode;

/// GLWE packing-compression operations (integer layer).
#[derive(Debug, Clone, Copy, Display, EnumString, enum_iterator::Sequence)]
#[strum(serialize_all = "snake_case")]
pub enum IntegerPackingOp {
    Pack,
    Unpack,
}

impl SpecLeafNode for IntegerPackingOp {}
