use strum::{Display, EnumString};

use crate::traits::SpecLeafNode;

/// GLWE packing-compression operations.
#[derive(Debug, Clone, Copy, Display, EnumString, enum_iterator::Sequence)]
#[strum(serialize_all = "snake_case")]
pub enum ShortintPackingOp {
    Pack,
    UnpackAll,
    UnpackOneLwe,
    #[strum(serialize = "unpack_64b")]
    Unpack64b,
    PackUnpack,
}

impl SpecLeafNode for ShortintPackingOp {}
