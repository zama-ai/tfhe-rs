use strum::{Display, EnumString};

use crate::traits::SpecLeafNode;

/// Casting operations between shortint parameter sets.
#[derive(Debug, Clone, Copy, Display, EnumString, enum_iterator::Sequence)]
#[strum(serialize_all = "snake_case")]
pub enum ShortintCastingOp {
    Cast,
    PackCast,
    PackCast64,
}

impl SpecLeafNode for ShortintCastingOp {}
