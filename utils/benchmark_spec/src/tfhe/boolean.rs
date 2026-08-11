use strum::{Display, EnumString};

use crate::traits::SpecLeafNode;

#[derive(Debug, Clone, Copy, Display, EnumString, enum_iterator::Sequence)]
#[strum(serialize_all = "snake_case")]
pub enum BooleanBench {
    And,
    Nand,
    Or,
    Xor,
    Xnor,
    Not,
    Mux,
}

impl SpecLeafNode for BooleanBench {}
