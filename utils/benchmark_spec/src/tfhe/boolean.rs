use strum::Display;

use crate::traits::SpecLeafNode;

#[derive(Debug, Clone, Copy, Display)]
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
