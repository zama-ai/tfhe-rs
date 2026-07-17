pub mod ops;

use ops::IntegerOp;
use strum::Display;

use crate::traits::SpecNode;

#[derive(Debug, Clone, Copy, Display)]
#[strum(serialize_all = "snake_case")]
pub enum IntegerOpBySign {
    Unsigned(IntegerOp),
    Signed(IntegerOp),
}

impl SpecNode for IntegerOpBySign {
    fn child(&self) -> Option<&dyn SpecNode> {
        Some(match self {
            IntegerOpBySign::Unsigned(op) | IntegerOpBySign::Signed(op) => op,
        })
    }
}

#[derive(Debug, Clone, Copy, Display)]
#[strum(serialize_all = "snake_case")]
pub enum IntegerBench {
    Ops(IntegerOpBySign),
}

impl SpecNode for IntegerBench {
    fn child(&self) -> Option<&dyn SpecNode> {
        Some(match self {
            IntegerBench::Ops(signedness) => signedness,
        })
    }
}
