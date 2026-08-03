pub mod ops;

use ops::IntegerOp;
use strum::Display;

use crate::traits::{SpecLeafNode, SpecNode};

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

/// GLWE packing-compression operations (integer layer).
#[derive(Debug, Clone, Copy, Display)]
#[strum(serialize_all = "snake_case")]
pub enum IntegerPackingOp {
    Pack,
    Unpack,
}

impl SpecLeafNode for IntegerPackingOp {}

/// Oblivious PRF flavors (integer layer).
#[derive(Debug, Clone, Copy, Display)]
#[strum(serialize_all = "snake_case")]
pub enum IntegerOprf {
    Unsigned,
    UnsignedBounded,
}

impl SpecLeafNode for IntegerOprf {}

/// Re-randomization modes.
#[derive(Debug, Clone, Copy, Display)]
#[strum(serialize_all = "snake_case")]
pub enum IntegerRerandMode {
    LegacyKeyswitch,
    NoKeyswitch,
}

impl SpecLeafNode for IntegerRerandMode {}

#[derive(Debug, Clone, Copy, Display)]
#[strum(serialize_all = "snake_case")]
pub enum IntegerBench {
    Ops(IntegerOpBySign),
    PackingCompression(IntegerPackingOp),
    Oprf(IntegerOprf),
    Rerand(IntegerRerandMode),
}

impl SpecNode for IntegerBench {
    fn child(&self) -> Option<&dyn SpecNode> {
        Some(match self {
            IntegerBench::Ops(signedness) => signedness,
            IntegerBench::PackingCompression(op) => op,
            IntegerBench::Oprf(kind) => kind,
            IntegerBench::Rerand(mode) => mode,
        })
    }
}
