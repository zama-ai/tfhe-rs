pub mod ops;

use ops::ShortintOp;
use strum::Display;

use crate::traits::{SpecLeafNode, SpecNode};

/// Casting operations between shortint parameter sets.
#[derive(Debug, Clone, Copy, Display)]
#[strum(serialize_all = "snake_case")]
pub enum ShortintCastingOp {
    Cast,
    PackCast,
    PackCast64,
}

impl SpecLeafNode for ShortintCastingOp {}

/// GLWE packing-compression operations.
#[derive(Debug, Clone, Copy, Display)]
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

/// Benchmarks of the `shortint` layer.
///
/// Mixed node: `Ops`/`Casting`/`PackingCompression` carry an inner leaf (a
/// child in the spec tree), while the remaining variants are leaves themselves.
#[derive(Debug, Clone, Copy, Display)]
#[strum(serialize_all = "snake_case")]
pub enum ShortintBench {
    Ops(ShortintOp),
    Casting(ShortintCastingOp),
    PackingCompression(ShortintPackingOp),
    Oprf,
    // Special ops kept as top-level leaves.
    CarryExtract,
    ProgrammableBootstrap,
    UncompressKey,
    DecompNoiseSquashComp,
}

impl SpecNode for ShortintBench {
    fn child(&self) -> Option<&dyn SpecNode> {
        match self {
            ShortintBench::Ops(op) => Some(op),
            ShortintBench::Casting(op) => Some(op),
            ShortintBench::PackingCompression(op) => Some(op),
            ShortintBench::Oprf
            | ShortintBench::CarryExtract
            | ShortintBench::ProgrammableBootstrap
            | ShortintBench::UncompressKey
            | ShortintBench::DecompNoiseSquashComp => None,
        }
    }
}
