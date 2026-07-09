pub mod dex;
pub mod erc7984;
pub mod kv_store;
pub mod noise_squash;
pub mod oprf;
pub mod transciphering;

use dex::Dex;
use erc7984::Erc7984;
use kv_store::KvStoreOp;
use noise_squash::NoiseSquashingKind;
use oprf::OprfKind;
use strum::Display;
use transciphering::Transciphering;

use crate::traits::SpecNode;

pub use super::hl_integer_op::HlIntegerOp;

/// Benchmark categories within the HLAPI layer.
///
/// Each variant represents a category of benchmarks (ops, erc7984, dex, etc.)
/// and carries its own op enum. Adding a new category requires:
/// 1. Add the variant here (strum handles the name)
/// 2. Add a match arm in `child()` returning the inner op as `&dyn SpecNode` (a leaf op enum just
///    needs `impl SpecNode for X {}`).
#[derive(Debug, Clone, Copy, Display)]
#[strum(serialize_all = "snake_case")]
pub enum HlapiBench {
    Ops(HlIntegerOp),
    Erc7984(Erc7984),
    Dex(Dex),
    KvStore(KvStoreOp),
    NoiseSquashing(NoiseSquashingKind),
    Oprf(OprfKind),
    Transciphering(Transciphering),
}

impl SpecNode for HlapiBench {
    fn child(&self) -> Option<&dyn SpecNode> {
        Some(match self {
            HlapiBench::Ops(op) => op,
            HlapiBench::Erc7984(op) => op,
            HlapiBench::Dex(op) => op,
            HlapiBench::KvStore(op) => op,
            HlapiBench::NoiseSquashing(op) => op,
            HlapiBench::Oprf(op) => op,
            HlapiBench::Transciphering(op) => op,
        })
    }
}
