pub mod boolean;
pub mod core_crypto;
pub mod hl_integer_op;
pub mod hlapi;
pub mod integer;
pub mod shortint;
pub mod transciphering;

use strum::Display;

use crate::traits::SpecNode;

pub use boolean::BooleanBench;
pub use core_crypto::CoreCryptoBench;
pub use hl_integer_op::HlIntegerOp;
pub use hlapi::HlapiBench;
pub use integer::ops::IntegerOp;
pub use integer::{IntegerBench, IntegerOpBySign};
pub use shortint::ShortintBench;
pub use transciphering::TranscipheringBench;

/// Layers of the `tfhe` crate.
///
/// Adding a new layer requires:
/// 1. Add the variant here (strum handles the name)
/// 2. Add a match arm in `child()` returning the inner type as `&dyn SpecNode` (the inner type must
///    implement `SpecNode`).
#[derive(Debug, Clone, Copy, Display)]
#[strum(serialize_all = "snake_case")]
pub enum TfheLayer {
    Boolean(BooleanBench),
    CoreCrypto(CoreCryptoBench),
    Hlapi(HlapiBench),
    Shortint(ShortintBench),
    Transciphering(TranscipheringBench),
    Integer(IntegerBench),
}

impl SpecNode for TfheLayer {
    fn child(&self) -> Option<&dyn SpecNode> {
        Some(match self {
            TfheLayer::Boolean(bench) => bench,
            TfheLayer::CoreCrypto(bench) => bench,
            TfheLayer::Hlapi(bench) => bench,
            TfheLayer::Shortint(bench) => bench,
            TfheLayer::Transciphering(bench) => bench,
            TfheLayer::Integer(bench) => bench,
        })
    }
}
