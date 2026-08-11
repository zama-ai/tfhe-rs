pub mod boolean;
pub mod core_crypto;
pub mod hl_integer_op;
pub mod hlapi;
pub mod integer;
pub mod shortint;
pub mod transciphering;

use std::str::FromStr;

use strum::{Display, EnumDiscriminants, EnumString};

use crate::error::SpecParseError;
use crate::traits::SpecNode;

pub use boolean::BooleanBench;
pub use core_crypto::CoreCryptoBench;
pub use hl_integer_op::HlIntegerOp;
pub use hlapi::HlapiBench;
pub use integer::ops::IntegerOp;
pub use integer::{
    IntegerBench, IntegerOpBySign, IntegerOprf, IntegerPackingOp, IntegerRerandMode,
};
pub use shortint::ops::ShortintOp;
pub use shortint::{ShortintBench, ShortintCastingOp, ShortintPackingOp};
pub use transciphering::TranscipheringBench;

/// Layers of the `tfhe` crate.
///
/// Adding a new layer requires:
/// 1. Add the variant here (strum handles the name)
/// 2. Add a match arm in `child()` returning the inner type as `&dyn SpecNode` (the inner type must
///    implement `SpecNode`).
#[derive(Debug, Clone, Copy, Display, EnumDiscriminants, enum_iterator::Sequence)]
#[strum(serialize_all = "snake_case")]
#[strum_discriminants(
    name(TfheLayerKind),
    derive(EnumString, Display),
    strum(serialize_all = "snake_case")
)]
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

impl FromStr for TfheLayer {
    type Err = SpecParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (head, rest) = s.split_once("::").unwrap_or((s, ""));
        match TfheLayerKind::from_str(head)
            .map_err(|_| SpecParseError::Unknown(format!("unknown tfhe layer: {head}")))?
        {
            TfheLayerKind::Shortint => Ok(Self::Shortint(rest.parse()?)),
            TfheLayerKind::Hlapi => Ok(Self::Hlapi(rest.parse()?)),
            TfheLayerKind::CoreCrypto => Ok(Self::CoreCrypto(rest.parse()?)),
            TfheLayerKind::Boolean => Ok(Self::Boolean(rest.parse()?)),
            TfheLayerKind::Integer => Ok(Self::Integer(rest.parse()?)),
            TfheLayerKind::Transciphering => Ok(Self::Transciphering(rest.parse()?)),
        }
    }
}
