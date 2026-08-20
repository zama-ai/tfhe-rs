use strum::{Display, EnumString};

use crate::traits::SpecLeafNode;

/// A key whose size is measured. Shared by the layers that own keys, so a given
/// layer only uses the subset that makes sense for it.
#[derive(Debug, Clone, Copy, Display, EnumString, enum_iterator::Sequence)]
#[strum(serialize_all = "snake_case")]
pub enum KeyKind {
    Ksk,
    KskCompressed,
    Bsk,
    BskCompressed,
    Cpk,
    CpkCompressed,
    CastingKey,
    CastingKeyCompressed,
    CompressionKey,
    DecompressionKey,
    CompressedCompressionKey,
    CompressedDecompressionKey,
    NoiseSquashingKey,
    NoiseSquashingCompressionKey,
}

impl SpecLeafNode for KeyKind {}
