use strum::{Display, EnumString};

use crate::traits::SpecLeafNode;

/// A ciphertext whose size is measured, by the form it is stored in.
#[derive(Debug, Clone, Copy, Display, EnumString, enum_iterator::Sequence)]
#[strum(serialize_all = "snake_case")]
pub enum CiphertextKind {
    Ct,
    SeededCt,
    /// Compressed by a modulus switch only.
    MsCompressedCt,
    CompressedCt,
    /// Noise-squashed.
    SnsCt,
    CompressedSnsCt,
    /// Encrypted under a compact public key.
    CpkCt,
    /// A compact list, whose size depends on how many it holds.
    CompactList,
}

impl SpecLeafNode for CiphertextKind {}
