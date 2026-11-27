use strum::{Display, EnumString};

use crate::traits::SpecLeafNode;

#[derive(Debug, Clone, Copy, Display, EnumString, enum_iterator::Sequence)]
#[strum(serialize_all = "snake_case")]
pub enum OneTimePadFlavor {
    /// Pad generation, compression, noise squashing and compression of the squashed pad
    PadWorker,
    /// Pad decompression and unmasking of a stream ciphertext list
    Unmask,
    /// Unmasking when the pad is not stored yet: pad generation, compression, decompression and
    /// unmasking of a stream ciphertext list
    UnmaskCold,
}

impl SpecLeafNode for OneTimePadFlavor {}
