use strum::{Display, EnumString};

use crate::traits::SpecLeafNode;

/// Server side of the one time pad, the client side has no FHE cost
#[derive(Debug, Clone, Copy, Display, EnumString, enum_iterator::Sequence)]
#[strum(serialize_all = "snake_case")]
pub enum OneTimePadFlavor {
    /// Generation of the encrypted mask by OPRF
    NewRandom,
    /// Keystream drawn from the mask, then applied to the input
    Transcipher,
}

impl SpecLeafNode for OneTimePadFlavor {}
