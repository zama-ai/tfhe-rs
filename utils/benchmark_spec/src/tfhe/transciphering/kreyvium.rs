use strum::{Display, EnumString};

use crate::traits::SpecLeafNode;

#[derive(Debug, Clone, Copy, Display, EnumString, enum_iterator::Sequence)]
#[strum(serialize_all = "snake_case")]
pub enum KreyviumFlavor {
    Warmup,
    #[strum(serialize = "keystream_64bits")]
    Keystream64Bits,
    #[strum(serialize = "transcipher_64bits")]
    Transcipher64Bits,
}

impl SpecLeafNode for KreyviumFlavor {}
