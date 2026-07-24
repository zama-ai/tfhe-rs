use strum::Display;

use crate::traits::SpecLeafNode;

#[derive(Debug, Clone, Copy, Display)]
#[strum(serialize_all = "snake_case")]
pub enum KreyviumFlavor {
    Warmup,
    #[strum(serialize = "keystream_64bits")]
    Keystream64Bits,
    #[strum(serialize = "transcipher_64bits")]
    Transcipher64Bits,
    #[strum(serialize = "transcipher_512bits")]
    Transcipher512Bits,
}

impl SpecLeafNode for KreyviumFlavor {}
