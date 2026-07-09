use core::fmt;

use strum::Display;

use crate::traits::SpecFmt;

#[derive(Debug, Clone, Copy, Display)]
#[strum(serialize_all = "snake_case")]
pub enum Transciphering {
    Aes(AesFlavor),
}

impl Transciphering {
    fn op(&self) -> &dyn fmt::Display {
        match self {
            Transciphering::Aes(op) => op,
        }
    }
}

impl SpecFmt for Transciphering {
    fn fmt_spec(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "::{}::{}", self, self.op())
    }
}

#[derive(Debug, Clone, Copy, Display)]
#[strum(serialize_all = "snake_case")]
pub enum AesFlavor {
    KeyExpansion,
    #[strum(serialize = "key_expansion_plus_1_block")]
    KeyExpansionPlus1Block,
    #[strum(serialize = "keystream_1_block")]
    Keystream1Block,
    #[strum(serialize = "keystream_16_blocks")]
    Keystream16Block,
    #[strum(serialize = "transcipher_16_blocks")]
    Transcipher16Blocks,
}
