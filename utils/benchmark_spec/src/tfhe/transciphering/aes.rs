use strum::Display;

use crate::traits::SpecLeafNode;

#[derive(Debug, Clone, Copy, Display)]
#[strum(serialize_all = "snake_case")]
pub enum AesFlavor {
    KeyExpansion,
    #[strum(serialize = "key_expansion_plus_1_block")]
    KeyExpansionPlus1Block,
    #[strum(serialize = "keystream_1_block")]
    Keystream1Block,
    #[strum(serialize = "keystream_16_blocks")]
    Keystream16Blocks,
    #[strum(serialize = "transcipher_16_blocks")]
    Transcipher16Blocks,
}

impl SpecLeafNode for AesFlavor {}
