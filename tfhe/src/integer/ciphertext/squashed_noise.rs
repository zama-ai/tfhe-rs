use crate::integer::backward_compatibility::ciphertext::{
    SquashedNoiseBooleanBlockVersions, SquashedNoiseRadixCiphertextVersions,
    SquashedNoiseSignedRadixCiphertextVersions,
};
use crate::shortint::ciphertext::SquashedNoiseCiphertext;
use serde::{Deserialize, Serialize};
use tfhe_versionable::Versionize;

#[derive(Serialize, Clone, Deserialize, PartialEq, Eq, Debug, Versionize)]
#[versionize(SquashedNoiseRadixCiphertextVersions)]
pub struct SquashedNoiseRadixCiphertext {
    pub(crate) packed_blocks: Vec<SquashedNoiseCiphertext>,
    pub(crate) original_block_count: usize,
}

#[derive(Serialize, Clone, Deserialize, PartialEq, Eq, Debug, Versionize)]
#[versionize(SquashedNoiseSignedRadixCiphertextVersions)]
pub struct SquashedNoiseSignedRadixCiphertext {
    pub(crate) packed_blocks: Vec<SquashedNoiseCiphertext>,
    pub(crate) original_block_count: usize,
}

#[derive(Serialize, Clone, Deserialize, PartialEq, Eq, Debug, Versionize)]
#[versionize(SquashedNoiseBooleanBlockVersions)]
pub struct SquashedNoiseBooleanBlock {
    pub(crate) ciphertext: SquashedNoiseCiphertext,
}

impl SquashedNoiseRadixCiphertext {
    pub fn packed_blocks(&self) -> &[SquashedNoiseCiphertext] {
        &self.packed_blocks
    }

    pub fn original_block_count(&self) -> usize {
        self.original_block_count
    }
}

impl SquashedNoiseSignedRadixCiphertext {
    pub fn packed_blocks(&self) -> &[SquashedNoiseCiphertext] {
        &self.packed_blocks
    }

    pub fn original_block_count(&self) -> usize {
        self.original_block_count
    }
}

impl SquashedNoiseBooleanBlock {
    pub fn packed_blocks(&self) -> &SquashedNoiseCiphertext {
        &self.ciphertext
    }
}
