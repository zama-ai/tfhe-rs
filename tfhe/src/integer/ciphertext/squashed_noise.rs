use crate::integer::backward_compatibility::ciphertext::SquashedNoiseIntegerCiphertextVersions;
use crate::shortint::ciphertext::SquashedNoiseCiphertext;
use serde::{Deserialize, Serialize};
use tfhe_versionable::Versionize;

#[derive(Serialize, Clone, Deserialize, PartialEq, Eq, Debug, Versionize)]
#[versionize(SquashedNoiseIntegerCiphertextVersions)]
pub enum SquashedNoiseIntegerCiphertext {
    RadixCiphertext {
        packed_blocks: Vec<SquashedNoiseCiphertext>,
        original_block_count: usize,
    },
    SignedRadixCiphertext {
        packed_blocks: Vec<SquashedNoiseCiphertext>,
        original_block_count: usize,
    },
    BooleanBlock {
        ciphertext: SquashedNoiseCiphertext,
    },
}
