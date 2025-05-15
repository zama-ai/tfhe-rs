use super::{DataKind, Expandable, RadixCiphertext, SignedRadixCiphertext};
use crate::integer::backward_compatibility::ciphertext::CompressedCiphertextListVersions;
use crate::integer::compression_keys::{CompressionKey, DecompressionKey};
use crate::integer::BooleanBlock;
use crate::shortint::ciphertext::CompressedCiphertextList as ShortintCompressedCiphertextList;
use crate::shortint::Ciphertext;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use tfhe_versionable::Versionize;

pub trait Compressible {
    fn compress_into(self, messages: &mut Vec<Ciphertext>) -> DataKind;
}

impl Compressible for BooleanBlock {
    fn compress_into(self, messages: &mut Vec<Ciphertext>) -> DataKind {
        messages.push(self.0);
        DataKind::Boolean
    }
}

impl Compressible for RadixCiphertext {
    fn compress_into(self, messages: &mut Vec<Ciphertext>) -> DataKind {
        let num_blocks = self.blocks.len();

        for block in self.blocks {
            messages.push(block);
        }

        DataKind::Unsigned(num_blocks)
    }
}

impl Compressible for SignedRadixCiphertext {
    fn compress_into(self, messages: &mut Vec<Ciphertext>) -> DataKind {
        let num_blocks = self.blocks.len();

        for block in self.blocks {
            messages.push(block);
        }

        DataKind::Signed(num_blocks)
    }
}

#[derive(Clone)]
pub struct CompressedCiphertextListBuilder {
    pub(crate) ciphertexts: Vec<Ciphertext>,
    pub(crate) info: Vec<DataKind>,
}

impl CompressedCiphertextListBuilder {
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self {
            ciphertexts: vec![],
            info: vec![],
        }
    }

    pub fn push<T>(&mut self, data: T) -> &mut Self
    where
        T: Compressible,
    {
        let n = self.ciphertexts.len();
        let kind = data.compress_into(&mut self.ciphertexts);
        let num_blocks = self
            .ciphertexts
            .last()
            .map_or(0, |ct| kind.num_blocks(ct.message_modulus));
        assert_eq!(n + num_blocks, self.ciphertexts.len());
        self.info.push(kind);
        self
    }

    pub fn extend<T>(&mut self, values: impl Iterator<Item = T>) -> &mut Self
    where
        T: Compressible,
    {
        for value in values {
            self.push(value);
        }
        self
    }

    pub fn build(&self, comp_key: &CompressionKey) -> CompressedCiphertextList {
        let packed_list = comp_key
            .key
            .compress_ciphertexts_into_list(&self.ciphertexts);

        CompressedCiphertextList {
            packed_list,
            info: self.info.clone(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, Versionize)]
#[versionize(CompressedCiphertextListVersions)]
pub struct CompressedCiphertextList {
    pub(crate) packed_list: ShortintCompressedCiphertextList,
    pub(crate) info: Vec<DataKind>,
}

impl CompressedCiphertextList {
    pub fn len(&self) -> usize {
        self.info.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn blocks_of(
        &self,
        index: usize,
        decomp_key: &DecompressionKey,
    ) -> Option<(Vec<Ciphertext>, DataKind)> {
        let preceding_infos = self.info.get(..index)?;
        let current_info = self.info.get(index).copied()?;
        let message_modulus = self.packed_list.message_modulus;

        let start_block_index: usize = preceding_infos
            .iter()
            .copied()
            .map(|kind| kind.num_blocks(message_modulus))
            .sum();

        let end_block_index = start_block_index + current_info.num_blocks(message_modulus);

        Some((
            (start_block_index..end_block_index)
                .into_par_iter()
                .map(|i| decomp_key.key.unpack(&self.packed_list, i).unwrap())
                .collect(),
            current_info,
        ))
    }

    pub fn get_kind_of(&self, index: usize) -> Option<DataKind> {
        self.info.get(index).copied()
    }

    pub fn get<T>(&self, index: usize, decomp_key: &DecompressionKey) -> crate::Result<Option<T>>
    where
        T: Expandable,
    {
        self.blocks_of(index, decomp_key)
            .map(|(blocks, kind)| T::from_expanded_blocks(blocks, kind))
            .transpose()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::integer::{gen_keys, IntegerKeyKind};
    use crate::shortint::parameters::test_params::{
        TEST_COMP_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        TEST_COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        TEST_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        TEST_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    };
    use crate::shortint::ShortintParameterSet;
    use itertools::Itertools;
    use rand::Rng;

    const NB_TESTS: usize = 10;
    const NB_OPERATOR_TESTS: usize = 10;
    const NUM_BLOCKS: usize = 32;

    #[test]
    fn test_ciphertext_compression() {
        for (params, comp_params) in [
            (
                TEST_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128.into(),
                TEST_COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
            ),
            (
                TEST_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128.into(),
                TEST_COMP_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
            ),
        ] {
            let (cks, sks) = gen_keys::<ShortintParameterSet>(params, IntegerKeyKind::Radix);

            let max_nb_messages: usize = 2 * comp_params.lwe_per_glwe.0 / NUM_BLOCKS;

            let private_compression_key = cks.new_compression_private_key(comp_params);

            let (compression_key, decompression_key) =
                cks.new_compression_decompression_keys(&private_compression_key);

            let mut rng = rand::rng();

            let message_modulus: u128 = cks.parameters().message_modulus().0 as u128;

            for _ in 0..NB_TESTS {
                // Unsigned
                let modulus = message_modulus.pow(NUM_BLOCKS as u32);
                for _ in 0..NB_OPERATOR_TESTS {
                    let nb_messages = rng.random_range(1..=max_nb_messages as u64);
                    let messages = (0..nb_messages)
                        .map(|_| rng.random::<u128>() % modulus)
                        .collect::<Vec<_>>();

                    let cts = messages
                        .iter()
                        .map(|message| cks.encrypt_radix(*message, NUM_BLOCKS))
                        .collect_vec();

                    let mut builder = CompressedCiphertextListBuilder::new();

                    for ct in cts {
                        let and_ct = sks.bitand_parallelized(&ct, &ct);
                        builder.push(and_ct);
                    }

                    let compressed = builder.build(&compression_key);

                    for (i, message) in messages.iter().enumerate() {
                        let decompressed = compressed.get(i, &decompression_key).unwrap().unwrap();
                        let decrypted: u128 = cks.decrypt_radix(&decompressed);
                        assert_eq!(decrypted, *message);
                    }
                }

                // Signed
                let modulus = message_modulus.pow((NUM_BLOCKS - 1) as u32) as i128;
                for _ in 0..NB_OPERATOR_TESTS {
                    let nb_messages = rng.random_range(1..=max_nb_messages as u64);
                    let messages = (0..nb_messages)
                        .map(|_| rng.random::<i128>() % modulus)
                        .collect::<Vec<_>>();

                    let cts = messages
                        .iter()
                        .map(|message| cks.encrypt_signed_radix(*message, NUM_BLOCKS))
                        .collect_vec();

                    let mut builder = CompressedCiphertextListBuilder::new();

                    for ct in cts {
                        let and_ct = sks.bitand_parallelized(&ct, &ct);
                        builder.push(and_ct);
                    }

                    let compressed = builder.build(&compression_key);

                    for (i, message) in messages.iter().enumerate() {
                        let decompressed = compressed.get(i, &decompression_key).unwrap().unwrap();
                        let decrypted: i128 = cks.decrypt_signed_radix(&decompressed);
                        assert_eq!(decrypted, *message);
                    }
                }

                // Boolean
                for _ in 0..NB_OPERATOR_TESTS {
                    let nb_messages = rng.random_range(1..=max_nb_messages as u64);
                    let messages = (0..nb_messages)
                        .map(|_| rng.random::<i64>() % 2 != 0)
                        .collect::<Vec<_>>();

                    let cts = messages
                        .iter()
                        .map(|message| cks.encrypt_bool(*message))
                        .collect_vec();

                    let mut builder = CompressedCiphertextListBuilder::new();

                    for ct in cts {
                        let and_ct = sks.boolean_bitand(&ct, &ct);
                        builder.push(and_ct);
                    }

                    let compressed = builder.build(&compression_key);

                    for (i, message) in messages.iter().enumerate() {
                        let decompressed = compressed.get(i, &decompression_key).unwrap().unwrap();
                        let decrypted = cks.decrypt_bool(&decompressed);
                        assert_eq!(decrypted, *message);
                    }
                }

                // Hybrid
                enum MessageType {
                    Unsigned(u128),
                    Signed(i128),
                    Boolean(bool),
                }
                for _ in 0..NB_OPERATOR_TESTS {
                    let mut builder = CompressedCiphertextListBuilder::new();

                    let nb_messages = rng.random_range(1..=max_nb_messages as u64);
                    let mut messages = vec![];
                    for _ in 0..nb_messages {
                        let case_selector = rng.random_range(0..3);
                        match case_selector {
                            0 => {
                                // Unsigned
                                let modulus = message_modulus.pow(NUM_BLOCKS as u32);
                                let message = rng.random::<u128>() % modulus;
                                let ct = cks.encrypt_radix(message, NUM_BLOCKS);
                                let and_ct = sks.bitand_parallelized(&ct, &ct);
                                builder.push(and_ct);
                                messages.push(MessageType::Unsigned(message));
                            }
                            1 => {
                                // Signed
                                let modulus = message_modulus.pow((NUM_BLOCKS - 1) as u32) as i128;
                                let message = rng.random::<i128>() % modulus;
                                let ct = cks.encrypt_signed_radix(message, NUM_BLOCKS);
                                let and_ct = sks.bitand_parallelized(&ct, &ct);
                                builder.push(and_ct);
                                messages.push(MessageType::Signed(message));
                            }
                            _ => {
                                // Boolean
                                let message = rng.random::<i64>() % 2 != 0;
                                let ct = cks.encrypt_bool(message);
                                let and_ct = sks.boolean_bitand(&ct, &ct);
                                builder.push(and_ct);
                                messages.push(MessageType::Boolean(message));
                            }
                        }
                    }

                    let compressed = builder.build(&compression_key);

                    for (i, val) in messages.iter().enumerate() {
                        match val {
                            MessageType::Unsigned(message) => {
                                let decompressed =
                                    compressed.get(i, &decompression_key).unwrap().unwrap();
                                let decrypted: u128 = cks.decrypt_radix(&decompressed);
                                assert_eq!(decrypted, *message);
                            }
                            MessageType::Signed(message) => {
                                let decompressed =
                                    compressed.get(i, &decompression_key).unwrap().unwrap();
                                let decrypted: i128 = cks.decrypt_signed_radix(&decompressed);
                                assert_eq!(decrypted, *message);
                            }
                            MessageType::Boolean(message) => {
                                let decompressed =
                                    compressed.get(i, &decompression_key).unwrap().unwrap();
                                let decrypted = cks.decrypt_bool(&decompressed);
                                assert_eq!(decrypted, *message);
                            }
                        }
                    }
                }
            }
        }
    }
}
