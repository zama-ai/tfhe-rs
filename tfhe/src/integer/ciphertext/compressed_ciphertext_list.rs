use super::{DataKind, Expandable, RadixCiphertext, SignedRadixCiphertext};
#[cfg(feature = "gpu")]
use crate::core_crypto::gpu::CudaStreams;
use crate::integer::backward_compatibility::ciphertext::CompressedCiphertextListVersions;
use crate::integer::compression_keys::{CompressionKey, DecompressionKey};
#[cfg(feature = "gpu")]
use crate::integer::gpu::list_compression::server_keys::CudaDecompressionKey;
use crate::integer::BooleanBlock;
use crate::shortint::ciphertext::CompressedCiphertextList as ShortintCompressedCiphertextList;
use crate::shortint::Ciphertext;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::num::NonZero;
use tfhe_versionable::Versionize;

pub trait Compressible {
    fn compress_into(self, messages: &mut Vec<Ciphertext>) -> Option<DataKind>;
}

impl Compressible for BooleanBlock {
    fn compress_into(self, messages: &mut Vec<Ciphertext>) -> Option<DataKind> {
        messages.push(self.0);
        Some(DataKind::Boolean)
    }
}

impl Compressible for RadixCiphertext {
    fn compress_into(self, messages: &mut Vec<Ciphertext>) -> Option<DataKind> {
        let num_blocks = self.blocks.len();

        for block in self.blocks {
            messages.push(block);
        }

        NonZero::new(num_blocks).map(DataKind::Unsigned)
    }
}

impl Compressible for SignedRadixCiphertext {
    fn compress_into(self, messages: &mut Vec<Ciphertext>) -> Option<DataKind> {
        let num_blocks = self.blocks.len();

        for block in self.blocks {
            messages.push(block);
        }

        NonZero::new(num_blocks).map(DataKind::Signed)
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
        let maybe_kind = data.compress_into(&mut self.ciphertexts);

        let Some(modulus) = self.ciphertexts.last().map(|ct| ct.message_modulus) else {
            // This means the list of blocks is still empty, so we assert the kind is None
            // i.e no type pushed, except for strings as we allow empty strings
            if matches!(maybe_kind, Some(DataKind::String { .. })) {
                self.info.push(maybe_kind.unwrap());
            } else {
                assert!(
                    maybe_kind.is_none(),
                    "Internal error: Incoherent block count with regard to kind"
                );
            }

            return self;
        };

        let Some(kind) = maybe_kind else {
            assert_eq!(
                n,
                self.ciphertexts.len(),
                "Internal error: Incoherent block count with regard to kind"
            );
            return self;
        };

        let num_blocks = kind.num_blocks(modulus);

        // Check that the number of blocks that were added matches the
        // number of blocks advertised by the DataKind
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
        let message_modulus = self.packed_list.message_modulus()?;

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
    #[cfg(feature = "gpu")]
    pub fn get_decompression_size_on_gpu(
        &self,
        index: usize,
        decomp_key: &CudaDecompressionKey,
        streams: &CudaStreams,
    ) -> Option<u64> {
        self.get_blocks_of_size_on_gpu(index, decomp_key, streams)
    }
    #[cfg(feature = "gpu")]
    fn get_blocks_of_size_on_gpu(
        &self,
        index: usize,
        decomp_key: &CudaDecompressionKey,
        streams: &CudaStreams,
    ) -> Option<u64> {
        let preceding_infos = self.info.get(..index)?;
        let current_info = self.info.get(index).copied()?;
        let message_modulus = self.packed_list.message_modulus()?;

        let start_block_index: usize = preceding_infos
            .iter()
            .copied()
            .map(|kind| kind.num_blocks(message_modulus))
            .sum();

        let end_block_index = start_block_index + current_info.num_blocks(message_modulus) - 1;

        Some(decomp_key.get_cpu_list_unpack_size_on_gpu(
            &self.packed_list,
            start_block_index,
            end_block_index,
            streams,
        ))
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
        TEST_PARAM_MESSAGE_2_CARRY_2_KS32_PBS_TUNIFORM_2M128,
        TEST_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    };
    use crate::shortint::ShortintParameterSet;
    use itertools::Itertools;
    use rand::Rng;

    const NB_TESTS: usize = 10;
    const NB_OPERATOR_TESTS: usize = 10;
    const NUM_BLOCKS: usize = 32;

    #[test]
    fn test_empty_list_compression() {
        let params = TEST_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128.into();

        let (cks, _) = gen_keys::<ShortintParameterSet>(params, IntegerKeyKind::Radix);

        let private_compression_key = cks
            .new_compression_private_key(TEST_COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128);

        let (compression_key, decompression_key) =
            cks.new_compression_decompression_keys(&private_compression_key);

        let builder = CompressedCiphertextListBuilder::new();

        let compressed = builder.build(&compression_key);

        assert_eq!(compressed.len(), 0);
        assert!(compressed
            .get::<RadixCiphertext>(0, &decompression_key)
            .unwrap()
            .is_none())
    }

    #[test]
    fn test_ciphertext_compression() {
        for (params, comp_params) in [
            (
                TEST_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128.into(),
                TEST_COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
            ),
            (
                TEST_PARAM_MESSAGE_2_CARRY_2_KS32_PBS_TUNIFORM_2M128.into(),
                TEST_COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
            ),
            (
                TEST_PARAM_MESSAGE_2_CARRY_2_KS32_PBS_TUNIFORM_2M128.into(),
                TEST_COMP_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
            ),
            (
                TEST_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128.into(),
                TEST_COMP_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
            ),
        ] {
            let (cks, sks) = gen_keys::<ShortintParameterSet>(params, IntegerKeyKind::Radix);

            let max_nb_messages: usize = 2 * comp_params.lwe_per_glwe().0 / NUM_BLOCKS;

            let private_compression_key = cks.new_compression_private_key(comp_params);

            let (compression_key, decompression_key) =
                cks.new_compression_decompression_keys(&private_compression_key);

            let mut rng = rand::rng();

            let message_modulus: u128 = cks.parameters().message_modulus().0 as u128;

            for _ in 0..NB_TESTS {
                // Unsigned
                let modulus = message_modulus.pow(NUM_BLOCKS as u32);
                for _ in 0..NB_OPERATOR_TESTS {
                    let nb_messages = rng.gen_range(1..=max_nb_messages as u64);
                    let messages = (0..nb_messages)
                        .map(|_| rng.gen::<u128>() % modulus)
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
                    let nb_messages = rng.gen_range(1..=max_nb_messages as u64);
                    let messages = (0..nb_messages)
                        .map(|_| rng.gen::<i128>() % modulus)
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
                    let nb_messages = rng.gen_range(1..=max_nb_messages as u64);
                    let messages = (0..nb_messages)
                        .map(|_| rng.gen::<i64>() % 2 != 0)
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

                    let nb_messages = rng.gen_range(1..=max_nb_messages as u64);
                    let mut messages = vec![];
                    for _ in 0..nb_messages {
                        let case_selector = rng.gen_range(0..3);
                        match case_selector {
                            0 => {
                                // Unsigned
                                let modulus = message_modulus.pow(NUM_BLOCKS as u32);
                                let message = rng.gen::<u128>() % modulus;
                                let ct = cks.encrypt_radix(message, NUM_BLOCKS);
                                let and_ct = sks.bitand_parallelized(&ct, &ct);
                                builder.push(and_ct);
                                messages.push(MessageType::Unsigned(message));
                            }
                            1 => {
                                // Signed
                                let modulus = message_modulus.pow((NUM_BLOCKS - 1) as u32) as i128;
                                let message = rng.gen::<i128>() % modulus;
                                let ct = cks.encrypt_signed_radix(message, NUM_BLOCKS);
                                let and_ct = sks.bitand_parallelized(&ct, &ct);
                                builder.push(and_ct);
                                messages.push(MessageType::Signed(message));
                            }
                            _ => {
                                // Boolean
                                let message = rng.gen::<i64>() % 2 != 0;
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
