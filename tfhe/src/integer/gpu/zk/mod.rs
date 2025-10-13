use crate::core_crypto::algorithms::verify_lwe_compact_ciphertext_list;
use crate::core_crypto::gpu::CudaStreams;
use crate::core_crypto::prelude::{CiphertextModulus, LweCiphertextCount};
use crate::integer::gpu::ciphertext::compact_list::{
    CudaCompactCiphertextListExpander, CudaFlattenedVecCompactCiphertextList,
};
use crate::integer::gpu::key_switching_key::CudaKeySwitchingKey;
use crate::integer::parameters::LweDimension;
use crate::integer::{CompactPublicKey, ProvenCompactCiphertextList};
use crate::zk::CompactPkeCrs;
use crate::GpuIndex;
use itertools::Itertools;
use rayon::iter::{IntoParallelRefIterator, ParallelIterator};

pub struct CudaProvenCompactCiphertextList {
    pub(crate) h_proved_lists: ProvenCompactCiphertextList,
    pub(crate) d_flattened_compact_lists: CudaFlattenedVecCompactCiphertextList,
}

impl CudaProvenCompactCiphertextList {
    pub fn duplicate(&self, streams: &CudaStreams) -> Self {
        Self {
            h_proved_lists: self.h_proved_lists.clone(),
            d_flattened_compact_lists: self.d_flattened_compact_lists.duplicate(streams),
        }
    }

    pub fn gpu_indexes(&self) -> &[GpuIndex] {
        self.d_flattened_compact_lists.gpu_indexes()
    }

    pub fn verify_and_expand(
        &self,
        crs: &CompactPkeCrs,
        public_key: &CompactPublicKey,
        metadata: &[u8],
        key: &CudaKeySwitchingKey,
        streams: &CudaStreams,
    ) -> crate::Result<CudaCompactCiphertextListExpander> {
        let (all_valid, r) = rayon::join(
            || {
                self.h_proved_lists
                    .ct_list
                    .proved_lists
                    .par_iter()
                    .all(|(ct_list, proof)| {
                        verify_lwe_compact_ciphertext_list(
                            &ct_list.ct_list,
                            &public_key.key.key,
                            proof,
                            crs,
                            metadata,
                        )
                        .is_valid()
                    })
            },
            || self.expand_without_verification(key, streams),
        );

        if all_valid {
            return r;
        }

        Err(crate::ErrorKind::InvalidZkProof.into())
    }

    /// # Safety
    ///
    /// - [CudaStreams::synchronize] __must__ be called after this function as soon as
    ///   synchronization is required
    pub fn expand_without_verification(
        &self,
        key: &CudaKeySwitchingKey,
        streams: &CudaStreams,
    ) -> crate::Result<CudaCompactCiphertextListExpander> {
        self.d_flattened_compact_lists.expand(key, streams)
    }

    pub fn from_proven_compact_ciphertext_list(
        h_proved_lists: &ProvenCompactCiphertextList,
        streams: &CudaStreams,
    ) -> Self {
        assert!(
            h_proved_lists.is_packed(),
            "Only packed lists are supported on GPUs"
        );
        let h_vec_compact_lists = h_proved_lists
            .ct_list
            .proved_lists
            .iter()
            .map(|(list, _)| list.clone())
            .collect_vec();
        let d_compact_lists =
            CudaFlattenedVecCompactCiphertextList::from_vec_shortint_compact_ciphertext_list(
                h_vec_compact_lists,
                h_proved_lists.info.clone(),
                streams,
            );

        Self {
            h_proved_lists: h_proved_lists.clone(),
            d_flattened_compact_lists: d_compact_lists,
        }
    }

    pub fn lwe_dimension(&self) -> LweDimension {
        self.d_flattened_compact_lists.lwe_dimension
    }

    pub fn lwe_ciphertext_count(&self) -> LweCiphertextCount {
        self.d_flattened_compact_lists.lwe_ciphertext_count
    }

    pub fn ciphertext_modulus(&self) -> CiphertextModulus<u64> {
        self.d_flattened_compact_lists.ciphertext_modulus
    }
}

impl<'de> serde::Deserialize<'de> for CudaProvenCompactCiphertextList {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let cpu_ct = ProvenCompactCiphertextList::deserialize(deserializer)?;
        let streams = CudaStreams::new_multi_gpu();

        Ok(Self::from_proven_compact_ciphertext_list(&cpu_ct, &streams))
    }
}

#[cfg(feature = "zk-pok")]
#[cfg(test)]
mod tests {
    // Test utils for tests here
    impl ProvenCompactCiphertextList {
        /// For testing and creating potentially invalid lists
        fn infos_mut_gpu(&mut self) -> &mut Vec<DataKind> {
            &mut self.info
        }
    }

    use crate::core_crypto::gpu::CudaStreams;
    use crate::core_crypto::prelude::LweCiphertextCount;
    use crate::integer::ciphertext::{CompactCiphertextList, DataKind};
    use crate::integer::gpu::ciphertext::boolean_value::CudaBooleanBlock;
    use crate::integer::gpu::ciphertext::CudaUnsignedRadixCiphertext;
    use crate::integer::gpu::key_switching_key::{
        CudaKeySwitchingKey, CudaKeySwitchingKeyMaterial,
    };
    use crate::integer::gpu::zk::CudaProvenCompactCiphertextList;
    use crate::integer::gpu::CudaServerKey;
    use crate::integer::key_switching_key::KeySwitchingKey;
    use crate::integer::{
        ClientKey, CompactPrivateKey, CompactPublicKey, CompressedServerKey,
        ProvenCompactCiphertextList,
    };
    use crate::shortint::parameters::test_params::TEST_PARAM_PKE_TO_BIG_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128_ZKV2;
    use crate::shortint::parameters::{
        CompactPublicKeyEncryptionParameters, ShortintKeySwitchingParameters,
        PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        PARAM_KEYSWITCH_TO_BIG_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        PARAM_KEYSWITCH_TO_SMALL_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    };
    use crate::shortint::PBSParameters;
    use crate::zk::{CompactPkeCrs, ZkComputeLoad};
    use rand::random;
    use std::num::NonZero;

    #[test]
    fn test_zk_compact_ciphertext_list_encryption() {
        let params: [(
            ShortintKeySwitchingParameters,
            CompactPublicKeyEncryptionParameters,
            PBSParameters,
        ); 3] = [
            (
                PARAM_KEYSWITCH_TO_BIG_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
                TEST_PARAM_PKE_TO_BIG_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128_ZKV2,
                PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128.into(),
            ),
            (
                PARAM_KEYSWITCH_TO_SMALL_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
                PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
                PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128.into(),
            ),
            (
                PARAM_KEYSWITCH_TO_SMALL_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
                PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
                PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128.into(),
            ),
        ];

        for (ksk_params, pke_params, fhe_params) in params {
            let metadata = [b'i', b'n', b't', b'e', b'g', b'e', b'r'];

            let num_blocks = 4usize;
            let modulus = pke_params
                .message_modulus
                .0
                .checked_pow(num_blocks as u32)
                .unwrap();

            let crs =
                CompactPkeCrs::from_shortint_params(pke_params, LweCiphertextCount(512)).unwrap();
            let cks = ClientKey::new(fhe_params);
            let compressed_server_key = CompressedServerKey::new_radix_compressed_server_key(&cks);

            let streams = CudaStreams::new_multi_gpu();
            let sk = compressed_server_key.decompress();
            let gpu_sk = CudaServerKey::decompress_from_cpu(&compressed_server_key, &streams);

            let compact_private_key = CompactPrivateKey::new(pke_params);
            let ksk = KeySwitchingKey::new((&compact_private_key, None), (&cks, &sk), ksk_params);
            let d_ksk_material =
                CudaKeySwitchingKeyMaterial::from_key_switching_key(&ksk, &streams);
            let d_ksk =
                CudaKeySwitchingKey::from_cuda_key_switching_key_material(&d_ksk_material, &gpu_sk);

            let pk = CompactPublicKey::new(&compact_private_key);

            let msgs = (0..512)
                .map(|_| random::<u64>() % modulus)
                .collect::<Vec<_>>();

            let proven_ct = CompactCiphertextList::builder(&pk)
                .extend_with_num_blocks(msgs.iter().copied(), num_blocks)
                .build_with_proof_packed(&crs, &metadata, ZkComputeLoad::Proof)
                .unwrap();
            let gpu_proven_ct =
                CudaProvenCompactCiphertextList::from_proven_compact_ciphertext_list(
                    &proven_ct, &streams,
                );

            let gpu_expander = gpu_proven_ct
                .verify_and_expand(&crs, &pk, &metadata, &d_ksk, &streams)
                .unwrap();

            for (idx, msg) in msgs.iter().copied().enumerate() {
                let gpu_expanded: CudaUnsignedRadixCiphertext =
                    gpu_expander.get(idx, &streams).unwrap().unwrap();
                let expanded = gpu_expanded.to_radix_ciphertext(&streams);
                let decrypted = cks.decrypt_radix::<u64>(&expanded);
                assert_eq!(msg, decrypted);
            }

            let unverified_expander = gpu_proven_ct
                .expand_without_verification(&d_ksk, &streams)
                .unwrap();

            for (idx, msg) in msgs.iter().copied().enumerate() {
                let gpu_expanded: CudaUnsignedRadixCiphertext =
                    unverified_expander.get(idx, &streams).unwrap().unwrap();
                let expanded = gpu_expanded.to_radix_ciphertext(&streams);
                let decrypted = cks.decrypt_radix::<u64>(&expanded);
                assert_eq!(msg, decrypted);
            }
        }
    }

    #[test]
    fn test_several_proven_lists() {
        let params: [(
            ShortintKeySwitchingParameters,
            CompactPublicKeyEncryptionParameters,
            PBSParameters,
        ); 3] = [
            (
                PARAM_KEYSWITCH_TO_BIG_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
                TEST_PARAM_PKE_TO_BIG_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128_ZKV2,
                PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128.into(),
            ),
            (
                PARAM_KEYSWITCH_TO_SMALL_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
                PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
                PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128.into(),
            ),
            (
                PARAM_KEYSWITCH_TO_SMALL_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
                PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
                PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128.into(),
            ),
        ];

        for (ksk_params, pke_params, fhe_params) in params {
            let metadata = [b'i', b'n', b't', b'e', b'g', b'e', b'r'];

            let crs_blocks_for_64_bits =
                64 / ((pke_params.message_modulus.0 * pke_params.carry_modulus.0).ilog2() as usize);
            let encryption_num_blocks = 64 / (pke_params.message_modulus.0.ilog2() as usize);

            let crs = CompactPkeCrs::from_shortint_params(
                pke_params,
                LweCiphertextCount(crs_blocks_for_64_bits),
            )
            .unwrap();
            let cks = ClientKey::new(fhe_params);
            let compressed_server_key = CompressedServerKey::new_radix_compressed_server_key(&cks);
            let sk = compressed_server_key.decompress();
            let streams = CudaStreams::new_multi_gpu();
            let gpu_sk = CudaServerKey::decompress_from_cpu(&compressed_server_key, &streams);

            let compact_private_key = CompactPrivateKey::new(pke_params);
            let ksk = KeySwitchingKey::new((&compact_private_key, None), (&cks, &sk), ksk_params);
            let d_ksk_material =
                CudaKeySwitchingKeyMaterial::from_key_switching_key(&ksk, &streams);
            let d_ksk =
                CudaKeySwitchingKey::from_cuda_key_switching_key_material(&d_ksk_material, &gpu_sk);

            let pk = CompactPublicKey::new(&compact_private_key);

            let msgs = (0..2).map(|_| random::<u64>()).collect::<Vec<_>>();

            let proven_ct = CompactCiphertextList::builder(&pk)
                .extend_with_num_blocks(msgs.iter().copied(), encryption_num_blocks)
                .build_with_proof_packed(&crs, &metadata, ZkComputeLoad::Proof)
                .unwrap();
            let gpu_proven_ct =
                CudaProvenCompactCiphertextList::from_proven_compact_ciphertext_list(
                    &proven_ct, &streams,
                );

            let gpu_expander = gpu_proven_ct
                .verify_and_expand(&crs, &pk, &metadata, &d_ksk, &streams)
                .unwrap();

            for (idx, msg) in msgs.iter().copied().enumerate() {
                let gpu_expanded: CudaUnsignedRadixCiphertext =
                    gpu_expander.get(idx, &streams).unwrap().unwrap();
                let expanded = gpu_expanded.to_radix_ciphertext(&streams);
                let decrypted = cks.decrypt_radix::<u64>(&expanded);
                assert_eq!(msg, decrypted);
            }

            let unverified_expander = gpu_proven_ct
                .expand_without_verification(&d_ksk, &streams)
                .unwrap();

            for (idx, msg) in msgs.iter().copied().enumerate() {
                let gpu_expanded: CudaUnsignedRadixCiphertext =
                    unverified_expander.get(idx, &streams).unwrap().unwrap();
                let expanded = gpu_expanded.to_radix_ciphertext(&streams);
                let decrypted = cks.decrypt_radix::<u64>(&expanded);
                assert_eq!(msg, decrypted);
            }
        }
    }

    #[test]
    fn test_malicious_boolean_proven_lists() {
        use crate::integer::ciphertext::DataKind;

        let params: [(
            ShortintKeySwitchingParameters,
            CompactPublicKeyEncryptionParameters,
            PBSParameters,
        ); 3] = [
            (
                PARAM_KEYSWITCH_TO_BIG_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
                TEST_PARAM_PKE_TO_BIG_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128_ZKV2,
                PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128.into(),
            ),
            (
                PARAM_KEYSWITCH_TO_SMALL_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
                PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
                PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128.into(),
            ),
            (
                PARAM_KEYSWITCH_TO_SMALL_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
                PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
                PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128.into(),
            ),
        ];

        for (ksk_params, pke_params, fhe_params) in params {
            let metadata = [b'i', b'n', b't', b'e', b'g', b'e', b'r'];

            let crs_blocks_for_64_bits =
                64 / ((pke_params.message_modulus.0 * pke_params.carry_modulus.0).ilog2() as usize);
            let encryption_num_blocks = 64 / (pke_params.message_modulus.0.ilog2() as usize);

            let crs = CompactPkeCrs::from_shortint_params(
                pke_params,
                LweCiphertextCount(crs_blocks_for_64_bits),
            )
            .unwrap();
            let cks = ClientKey::new(fhe_params);
            let compressed_server_key = CompressedServerKey::new_radix_compressed_server_key(&cks);
            let sk = compressed_server_key.decompress();
            let streams = CudaStreams::new_multi_gpu();
            let gpu_sk = CudaServerKey::decompress_from_cpu(&compressed_server_key, &streams);

            let compact_private_key = CompactPrivateKey::new(pke_params);
            let ksk = KeySwitchingKey::new((&compact_private_key, None), (&cks, &sk), ksk_params);
            let d_ksk_material =
                CudaKeySwitchingKeyMaterial::from_key_switching_key(&ksk, &streams);
            let d_ksk =
                CudaKeySwitchingKey::from_cuda_key_switching_key_material(&d_ksk_material, &gpu_sk);

            let pk = CompactPublicKey::new(&compact_private_key);

            let msgs = (0..2).map(|_| random::<u64>()).collect::<Vec<_>>();

            let proven_ct = CompactCiphertextList::builder(&pk)
                .extend_with_num_blocks(msgs.iter().copied(), encryption_num_blocks)
                .build_with_proof_packed(&crs, &metadata, ZkComputeLoad::Proof)
                .unwrap();

            let infos_block_count = {
                let mut infos_block_count = 0;
                let proven_ct_len = proven_ct.len();
                for idx in 0..proven_ct_len {
                    infos_block_count += proven_ct
                        .get_kind_of(idx)
                        .unwrap()
                        .num_blocks(pke_params.message_modulus);
                }

                infos_block_count
            };

            let mut new_infos = Vec::new();

            let mut curr_block_count = 0;
            for _ in 0..infos_block_count {
                let map_to_fake_boolean = random::<u8>() % 2 == 1;
                if map_to_fake_boolean {
                    if let Some(count) = NonZero::new(curr_block_count) {
                        new_infos.push(DataKind::Unsigned(count));
                        curr_block_count = 0;
                    }
                    new_infos.push(DataKind::Boolean);
                } else {
                    curr_block_count += 1;
                }
            }
            if let Some(count) = NonZero::new(curr_block_count) {
                new_infos.push(DataKind::Unsigned(count));
            }

            assert_eq!(
                new_infos
                    .iter()
                    .map(|x| x.num_blocks(pke_params.message_modulus))
                    .sum::<usize>(),
                infos_block_count
            );

            let boolean_block_idx = new_infos
                .iter()
                .enumerate()
                .filter(|(_, kind)| matches!(kind, DataKind::Boolean))
                .map(|(index, _)| index)
                .collect::<Vec<_>>();

            let proven_ct = {
                let mut proven_ct = proven_ct;
                *proven_ct.infos_mut_gpu() = new_infos;
                proven_ct
            };
            let gpu_proven_ct =
                CudaProvenCompactCiphertextList::from_proven_compact_ciphertext_list(
                    &proven_ct, &streams,
                );

            let gpu_expander = gpu_proven_ct
                .verify_and_expand(&crs, &pk, &metadata, &d_ksk, &streams)
                .unwrap();

            for idx in boolean_block_idx.iter().copied() {
                let gpu_expanded: CudaBooleanBlock =
                    gpu_expander.get(idx, &streams).unwrap().unwrap();
                let expanded = gpu_expanded.to_boolean_block(&streams);
                let decrypted = cks.key.decrypt_message_and_carry(&expanded.0);
                // check sanitization is applied even if the original data was not supposed to be
                // boolean
                assert!(decrypted < 2);
            }

            let unverified_expander = gpu_proven_ct
                .expand_without_verification(&d_ksk, &streams)
                .unwrap();

            for idx in boolean_block_idx.iter().copied() {
                let gpu_expanded: CudaBooleanBlock =
                    unverified_expander.get(idx, &streams).unwrap().unwrap();
                let expanded = gpu_expanded.to_boolean_block(&streams);
                let decrypted = cks.key.decrypt_message_and_carry(&expanded.0);
                // check sanitization is applied even if the original data was not supposed to be
                // boolean
                assert!(decrypted < 2);
            }
        }
    }
}
