use crate::core_crypto::algorithms::verify_lwe_compact_ciphertext_list;
use crate::core_crypto::entities::lwe_compact_ciphertext_list_size;
use crate::core_crypto::gpu::lwe_ciphertext_list::CudaLweCiphertextList;
use crate::core_crypto::gpu::vec::CudaVec;
use crate::core_crypto::gpu::CudaStreams;
use crate::core_crypto::prelude::{CiphertextModulus, LweBskGroupingFactor, LweCiphertextCount};
use crate::integer::ciphertext::DataKind;
use crate::integer::gpu::ciphertext::compact_list::{
    CudaCompactCiphertextList, CudaCompactCiphertextListExpander, CudaCompactCiphertextListInfo,
};
use crate::integer::gpu::ciphertext::info::CudaBlockInfo;
use crate::integer::gpu::ciphertext::{expand_async, KsType};
use crate::integer::gpu::key_switching_key::CudaKeySwitchingKey;
use crate::integer::gpu::server_key::CudaBootstrappingKey;
use crate::integer::gpu::PBSType;
use crate::integer::parameters::LweDimension;
use crate::integer::{CompactPublicKey, ProvenCompactCiphertextList};
use crate::shortint::ciphertext::{Degree, NoiseLevel};
use crate::shortint::AtomicPatternKind;
use crate::zk::CompactPkeCrs;
use crate::GpuIndex;
use itertools::Itertools;
use rayon::iter::{IntoParallelRefIterator, ParallelIterator};
use tfhe_cuda_backend::cuda_bind::cuda_memcpy_async_gpu_to_gpu;

pub struct CudaProvenCompactCiphertextList {
    pub(crate) h_proved_lists: ProvenCompactCiphertextList,
    pub(crate) d_compact_lists: Vec<CudaCompactCiphertextList>,
}

impl CudaProvenCompactCiphertextList {
    pub fn duplicate(&self, streams: &CudaStreams) -> Self {
        Self {
            h_proved_lists: self.h_proved_lists.clone(),
            d_compact_lists: self
                .d_compact_lists
                .iter()
                .map(|ct_list| ct_list.duplicate(streams))
                .collect_vec(),
        }
    }

    pub fn gpu_indexes(&self) -> &[GpuIndex] {
        self.d_compact_lists
            .first()
            .unwrap()
            .d_ct_list
            .0
            .d_vec
            .gpu_indexes
            .as_slice()
    }

    unsafe fn flatten_async(
        slice_ciphertext_list: &[CudaCompactCiphertextList],
        streams: &CudaStreams,
    ) -> CudaLweCiphertextList<u64> {
        let first = slice_ciphertext_list.first().unwrap();

        // We assume all ciphertexts will have the same lwe dimension
        let lwe_dimension = first.d_ct_list.0.lwe_dimension;
        let ciphertext_modulus = first.d_ct_list.0.ciphertext_modulus;

        // Compute total number of lwe ciphertexts we will be handling
        let total_num_blocks = LweCiphertextCount(
            slice_ciphertext_list
                .iter()
                .map(|x| x.d_ct_list.0.lwe_ciphertext_count.0)
                .sum(),
        );
        let total_size = slice_ciphertext_list
            .iter()
            .map(|x| {
                lwe_compact_ciphertext_list_size(lwe_dimension, x.d_ct_list.0.lwe_ciphertext_count)
            })
            .sum();

        let mut d_vec = CudaVec::new_async(total_size, streams, 0);
        let mut offset: usize = 0;
        for ciphertext_list in slice_ciphertext_list {
            let length = lwe_compact_ciphertext_list_size(
                lwe_dimension,
                ciphertext_list.d_ct_list.0.lwe_ciphertext_count,
            );
            let dest_ptr = d_vec
                .as_mut_c_ptr(0)
                .add(offset * std::mem::size_of::<u64>());
            cuda_memcpy_async_gpu_to_gpu(
                dest_ptr,
                ciphertext_list.d_ct_list.0.d_vec.as_c_ptr(0),
                (length * std::mem::size_of::<u64>()) as u64,
                streams.ptr[0],
                streams.gpu_indexes[0].get(),
            );

            offset += ciphertext_list.d_ct_list.0.d_vec.len;
        }

        CudaLweCiphertextList::from_cuda_vec(d_vec, total_num_blocks, ciphertext_modulus)
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
        let lwe_dimension = self.lwe_dimension();

        let (ct_list, _) = self.h_proved_lists.ct_list.proved_lists.first().unwrap();
        let message_modulus = ct_list.message_modulus;
        let carry_modulus = ct_list.carry_modulus;

        let num_lwe_per_compact_list = self
            .h_proved_lists
            .ct_list
            .proved_lists
            .iter()
            .map(|pair| pair.0.ct_list.lwe_ciphertext_count().0 as u32)
            .collect_vec();

        assert!(
            !self
                .h_proved_lists
                .info
                .iter()
                .any(|x| matches!(x, DataKind::String { .. })),
            "Strings are not supported on GPUs"
        );

        let vec_is_boolean = self
            .h_proved_lists
            .info
            .iter()
            .flat_map(|data_kind| {
                let repetitions = match data_kind {
                    DataKind::Boolean => 1,
                    DataKind::Signed(x) => *x,
                    DataKind::Unsigned(x) => *x,
                    DataKind::String { .. } => panic!("DataKind not supported on GPUs"),
                };
                std::iter::repeat_n(matches!(data_kind, DataKind::Boolean), repetitions)
            })
            .collect_vec();

        let blocks_info = self
            .h_proved_lists
            .info
            .iter()
            .map(|x| CudaCompactCiphertextListInfo {
                info: CudaBlockInfo {
                    degree: match x {
                        DataKind::Boolean => Degree(1),
                        _ => Degree(message_modulus.0 - 1),
                    },
                    message_modulus,
                    carry_modulus,
                    atomic_pattern: AtomicPatternKind::Standard(key.dest_server_key.pbs_order),
                    noise_level: NoiseLevel::NOMINAL,
                },
                data_kind: *x,
            })
            .collect_vec();

        let input_lwe_ciphertext_count =
            LweCiphertextCount(num_lwe_per_compact_list.iter().sum::<u32>() as usize);
        let output_lwe_ciphertext_count = LweCiphertextCount(2 * input_lwe_ciphertext_count.0);
        let ciphertext_modulus = self.ciphertext_modulus();

        let d_output = unsafe {
            let mut d_output = CudaLweCiphertextList::new(
                lwe_dimension,
                output_lwe_ciphertext_count,
                ciphertext_modulus,
                streams,
            );

            let d_input = &Self::flatten_async(self.d_compact_lists.as_slice(), streams);
            let casting_key = &key.key_switching_key_material;
            let sks = &key.dest_server_key;
            let computing_ks_key = &key.dest_server_key.key_switching_key;

            let casting_key_type: KsType = casting_key.destination_key.into();

            match &sks.bootstrapping_key {
                CudaBootstrappingKey::Classic(d_bsk) => {
                    expand_async(
                        streams,
                        &mut d_output,
                        d_input,
                        &d_bsk.d_vec,
                        &computing_ks_key.d_vec,
                        &casting_key.lwe_keyswitch_key.d_vec,
                        sks.message_modulus,
                        sks.carry_modulus,
                        d_bsk.glwe_dimension(),
                        d_bsk.polynomial_size(),
                        d_bsk.input_lwe_dimension(),
                        computing_ks_key.decomposition_level_count(),
                        computing_ks_key.decomposition_base_log(),
                        casting_key
                            .lwe_keyswitch_key
                            .input_key_lwe_size()
                            .to_lwe_dimension(),
                        casting_key
                            .lwe_keyswitch_key
                            .output_key_lwe_size()
                            .to_lwe_dimension(),
                        casting_key.lwe_keyswitch_key.decomposition_level_count(),
                        casting_key.lwe_keyswitch_key.decomposition_base_log(),
                        d_bsk.decomp_level_count,
                        d_bsk.decomp_base_log,
                        PBSType::Classical,
                        casting_key_type,
                        LweBskGroupingFactor(0),
                        num_lwe_per_compact_list.as_slice(),
                        vec_is_boolean.as_slice(),
                        d_bsk.d_ms_noise_reduction_key.as_ref(),
                    );
                }
                CudaBootstrappingKey::MultiBit(d_multibit_bsk) => {
                    expand_async(
                        streams,
                        &mut d_output,
                        &Self::flatten_async(self.d_compact_lists.as_slice(), streams),
                        &d_multibit_bsk.d_vec,
                        &computing_ks_key.d_vec,
                        &casting_key.lwe_keyswitch_key.d_vec,
                        sks.message_modulus,
                        sks.carry_modulus,
                        d_multibit_bsk.glwe_dimension(),
                        d_multibit_bsk.polynomial_size(),
                        d_multibit_bsk.input_lwe_dimension(),
                        computing_ks_key.decomposition_level_count(),
                        computing_ks_key.decomposition_base_log(),
                        casting_key
                            .lwe_keyswitch_key
                            .input_key_lwe_size()
                            .to_lwe_dimension(),
                        casting_key
                            .lwe_keyswitch_key
                            .output_key_lwe_size()
                            .to_lwe_dimension(),
                        casting_key.lwe_keyswitch_key.decomposition_level_count(),
                        casting_key.lwe_keyswitch_key.decomposition_base_log(),
                        d_multibit_bsk.decomp_level_count,
                        d_multibit_bsk.decomp_base_log,
                        PBSType::MultiBit,
                        casting_key_type,
                        d_multibit_bsk.grouping_factor,
                        num_lwe_per_compact_list.as_slice(),
                        vec_is_boolean.as_slice(),
                        None,
                    );
                }
            }
            d_output
        };

        Ok(CudaCompactCiphertextListExpander {
            expanded_blocks: d_output,
            blocks_info,
        })
    }

    pub fn from_proven_compact_ciphertext_list(
        h_proved_lists: &ProvenCompactCiphertextList,
        streams: &CudaStreams,
    ) -> Self {
        assert!(
            h_proved_lists.is_packed(),
            "Only packed lists are supported on GPUs"
        );

        let d_compact_lists: Vec<CudaCompactCiphertextList> = h_proved_lists
            .ct_list
            .proved_lists
            .par_iter()
            .map(|(ct_list, _proof)| {
                CudaCompactCiphertextList::from_compact_ciphertext_list(ct_list, streams)
            })
            .collect();

        Self {
            h_proved_lists: h_proved_lists.clone(),
            d_compact_lists,
        }
    }

    pub fn lwe_dimension(&self) -> LweDimension {
        self.d_compact_lists
            .first()
            .unwrap()
            .d_ct_list
            .0
            .lwe_dimension
    }

    pub fn lwe_ciphertext_count(&self) -> LweCiphertextCount {
        self.d_compact_lists
            .first()
            .unwrap()
            .d_ct_list
            .0
            .lwe_ciphertext_count
    }

    pub fn ciphertext_modulus(&self) -> CiphertextModulus<u64> {
        self.d_compact_lists
            .first()
            .unwrap()
            .d_ct_list
            .0
            .ciphertext_modulus
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
    // TODO test params update for the v1_2
    use crate::shortint::parameters::v1_2::V1_2_PARAM_KEYSWITCH_PKE_TO_BIG_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
    use crate::shortint::parameters::{
        CompactPublicKeyEncryptionParameters, ShortintKeySwitchingParameters,
        PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        PARAM_KEYSWITCH_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    };
    use crate::shortint::PBSParameters;
    use crate::zk::{CompactPkeCrs, ZkComputeLoad};
    use rand::random;

    #[test]
    fn test_zk_compact_ciphertext_list_encryption() {
        let params: [(
            ShortintKeySwitchingParameters,
            CompactPublicKeyEncryptionParameters,
            PBSParameters,
        ); 3] = [
            (
                V1_2_PARAM_KEYSWITCH_PKE_TO_BIG_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
                TEST_PARAM_PKE_TO_BIG_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128_ZKV2,
                PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128.into(),
            ),
            (
                PARAM_KEYSWITCH_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
                PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
                PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128.into(),
            ),
            (
                PARAM_KEYSWITCH_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
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
                V1_2_PARAM_KEYSWITCH_PKE_TO_BIG_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
                TEST_PARAM_PKE_TO_BIG_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128_ZKV2,
                PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128.into(),
            ),
            (
                PARAM_KEYSWITCH_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
                PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
                PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128.into(),
            ),
            (
                PARAM_KEYSWITCH_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
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
        use super::DataKind;

        let params: [(
            ShortintKeySwitchingParameters,
            CompactPublicKeyEncryptionParameters,
            PBSParameters,
        ); 3] = [
            (
                V1_2_PARAM_KEYSWITCH_PKE_TO_BIG_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
                TEST_PARAM_PKE_TO_BIG_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128_ZKV2,
                PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128.into(),
            ),
            (
                PARAM_KEYSWITCH_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
                PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
                PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128.into(),
            ),
            (
                PARAM_KEYSWITCH_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
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
                    if curr_block_count != 0 {
                        new_infos.push(DataKind::Unsigned(curr_block_count));
                        curr_block_count = 0;
                    }
                    new_infos.push(DataKind::Boolean);
                } else {
                    curr_block_count += 1;
                }
            }
            if curr_block_count != 0 {
                new_infos.push(DataKind::Unsigned(curr_block_count));
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
