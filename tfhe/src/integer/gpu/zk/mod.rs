use crate::core_crypto::algorithms::verify_lwe_compact_ciphertext_list;
use crate::core_crypto::gpu::CudaStreams;
use crate::core_crypto::prelude::{CiphertextModulus, LweCiphertextCount};
use crate::integer::ciphertext::ReRandomizationSeed;
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

    pub fn verify_re_randomize_and_expand(
        &self,
        crs: &CompactPkeCrs,
        public_key: &CompactPublicKey,
        metadata: &[u8],
        key: &CudaKeySwitchingKey,
        seed: ReRandomizationSeed,
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
            || self.re_randomize_and_expand_without_verification(key, public_key, seed, streams),
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
        self.d_flattened_compact_lists
            .expand(key, super::ZKType::Casting, streams)
    }

    /// # Safety
    ///
    /// - [CudaStreams::synchronize] __must__ be called after this function as soon as
    ///   synchronization is required
    pub fn re_randomize_and_expand_without_verification(
        &self,
        key: &CudaKeySwitchingKey,
        public_key: &CompactPublicKey,
        seed: ReRandomizationSeed,
        streams: &CudaStreams,
    ) -> crate::Result<CudaCompactCiphertextListExpander> {
        let mut rerandomized = self.duplicate(streams);
        rerandomized.re_randomize(public_key, seed, streams)?;

        rerandomized.expand_without_verification(key, streams)
    }

    pub fn re_randomize(
        &mut self,
        public_key: &CompactPublicKey,
        seed: ReRandomizationSeed,
        streams: &CudaStreams,
    ) -> crate::Result<()> {
        self.h_proved_lists.re_randomize(public_key, seed)?;
        let cpu_lists = self
            .h_proved_lists
            .ct_list
            .proved_lists
            .iter()
            .map(|(list, _)| list.clone())
            .collect_vec();
        self.d_flattened_compact_lists =
            CudaFlattenedVecCompactCiphertextList::from_vec_shortint_compact_ciphertext_list(
                &cpu_lists,
                self.h_proved_lists.info.clone(),
                streams,
            )?;
        Ok(())
    }

    /// Moves a proven compact ciphertext list to the GPU.
    ///
    /// The list is user provided data, which may have been crafted by an attacker and only has to
    /// pass the conformance checks. Every rejection must therefore be an error rather than a panic:
    /// an empty list, for instance, is conformant but is not packed.
    pub fn from_proven_compact_ciphertext_list(
        h_proved_lists: &ProvenCompactCiphertextList,
        streams: &CudaStreams,
    ) -> crate::Result<Self> {
        // `is_empty` looks at the `info` metadata while `is_packed` reads `proved_lists`: a
        // malformed list may have one empty and not the other, so check both
        if h_proved_lists.is_empty() || h_proved_lists.ct_list.proved_lists.is_empty() {
            return Err(crate::error!(
                "Cannot expand an empty compact ciphertext list on GPUs"
            ));
        }
        if !h_proved_lists.is_packed() {
            return Err(crate::error!(
                "Only packed lists are supported on GPUs (built with build_with_proof_packed)"
            ));
        }
        let h_vec_compact_lists = h_proved_lists
            .ct_list
            .proved_lists
            .iter()
            .map(|(list, _)| list.clone())
            .collect_vec();
        let d_compact_lists =
            CudaFlattenedVecCompactCiphertextList::from_vec_shortint_compact_ciphertext_list(
                &h_vec_compact_lists,
                h_proved_lists.info.clone(),
                streams,
            )?;

        Ok(Self {
            h_proved_lists: h_proved_lists.clone(),
            d_flattened_compact_lists: d_compact_lists,
        })
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

        Self::from_proven_compact_ciphertext_list(&cpu_ct, &streams)
            .map_err(serde::de::Error::custom)
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

    use crate::conformance::ParameterSetConformant;
    use crate::core_crypto::gpu::CudaStreams;
    use crate::core_crypto::prelude::LweCiphertextCount;
    use crate::integer::ciphertext::{
        CompactCiphertextList, DataKind, IntegerProvenCompactCiphertextListConformanceParams,
    };
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

    /// [`Result::unwrap_err`] requires `T: Debug`, which the CUDA types do not implement
    #[track_caller]
    fn expect_err<T>(result: crate::Result<T>) -> crate::Error {
        match result {
            Ok(_) => panic!("expected an error, got a value"),
            Err(err) => err,
        }
    }

    /// Keys and crs shared by the tests checking that malicious, but conformant, lists are
    /// rejected gracefully
    struct MaliciousListTestContext {
        streams: CudaStreams,
        crs: CompactPkeCrs,
        pk: CompactPublicKey,
        pke_params: CompactPublicKeyEncryptionParameters,
        d_ksk_material: CudaKeySwitchingKeyMaterial,
        gpu_sk: CudaServerKey,
    }

    impl MaliciousListTestContext {
        fn new() -> Self {
            let ksk_params = PARAM_KEYSWITCH_TO_SMALL_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
            let pke_params = PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
            let fhe_params: PBSParameters = PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128.into();

            let crs_blocks_for_64_bits = 64
                / ((pke_params.message_modulus.0 * pke_params.carry_modulus.0).ilog2() as usize);

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
            let pk = CompactPublicKey::new(&compact_private_key);

            Self {
                streams,
                crs,
                pk,
                pke_params,
                d_ksk_material,
                gpu_sk,
            }
        }

        fn cuda_ksk(&self) -> CudaKeySwitchingKey<'_> {
            CudaKeySwitchingKey::from_cuda_key_switching_key_material(
                &self.d_ksk_material,
                &self.gpu_sk,
            )
        }

        fn conformance_params(&self) -> IntegerProvenCompactCiphertextListConformanceParams {
            IntegerProvenCompactCiphertextListConformanceParams::from_crs_and_parameters(
                self.pke_params,
                &self.crs,
            )
        }
    }

    /// Strings are not supported on GPUs, but a list holding a [`DataKind::String`] is perfectly
    /// conformant. The list is attacker controlled data, so every GPU entry point must reject it
    /// with an error instead of panicking, otherwise this is a denial of service vector.
    #[test]
    fn test_malicious_string_proven_lists() {
        let ctx = MaliciousListTestContext::new();
        let metadata = b"integer";

        let encryption_num_blocks = 64 / (ctx.pke_params.message_modulus.0.ilog2() as usize);
        let msgs = (0..2).map(|_| random::<u64>()).collect::<Vec<_>>();

        let mut proven_ct = CompactCiphertextList::builder(&ctx.pk)
            .extend_with_num_blocks(msgs.iter().copied(), encryption_num_blocks)
            .build_with_proof_packed(&ctx.crs, metadata, ZkComputeLoad::Proof)
            .unwrap();

        // Replace the metadata by one describing a string spanning exactly the same number of
        // blocks, which keeps the list conformant
        let total_block_count: usize = (0..proven_ct.len())
            .map(|idx| {
                proven_ct
                    .get_kind_of(idx)
                    .unwrap()
                    .num_blocks(ctx.pke_params.message_modulus)
            })
            .sum();
        let blocks_per_char = 7u32.div_ceil(ctx.pke_params.message_modulus.0.ilog2()) as usize;

        let mut new_infos = vec![DataKind::String {
            n_chars: (total_block_count / blocks_per_char) as u32,
            padded: false,
        }];
        if let Some(count) = NonZero::new(total_block_count % blocks_per_char) {
            new_infos.push(DataKind::Unsigned(count));
        }
        assert_eq!(
            new_infos
                .iter()
                .map(|x| x.num_blocks(ctx.pke_params.message_modulus))
                .sum::<usize>(),
            total_block_count
        );
        *proven_ct.infos_mut_gpu() = new_infos;

        // The crafted list still passes the conformance checks ...
        assert!(proven_ct.is_conformant(&ctx.conformance_params()));

        // ... so moving it to the GPU must fail gracefully
        let err = expect_err(
            CudaProvenCompactCiphertextList::from_proven_compact_ciphertext_list(
                &proven_ct,
                &ctx.streams,
            ),
        );
        assert!(
            err.to_string().contains("Strings are not supported on GPUs"),
            "unexpected error: {err}"
        );

        // A string appearing only after the list reached the device must be rejected by expand()
        // as well
        let mut gpu_list = {
            let mut sane = proven_ct.clone();
            *sane.infos_mut_gpu() = vec![DataKind::Unsigned(
                NonZero::new(total_block_count).unwrap(),
            )];
            CudaProvenCompactCiphertextList::from_proven_compact_ciphertext_list(
                &sane,
                &ctx.streams,
            )
            .unwrap()
        };
        gpu_list.d_flattened_compact_lists.data_info = vec![DataKind::String {
            n_chars: (total_block_count / blocks_per_char) as u32,
            padded: false,
        }];
        let err = expect_err(gpu_list.expand_without_verification(&ctx.cuda_ksk(), &ctx.streams));
        assert!(
            err.to_string().contains("Strings are not supported on GPUs"),
            "unexpected error: {err}"
        );
    }

    /// An empty list is conformant, the GPU does not support it, so it must be reported as an
    /// error instead of panicking.
    #[test]
    fn test_empty_proven_list_on_gpu() {
        let ctx = MaliciousListTestContext::new();
        let metadata = b"integer";

        let proven_ct = CompactCiphertextList::builder(&ctx.pk)
            .build_with_proof_packed(&ctx.crs, metadata, ZkComputeLoad::Proof)
            .unwrap();

        assert!(proven_ct.is_empty());
        assert!(proven_ct.is_conformant(&ctx.conformance_params()));

        let err = expect_err(
            CudaProvenCompactCiphertextList::from_proven_compact_ciphertext_list(
                &proven_ct,
                &ctx.streams,
            ),
        );
        assert!(
            err.to_string()
                .contains("Cannot expand an empty compact ciphertext list on GPUs"),
            "unexpected error: {err}"
        );
    }

    /// A list whose `info` metadata is not empty while it holds no ciphertext at all is not
    /// conformant, but it must still be rejected with an error rather than a panic.
    #[test]
    fn test_proven_list_without_ciphertexts_on_gpu() {
        let ctx = MaliciousListTestContext::new();
        let metadata = b"integer";

        let mut proven_ct = CompactCiphertextList::builder(&ctx.pk)
            .push(1u8)
            .build_with_proof_packed(&ctx.crs, metadata, ZkComputeLoad::Proof)
            .unwrap();

        proven_ct.ct_list.proved_lists = Vec::new();
        assert!(!proven_ct.is_conformant(&ctx.conformance_params()));

        let err = expect_err(
            CudaProvenCompactCiphertextList::from_proven_compact_ciphertext_list(
                &proven_ct,
                &ctx.streams,
            ),
        );
        assert!(
            err.to_string()
                .contains("Cannot expand an empty compact ciphertext list on GPUs"),
            "unexpected error: {err}"
        );
    }

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
            let metadata = b"integer";

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
                .build_with_proof_packed(&crs, metadata, ZkComputeLoad::Proof)
                .unwrap();
            let gpu_proven_ct =
                CudaProvenCompactCiphertextList::from_proven_compact_ciphertext_list(
                    &proven_ct, &streams,
                )
                .unwrap();

            let gpu_expander = gpu_proven_ct
                .verify_and_expand(&crs, &pk, metadata, &d_ksk, &streams)
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
            let metadata = b"integer";

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
                .build_with_proof_packed(&crs, metadata, ZkComputeLoad::Proof)
                .unwrap();
            let gpu_proven_ct =
                CudaProvenCompactCiphertextList::from_proven_compact_ciphertext_list(
                    &proven_ct, &streams,
                )
                .unwrap();

            let gpu_expander = gpu_proven_ct
                .verify_and_expand(&crs, &pk, metadata, &d_ksk, &streams)
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
            let metadata = b"integer";

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
                .build_with_proof_packed(&crs, metadata, ZkComputeLoad::Proof)
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
                )
                .unwrap();

            let gpu_expander = gpu_proven_ct
                .verify_and_expand(&crs, &pk, metadata, &d_ksk, &streams)
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

    #[test]
    fn test_expander_length_matches_data_items() {
        // This test ensures len() returns the number of data items, not the total number of blocks.
        use crate::high_level_api::prelude::*;
        use crate::high_level_api::set_server_key;
        use crate::zk::ZkComputeLoad;

        let params = crate::shortint::parameters::PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
        let cpk_params =
            crate::shortint::parameters::PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
        let casting_params =
            crate::shortint::parameters::PARAM_KEYSWITCH_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;

        let config = crate::ConfigBuilder::with_custom_parameters(params)
            .use_dedicated_compact_public_key_parameters((cpk_params, casting_params))
            .build();

        let client_key = crate::ClientKey::generate(config);
        let compressed_server_key = crate::CompressedServerKey::new(&client_key);
        let gpu_server_key = compressed_server_key.decompress_to_gpu();

        let crs = CompactPkeCrs::from_config(config, 64).unwrap();
        let public_key = crate::CompactPublicKey::try_new(&client_key).unwrap();
        let metadata = b"TFHE-rs";

        // Create a proven compact list with 6 items (matching user's scenario)
        let m0 = true;
        let m1 = 42u8;
        let m2 = 42u8;
        let m3 = 12345u16;
        let m4 = 67890u32;
        let m5 = 1234567890u64;
        let proven_compact_list = crate::ProvenCompactCiphertextList::builder(&public_key)
            .push(m0)
            .push(m1)
            .push(m2)
            .push(m3)
            .push(m4)
            .push(m5)
            .build_with_proof_packed(&crs, metadata, ZkComputeLoad::Verify)
            .unwrap();

        // Set GPU server key
        set_server_key(gpu_server_key);

        // Verify and expand on GPU
        let expander = proven_compact_list
            .verify_and_expand(&crs, &public_key, metadata)
            .unwrap();

        // The expander should have length 6 (number of data items), not 66 (total blocks)
        assert_eq!(
            expander.len(),
            6,
            "Expander length should be 6 (number of data items), not the total number of blocks"
        );

        // Verify we can get the kind for all 6 items
        assert!(
            expander.get_kind_of(0).is_some(),
            "Should be able to get kind at index 0"
        );
        assert!(
            expander.get_kind_of(1).is_some(),
            "Should be able to get kind at index 1"
        );
        assert!(
            expander.get_kind_of(2).is_some(),
            "Should be able to get kind at index 2"
        );
        assert!(
            expander.get_kind_of(3).is_some(),
            "Should be able to get kind at index 3"
        );
        assert!(
            expander.get_kind_of(4).is_some(),
            "Should be able to get kind at index 4"
        );
        assert!(
            expander.get_kind_of(5).is_some(),
            "Should be able to get kind at index 5"
        );

        // Verify indices beyond the data item count return None
        assert!(
            expander.get_kind_of(6).is_none(),
            "Index 6 should return None (beyond data item count)"
        );
        assert!(
            expander.get_kind_of(65).is_none(),
            "Index 65 should return None (beyond data item count)"
        );

        // Verify we can actually retrieve the values
        let bool_val: crate::FheBool = expander.get(0).unwrap().unwrap();
        let u8_val_1: crate::FheUint8 = expander.get(1).unwrap().unwrap();
        let u8_val_2: crate::FheUint8 = expander.get(2).unwrap().unwrap();
        let u16_val: crate::FheUint16 = expander.get(3).unwrap().unwrap();
        let u32_val: crate::FheUint32 = expander.get(4).unwrap().unwrap();
        let u64_val: crate::FheUint64 = expander.get(5).unwrap().unwrap();

        // Check if we retrieve the original values after decryption
        let decrypted_m0: bool = bool_val.decrypt(&client_key);
        assert_eq!(decrypted_m0, m0);
        let decrypted_m1: u8 = u8_val_1.decrypt(&client_key);
        assert_eq!(decrypted_m1, m1);
        let decrypted_m2: u8 = u8_val_2.decrypt(&client_key);
        assert_eq!(decrypted_m2, m2);
        let decrypted_m3: u16 = u16_val.decrypt(&client_key);
        assert_eq!(decrypted_m3, m3);
        let decrypted_m4: u32 = u32_val.decrypt(&client_key);
        assert_eq!(decrypted_m4, m4);
        let decrypted_m5: u64 = u64_val.decrypt(&client_key);
        assert_eq!(decrypted_m5, m5);
    }
}
