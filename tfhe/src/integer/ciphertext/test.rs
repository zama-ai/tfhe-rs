use crate::integer::ciphertext::compressed_ciphertext_list::*;
use crate::integer::ciphertext::{ReRandomizationContext, ReRandomizationKey};
use crate::integer::key_switching_key::{KeySwitchingKeyBuildHelper, KeySwitchingKeyMaterial};
use crate::integer::{
    gen_keys, BooleanBlock, CompactPrivateKey, CompactPublicKey, IntegerKeyKind, RadixCiphertext,
    SignedRadixCiphertext,
};
use crate::shortint::parameters::test_params::{
    TEST_COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    TEST_PARAM_KEYSWITCH_PKE_TO_BIG_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    TEST_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    TEST_PARAM_PKE_TO_BIG_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128_ZKV2,
};
use crate::shortint::parameters::{
    CompactPublicKeyEncryptionParameters, CompressionParameters, ReRandomizationParameters,
};
use crate::shortint::ShortintParameterSet;
use itertools::Itertools;
use rand::Rng;

const NB_TESTS: usize = 10;
const NUM_BLOCKS: usize = 32;

#[test]
fn test_ciphertext_re_randomization_after_compression_with_dedicated_cpk() {
    let params = TEST_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
    let comp_params = TEST_COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
    let cpk_params = TEST_PARAM_PKE_TO_BIG_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128_ZKV2;
    let rerand_ksk_params = TEST_PARAM_KEYSWITCH_PKE_TO_BIG_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;

    let rerand_params =
        ReRandomizationParameters::LegacyDedicatedCPKWithKeySwitch { rerand_ksk_params };

    test_ciphertext_re_randomization_after_compression_impl(
        params.into(),
        comp_params,
        Some(cpk_params),
        rerand_params,
    );
}

#[test]
fn test_ciphertext_re_randomization_after_compression_with_derived_cpk() {
    let params = TEST_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
    let comp_params = TEST_COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
    let rerand_params = ReRandomizationParameters::DerivedCPKWithoutKeySwitch;

    test_ciphertext_re_randomization_after_compression_impl(
        params.into(),
        comp_params,
        None,
        rerand_params,
    );
}

fn test_ciphertext_re_randomization_after_compression_impl(
    params: ShortintParameterSet,
    comp_params: CompressionParameters,
    cpk_params: Option<CompactPublicKeyEncryptionParameters>,
    rerand_params: ReRandomizationParameters,
) {
    let (cks, sks) = gen_keys::<ShortintParameterSet>(params, IntegerKeyKind::Radix);

    let private_compression_key = cks.new_compression_private_key(comp_params);

    let (compression_key, decompression_key) =
        cks.new_compression_decompression_keys(&private_compression_key);

    let cpk;
    let rerand_ksk: KeySwitchingKeyMaterial;
    let re_randomization_key = match (cpk_params, rerand_params) {
        (
            Some(cpk_params),
            ReRandomizationParameters::LegacyDedicatedCPKWithKeySwitch { rerand_ksk_params },
        ) => {
            let dedicated_compact_private_key = CompactPrivateKey::new(cpk_params);
            cpk = CompactPublicKey::new(&dedicated_compact_private_key);
            rerand_ksk = KeySwitchingKeyBuildHelper::new(
                (&dedicated_compact_private_key, None),
                (&cks, &sks),
                rerand_ksk_params,
            )
            .into();
            ReRandomizationKey::LegacyDedicatedCPK {
                cpk: &cpk,
                ksk: rerand_ksk.as_view(),
            }
        }
        // For this test we use the cks directly which is instantiated from the compute
        // params, we need the secret key to be the same otherwise we would have
        // inconsistencies in the encryptions being used
        (None, ReRandomizationParameters::DerivedCPKWithoutKeySwitch) => {
            let derived_compact_private_key: CompactPrivateKey<&[u64]> = (&cks).try_into().unwrap();
            cpk = CompactPublicKey::new(&derived_compact_private_key);
            ReRandomizationKey::DerivedCPKWithoutKeySwitch { cpk: &cpk }
        }
        _ => panic!("Inconsistent rerand test setup"),
    };

    let rerand_domain_separator = *b"TFHE_Rrd";
    let compact_public_encryption_domain_separator = *b"TFHE_Enc";
    let metadata = b"lol".as_slice();

    let mut rng = rand::thread_rng();

    let message_modulus: u128 = cks.parameters().message_modulus().0 as u128;

    // Unsigned
    let modulus = message_modulus.pow(NUM_BLOCKS as u32);
    for _ in 0..NB_TESTS {
        let message = rng.gen::<u128>() % modulus;

        let ct = cks.encrypt_radix(message, NUM_BLOCKS);

        let mut builder = CompressedCiphertextListBuilder::new();

        builder.push(ct);

        let compressed = builder.build(&compression_key);

        let decompressed: RadixCiphertext = compressed.get(0, &decompression_key).unwrap().unwrap();

        let mut re_randomizer_context = ReRandomizationContext::new(
            rerand_domain_separator,
            [metadata],
            compact_public_encryption_domain_separator,
        );

        re_randomizer_context.add_ciphertext(&decompressed);

        let mut seed_gen = re_randomizer_context.finalize();

        let mut re_randomized = decompressed.clone();
        re_randomized
            .re_randomize(re_randomization_key, seed_gen.next_seed().unwrap())
            .unwrap();

        assert_ne!(decompressed, re_randomized);

        let decrypted: u128 = cks.decrypt_radix(&re_randomized);
        assert_eq!(decrypted, message);
    }

    // Signed
    let modulus = message_modulus.pow((NUM_BLOCKS - 1) as u32) as i128;
    for _ in 0..NB_TESTS {
        let message = rng.gen::<i128>() % modulus;

        let ct = cks.encrypt_signed_radix(message, NUM_BLOCKS);

        let mut builder = CompressedCiphertextListBuilder::new();

        builder.push(ct);

        let compressed = builder.build(&compression_key);

        let decompressed: SignedRadixCiphertext =
            compressed.get(0, &decompression_key).unwrap().unwrap();

        let mut re_randomizer_context = ReRandomizationContext::new(
            rerand_domain_separator,
            [metadata],
            compact_public_encryption_domain_separator,
        );

        re_randomizer_context.add_ciphertext(&decompressed);

        let mut seed_gen = re_randomizer_context.finalize();

        let mut re_randomized = decompressed.clone();
        re_randomized
            .re_randomize(re_randomization_key, seed_gen.next_seed().unwrap())
            .unwrap();

        assert_ne!(decompressed, re_randomized);

        let decrypted: i128 = cks.decrypt_signed_radix(&re_randomized);
        assert_eq!(decrypted, message);
    }

    // Boolean
    for _ in 0..NB_TESTS {
        let messages = [false, true];

        let cts = messages
            .iter()
            .map(|message| cks.encrypt_bool(*message))
            .collect_vec();

        let mut builder = CompressedCiphertextListBuilder::new();

        builder.extend(cts.into_iter());

        let compressed = builder.build(&compression_key);

        for (i, message) in messages.iter().enumerate() {
            let decompressed: BooleanBlock =
                compressed.get(i, &decompression_key).unwrap().unwrap();

            let mut re_randomizer_context = ReRandomizationContext::new(
                rerand_domain_separator,
                [metadata],
                compact_public_encryption_domain_separator,
            );

            re_randomizer_context.add_ciphertext(&decompressed);

            let mut seed_gen = re_randomizer_context.finalize();

            let mut re_randomized = decompressed.clone();
            re_randomized
                .re_randomize(re_randomization_key, seed_gen.next_seed().unwrap())
                .unwrap();

            assert_ne!(decompressed, re_randomized);

            let decrypted = cks.decrypt_bool(&re_randomized);
            assert_eq!(decrypted, *message);
        }
    }
}

#[cfg(feature = "zk-pok")]
mod zk {
    use crate::core_crypto::prelude::LweCiphertextCount;
    use crate::integer::ciphertext::{ProvenCompactCiphertextList, ReRandomizationContext};
    use crate::integer::key_switching_key::KeySwitchingKey;
    use crate::integer::parameters::IntegerCompactCiphertextListExpansionMode;
    use crate::integer::{
        BooleanBlock, ClientKey, CompactPrivateKey, CompactPublicKey, RadixCiphertext, ServerKey,
        SignedRadixCiphertext,
    };
    use crate::shortint::parameters::test_params::{
        TEST_PARAM_KEYSWITCH_PKE_TO_BIG_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        TEST_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        TEST_PARAM_PKE_TO_BIG_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128_ZKV2,
    };
    use crate::zk::{CompactPkeCrs, ZkComputeLoad};
    use rand::Rng;

    #[test]
    fn test_proven_compact_ciphertext_list_re_randomization() {
        let pke_params = TEST_PARAM_PKE_TO_BIG_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128_ZKV2;
        let ksk_params = TEST_PARAM_KEYSWITCH_PKE_TO_BIG_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
        let fhe_params = TEST_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;

        let num_blocks = 4usize;
        let metadata = *b"test";
        let rerand_domain_separator = *b"TFHE_Rrd";
        let compact_public_encryption_domain_separator = *b"TFHE_Enc";

        let cks = ClientKey::new(fhe_params);
        let sks = ServerKey::new_radix_server_key(&cks);
        let compact_private_key = CompactPrivateKey::new(pke_params);
        let ksk = KeySwitchingKey::new((&compact_private_key, None), (&cks, &sks), ksk_params);
        let pk = CompactPublicKey::new(&compact_private_key);

        let crs = CompactPkeCrs::from_shortint_params(pke_params, LweCiphertextCount(512)).unwrap();

        let mut rng = rand::thread_rng();
        let message_modulus = pke_params.message_modulus.0 as u128;

        // Unsigned
        {
            let modulus = message_modulus.pow(num_blocks as u32);
            let message = rng.gen::<u128>() % modulus;

            let mut builder = ProvenCompactCiphertextList::builder(&pk);
            builder.push_with_num_blocks(message, num_blocks);

            let proven_ct = builder
                .build_with_proof_packed(&crs, &metadata, ZkComputeLoad::Proof)
                .unwrap();

            let mut re_rand_context = ReRandomizationContext::new(
                rerand_domain_separator,
                [metadata.as_slice()],
                compact_public_encryption_domain_separator,
            );

            re_rand_context.add_proven_ciphertext_list(&proven_ct);

            let mut seed_gen = re_rand_context.finalize();

            let mut re_randomized = proven_ct.clone();
            re_randomized
                .re_randomize(&pk, seed_gen.next_seed().unwrap())
                .unwrap();

            assert!(proven_ct != re_randomized);

            let expander = re_randomized
                .expand_without_verification(
                    IntegerCompactCiphertextListExpansionMode::CastAndUnpackIfNecessary(
                        ksk.as_view(),
                    ),
                )
                .unwrap();

            let expanded: RadixCiphertext = expander.get(0).unwrap().unwrap();
            let decrypted: u128 = cks.decrypt_radix(&expanded);
            assert_eq!(decrypted, message);
        }

        // Signed
        {
            let modulus = message_modulus.pow((num_blocks - 1) as u32) as i128;
            let message = rng.gen::<i128>() % modulus;

            let mut builder = ProvenCompactCiphertextList::builder(&pk);
            builder.push_with_num_blocks(message, num_blocks);

            let proven_ct = builder
                .build_with_proof_packed(&crs, &metadata, ZkComputeLoad::Proof)
                .unwrap();

            let mut re_rand_context = ReRandomizationContext::new(
                rerand_domain_separator,
                [metadata.as_slice()],
                compact_public_encryption_domain_separator,
            );

            re_rand_context.add_proven_ciphertext_list(&proven_ct);

            let mut seed_gen = re_rand_context.finalize();

            let mut re_randomized = proven_ct.clone();
            re_randomized
                .re_randomize(&pk, seed_gen.next_seed().unwrap())
                .unwrap();

            assert!(proven_ct != re_randomized);

            let expander = re_randomized
                .expand_without_verification(
                    IntegerCompactCiphertextListExpansionMode::CastAndUnpackIfNecessary(
                        ksk.as_view(),
                    ),
                )
                .unwrap();

            let expanded: SignedRadixCiphertext = expander.get(0).unwrap().unwrap();
            let decrypted: i128 = cks.decrypt_signed_radix(&expanded);
            assert_eq!(decrypted, message);
        }

        // Boolean
        {
            for message in [false, true] {
                let mut builder = ProvenCompactCiphertextList::builder(&pk);
                builder.push(message);

                let proven_ct = builder
                    .build_with_proof_packed(&crs, &metadata, ZkComputeLoad::Proof)
                    .unwrap();

                let mut re_rand_context = ReRandomizationContext::new(
                    rerand_domain_separator,
                    [metadata.as_slice()],
                    compact_public_encryption_domain_separator,
                );

                re_rand_context.add_proven_ciphertext_list(&proven_ct);

                let mut seed_gen = re_rand_context.finalize();

                let mut re_randomized = proven_ct.clone();
                re_randomized
                    .re_randomize(&pk, seed_gen.next_seed().unwrap())
                    .unwrap();

                assert!(proven_ct != re_randomized);

                let expander = re_randomized
                    .expand_without_verification(
                        IntegerCompactCiphertextListExpansionMode::CastAndUnpackIfNecessary(
                            ksk.as_view(),
                        ),
                    )
                    .unwrap();

                let expanded: BooleanBlock = expander.get(0).unwrap().unwrap();
                let decrypted = cks.decrypt_bool(&expanded);
                assert_eq!(decrypted, message);
            }
        }
    }

    #[cfg(feature = "gpu")]
    #[test]
    fn test_proven_compact_ciphertext_list_re_rand_cpu_gpu_compatibility() {
        use crate::core_crypto::gpu::CudaStreams;
        use crate::integer::gpu::zk::CudaProvenCompactCiphertextList;
        use crate::shortint::parameters::test_params::TEST_PARAM_PKE_TO_SMALL_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128_ZKV2;

        let pke_params = TEST_PARAM_PKE_TO_SMALL_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128_ZKV2;

        let compact_private_key = CompactPrivateKey::new(pke_params);
        let pk = CompactPublicKey::new(&compact_private_key);

        let compact_public_encryption_domain_separator = *b"TFHE_Enc";
        let rerand_domain_separator = *b"TFHE_Rrd";

        // Intentionally low so that we test when multiple lists and proofs are needed
        let crs = CompactPkeCrs::from_shortint_params(pke_params, LweCiphertextCount(8)).unwrap();
        let metadata = b"rerand";

        let clear_a = rand::random::<u64>();
        let clear_b = rand::random::<i8>();

        let proven_ct = ProvenCompactCiphertextList::builder(&pk)
            .push(clear_a)
            .push(clear_b)
            .push(false)
            .build_with_proof_packed(&crs, metadata, ZkComputeLoad::Proof)
            .unwrap();

        // Clone the list so both CPU and GPU start from the same state
        let mut cpu_list = proven_ct.clone();

        // Simulate a 256 bits nonce
        let nonce: [u8; 256 / 8] = core::array::from_fn(|_| rand::random());

        // Create two identical seeds from the same context inputs
        let cpu_seed = {
            let mut ctx = ReRandomizationContext::new(
                rerand_domain_separator,
                [b"expand".as_slice(), nonce.as_slice()],
                compact_public_encryption_domain_separator,
            );
            ctx.add_proven_ciphertext_list(&proven_ct);
            ctx.finalize().next_seed().unwrap()
        };

        let gpu_seed = {
            let mut ctx = ReRandomizationContext::new(
                rerand_domain_separator,
                [b"expand".as_slice(), nonce.as_slice()],
                compact_public_encryption_domain_separator,
            );
            ctx.add_proven_ciphertext_list(&proven_ct);
            ctx.finalize().next_seed().unwrap()
        };

        // Re-randomize on CPU
        cpu_list.re_randomize(&pk, cpu_seed).unwrap();

        // Re-randomize on GPU
        let streams = CudaStreams::new_multi_gpu();
        let mut gpu_list = CudaProvenCompactCiphertextList::from_proven_compact_ciphertext_list(
            &proven_ct, &streams,
        );
        gpu_list.re_randomize(&pk, gpu_seed, &streams).unwrap();

        // Read ciphertext data back from GPU and reconstruct an integer proven list
        let gpu_compact_lists = gpu_list
            .d_flattened_compact_lists
            .to_vec_shortint_compact_ciphertext_list(&streams)
            .unwrap();

        let gpu_proved_lists: Vec<_> = gpu_compact_lists
            .into_iter()
            .zip(gpu_list.h_proved_lists.ct_list.proved_lists.iter())
            .map(|(ct, (_, proof))| (ct, proof.clone()))
            .collect();

        let gpu_on_cpu = ProvenCompactCiphertextList {
            ct_list: crate::shortint::ciphertext::ProvenCompactCiphertextList {
                proved_lists: gpu_proved_lists,
            },
            info: gpu_list.h_proved_lists.info.clone(),
        };

        assert!(cpu_list == gpu_on_cpu);
    }
}
