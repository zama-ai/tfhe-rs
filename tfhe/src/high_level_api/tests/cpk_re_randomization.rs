use crate::high_level_api::prelude::*;
use crate::high_level_api::{
    CompactPublicKey, CompressedCiphertextListBuilder, FheBool, FheInt8, FheUint64,
    ReRandomizationContext,
};
use crate::shortint::parameters::v1_5::meta::cpu::V1_5_META_PARAM_CPU_2_2_KS_PBS_PKE_TO_BIG_ZKV2_TUNIFORM_2M128;
use crate::shortint::parameters::v1_6::meta::cpu::V1_6_META_PARAM_CPU_2_2_KS_PBS_PKE_TO_BIG_ZKV2_TUNIFORM_2M128;
use crate::shortint::parameters::MetaParameters;
use crate::{
    set_server_key, ClientKey, CompressedServerKey, ReRandomizationMode, ReRandomizationSupport,
    ServerKey,
};

#[test]
fn test_dyn_rerand() {
    // Need legacy for nist-like rerand
    let params = V1_5_META_PARAM_CPU_2_2_KS_PBS_PKE_TO_BIG_ZKV2_TUNIFORM_2M128;
    let (cks, sks, cpk) = setup_re_rand_test(params);
    set_server_key(sks.decompress());
    execute_dyn_rerand_test(&cks, &cpk);
}

fn execute_dyn_rerand_test(cks: &ClientKey, cpk: &CompactPublicKey) {
    use crate::high_level_api::re_randomization::NistSubmissionReRandomize;
    fn nist_submission_preproc_eval(
        inputs: &mut [&mut dyn NistSubmissionReRandomize],
        function_description: &[u8],
        compact_public_key: &CompactPublicKey,
    ) {
        let mut re_rand_context =
            ReRandomizationContext::new(*b"TFHE_Rrd", [function_description], *b"TFHE_Enc");

        for input in inputs.iter_mut() {
            re_rand_context.add_ciphertext(&**input);
        }

        let mut seed_gen = re_rand_context.finalize();

        for input in inputs {
            input
                .nist_submission_re_randomize(compact_public_key, seed_gen.next_seed().unwrap())
                .unwrap();
        }
    }

    let clear_a = rand::random::<u64>();
    let clear_b = rand::random::<u64>();
    let mut a = FheUint64::encrypt(clear_a, cks);
    let mut b = FheUint64::encrypt(clear_b, cks);

    // Simulate a 256 bits hash added as metadata
    let rand_a: [u8; 256 / 8] = core::array::from_fn(|_| rand::random());
    let rand_b: [u8; 256 / 8] = core::array::from_fn(|_| rand::random());
    a.re_randomization_metadata_mut().set_data(&rand_a);
    b.re_randomization_metadata_mut().set_data(&rand_b);

    let mut builder = CompressedCiphertextListBuilder::new();
    builder.push(a);
    builder.push(b);
    let list = builder.build().unwrap();

    let mut a: FheUint64 = list.get(0).unwrap().unwrap();
    let mut b: FheUint64 = list.get(1).unwrap().unwrap();

    assert_eq!(a.re_randomization_metadata().data(), &rand_a);
    assert_eq!(b.re_randomization_metadata().data(), &rand_b);

    let mut dyn_cts: Vec<&mut dyn NistSubmissionReRandomize> = vec![&mut a, &mut b];

    nist_submission_preproc_eval(&mut dyn_cts, b"FheUint64+FheUint64".as_slice(), cpk);

    assert!(a.re_randomization_metadata().data().is_empty());
    assert!(b.re_randomization_metadata().data().is_empty());

    let c = a + b;
    let dec: u64 = c.decrypt(cks);

    assert_eq!(clear_a.wrapping_add(clear_b), dec);
}

fn execute_re_rand_test(cks: &ClientKey, cpk: &CompactPublicKey) {
    let compact_public_encryption_domain_separator = *b"TFHE_Enc";
    let rerand_domain_separator = *b"TFHE_Rrd";
    // Case where we want to compute FheUint64 + FheUint64 and re-randomize those inputs
    {
        let clear_a = rand::random::<u64>();
        let clear_b = rand::random::<u64>();
        let mut a = FheUint64::encrypt(clear_a, cks);
        let mut b = FheUint64::encrypt(clear_b, cks);

        // Simulate a 256 bits hash added as metadata
        let rand_a: [u8; 256 / 8] = core::array::from_fn(|_| rand::random());
        let rand_b: [u8; 256 / 8] = core::array::from_fn(|_| rand::random());
        a.re_randomization_metadata_mut().set_data(&rand_a);
        b.re_randomization_metadata_mut().set_data(&rand_b);

        let mut builder = CompressedCiphertextListBuilder::new();
        builder.push(a);
        builder.push(b);
        let list = builder.build().unwrap();

        let mut a: FheUint64 = list.get(0).unwrap().unwrap();
        let mut b: FheUint64 = list.get(1).unwrap().unwrap();

        assert_eq!(a.re_randomization_metadata().data(), &rand_a);
        assert_eq!(b.re_randomization_metadata().data(), &rand_b);

        // Simulate a 256 bits nonce
        let nonce: [u8; 256 / 8] = core::array::from_fn(|_| rand::random());

        let mut re_rand_context = ReRandomizationContext::new(
            rerand_domain_separator,
            // First is the function description, second is a nonce
            [b"FheUint64+FheUint64".as_slice(), nonce.as_slice()],
            compact_public_encryption_domain_separator,
        );

        // Add ciphertexts to the context

        re_rand_context.add_ciphertext(&a);
        re_rand_context.add_ciphertext(&b);

        let mut seed_gen = re_rand_context.finalize();

        match ServerKey::current_server_key_re_randomization_support().unwrap() {
            ReRandomizationSupport::NoSupport => {
                panic!("This test runs rerand, the current ServerKey does not support it")
            }
            ReRandomizationSupport::LegacyDedicatedCPKWithKeySwitch => {
                a.re_randomize(
                    ReRandomizationMode::UseLegacyCPKIfNeeded { cpk },
                    seed_gen.next_seed().unwrap(),
                )
                .unwrap();
                b.re_randomize(
                    ReRandomizationMode::UseLegacyCPKIfNeeded { cpk },
                    seed_gen.next_seed().unwrap(),
                )
                .unwrap();
            }
            ReRandomizationSupport::DerivedCPKWithoutKeySwitch => {
                a.re_randomize(
                    ReRandomizationMode::UseAvailableMode,
                    seed_gen.next_seed().unwrap(),
                )
                .unwrap();
                b.re_randomize(
                    ReRandomizationMode::UseAvailableMode,
                    seed_gen.next_seed().unwrap(),
                )
                .unwrap();
            }
        }

        assert!(a.re_randomization_metadata().data().is_empty());
        assert!(b.re_randomization_metadata().data().is_empty());

        let c = a + b;
        let dec: u64 = c.decrypt(cks);

        assert_eq!(clear_a.wrapping_add(clear_b), dec);
    }

    // Case where we want to compute FheInt8 + FheInt8 and re-randomize those inputs
    {
        let clear_a = rand::random::<i8>();
        let clear_b = rand::random::<i8>();
        let mut a = FheInt8::encrypt(clear_a, cks);
        let mut b = FheInt8::encrypt(clear_b, cks);

        // Simulate a 256 bits hash added as metadata
        let rand_a: [u8; 256 / 8] = core::array::from_fn(|_| rand::random());
        let rand_b: [u8; 256 / 8] = core::array::from_fn(|_| rand::random());
        a.re_randomization_metadata_mut().set_data(&rand_a);
        b.re_randomization_metadata_mut().set_data(&rand_b);

        let mut builder = CompressedCiphertextListBuilder::new();
        builder.push(a);
        builder.push(b);
        let list = builder.build().unwrap();

        let mut a: FheInt8 = list.get(0).unwrap().unwrap();
        let mut b: FheInt8 = list.get(1).unwrap().unwrap();

        assert_eq!(a.re_randomization_metadata().data(), &rand_a);
        assert_eq!(b.re_randomization_metadata().data(), &rand_b);

        // Simulate a 256 bits nonce
        let nonce: [u8; 256 / 8] = core::array::from_fn(|_| rand::random());
        let compact_public_encryption_domain_separator = *b"TFHE_Enc";

        let mut re_rand_context = ReRandomizationContext::new(
            rerand_domain_separator,
            // First is the function description, second is a nonce
            [b"FheInt8+FheInt8".as_slice(), nonce.as_slice()],
            compact_public_encryption_domain_separator,
        );

        // Add ciphertexts to the context

        re_rand_context.add_ciphertext(&a);
        re_rand_context.add_ciphertext(&b);

        let mut seed_gen = re_rand_context.finalize();

        match ServerKey::current_server_key_re_randomization_support().unwrap() {
            ReRandomizationSupport::NoSupport => {
                panic!("This test runs rerand, the current ServerKey does not support it")
            }
            ReRandomizationSupport::LegacyDedicatedCPKWithKeySwitch => {
                a.re_randomize(
                    ReRandomizationMode::UseLegacyCPKIfNeeded { cpk },
                    seed_gen.next_seed().unwrap(),
                )
                .unwrap();
                b.re_randomize(
                    ReRandomizationMode::UseLegacyCPKIfNeeded { cpk },
                    seed_gen.next_seed().unwrap(),
                )
                .unwrap();
            }
            ReRandomizationSupport::DerivedCPKWithoutKeySwitch => {
                a.re_randomize(
                    ReRandomizationMode::UseAvailableMode,
                    seed_gen.next_seed().unwrap(),
                )
                .unwrap();
                b.re_randomize(
                    ReRandomizationMode::UseAvailableMode,
                    seed_gen.next_seed().unwrap(),
                )
                .unwrap();
            }
        }

        assert!(a.re_randomization_metadata().data().is_empty());
        assert!(b.re_randomization_metadata().data().is_empty());

        let c = a + b;
        let dec: i8 = c.decrypt(cks);

        assert_eq!(clear_a.wrapping_add(clear_b), dec);
    }

    // Case where we want to compute FheBool && FheBool and re-randomize those inputs
    {
        for clear_a in [false, true] {
            for clear_b in [false, true] {
                let mut a = FheBool::encrypt(clear_a, cks);
                let mut b = FheBool::encrypt(clear_b, cks);

                // Simulate a 256 bits hash added as metadata
                let rand_a: [u8; 256 / 8] = core::array::from_fn(|_| rand::random());
                let rand_b: [u8; 256 / 8] = core::array::from_fn(|_| rand::random());
                a.re_randomization_metadata_mut().set_data(&rand_a);
                b.re_randomization_metadata_mut().set_data(&rand_b);

                let mut builder = CompressedCiphertextListBuilder::new();
                builder.push(a);
                builder.push(b);
                let list = builder.build().unwrap();

                let mut a: FheBool = list.get(0).unwrap().unwrap();
                let mut b: FheBool = list.get(1).unwrap().unwrap();

                assert_eq!(a.re_randomization_metadata().data(), &rand_a);
                assert_eq!(b.re_randomization_metadata().data(), &rand_b);

                // Simulate a 256 bits nonce
                let nonce: [u8; 256 / 8] = core::array::from_fn(|_| rand::random());
                let compact_public_encryption_domain_separator = *b"TFHE_Enc";

                let mut re_rand_context = ReRandomizationContext::new(
                    rerand_domain_separator,
                    // First is the function description, second is a nonce
                    [b"FheBool&FheBool".as_slice(), nonce.as_slice()],
                    compact_public_encryption_domain_separator,
                );

                // Add ciphertexts to the context
                re_rand_context.add_ciphertext(&a);
                re_rand_context.add_ciphertext(&b);

                let mut seed_gen = re_rand_context.finalize();

                match ServerKey::current_server_key_re_randomization_support().unwrap() {
                    ReRandomizationSupport::NoSupport => {
                        panic!("This test runs rerand, the current ServerKey does not support it")
                    }
                    ReRandomizationSupport::LegacyDedicatedCPKWithKeySwitch => {
                        a.re_randomize(
                            ReRandomizationMode::UseLegacyCPKIfNeeded { cpk },
                            seed_gen.next_seed().unwrap(),
                        )
                        .unwrap();
                        b.re_randomize(
                            ReRandomizationMode::UseLegacyCPKIfNeeded { cpk },
                            seed_gen.next_seed().unwrap(),
                        )
                        .unwrap();
                    }
                    ReRandomizationSupport::DerivedCPKWithoutKeySwitch => {
                        a.re_randomize(
                            ReRandomizationMode::UseAvailableMode,
                            seed_gen.next_seed().unwrap(),
                        )
                        .unwrap();
                        b.re_randomize(
                            ReRandomizationMode::UseAvailableMode,
                            seed_gen.next_seed().unwrap(),
                        )
                        .unwrap();
                    }
                }

                assert!(a.re_randomization_metadata().data().is_empty());
                assert!(b.re_randomization_metadata().data().is_empty());

                let c = a & b;
                let dec: bool = c.decrypt(cks);

                assert_eq!(clear_a && clear_b, dec);
            }
        }
    }
}

#[cfg(feature = "zk-pok")]
mod zk {
    use super::*;
    use crate::high_level_api::{FheInt64, FheUint32};
    use crate::zk::{CompactPkeCrs, ZkComputeLoad};
    use crate::{Config, ProvenCompactCiphertextList};

    #[test]
    fn test_compact_list_re_rand() {
        use crate::shortint::parameters::test_params::TEST_META_PARAM_CPU_2_2_KS_PBS_PKE_TO_SMALL_ZKV2_TUNIFORM_2M128;

        let params = TEST_META_PARAM_CPU_2_2_KS_PBS_PKE_TO_SMALL_ZKV2_TUNIFORM_2M128;
        let (cks, sks, cpk) = setup_re_rand_test(params);
        set_server_key(sks.decompress());

        let config = Config::from(params);

        let compact_public_encryption_domain_separator = *b"TFHE_Enc";
        let rerand_domain_separator = *b"TFHE_Rrd";

        // Intentionally low so that we test when multiple lists and proofs are needed
        let crs = CompactPkeCrs::from_config(config, 32).unwrap();
        let metadata = [b'r', b'e', b'r', b'a', b'n', b'd'];

        // Case where we want to re-randomize a CompactCiphertextList containing
        // FheUint64, FheInt8, and FheBool
        {
            let clear_a = rand::random::<u64>();
            let clear_b = rand::random::<i8>();

            let compact_list = ProvenCompactCiphertextList::builder(&cpk)
                .push(clear_a)
                .push(clear_b)
                .push(false)
                .build_with_proof_packed(&crs, &metadata, ZkComputeLoad::Proof)
                .unwrap();

            // Simulate a 256 bits nonce
            let nonce: [u8; 256 / 8] = core::array::from_fn(|_| rand::random());

            let mut re_rand_context = ReRandomizationContext::new(
                rerand_domain_separator,
                [b"expand".as_slice(), nonce.as_slice()],
                compact_public_encryption_domain_separator,
            );

            // Add the compact list to the context
            re_rand_context.add_ciphertext(&compact_list);

            let mut seed_gen = re_rand_context.finalize();

            // Verify, re_randomize and expand
            let expander = compact_list
                .verify_re_randomize_and_expand(
                    &crs,
                    &cpk,
                    &metadata,
                    seed_gen.next_seed().unwrap(),
                )
                .unwrap();

            let a: FheUint64 = expander.get(0).unwrap().unwrap();
            let b: FheInt8 = expander.get(1).unwrap().unwrap();
            let c: FheBool = expander.get(2).unwrap().unwrap();

            let dec_a: u64 = a.decrypt(&cks);
            assert_eq!(dec_a, clear_a);
            let dec_b: i8 = b.decrypt(&cks);
            assert_eq!(dec_b, clear_b);
            let dec_c: bool = c.decrypt(&cks);
            assert!(!dec_c);
        }

        // Also test expand_and_re_randomize_without_verification
        {
            let clear_a = rand::random::<u32>();
            let clear_b = rand::random::<i64>();

            let compact_list = ProvenCompactCiphertextList::builder(&cpk)
                .push(clear_a)
                .push(clear_b)
                .push(false)
                .build_with_proof_packed(&crs, &metadata, ZkComputeLoad::Proof)
                .unwrap();

            let nonce: [u8; 256 / 8] = core::array::from_fn(|_| rand::random());

            let mut re_rand_context = ReRandomizationContext::new(
                rerand_domain_separator,
                [b"expand".as_slice(), nonce.as_slice()],
                compact_public_encryption_domain_separator,
            );

            re_rand_context.add_ciphertext(&compact_list);

            let mut seed_gen = re_rand_context.finalize();

            let expander = compact_list
                .re_randomize_and_expand_without_verification(&cpk, seed_gen.next_seed().unwrap())
                .unwrap();

            let a: FheUint32 = expander.get(0).unwrap().unwrap();
            let b: FheInt64 = expander.get(1).unwrap().unwrap();
            let c: FheBool = expander.get(2).unwrap().unwrap();

            let dec_a: u32 = a.decrypt(&cks);
            assert_eq!(dec_a, clear_a);
            let dec_b: i64 = b.decrypt(&cks);
            assert_eq!(dec_b, clear_b);
            let dec_c: bool = c.decrypt(&cks);
            assert!(!dec_c);
        }
    }
}

fn setup_re_rand_test(
    mut params: MetaParameters,
) -> (crate::ClientKey, CompressedServerKey, CompactPublicKey) {
    // we don't use noise squashing
    params.noise_squashing_parameters = None;

    let cks = crate::ClientKey::generate(params);
    let sks = cks.generate_compressed_server_key();
    let cpk = CompactPublicKey::new(&cks);

    (cks, sks, cpk)
}

#[test]
fn test_legacy_re_rand() {
    let params = V1_5_META_PARAM_CPU_2_2_KS_PBS_PKE_TO_BIG_ZKV2_TUNIFORM_2M128;
    let (cks, sks, cpk) = setup_re_rand_test(params);

    set_server_key(sks.decompress());

    execute_re_rand_test(&cks, &cpk);
}

#[test]
fn test_re_rand() {
    let params = V1_6_META_PARAM_CPU_2_2_KS_PBS_PKE_TO_BIG_ZKV2_TUNIFORM_2M128;
    let (cks, sks, cpk) = setup_re_rand_test(params);

    set_server_key(sks.decompress());

    execute_re_rand_test(&cks, &cpk);
}

#[cfg(feature = "gpu")]
mod gpu {
    use super::*;
    use crate::high_level_api::ReRandomizationSeedGen;
    use crate::shortint::parameters::v1_5::meta::gpu::V1_5_META_PARAM_GPU_2_2_MULTI_BIT_GROUP_4_KS_PBS_PKE_TO_BIG_ZKV2_TUNIFORM_2M128;
    use crate::shortint::parameters::v1_6::meta::gpu::V1_6_META_PARAM_GPU_2_2_MULTI_BIT_GROUP_4_KS_PBS_PKE_TO_BIG_ZKV2_TUNIFORM_2M128;

    #[test]
    fn test_gpu_legacy_re_rand() {
        let params =
            V1_5_META_PARAM_GPU_2_2_MULTI_BIT_GROUP_4_KS_PBS_PKE_TO_BIG_ZKV2_TUNIFORM_2M128;
        let (cks, sks, cpk) = setup_re_rand_test(params);

        set_server_key(sks.decompress_to_gpu());

        execute_re_rand_test(&cks, &cpk);
    }

    #[test]
    fn test_gpu_re_rand() {
        let params =
            V1_6_META_PARAM_GPU_2_2_MULTI_BIT_GROUP_4_KS_PBS_PKE_TO_BIG_ZKV2_TUNIFORM_2M128;
        let (cks, sks, cpk) = setup_re_rand_test(params);

        set_server_key(sks.decompress_to_gpu());

        execute_re_rand_test(&cks, &cpk);
    }

    #[test]
    fn test_gpu_legacy_dyn_rerand() {
        let params =
            V1_5_META_PARAM_GPU_2_2_MULTI_BIT_GROUP_4_KS_PBS_PKE_TO_BIG_ZKV2_TUNIFORM_2M128;
        let (cks, sks, cpk) = setup_re_rand_test(params);
        set_server_key(sks.decompress_to_gpu());
        execute_dyn_rerand_test(&cks, &cpk);
    }

    #[test]
    fn test_rerand_gpu_cpu_equivalence() {
        use rand::rngs::StdRng;
        use rand::{Rng, SeedableRng};

        for params in [
            V1_5_META_PARAM_GPU_2_2_MULTI_BIT_GROUP_4_KS_PBS_PKE_TO_BIG_ZKV2_TUNIFORM_2M128,
            V1_6_META_PARAM_GPU_2_2_MULTI_BIT_GROUP_4_KS_PBS_PKE_TO_BIG_ZKV2_TUNIFORM_2M128,
        ] {
            let seed: u64 = std::env::var("TFHE_RS_RERAND_TEST_SEED").ok().map_or_else(
                || rand::thread_rng().gen(),
                |val| {
                    u64::from_str_radix(&val, 16).unwrap_or_else(|_| {
                        panic!("TFHE_RS_RERAND_TEST_SEED={val} is not valid hex u64")
                    })
                },
            );
            println!("test_rerand_gpu_cpu_equivalence {params:?} seed: {seed:x}");
            let mut rng = StdRng::seed_from_u64(seed);

            let (cks, sks, cpk) = setup_re_rand_test(params);
            let cpu_sks = sks.decompress();
            let gpu_sks = sks.decompress_to_gpu();

            execute_rerand_gpu_cpu_equivalence(&cks, &cpk, &cpu_sks, &gpu_sks, &mut rng);
        }
    }

    fn execute_rerand_gpu_cpu_equivalence(
        cks: &crate::ClientKey,
        cpk: &CompactPublicKey,
        cpu_sks: &crate::ServerKey,
        gpu_sks: &crate::CudaServerKey,
        rng: &mut rand::rngs::StdRng,
    ) {
        use rand::Rng;

        rerand_equivalence_for_type::<FheUint64, _>(
            cks,
            cpk,
            cpu_sks,
            gpu_sks,
            b"FheUint64+FheUint64",
            rng.gen(),
            (rng.gen::<u64>(), rng.gen::<u64>()),
            |ct| ct.move_to_current_device(),
        );
        rerand_equivalence_for_type::<FheInt8, _>(
            cks,
            cpk,
            cpu_sks,
            gpu_sks,
            b"FheInt8+FheInt8",
            rng.gen(),
            (rng.gen::<i8>(), rng.gen::<i8>()),
            |ct| ct.move_to_current_device(),
        );
        rerand_equivalence_for_type::<FheBool, _>(
            cks,
            cpk,
            cpu_sks,
            gpu_sks,
            b"FheBool&FheBool",
            rng.gen(),
            (rng.gen::<bool>(), rng.gen::<bool>()),
            |ct| ct.move_to_current_device(),
        );
    }

    fn rerand_equivalence_for_type<T, Clear>(
        cks: &crate::ClientKey,
        cpk: &CompactPublicKey,
        cpu_sks: &crate::ServerKey,
        gpu_sks: &crate::CudaServerKey,
        function_description: &[u8],
        nonce: [u8; 32],
        (clear_a, clear_b): (Clear, Clear),
        move_to_current_device: impl Fn(&mut T),
    ) where
        T: crate::high_level_api::prelude::ReRandomize
            + Clone
            + serde::Serialize
            + FheEncrypt<Clear, crate::ClientKey>
            + FheDecrypt<Clear>,
        Clear: Copy + PartialEq + std::fmt::Debug,
    {
        let rerand_domain_separator = *b"TFHE_Rrd";
        let compact_public_encryption_domain_separator = *b"TFHE_Enc";

        set_server_key(cpu_sks.clone());
        let a_orig = T::encrypt(clear_a, cks);
        let b_orig = T::encrypt(clear_b, cks);

        let mut a_cpu = a_orig.clone();
        let mut b_cpu = b_orig.clone();
        let mut a_gpu = a_orig;
        let mut b_gpu = b_orig;

        let build_context = |a: &T, b: &T| {
            let mut ctx = ReRandomizationContext::new(
                rerand_domain_separator,
                [function_description, nonce.as_slice()],
                compact_public_encryption_domain_separator,
            );
            ctx.add_ciphertext(a);
            ctx.add_ciphertext(b);
            ctx.finalize()
        };

        let mut seed_gen_cpu = build_context(&a_cpu, &b_cpu);
        let mut seed_gen_gpu = build_context(&a_gpu, &b_gpu);

        let mode = ServerKey::current_server_key_re_randomization_support().unwrap();

        let apply_rerand = |ct: &mut T, seed_gen: &mut ReRandomizationSeedGen| match mode {
            ReRandomizationSupport::NoSupport => {
                panic!("ServerKey does not support re-randomization")
            }
            ReRandomizationSupport::LegacyDedicatedCPKWithKeySwitch => {
                ct.re_randomize(
                    ReRandomizationMode::UseLegacyCPKIfNeeded { cpk },
                    seed_gen.next_seed().unwrap(),
                )
                .unwrap();
            }
            ReRandomizationSupport::DerivedCPKWithoutKeySwitch => {
                ct.re_randomize(
                    ReRandomizationMode::UseAvailableMode,
                    seed_gen.next_seed().unwrap(),
                )
                .unwrap();
            }
        };

        apply_rerand(&mut a_cpu, &mut seed_gen_cpu);
        apply_rerand(&mut b_cpu, &mut seed_gen_cpu);

        set_server_key(gpu_sks.clone());

        move_to_current_device(&mut a_gpu);
        move_to_current_device(&mut b_gpu);

        apply_rerand(&mut a_gpu, &mut seed_gen_gpu);
        apply_rerand(&mut b_gpu, &mut seed_gen_gpu);

        assert_ne!(
        bincode::serialize(&a_cpu).unwrap(),
        bincode::serialize(&a_orig.clone()).unwrap(),
                "a: CPU results before and after rerand must differ"
        );

        assert_ne!(
        bincode::serialize(&a_gpu).unwrap(),
        bincode::serialize(&a_orig.clone()).unwrap(),
                "a: GPU results before and after rerand must differ"
        );

        assert_eq!(
            bincode::serialize(&a_cpu).unwrap(),
            bincode::serialize(&a_gpu).unwrap(),
            "a: CPU and GPU rerand produced byte-different ciphertexts (clear_a={clear_a:?})"
        );
        assert_eq!(
            bincode::serialize(&b_cpu).unwrap(),
            bincode::serialize(&b_gpu).unwrap(),
            "b: CPU and GPU rerand produced byte-different ciphertexts (clear_b={clear_b:?})"
        );

        set_server_key(cpu_sks.clone());
        let dec_a: Clear = a_cpu.decrypt(cks);
        let dec_b: Clear = b_cpu.decrypt(cks);
        assert_eq!(dec_a, clear_a);
        assert_eq!(dec_b, clear_b);
    }
}
