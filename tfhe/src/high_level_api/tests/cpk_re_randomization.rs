use crate::high_level_api::prelude::*;
use crate::high_level_api::{
    CompactPublicKey, CompressedCiphertextListBuilder, FheBool, FheInt8, FheUint64,
    ReRandomizationContext,
};
use crate::shortint::parameters::v1_5::meta::cpu::V1_5_META_PARAM_CPU_2_2_KS_PBS_PKE_TO_BIG_ZKV2_TUNIFORM_2M128;
use crate::shortint::parameters::v1_6::meta::cpu::V1_6_META_PARAM_CPU_2_2_KS_PBS_PKE_TO_BIG_ZKV2_TUNIFORM_2M128;
use crate::shortint::parameters::MetaParameters;
use crate::{set_server_key, ClientKey, CompressedServerKey, ReRandomizationSupport, ServerKey};

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
                #[allow(deprecated)]
                a.re_randomize(cpk, seed_gen.next_seed().unwrap()).unwrap();
                #[allow(deprecated)]
                b.re_randomize(cpk, seed_gen.next_seed().unwrap()).unwrap();
            }
            ReRandomizationSupport::DerivedCPKWithoutKeySwitch => {
                a.re_randomize_without_keyswitch(seed_gen.next_seed().unwrap())
                    .unwrap();
                b.re_randomize_without_keyswitch(seed_gen.next_seed().unwrap())
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
                #[allow(deprecated)]
                a.re_randomize(cpk, seed_gen.next_seed().unwrap()).unwrap();
                #[allow(deprecated)]
                b.re_randomize(cpk, seed_gen.next_seed().unwrap()).unwrap();
            }
            ReRandomizationSupport::DerivedCPKWithoutKeySwitch => {
                a.re_randomize_without_keyswitch(seed_gen.next_seed().unwrap())
                    .unwrap();
                b.re_randomize_without_keyswitch(seed_gen.next_seed().unwrap())
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
                        #[allow(deprecated)]
                        a.re_randomize(cpk, seed_gen.next_seed().unwrap()).unwrap();
                        #[allow(deprecated)]
                        b.re_randomize(cpk, seed_gen.next_seed().unwrap()).unwrap();
                    }
                    ReRandomizationSupport::DerivedCPKWithoutKeySwitch => {
                        a.re_randomize_without_keyswitch(seed_gen.next_seed().unwrap())
                            .unwrap();
                        b.re_randomize_without_keyswitch(seed_gen.next_seed().unwrap())
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
    // for legacy params
    use crate::shortint::parameters::v1_5::meta::gpu::V1_5_META_PARAM_GPU_2_2_MULTI_BIT_GROUP_4_KS_PBS_PKE_TO_BIG_ZKV2_TUNIFORM_2M128;

    #[test]
    fn test_gpu_legacy_re_rand() {
        let params =
            V1_5_META_PARAM_GPU_2_2_MULTI_BIT_GROUP_4_KS_PBS_PKE_TO_BIG_ZKV2_TUNIFORM_2M128;
        let (cks, sks, cpk) = setup_re_rand_test(params);

        set_server_key(sks.decompress_to_gpu());

        execute_re_rand_test(&cks, &cpk);
    }
}
