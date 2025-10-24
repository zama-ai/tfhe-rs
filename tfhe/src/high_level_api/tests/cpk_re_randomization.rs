use crate::high_level_api::prelude::*;
use crate::high_level_api::{
    CompactPublicKey, CompressedCiphertextListBuilder, ConfigBuilder, FheBool, FheInt8, FheUint64,
    ReRandomizationContext,
};
use crate::shortint::parameters::v1_5::meta::cpu::V1_5_META_PARAM_CPU_2_2_KS_PBS_PKE_TO_BIG_ZKV2_TUNIFORM_2M128;
#[cfg(feature = "gpu")]
use crate::shortint::parameters::v1_5::meta::gpu::V1_5_META_PARAM_GPU_2_2_MULTI_BIT_GROUP_4_KS_PBS_PKE_TO_BIG_ZKV2_TUNIFORM_2M128;
use crate::shortint::parameters::{MetaParameters, ShortintKeySwitchingParameters};
use crate::{set_server_key, ClientKey, CompressedServerKey};

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

        a.re_randomize(cpk, seed_gen.next_seed().unwrap()).unwrap();
        assert!(a.re_randomization_metadata().data().is_empty());

        b.re_randomize(cpk, seed_gen.next_seed().unwrap()).unwrap();
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

        a.re_randomize(cpk, seed_gen.next_seed().unwrap()).unwrap();
        assert!(a.re_randomization_metadata().data().is_empty());

        b.re_randomize(cpk, seed_gen.next_seed().unwrap()).unwrap();
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

                a.re_randomize(cpk, seed_gen.next_seed().unwrap()).unwrap();
                assert!(a.re_randomization_metadata().data().is_empty());

                b.re_randomize(cpk, seed_gen.next_seed().unwrap()).unwrap();
                assert!(b.re_randomization_metadata().data().is_empty());

                let c = a & b;
                let dec: bool = c.decrypt(cks);

                assert_eq!(clear_a && clear_b, dec);
            }
        }
    }
}

fn setup_re_rand_test(
    params: MetaParameters,
) -> (crate::ClientKey, CompressedServerKey, CompactPublicKey) {
    let cpk_params = (
        params
            .dedicated_compact_public_key_parameters
            .unwrap()
            .pke_params,
        params
            .dedicated_compact_public_key_parameters
            .unwrap()
            .ksk_params,
    );
    let comp_params = params.compression_parameters.unwrap();
    let compute_params = params.compute_parameters;
    let ksk_params = ShortintKeySwitchingParameters::new(
        compute_params.ks_base_log(),
        compute_params.ks_level(),
        compute_params.encryption_key_choice(),
    );

    let config = ConfigBuilder::with_custom_parameters(compute_params)
        .use_dedicated_compact_public_key_parameters(cpk_params)
        .enable_compression(comp_params)
        .enable_ciphertext_re_randomization(ksk_params)
        .build();

    let cks = crate::ClientKey::generate(config);
    let sks = cks.generate_compressed_server_key();
    let cpk = CompactPublicKey::new(&cks);

    (cks, sks, cpk)
}

#[test]
fn test_re_rand() {
    let params = V1_5_META_PARAM_CPU_2_2_KS_PBS_PKE_TO_BIG_ZKV2_TUNIFORM_2M128;
    let (cks, sks, cpk) = setup_re_rand_test(params);

    set_server_key(sks.decompress());

    execute_re_rand_test(&cks, &cpk);
}

#[cfg(feature = "gpu")]
#[test]
fn test_gpu_re_rand() {
    let params = V1_5_META_PARAM_GPU_2_2_MULTI_BIT_GROUP_4_KS_PBS_PKE_TO_BIG_ZKV2_TUNIFORM_2M128;
    let (cks, sks, cpk) = setup_re_rand_test(params);

    set_server_key(sks.decompress_to_gpu());

    execute_re_rand_test(&cks, &cpk);
}
