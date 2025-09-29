use crate::high_level_api::prelude::*;
use crate::high_level_api::{
    generate_keys, CompactPublicKey, CompressedCiphertextListBuilder, ConfigBuilder, FheBool,
    FheInt8, FheUint64, ReRandomizationContext,
};
use crate::set_server_key;
use crate::shortint::parameters::{
    COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    PARAM_KEYSWITCH_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    PARAM_KEYSWITCH_TO_BIG_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
};

#[test]
fn test_re_rand() {
    let params = PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
    let cpk_params = (
        PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        PARAM_KEYSWITCH_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    );
    let comp_params = COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
    let re_rand_ks_params = PARAM_KEYSWITCH_TO_BIG_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;

    let config = ConfigBuilder::with_custom_parameters(params)
        .use_dedicated_compact_public_key_parameters(cpk_params)
        .enable_compression(comp_params)
        .enable_ciphertext_re_randomization(re_rand_ks_params)
        .build();

    let (cks, sks) = generate_keys(config);
    let cpk = CompactPublicKey::new(&cks);

    let compact_public_encryption_domain_separator = *b"TFHE_Enc";
    let rerand_domain_separator = *b"TFHE_Rrd";

    set_server_key(sks);

    // Case where we want to compute FheUint64 + FheUint64 and re-randomize those inputs
    {
        let clear_a = rand::random::<u64>();
        let clear_b = rand::random::<u64>();
        let mut a = FheUint64::encrypt(clear_a, &cks);
        let mut b = FheUint64::encrypt(clear_b, &cks);

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

        a.re_randomize(&cpk, seed_gen.next_seed().unwrap()).unwrap();
        assert!(a.re_randomization_metadata().data().is_empty());

        b.re_randomize(&cpk, seed_gen.next_seed().unwrap()).unwrap();
        assert!(b.re_randomization_metadata().data().is_empty());

        let c = a + b;
        let dec: u64 = c.decrypt(&cks);

        assert_eq!(clear_a.wrapping_add(clear_b), dec);
    }

    // Case where we want to compute FheInt8 + FheInt8 and re-randomize those inputs
    {
        let clear_a = rand::random::<i8>();
        let clear_b = rand::random::<i8>();
        let mut a = FheInt8::encrypt(clear_a, &cks);
        let mut b = FheInt8::encrypt(clear_b, &cks);

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

        a.re_randomize(&cpk, seed_gen.next_seed().unwrap()).unwrap();
        assert!(a.re_randomization_metadata().data().is_empty());

        b.re_randomize(&cpk, seed_gen.next_seed().unwrap()).unwrap();
        assert!(b.re_randomization_metadata().data().is_empty());

        let c = a + b;
        let dec: i8 = c.decrypt(&cks);

        assert_eq!(clear_a.wrapping_add(clear_b), dec);
    }

    // Case where we want to compute FheBool && FheBool and re-randomize those inputs
    {
        for clear_a in [false, true] {
            for clear_b in [false, true] {
                let mut a = FheBool::encrypt(clear_a, &cks);
                let mut b = FheBool::encrypt(clear_b, &cks);

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

                a.re_randomize(&cpk, seed_gen.next_seed().unwrap()).unwrap();
                assert!(a.re_randomization_metadata().data().is_empty());

                b.re_randomize(&cpk, seed_gen.next_seed().unwrap()).unwrap();
                assert!(b.re_randomization_metadata().data().is_empty());

                let c = a & b;
                let dec: bool = c.decrypt(&cks);

                assert_eq!(clear_a && clear_b, dec);
            }
        }
    }
}
