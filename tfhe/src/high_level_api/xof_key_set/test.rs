use super::*;
use crate::core_crypto::prelude::new_seeder;
use crate::prelude::*;
use crate::xof_key_set::{CompressedXofKeySet, XofKeySet};
use crate::*;

#[test]
fn test_xof_key_set_classic_params() {
    let params =
        shortint::parameters::test_params::TEST_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
    let cpk_params =
        shortint::parameters::test_params::TEST_PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
    let casting_params = shortint::parameters::test_params::TEST_PARAM_KEYSWITCH_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
    let noise_squashing_params = shortint::parameters::test_params::TEST_PARAM_NOISE_SQUASHING_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
    let compression_params =
        shortint::parameters::test_params::TEST_COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
    let re_rand_ksk_params = shortint::parameters::test_params::TEST_PARAM_KEYSWITCH_PKE_TO_BIG_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
    let noise_squashing_compression_params = shortint::parameters::test_params::TEST_PARAM_NOISE_SQUASHING_COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;

    let config = ConfigBuilder::with_custom_parameters(params)
        .use_dedicated_compact_public_key_parameters((cpk_params, casting_params))
        .enable_noise_squashing(noise_squashing_params)
        .enable_noise_squashing_compression(noise_squashing_compression_params)
        .enable_compression(compression_params)
        .enable_ciphertext_re_randomization(re_rand_ksk_params)
        .build();

    let mut seeder = new_seeder();
    let private_seed_bytes = seeder.seed().0.to_le_bytes().to_vec();
    let security_bits = 128;
    let max_norm_hwt = NormalizedHammingWeightBound::new(0.8).unwrap();
    let tag = Tag::from("classic_2_2");

    let (cks, compressed_key_set) = CompressedXofKeySet::generate(
        config,
        private_seed_bytes,
        security_bits,
        max_norm_hwt,
        tag.clone(),
    )
    .unwrap();

    assert_eq!(cks.tag(), compressed_key_set.compressed_public_key.tag());
    assert_eq!(cks.tag(), &tag);
    test_xof_key_set(&compressed_key_set, config, &cks);
}

#[test]
fn test_xof_key_set_ks32_params_big_pke() {
    let params =
        shortint::parameters::test_params::TEST_PARAM_MESSAGE_2_CARRY_2_KS32_PBS_TUNIFORM_2M128;
    let cpk_params = shortint::parameters::test_params::TEST_PARAM_PKE_TO_BIG_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128_ZKV2;
    let casting_params = shortint::parameters::test_params::TEST_PARAM_KEYSWITCH_PKE_TO_BIG_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
    let noise_squashing_params = shortint::parameters::test_params::TEST_PARAM_NOISE_SQUASHING_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
    let compression_params =
        shortint::parameters::test_params::TEST_COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
    let re_rand_ksk_params = shortint::parameters::test_params::TEST_PARAM_KEYSWITCH_PKE_TO_BIG_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
    let noise_squashing_compression_params = shortint::parameters::test_params::TEST_PARAM_NOISE_SQUASHING_COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;

    let config = ConfigBuilder::with_custom_parameters(params)
        .use_dedicated_compact_public_key_parameters((cpk_params, casting_params))
        .enable_noise_squashing(noise_squashing_params)
        .enable_noise_squashing_compression(noise_squashing_compression_params)
        .enable_compression(compression_params)
        .enable_ciphertext_re_randomization(re_rand_ksk_params)
        .build();

    let mut seeder = new_seeder();
    let private_seed_bytes = seeder.seed().0.to_le_bytes().to_vec();
    let security_bits = 128;
    let max_norm_hwt = NormalizedHammingWeightBound::new(0.8).unwrap();
    let tag = Tag::from("ks32 big pke");

    let (cks, compressed_key_set) = CompressedXofKeySet::generate(
        config,
        private_seed_bytes,
        security_bits,
        max_norm_hwt,
        tag.clone(),
    )
    .unwrap();

    assert_eq!(cks.tag(), compressed_key_set.compressed_public_key.tag());
    assert_eq!(cks.tag(), &tag);
    test_xof_key_set(&compressed_key_set, config, &cks);
}

#[test]
fn test_xof_key_set_ks32_params_small_pke() {
    let params =
        shortint::parameters::test_params::TEST_PARAM_MESSAGE_2_CARRY_2_KS32_PBS_TUNIFORM_2M128;
    let cpk_params = shortint::parameters::test_params::TEST_PARAM_PKE_TO_SMALL_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128_ZKV2;
    let casting_params = shortint::parameters::test_params::TEST_PARAM_KEYSWITCH_PKE_TO_SMALL_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
    let noise_squashing_params = shortint::parameters::test_params::TEST_PARAM_NOISE_SQUASHING_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
    let compression_params =
        shortint::parameters::test_params::TEST_COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
    let re_rand_ksk_params = shortint::parameters::test_params::TEST_PARAM_KEYSWITCH_PKE_TO_BIG_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
    let noise_squashing_compression_params = shortint::parameters::test_params::TEST_PARAM_NOISE_SQUASHING_COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;

    let config = ConfigBuilder::with_custom_parameters(params)
        .use_dedicated_compact_public_key_parameters((cpk_params, casting_params))
        .enable_noise_squashing(noise_squashing_params)
        .enable_noise_squashing_compression(noise_squashing_compression_params)
        .enable_compression(compression_params)
        .enable_ciphertext_re_randomization(re_rand_ksk_params)
        .build();

    let mut seeder = new_seeder();
    let private_seed_bytes = seeder.seed().0.to_le_bytes().to_vec();
    let security_bits = 128;
    let max_norm_hwt = NormalizedHammingWeightBound::new(0.8).unwrap();
    let tag = Tag::from("ks32 small pke");

    let (cks, compressed_key_set) = CompressedXofKeySet::generate(
        config,
        private_seed_bytes,
        security_bits,
        max_norm_hwt,
        tag.clone(),
    )
    .unwrap();

    assert_eq!(cks.tag(), compressed_key_set.compressed_public_key.tag());
    assert_eq!(cks.tag(), &tag);
    test_xof_key_set(&compressed_key_set, config, &cks);
}

fn test_xof_key_set(compressed_key_set: &CompressedXofKeySet, config: Config, cks: &ClientKey) {
    let compressed_size_limit = 1 << 30;
    let mut data = vec![];
    crate::safe_serialization::safe_serialize(compressed_key_set, &mut data, compressed_size_limit)
        .unwrap();
    let compressed_key_set: CompressedXofKeySet =
        crate::safe_serialization::safe_deserialize(data.as_slice(), compressed_size_limit)
            .unwrap();

    let expected_pk_tag = compressed_key_set.compressed_public_key.tag().clone();
    let expected_sk_tag = compressed_key_set.compressed_server_key.tag().clone();
    let key_set = compressed_key_set.decompress().unwrap();

    let size_limit = 1 << 32;
    let mut data = vec![];
    crate::safe_serialization::safe_serialize(&key_set, &mut data, size_limit).unwrap();
    let key_set: XofKeySet =
        crate::safe_serialization::safe_deserialize(data.as_slice(), size_limit).unwrap();

    let (pk, sk) = key_set.into_raw_parts();
    assert_eq!(pk.tag(), &expected_pk_tag);
    assert_eq!(sk.tag(), &expected_sk_tag);

    assert!(sk.is_conformant(&config.into()));

    set_server_key(sk);

    let clear_a = rand::random::<u32>();
    let clear_b = rand::random::<u32>();

    {
        let a = FheUint32::encrypt(clear_a, cks);
        let b = FheUint32::encrypt(clear_b, cks);

        let c = &a * &b;
        let d = &a & &b;

        let c_dec: u32 = c.decrypt(cks);
        let d_dec: u32 = d.decrypt(cks);

        assert_eq!(clear_a.wrapping_mul(clear_b), c_dec);
        assert_eq!(clear_a & clear_b, d_dec);
    }

    let list = CompactCiphertextList::builder(&pk)
        .push(clear_a)
        .push(clear_b)
        .build();
    let expander = list.expand().unwrap();
    let mut a = expander.get::<FheUint32>(0).unwrap().unwrap();
    let mut b = expander.get::<FheUint32>(1).unwrap().unwrap();

    // Test re-randomization
    {
        // Simulate a 256 bits nonce
        let nonce: [u8; 256 / 8] = core::array::from_fn(|_| rand::random());
        let compact_public_encryption_domain_separator = *b"TFHE_Enc";
        let rerand_domain_separator = *b"TFHE_Rrd";

        let mut re_rand_context = ReRandomizationContext::new(
            rerand_domain_separator,
            // First is the function description, second is a nonce
            [b"FheUint32 bin ops".as_slice(), nonce.as_slice()],
            compact_public_encryption_domain_separator,
        );

        re_rand_context.add_ciphertext(&a);
        re_rand_context.add_ciphertext(&b);

        let mut seed_gen = re_rand_context.finalize();

        a.re_randomize(&pk, seed_gen.next_seed().unwrap()).unwrap();

        b.re_randomize(&pk, seed_gen.next_seed().unwrap()).unwrap();
    }

    let c = &a * &b;
    let d = &a & &b;

    let c_dec: u32 = c.decrypt(cks);
    let d_dec: u32 = d.decrypt(cks);

    assert_eq!(clear_a.wrapping_mul(clear_b), c_dec);
    assert_eq!(clear_a & clear_b, d_dec);

    let ns_c = c.squash_noise().unwrap();
    let ns_c_dec: u32 = ns_c.decrypt(cks);
    assert_eq!(clear_a.wrapping_mul(clear_b), ns_c_dec);

    let ns_d = d.squash_noise().unwrap();
    let ns_d_dec: u32 = ns_d.decrypt(cks);
    assert_eq!(clear_a & clear_b, ns_d_dec);

    let compressed_list = CompressedCiphertextListBuilder::new()
        .push(a)
        .push(b)
        .push(c)
        .push(d)
        .build()
        .unwrap();

    let a: FheUint32 = compressed_list.get(0).unwrap().unwrap();
    let da: u32 = a.decrypt(cks);
    assert_eq!(da, clear_a);
    let b: FheUint32 = compressed_list.get(1).unwrap().unwrap();
    let db: u32 = b.decrypt(cks);
    assert_eq!(db, clear_b);
    let c: FheUint32 = compressed_list.get(2).unwrap().unwrap();
    let dc: u32 = c.decrypt(cks);
    assert_eq!(dc, clear_a.wrapping_mul(clear_b));
    let d: FheUint32 = compressed_list.get(3).unwrap().unwrap();
    let db: u32 = d.decrypt(cks);
    assert_eq!(db, clear_a & clear_b);

    let ns_compressed_list = CompressedSquashedNoiseCiphertextListBuilder::new()
        .push(ns_c)
        .push(ns_d)
        .build()
        .unwrap();

    let ns_c: SquashedNoiseFheUint = ns_compressed_list.get(0).unwrap().unwrap();
    let dc: u32 = ns_c.decrypt(cks);
    assert_eq!(dc, clear_a.wrapping_mul(clear_b));
    let ns_d: SquashedNoiseFheUint = ns_compressed_list.get(1).unwrap().unwrap();
    let db: u32 = ns_d.decrypt(cks);
    assert_eq!(db, clear_a & clear_b);
}
