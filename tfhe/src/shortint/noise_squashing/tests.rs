use crate::shortint::keycache::KEY_CACHE;
use crate::shortint::noise_squashing::{
    CompressedNoiseSquashingKey, NoiseSquashingKey, NoiseSquashingPrivateKey,
};
use crate::shortint::parameters::test_params::{
    TEST_META_PARAM_CPU_2_2_KS32_PBS_PKE_TO_SMALL_ZKV2_TUNIFORM_2M128,
    TEST_META_PARAM_GPU_2_2_MULTI_BIT_GROUP_4_KS_PBS_PKE_TO_SMALL_ZKV2_TUNIFORM_2M128,
    TEST_META_PARAM_PROD_CPU_2_2_KS_PBS_PKE_TO_SMALL_ZKV2_TUNIFORM_2M128,
};
use crate::shortint::parameters::MetaParameters;
use crate::shortint::server_key::tests::parameterized_test::create_parameterized_test;
use rand::prelude::*;
use rand::thread_rng;

fn test_noise_squashing(meta_params: MetaParameters) {
    let (params, noise_squashing_params) = {
        let meta_noise_squashing_params = meta_params
            .noise_squashing_parameters
            .expect("MetaParameters should have noise_squashing_parameters");
        (
            meta_params.compute_parameters,
            meta_noise_squashing_params.parameters,
        )
    };

    let keycache_entry = KEY_CACHE.get_from_param(params);
    let (cks, sks) = (keycache_entry.client_key(), keycache_entry.server_key());
    let noise_squashing_private_key = NoiseSquashingPrivateKey::new(noise_squashing_params);
    let decompressed_noise_squashing_key = {
        let compressed_noise_squashing_key =
            CompressedNoiseSquashingKey::new(cks, &noise_squashing_private_key);
        compressed_noise_squashing_key.decompress()
    };
    let noise_squashing_key = NoiseSquashingKey::new(cks, &noise_squashing_private_key);

    let mut rng = thread_rng();

    let id_lut = sks.generate_lookup_table(|x| x);

    for _ in 0..50 {
        let msg_1 = rng.gen::<u64>() % cks.parameters().message_modulus().0;
        let msg_2 = rng.gen::<u64>() % cks.parameters().message_modulus().0;

        let mut ct_1 = cks.encrypt(msg_1);
        let mut ct_2 = cks.encrypt(msg_2);

        // Set ciphertext noise level to nominal
        rayon::join(
            || sks.apply_lookup_table_assign(&mut ct_1, &id_lut),
            || sks.apply_lookup_table_assign(&mut ct_2, &id_lut),
        );

        // Pack
        let packed = sks.unchecked_add(
            &sks.unchecked_scalar_mul(&ct_1, sks.message_modulus.0.try_into().unwrap()),
            &ct_2,
        );

        let squashed_noise_ct_from_compressed =
            decompressed_noise_squashing_key.squash_ciphertext_noise(&packed, sks);
        let squashed_noise_ct = noise_squashing_key.squash_ciphertext_noise(&packed, sks);

        assert_eq!(squashed_noise_ct.degree(), packed.degree);
        assert_eq!(squashed_noise_ct_from_compressed.degree(), packed.degree);

        let recovered_from_compressed = noise_squashing_private_key
            .decrypt_squashed_noise_ciphertext(&squashed_noise_ct_from_compressed);
        let recovered =
            noise_squashing_private_key.decrypt_squashed_noise_ciphertext(&squashed_noise_ct);

        let expected_u128: u128 = (msg_1 * sks.message_modulus.0 + msg_2).into();
        assert_eq!(recovered_from_compressed, expected_u128);
        assert_eq!(recovered, expected_u128);
    }
}

create_parameterized_test!(test_noise_squashing {
    (TEST_META_PARAM_PROD_CPU_2_2_KS_PBS_PKE_TO_SMALL_ZKV2_TUNIFORM_2M128, CPU_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128),
    (TEST_META_PARAM_GPU_2_2_MULTI_BIT_GROUP_4_KS_PBS_PKE_TO_SMALL_ZKV2_TUNIFORM_2M128, GPU_MESSAGE_2_CARRY_2_MULTI_BIT_GROUP_4_KS_PBS_TUNIFORM_2M128),
    (TEST_META_PARAM_CPU_2_2_KS32_PBS_PKE_TO_SMALL_ZKV2_TUNIFORM_2M128, CPU_MESSAGE_2_CARRY_2_KS32_PBS_TUNIFORM_2M128)
});
