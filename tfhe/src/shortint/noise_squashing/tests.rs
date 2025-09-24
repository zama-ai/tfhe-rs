use crate::shortint::keycache::KEY_CACHE;
use crate::shortint::noise_squashing::{
    CompressedNoiseSquashingKey, NoiseSquashingKey, NoiseSquashingPrivateKey,
};
use crate::shortint::parameters::*;
use rand::prelude::*;
use rand::thread_rng;

#[test]
fn test_classic_noise_squashing_ci_run_filter() {
    test_noise_squashing(
        PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        NOISE_SQUASHING_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    );
}

#[test]
fn test_multi_bit_noise_squashing_ci_run_filter() {
    test_noise_squashing(
        PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        NOISE_SQUASHING_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    );
}

#[test]
fn test_ks32_noise_squashing_ci_run_filter() {
    test_noise_squashing(
        PARAM_MESSAGE_2_CARRY_2_KS32_PBS_TUNIFORM_2M128,
        NOISE_SQUASHING_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    );
}

fn test_noise_squashing(
    classic_params: impl Into<AtomicPatternParameters>,
    noise_squashing_params: NoiseSquashingParameters,
) {
    let keycache_entry = KEY_CACHE.get_from_param(classic_params);
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
