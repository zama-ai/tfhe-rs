use crate::integer::keycache::KEY_CACHE;
use crate::integer::noise_squashing::{NoiseSquashingKey, NoiseSquashingPrivateKey};
use crate::integer::IntegerKeyKind;
use crate::shortint::parameters::{
    NOISE_SQUASHING_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
};
use rand::prelude::*;

#[test]
fn test_integer_noise_squashing_decrypt_auto_cast_and_bool() {
    let param = PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
    let noise_squashing_parameters = NOISE_SQUASHING_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;

    // The goal is to test that encrypting a value stored in a type
    // for which the bit count does not match the target block count of the encrypted
    // radix properly applies upcasting/downcasting
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let noise_squashing_private_key = NoiseSquashingPrivateKey::new(noise_squashing_parameters);
    let noise_squashing_key = NoiseSquashingKey::new(&cks, &noise_squashing_private_key);

    let mut rng = rand::rng();

    let num_blocks = 32u32.div_ceil(param.message_modulus.0.ilog2()) as usize;

    // Positive signed value
    let value = rng.gen_range(0..=i32::MAX);
    let ct = cks.encrypt_signed_radix(value, num_blocks * 2);
    let ct = sks.bitand_parallelized(&ct, &ct);
    let ct = noise_squashing_key
        .squash_signed_radix_ciphertext_noise(&sks, &ct)
        .unwrap();
    let d: i64 = noise_squashing_private_key
        .decrypt_signed_radix(&ct)
        .unwrap();
    assert_eq!(i64::from(value), d);

    let ct = cks.encrypt_signed_radix(value, num_blocks.div_ceil(2));
    let ct = sks.bitand_parallelized(&ct, &ct);
    let ct = noise_squashing_key
        .squash_signed_radix_ciphertext_noise(&sks, &ct)
        .unwrap();
    let d: i16 = noise_squashing_private_key
        .decrypt_signed_radix(&ct)
        .unwrap();
    assert_eq!(value as i16, d);

    let odd_block_count = if num_blocks % 2 == 1 {
        num_blocks
    } else {
        num_blocks + 1
    };

    // Negative signed value
    for block_count in [odd_block_count, num_blocks * 2, num_blocks.div_ceil(2)] {
        let value = rng.gen_range(i8::MIN..0);
        let ct = cks.encrypt_signed_radix(value, block_count);
        let ct = sks.bitand_parallelized(&ct, &ct);
        let ct = noise_squashing_key
            .squash_signed_radix_ciphertext_noise(&sks, &ct)
            .unwrap();
        let d: i64 = noise_squashing_private_key
            .decrypt_signed_radix(&ct)
            .unwrap();
        assert_eq!(i64::from(value), d);

        let ct = cks.encrypt_signed_radix(value, block_count);
        let ct = sks.bitand_parallelized(&ct, &ct);
        let ct = noise_squashing_key
            .squash_signed_radix_ciphertext_noise(&sks, &ct)
            .unwrap();
        let d: i16 = noise_squashing_private_key
            .decrypt_signed_radix(&ct)
            .unwrap();
        assert_eq!(value as i16, d);
    }

    // Unsigned value
    let value = rng.gen::<u32>();
    let ct = cks.encrypt_radix(value, num_blocks * 2);
    let ct = sks.bitand_parallelized(&ct, &ct);
    let ct = noise_squashing_key
        .squash_radix_ciphertext_noise(&sks, &ct)
        .unwrap();
    let d: u64 = noise_squashing_private_key.decrypt_radix(&ct).unwrap();
    assert_eq!(u64::from(value), d);

    let ct = cks.encrypt_radix(value, num_blocks.div_ceil(2));
    let ct = sks.bitand_parallelized(&ct, &ct);
    let ct = noise_squashing_key
        .squash_radix_ciphertext_noise(&sks, &ct)
        .unwrap();
    let d: u16 = noise_squashing_private_key.decrypt_radix(&ct).unwrap();
    assert_eq!(value as u16, d);

    // Booleans
    for val in [true, false] {
        let ct = cks.encrypt_bool(val);
        let ct = sks.boolean_bitand(&ct, &ct);
        let ct = noise_squashing_key
            .squash_boolean_block_noise(&sks, &ct)
            .unwrap();
        let d = noise_squashing_private_key.decrypt_bool(&ct).unwrap();
        assert_eq!(val, d);
    }
}
