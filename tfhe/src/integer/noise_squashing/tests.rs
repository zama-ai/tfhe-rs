use crate::integer::keycache::KEY_CACHE;
use crate::integer::noise_squashing::{NoiseSquashingKey, NoiseSquashingPrivateKey};
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
    let (cks, sks) = KEY_CACHE.get_from_params(param);
    let noise_squashing_private_key = NoiseSquashingPrivateKey::new(noise_squashing_parameters);
    let noise_squashing_key = NoiseSquashingKey::new(&cks, &noise_squashing_private_key);

    let mut rng = rand::thread_rng();

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

#[test]
fn test_repro_noise_squashing_degree_handling() {
    use crate::integer::noise_squashing::{NoiseSquashingKey, NoiseSquashingPrivateKey};
    use crate::integer::{gen_keys_radix, ClientKey, IntegerCiphertext};
    use crate::shortint::parameters::{
        NOISE_SQUASHING_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128 as NSP,
        PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128 as P22,
    };

    let (rck, sks) = gen_keys_radix(P22, 4);
    let cks: &ClientKey = rck.as_ref();
    // public handle on the underlying shortint key (integer ServerKey::key is private)
    let shortint_sks = sks.clone().into_raw_parts();
    let nspk = NoiseSquashingPrivateKey::new(NSP);
    let nsk = NoiseSquashingKey::new(cks, &nspk);

    // --- non-canonical but valid radix encoding of 17 -> blocks [1, 4, 0, 0] ---
    {
        let mut ct = cks.encrypt_signed_radix(1i8, 4);
        shortint_sks.unchecked_scalar_add_assign(&mut ct.blocks_mut()[1], 4);
        let dec_signed: i8 = cks.decrypt_signed_radix(&ct);
        assert_eq!(dec_signed, 17);
        let should_fail_signed = nsk.squash_signed_radix_ciphertext_noise(&sks, &ct);
        assert!(should_fail_signed.is_err());
    }

    // unsigned mirror of the identical construction
    {
        let mut ctu = cks.encrypt_radix(1u8, 4);
        shortint_sks.unchecked_scalar_add_assign(&mut ctu.blocks_mut()[1], 4);
        let dec_unsigned: u8 = cks.decrypt_radix(&ctu);
        assert_eq!(dec_unsigned, 17);
        let should_fail_unsigned = nsk.squash_radix_ciphertext_noise(&sks, &ctu);
        assert!(should_fail_unsigned.is_err());
    }
}

#[test]
fn test_noise_squashing_rejects_unpackable_inputs() {
    use crate::integer::noise_squashing::{NoiseSquashingKey, NoiseSquashingPrivateKey};
    use crate::integer::{gen_keys_radix, ClientKey, IntegerCiphertext};
    use crate::shortint::ciphertext::NoiseLevel;
    use crate::shortint::parameters::{
        NOISE_SQUASHING_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128 as NSP,
        PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128 as P22,
    };

    let (rck, sks) = gen_keys_radix(P22, 3);
    let cks: &ClientKey = rck.as_ref();
    let shortint_sks = sks.clone().into_raw_parts();
    let max_noise_level = shortint_sks.max_noise_level;
    let nspk = NoiseSquashingPrivateKey::new(NSP);
    let nsk = NoiseSquashingKey::new(cks, &nspk);

    // Odd block count: the last block is not packed but its carry must still be empty
    {
        let mut ct = cks.encrypt_radix(16u8, 3);
        shortint_sks.unchecked_scalar_add_assign(&mut ct.blocks_mut()[2], 4);
        assert!(nsk.squash_radix_ciphertext_noise(&sks, &ct).is_err());
    }
    {
        let mut ct = cks.encrypt_signed_radix(17i8, 3);
        shortint_sks.unchecked_scalar_add_assign(&mut ct.blocks_mut()[2], 16);
        let dec: i8 = cks.decrypt_signed_radix(&ct);
        assert_eq!(dec, 17);
        assert!(nsk.squash_signed_radix_ciphertext_noise(&sks, &ct).is_err());
    }
    // Single block radix
    {
        let mut ct = cks.encrypt_radix(1u8, 1);
        shortint_sks.unchecked_scalar_add_assign(&mut ct.blocks_mut()[0], 4);
        assert!(nsk.squash_radix_ciphertext_noise(&sks, &ct).is_err());
    }

    // Clean carries but the noise of the packed block exceeds the max noise level
    for (low_noise, high_noise) in [
        (NoiseLevel(1), NoiseLevel(2)),
        (NoiseLevel(5), NoiseLevel(1)),
    ] {
        let mut ct = cks.encrypt_radix(5u8, 2);
        ct.blocks_mut()[0].set_noise_level(low_noise, max_noise_level);
        ct.blocks_mut()[1].set_noise_level(high_noise, max_noise_level);
        assert!(ct.blocks().iter().all(|b| b.carry_is_empty()));
        assert!(nsk.squash_radix_ciphertext_noise(&sks, &ct).is_err());
    }

    // BooleanBlock with a non empty carry
    {
        let mut b = cks.encrypt_bool(false);
        shortint_sks.unchecked_scalar_add_assign(&mut b.0, 4);
        assert!(!cks.decrypt_bool(&b));
        assert!(nsk.squash_boolean_block_noise(&sks, &b).is_err());
    }
    // BooleanBlock with degree 2 but an empty carry: accepted, both decryptions agree
    {
        let mut b = cks.encrypt_bool(true);
        shortint_sks.unchecked_scalar_add_assign(&mut b.0, 1);
        assert!(b.0.degree.get() > 1 && b.0.carry_is_empty());
        assert!(cks.decrypt_bool(&b));
        let squashed = nsk.squash_boolean_block_noise(&sks, &b).unwrap();
        assert!(nspk.decrypt_bool(&squashed).unwrap());
    }
    // BooleanBlock from a list expanded without key keeps the degree of the list blocks
    // (message_modulus - 1) while holding a value in {0, 1}, it must be accepted
    {
        use crate::integer::ciphertext::CompactCiphertextList;
        use crate::integer::{BooleanBlock, CompactPublicKey};

        let pk = CompactPublicKey::new(cks);
        let list = CompactCiphertextList::builder(&pk)
            .push(false)
            .push(true)
            .build();
        let expander = list.expand_without_key().unwrap();
        for (i, expected) in [false, true].into_iter().enumerate() {
            let b: BooleanBlock = expander.get(i).unwrap().unwrap();
            assert!(b.0.degree.get() > 1 && b.0.carry_is_empty());
            let squashed = nsk.squash_boolean_block_noise(&sks, &b).unwrap();
            assert_eq!(nspk.decrypt_bool(&squashed).unwrap(), expected);
        }
    }

    // Sanity check: clean inputs with odd block counts still work
    for num_blocks in [1, 3] {
        let ct = cks.encrypt_radix(2u8, num_blocks);
        let squashed = nsk.squash_radix_ciphertext_noise(&sks, &ct).unwrap();
        let d: u8 = nspk.decrypt_radix(&squashed).unwrap();
        assert_eq!(d, 2);

        let ct = cks.encrypt_signed_radix(-1i8, num_blocks);
        let squashed = nsk.squash_signed_radix_ciphertext_noise(&sks, &ct).unwrap();
        let d: i8 = nspk.decrypt_signed_radix(&squashed).unwrap();
        assert_eq!(d, -1);
    }
}
