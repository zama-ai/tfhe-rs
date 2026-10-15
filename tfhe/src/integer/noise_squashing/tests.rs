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

    // --- Case 1: non-canonical but valid radix encoding of 17 -> blocks [1, 4, 0, 0] ---
    let mut ct = cks.encrypt_signed_radix(1i8, 4);
    shortint_sks.unchecked_scalar_add_assign(&mut ct.blocks_mut()[1], 4);
    let truth: i8 = cks.decrypt_signed_radix(&ct);
    assert_eq!(truth, 17);
    println!(
        "\n[case1] degrees={:?} carry_empty={:?} noise={:?}",
        ct.blocks()
            .iter()
            .map(|b| b.degree.get())
            .collect::<Vec<_>>(),
        ct.blocks()
            .iter()
            .map(|b| b.carry_is_empty())
            .collect::<Vec<_>>(),
        ct.blocks()
            .iter()
            .map(|b| b.noise_level())
            .collect::<Vec<_>>()
    );
    match nsk.squash_signed_radix_ciphertext_noise(&sks, &ct) {
        Ok(sq) => {
            let v: i64 = nspk.decrypt_signed_radix(&sq).unwrap();
            let matched = i64::from(truth) == v;
            println!("[case1] SIGNED   true={truth} squashed={v} MATCH={matched}");
            assert!(matched, "Invalid decryption after noise squashing");
        }
        Err(e) => println!("[case1] SIGNED   rejected: {e}"),
    }
    // unsigned mirror of the identical construction
    let mut ctu = cks.encrypt_radix(1u8, 4);
    shortint_sks.unchecked_scalar_add_assign(&mut ctu.blocks_mut()[1], 4);
    let tu: u8 = cks.decrypt_radix(&ctu);
    assert_eq!(tu, 17);
    match nsk.squash_radix_ciphertext_noise(&sks, &ctu) {
        Ok(sq) => {
            let v: u128 = nspk.decrypt_radix(&sq).unwrap();
            let matched = u128::from(tu) == v;
            println!("[case1] UNSIGNED true={tu} squashed={v} MATCH={matched}");
            assert!(matched, "Invalid decryption after noise squashing");
        }
        Err(e) => println!("[case1] UNSIGNED rejected (safe): {e}"),
    }
}
