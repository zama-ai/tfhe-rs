use rand::Rng;

use crate::integer::{gen_keys, CompressedPublicKey, PublicKey};
use crate::shortint::parameters::*;
use crate::shortint::ClassicPBSParameters;

use crate::integer::keycache::KEY_CACHE;

create_parametrized_test!(big_radix_encrypt_decrypt_128_bits {
    PARAM_MESSAGE_1_CARRY_1_KS_PBS,
    PARAM_MESSAGE_2_CARRY_2_KS_PBS /* PARAM_MESSAGE_3_CARRY_3_KS_PBS, Skipped as the key requires
                                    * 32GB
                                    * PARAM_MESSAGE_4_CARRY_4_KS_PBS, Skipped as the key requires
                                    * 550GB */
});
create_parametrized_test!(radix_encrypt_decrypt_compressed_128_bits {
    PARAM_MESSAGE_1_CARRY_1_KS_PBS,
    PARAM_MESSAGE_2_CARRY_2_KS_PBS /* PARAM_MESSAGE_3_CARRY_3_KS_PBS, Skipped as its slow
                                    * PARAM_MESSAGE_4_CARRY_4_KS_PBS, Skipped as its slow */
});

create_parametrized_test!(big_radix_encrypt_decrypt_compact_128_bits_list {
    PARAM_MESSAGE_2_CARRY_2_COMPACT_PK_KS_PBS
});

create_parametrized_test!(small_radix_encrypt_decrypt_compact_128_bits_list {
    PARAM_MESSAGE_2_CARRY_2_COMPACT_PK_PBS_KS
});

/// Test that the public key can encrypt a 128 bit number
/// in radix decomposition, and that the client key can decrypt it
fn big_radix_encrypt_decrypt_128_bits(param: ClassicPBSParameters) {
    let (cks, _) = KEY_CACHE.get_from_params(param);
    let public_key = PublicKey::new(&cks);

    // RNG
    let mut rng = rand::thread_rng();
    let num_block = (128f64 / (param.message_modulus.0 as f64).log(2.0)).ceil() as usize;

    let clear = rng.gen::<u128>();

    //encryption
    let ct = public_key.encrypt_radix(clear, num_block);

    // decryption
    let dec: u128 = cks.decrypt_radix(&ct);

    // assert
    assert_eq!(clear, dec);
}

fn radix_encrypt_decrypt_compressed_128_bits(param: ClassicPBSParameters) {
    let (cks, _) = KEY_CACHE.get_from_params(param);
    let public_key = CompressedPublicKey::new(&cks);

    // RNG
    let mut rng = rand::thread_rng();
    let num_block = (128f64 / (param.message_modulus.0 as f64).log(2.0)).ceil() as usize;

    let clear = rng.gen::<u128>();

    //encryption
    let ct = public_key.encrypt_radix(clear, num_block);

    // decryption
    let dec: u128 = cks.decrypt_radix(&ct);

    // assert
    assert_eq!(clear, dec);
}

fn big_radix_encrypt_decrypt_compact_128_bits_list(params: ClassicPBSParameters) {
    radix_encrypt_decrypt_compact_128_bits_list(params);
}

fn small_radix_encrypt_decrypt_compact_128_bits_list(params: ClassicPBSParameters) {
    radix_encrypt_decrypt_compact_128_bits_list(params);
}

fn radix_encrypt_decrypt_compact_128_bits_list(params: ClassicPBSParameters) {
    let (cks, _) = gen_keys(params);
    let pk = crate::integer::public_key::CompactPublicKey::new(&cks);

    let mut rng = rand::thread_rng();
    let num_block = (128f64 / (params.message_modulus.0 as f64).log(2.0)).ceil() as usize;

    const MAX_CT: usize = 20;

    let mut clear_vec = Vec::with_capacity(MAX_CT);
    for _ in 0..25 {
        let num_ct_for_this_iter = rng.gen_range(1..=MAX_CT);
        clear_vec.truncate(0);
        for _ in 0..num_ct_for_this_iter {
            let clear = rng.gen::<u128>();
            clear_vec.push(clear);
        }

        let compact_encrypted_list = pk.encrypt_slice_radix_compact(&clear_vec, num_block);

        let ciphertext_vec = compact_encrypted_list.expand();

        for (ciphertext, clear) in ciphertext_vec.iter().zip(clear_vec.iter().copied()) {
            let decrypted: u128 = cks.decrypt_radix(ciphertext);
            assert_eq!(decrypted, clear);
        }
    }
}
