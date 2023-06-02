use rand::Rng;

use crate::integer::{CompressedPublicKeyBig, PublicKeyBig};
use crate::shortint::parameters::*;
use crate::shortint::ClassicPBSParameters;

use crate::integer::keycache::KEY_CACHE;

create_parametrized_test!(big_radix_encrypt_decrypt_128_bits {
    PARAM_MESSAGE_1_CARRY_1,
    PARAM_MESSAGE_2_CARRY_2 /* PARAM_MESSAGE_3_CARRY_3, Skipped as the key requires 32GB
                             * PARAM_MESSAGE_4_CARRY_4, Skipped as the key requires 550GB */
});
create_parametrized_test!(radix_encrypt_decrypt_compressed_128_bits {
    PARAM_MESSAGE_1_CARRY_1,
    PARAM_MESSAGE_2_CARRY_2 /* PARAM_MESSAGE_3_CARRY_3, Skipped as its slow
                             * PARAM_MESSAGE_4_CARRY_4, Skipped as its slow */
});

/// Test that the public key can encrypt a 128 bit number
/// in radix decomposition, and that the client key can decrypt it
fn big_radix_encrypt_decrypt_128_bits(param: ClassicPBSParameters) {
    let (cks, _) = KEY_CACHE.get_from_params(param);
    let public_key = PublicKeyBig::new(&cks);

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
    let public_key = CompressedPublicKeyBig::new(&cks);

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
