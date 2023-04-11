use tfhe::integer::{gen_keys_crt, gen_keys_radix};
use tfhe::prelude::*;
use tfhe::shortint::prelude::*;
use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint16};

fn main() {
    // crt_mul();
    // min_blog_post_example();
    hl_api_example();
}

fn hl_api_example() {
    // Client-side
    let config = ConfigBuilder::all_disabled()
        .enable_default_uint16()
        .build();

    let (client_key, server_key) = generate_keys(config);

    let clear_a = 12345u16;
    let clear_b = 6789u16;
    let clear_c = 1011u16;

    let a = FheUint16::encrypt(clear_a, &client_key);
    let b = FheUint16::encrypt(clear_b, &client_key);
    let c = FheUint16::encrypt(clear_c, &client_key);

    // Server-side
    set_server_key(server_key);
    let result = ((a << 2u16) * b) + c;

    // Client-side
    let decrypted_result: u16 = result.decrypt(&client_key);
    let clear_result = ((clear_a << 2) * clear_b) + clear_c;
    assert_eq!(decrypted_result, clear_result);
}

fn crt_mul() {
    //CRT-based integer modulus 3*4*5*7 = 420
    //To work with homomorphic unsigned integers > 8 bits
    let basis = vec![3, 4, 5, 7];
    let modulus = 420;

    let param = PARAM_MESSAGE_3_CARRY_3;
    let (cks, sks) = gen_keys_crt(&param, basis.clone());

    let clear_0 = 234;
    let clear_1 = 123;

    // encryption of an integer
    let mut ct_zero = cks.encrypt(clear_0);
    let mut ct_one = cks.encrypt(clear_1);

    // mul the two ciphertexts
    let ct_res = sks.smart_crt_mul_parallelized(&mut ct_zero, &mut ct_one);

    // decryption of ct_res
    let dec_res = cks.decrypt(&ct_res);

    assert_eq!((clear_0 * clear_1) % modulus, dec_res % modulus);
}

fn min_blog_post_example() {
    let param = PARAM_MESSAGE_2_CARRY_2;

    //Radix-based integers over 8 bits
    let num_block = 4;
    let (cks, sks) = gen_keys_radix(&param, num_block);

    let clear_0 = 157;
    let clear_1 = 127;

    let mut ct_0 = cks.encrypt(clear_0);
    let mut ct_1 = cks.encrypt(clear_1);

    let ct_res = sks.smart_min_parallelized(&mut ct_0, &mut ct_1);

    let dec_res = cks.decrypt(&ct_res);

    assert_eq!(u64::min(clear_0, clear_1), dec_res);
}
