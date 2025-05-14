use crate::float_wopbs::client_key::{float_to_uint, uint_to_float};
use crate::float_wopbs::gen_keys;
use crate::float_wopbs::keycache::{get_cks, get_sks, save_cks, save_sks};
use crate::float_wopbs::parameters::*;
use rand::Rng;
use std::time::Instant;

#[test]
pub fn float_wopbs_encode() {
    let mut rng = rand::thread_rng();
    let bit_mantissa = 3_usize;
    let bit_exponent = 4_usize;
    let e_min = -5;

    let (cks, _) = gen_keys(PARAM_TEST_WOP);

    let msg = rng.gen::<f32>() as f64;
    // Encryption of one message:
    let ct = cks.encrypt(msg, e_min, bit_mantissa, bit_exponent);

    let clear = uint_to_float(
        float_to_uint(msg, e_min, bit_mantissa, bit_exponent),
        e_min,
        bit_mantissa,
        bit_exponent,
    );
    println!("///////////////////////////////////////////////");
    let res = cks.decrypt(&ct);
    println!("clear :    {res:?}");
    println!("result:    {res:?}");
    println!("///////////////////////////////////////////////");
    assert_eq!(res, clear);
}

#[test]
pub fn float_wopbs_lut() {
    let mut rng = rand::thread_rng();
    let bit_mantissa = 3_usize;
    let bit_exponent = 4_usize;
    let e_min = -5;

    let param_set = "PARAM_MESSAGE_2_16_BITS";

    let cks = get_cks(param_set);
    let sks = get_sks(param_set);

    let (cks, sks) = match (cks, sks) {
        (Some(cks), Some(sks)) => (cks, sks),
        _ => {
            // Generate the client key and the server key:
            let (cks, sks) = gen_keys(PARAM_MESSAGE_2_16_BITS);
            save_cks(&cks, param_set);
            save_sks(&sks, param_set);
            (cks, sks)
        }
    };

    let msg = rng.gen::<f32>() as f64;

    // Encryption of one message:
    let mut ct = cks.encrypt(msg, e_min, bit_mantissa, bit_exponent);

    println!("///////////////////////////////////////////////");

    let res = cks.decrypt(&ct);
    println!("res_1      {res:?}");

    let lut = sks.create_lut(&mut ct, |x| x);

    let now = Instant::now();
    let ct = sks.wop_pbs(&sks, &mut ct, &lut);
    let res_wop = cks.decrypt(&ct);
    println!("res_wop      {res_wop:?}");

    let elapsed = now.elapsed();
    println!(
        "sks param modulus {:?} time : {elapsed:.2?}",
        sks.key.message_modulus
    );

    println!("///////////////////////////////////////////////");
    assert_eq!(res, res_wop);
    // panic!()
}

#[test]
pub fn float_wopbs_bivariate() {
    let bit_mantissa = 4_usize;
    let bit_exponent = 3_usize;
    let e_min = -5;
    let param_set = "PARAM_2_BIT_LWE_8_BITS";

    //generate secret keys
    let cks = get_cks(param_set);
    let sks = get_sks(param_set);
    let (cks, sks) = match (cks, sks) {
        (Some(cks), Some(sks)) => (cks, sks),
        _ => {
            // Generate the client key and the server key:
            let (cks, sks) = gen_keys(PARAM_MESSAGE_2_16_BITS);
            save_cks(&cks, param_set);
            save_sks(&sks, param_set);
            (cks, sks)
        }
    };

    // take two random messages
    let mut rng = rand::thread_rng();
    let msg_1 = rng.gen::<f32>() as f64;
    let msg_2 = -rng.gen::<f32>() as f64;

    // convert 64 bits floating point in 8 bits floating point
    let msg_1_round = uint_to_float(
        float_to_uint(msg_1, e_min, bit_mantissa, bit_exponent),
        e_min,
        bit_mantissa,
        bit_exponent,
    );

    let msg_2_round = uint_to_float(
        float_to_uint(msg_2, e_min, bit_mantissa, bit_exponent),
        e_min,
        bit_mantissa,
        bit_exponent,
    );
    println!("\nmessage 1 (8 bits floating point): {:?}", msg_1_round);
    println!("message 2 (8 bits floating point): {:?} \n", msg_2_round);

    let mut ct_1 = cks.encrypt(msg_1, e_min, bit_mantissa, bit_exponent);
    let res = cks.decrypt(&ct_1);
    println!("encrypt/decrypt ct_1 (8 bits): {res:?}");
    let mut ct_2 = cks.encrypt(msg_2, e_min, bit_mantissa, bit_exponent);
    let res = cks.decrypt(&ct_2);
    println!("encrypt/decrypt ct_2 (8 bits): {res:?}");
    let lut = sks.create_bivariate_lut(&mut ct_1, |x, y| x + y);

    let ct = sks.wop_pbs_bivariate(&sks, &mut ct_1, &mut ct_2, &lut);
    let res = cks.decrypt(&ct);

    // Clear operation done on 64 bits floating point
    let exact = msg_1_round + msg_2_round;
    // Convert result on 8 bits floating points
    let exact = uint_to_float(
        float_to_uint(exact, e_min, bit_mantissa, bit_exponent),
        e_min,
        bit_mantissa,
        bit_exponent,
    );
    println!("\n//////////////////////////////////////////");
    println!("Clear result                           :{exact:?}");
    println!("Decrypted result (WoPBS-based)         :{res:?}");
    println!("///////////////////////////////////////////////\n");
    assert_eq!(res, exact);
}

#[test]
pub fn float_wopbs_trivariate() {
    let bit_mantissa = 3_usize;
    let bit_exponent = 4_usize;
    let e_min = -5;

    let param_set = "PARAM_MESSAGE_2_16_BITS";

    let cks = get_cks(param_set);
    let sks = get_sks(param_set);

    let (cks, sks) = match (cks, sks) {
        (Some(cks), Some(sks)) => (cks, sks),
        _ => {
            // Generate the client key and the server key:
            let (cks, sks) = gen_keys(PARAM_MESSAGE_2_4_8_BITS_TRI);
            save_cks(&cks, param_set);
            save_sks(&sks, param_set);
            (cks, sks)
        }
    };

    let mut rng = rand::thread_rng();
    let msg_1 = rng.gen::<f32>() as f64;
    let msg_2 = -rng.gen::<f32>() as f64;
    let msg_3 = rng.gen::<f32>() as f64;
    println!("message 1 (64 bits): {:?}", msg_1);
    println!("message 2 (64 bits): {:?}", msg_2);
    println!("message 3 (64 bits): {:?}", msg_3);

    let mut ct_1 = cks.encrypt(msg_1, e_min, bit_mantissa, bit_exponent);
    let mut ct_2 = cks.encrypt(msg_2, e_min, bit_mantissa, bit_exponent);
    let mut ct_3 = cks.encrypt(msg_3, e_min, bit_mantissa, bit_exponent);
    println!("encrypt/decrypt ct_1 (8 bits): {:?}", cks.decrypt(&ct_1));
    println!("encrypt/decrypt ct_2 (8 bits): {:?}", cks.decrypt(&ct_2));
    println!("encrypt/decrypt ct_3 (8 bits): {:?}", cks.decrypt(&ct_3));

    let lut = sks.create_trivariate_lut(&mut ct_1, |x, y, z| x + y - z);
    let ct = sks.wop_pbs_trivariate(&sks, &mut ct_1, &mut ct_2, &mut ct_3, &lut);
    let res = cks.decrypt(&ct);
    let exact = msg_1 + msg_2 - msg_3;
    let msg_1_round = uint_to_float(
        float_to_uint(msg_1, e_min, bit_mantissa, bit_exponent),
        e_min,
        bit_mantissa,
        bit_exponent,
    );
    let msg_2_round = uint_to_float(
        float_to_uint(msg_2, e_min, bit_mantissa, bit_exponent),
        e_min,
        bit_mantissa,
        bit_exponent,
    );
    let msg_3_round = uint_to_float(
        float_to_uint(msg_3, e_min, bit_mantissa, bit_exponent),
        e_min,
        bit_mantissa,
        bit_exponent,
    );

    let exact_round = uint_to_float(
        float_to_uint(
            msg_1_round + msg_2_round - msg_3_round,
            e_min,
            bit_mantissa,
            bit_exponent,
        ),
        e_min,
        bit_mantissa,
        bit_exponent,
    );
    println!("\n///////////////////////////////////////////////");
    println!("Clear result (64 bits)                      :{exact:?}");
    println!("Clear result (8 bits)                       :{exact_round:?}");
    println!("Decrypted result (WoPBS-based)              :{res:?}");
    println!("///////////////////////////////////////////////\n");
    assert_eq!(res, exact_round);
}
