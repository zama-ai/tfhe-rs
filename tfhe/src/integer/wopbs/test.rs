#![allow(unused)]

use crate::integer::gen_keys;
use crate::integer::parameters::*;
use crate::integer::wopbs::{encode_radix, WopbsKey};
use crate::shortint::parameters::parameters_wopbs::*;
use crate::shortint::parameters::parameters_wopbs_message_carry::*;
use crate::shortint::parameters::{ClassicPBSParameters, *};
use rand::Rng;
use std::cmp::max;

use crate::integer::keycache::{KEY_CACHE, KEY_CACHE_WOPBS};
use paste::paste;

const NB_TEST: usize = 10;

macro_rules! create_parametrized_test{
    ($name:ident { $( ($sks_param:ident, $wopbs_param:ident) ),* }) => {
        paste! {
            $(
            #[test]
            fn [<test_ $name _ $wopbs_param:lower>]() {
                $name(($sks_param, $wopbs_param))
            }
            )*
        }
    };
     ($name:ident)=> {
        create_parametrized_test!($name
        {
            (PARAM_MESSAGE_2_CARRY_2_KS_PBS, WOPBS_PARAM_MESSAGE_2_CARRY_2_KS_PBS),
            (PARAM_MESSAGE_3_CARRY_3_KS_PBS, WOPBS_PARAM_MESSAGE_3_CARRY_3_KS_PBS),
            (PARAM_MESSAGE_4_CARRY_4_KS_PBS, WOPBS_PARAM_MESSAGE_4_CARRY_4_KS_PBS)
        });
    };
}

create_parametrized_test!(wopbs_crt);
create_parametrized_test!(wopbs_bivariate_radix);
create_parametrized_test!(wopbs_bivariate_crt);
create_parametrized_test!(wopbs_radix);

fn make_basis(message_modulus: usize) -> Vec<u64> {
    match message_modulus {
        2 => vec![2],
        3 => vec![2],
        n if n < 8 => vec![2, 3],
        n if n < 16 => vec![2, 5, 7],
        _ => vec![3, 7, 13],
    }
}

pub fn wopbs_native_crt() {
    let mut rng = rand::thread_rng();

    let basis: Vec<u64> = vec![2, 3];
    let nb_block = basis.len();

    let params = crate::shortint::parameters::parameters_wopbs::PARAM_4_BITS_5_BLOCKS;

    let (cks, sks) = gen_keys(params);
    let wopbs_key = WopbsKey::new_wopbs_key_only_for_wopbs(&cks, &sks);

    let mut msg_space = 1;
    for modulus in basis.iter() {
        msg_space *= modulus;
    }

    let nb_test = 10;

    for _ in 0..nb_test {
        let clear1 = rng.gen::<u64>() % msg_space; // Encrypt the integers
        let mut ct1 = cks.encrypt_native_crt(clear1, basis.clone());

        let lut = wopbs_key.generate_lut_native_crt(&ct1, |x| x);

        let ct_res = wopbs_key.wopbs_native_crt(&ct1, &lut);
        let res = cks.decrypt_native_crt(&ct_res);

        assert_eq!(res, clear1);
    }
}

pub fn wopbs_native_crt_bivariate() {
    let mut rng = rand::thread_rng();

    let basis: Vec<u64> = vec![9, 11];

    let nb_block = basis.len();

    let wopbs_params = crate::shortint::parameters::parameters_wopbs::PARAM_4_BITS_5_BLOCKS;

    let pbs_params = ClassicPBSParameters {
        lwe_dimension: wopbs_params.lwe_dimension,
        glwe_dimension: wopbs_params.glwe_dimension,
        polynomial_size: wopbs_params.polynomial_size,
        lwe_modular_std_dev: wopbs_params.lwe_modular_std_dev,
        glwe_modular_std_dev: wopbs_params.glwe_modular_std_dev,
        pbs_base_log: wopbs_params.pbs_base_log,
        pbs_level: wopbs_params.pbs_level,
        ks_base_log: wopbs_params.ks_base_log,
        ks_level: wopbs_params.ks_level,
        message_modulus: wopbs_params.message_modulus,
        carry_modulus: wopbs_params.carry_modulus,
        ciphertext_modulus: wopbs_params.ciphertext_modulus,
        encryption_key_choice: wopbs_params.encryption_key_choice,
    };

    let params = (pbs_params, wopbs_params);

    let (cks, sks) = gen_keys(params.0);
    let wopbs_key = KEY_CACHE_WOPBS.get_from_params(params);

    let mut msg_space = 1;
    for modulus in basis.iter() {
        msg_space *= modulus;
    }

    let nb_test = 10;
    let mut tmp = 0;
    for _ in 0..nb_test {
        let clear1 = rng.gen::<u64>() % msg_space; // Encrypt the integers
        let clear2 = rng.gen::<u64>() % msg_space; // Encrypt the integers
        let mut ct1 = cks.encrypt_native_crt(clear1, basis.clone());
        let mut ct2 = cks.encrypt_native_crt(clear2, basis.clone());

        let lut = wopbs_key.generate_lut_bivariate_native_crt(&ct1, |x, y| x * y);
        let ct_res = wopbs_key.bivariate_wopbs_native_crt(&ct1, &ct2, &lut);
        let res = cks.decrypt_native_crt(&ct_res);

        if (clear1 * clear2) % msg_space != res {
            tmp += 1;
        }
    }
    assert_eq!(tmp, 0);
}

// test wopbs fake crt with different degree for each Ct
pub fn wopbs_crt(params: (ClassicPBSParameters, WopbsParameters)) {
    let mut rng = rand::thread_rng();

    let basis = make_basis(params.1.message_modulus.0);

    let nb_block = basis.len();

    let (cks, sks) = gen_keys(params.0);
    let wopbs_key = KEY_CACHE_WOPBS.get_from_params(params);

    let mut msg_space = 1;
    for modulus in basis.iter() {
        msg_space *= modulus;
    }

    let nb_test = 10;
    let mut tmp = 0;
    for _ in 0..nb_test {
        let clear1 = rng.gen::<u64>() % msg_space;
        let mut ct1 = cks.encrypt_crt(clear1, basis.clone());
        //artificially modify the degree
        for ct in ct1.blocks.iter_mut() {
            let degree = params.0.message_modulus.0
                * ((rng.gen::<usize>() % (params.0.carry_modulus.0 - 1)) + 1);
            ct.degree.0 = degree;
        }
        let res = cks.decrypt_crt(&ct1);

        let ct1 = wopbs_key.keyswitch_to_wopbs_params(&sks, &ct1);
        let lut = wopbs_key.generate_lut_crt(&ct1, |x| (x * x) + x);
        let ct_res = wopbs_key.wopbs(&ct1, &lut);
        let ct_res = wopbs_key.keyswitch_to_pbs_params(&ct_res);

        let res_wop = cks.decrypt_crt(&ct_res);
        if ((res * res) + res) % msg_space != res_wop {
            tmp += 1;
        }
    }
    if tmp != 0 {
        println!("failure rate {tmp:?}/{nb_test:?}");
        panic!()
    }
}

// test wopbs radix with different degree for each Ct
pub fn wopbs_radix(params: (ClassicPBSParameters, WopbsParameters)) {
    let mut rng = rand::thread_rng();

    let nb_block = 2;

    let (cks, sks) = gen_keys(params.0);
    let wopbs_key = KEY_CACHE_WOPBS.get_from_params(params);

    let mut msg_space: u64 = params.0.message_modulus.0 as u64;
    for modulus in 1..nb_block {
        msg_space *= params.0.message_modulus.0 as u64;
    }

    let nb_test = 10;
    let mut tmp = 0;
    for _ in 0..nb_test {
        let clear1 = rng.gen::<u64>() % msg_space;
        let mut ct1 = cks.encrypt_radix(clear1, nb_block);

        // //artificially modify the degree
        let res: u64 = cks.decrypt_radix(&ct1);
        let ct1 = wopbs_key.keyswitch_to_wopbs_params(&sks, &ct1);
        let lut = wopbs_key.generate_lut_radix(&ct1, |x| x);
        let ct_res = wopbs_key.wopbs(&ct1, &lut);
        let ct_res = wopbs_key.keyswitch_to_pbs_params(&ct_res);
        let res_wop: u64 = cks.decrypt_radix(&ct_res);
        if res % msg_space != res_wop {
            tmp += 1;
        }
    }
    if tmp != 0 {
        println!("failure rate {tmp:?}/{nb_test:?}");
        panic!()
    }
}

// test wopbs radix with different degree for each Ct
pub fn wopbs_bivariate_radix(params: (ClassicPBSParameters, WopbsParameters)) {
    let mut rng = rand::thread_rng();

    let nb_block = 2;

    let (cks, sks) = gen_keys(params.0);
    let wopbs_key = KEY_CACHE_WOPBS.get_from_params(params);

    let mut msg_space: u64 = params.0.message_modulus.0 as u64;
    for modulus in 1..nb_block {
        msg_space *= params.0.message_modulus.0 as u64;
    }

    let nb_test = 10;

    for _ in 0..nb_test {
        let mut clear1 = rng.gen::<u64>() % msg_space;
        let mut clear2 = rng.gen::<u64>() % msg_space;

        let mut ct1 = cks.encrypt_radix(clear1, nb_block);
        let scalar = rng.gen::<u64>() % msg_space;
        sks.smart_scalar_add_assign(&mut ct1, scalar);
        let dec1: u64 = cks.decrypt_radix(&ct1);

        let mut ct2 = cks.encrypt_radix(clear2, nb_block);
        let scalar = rng.gen::<u64>() % msg_space;
        sks.smart_scalar_add_assign(&mut ct2, scalar);
        let dec2: u64 = cks.decrypt_radix(&ct2);

        let ct1 = wopbs_key.keyswitch_to_wopbs_params(&sks, &ct1);
        let ct2 = wopbs_key.keyswitch_to_wopbs_params(&sks, &ct2);

        let lut = wopbs_key.generate_lut_bivariate_radix(&ct1, &ct2, |x, y| x + y * x);
        let ct_res = wopbs_key.bivariate_wopbs_with_degree(&ct1, &ct2, &lut);
        let ct_res = wopbs_key.keyswitch_to_pbs_params(&ct_res);

        let res: u64 = cks.decrypt_radix(&ct_res);
        assert_eq!(res, (dec1 + dec2 * dec1) % msg_space);
    }
}

// test wopbs bivariate fake crt with different degree for each Ct
pub fn wopbs_bivariate_crt(params: (ClassicPBSParameters, WopbsParameters)) {
    let mut rng = rand::thread_rng();

    let basis = make_basis(params.1.message_modulus.0);
    let modulus = basis.iter().product::<u64>();

    let (cks, sks) = gen_keys(params.0);
    let wopbs_key = KEY_CACHE_WOPBS.get_from_params(params);

    let mut msg_space: u64 = 1;
    for modulus in basis.iter() {
        msg_space *= modulus;
    }

    let nb_test = 10;

    for _ in 0..nb_test {
        let clear1 = rng.gen::<u64>() % msg_space;
        let clear2 = rng.gen::<u64>() % msg_space;
        let mut ct1 = cks.encrypt_crt(clear1, basis.clone());
        let mut ct2 = cks.encrypt_crt(clear2, basis.clone());
        //artificially modify the degree
        for (ct_1, ct_2) in ct1.blocks.iter_mut().zip(ct2.blocks.iter_mut()) {
            let degree = params.0.message_modulus.0
                * ((rng.gen::<usize>() % (params.0.carry_modulus.0 - 1)) + 1);
            ct_1.degree.0 = degree;
            let degree = params.0.message_modulus.0
                * ((rng.gen::<usize>() % (params.0.carry_modulus.0 - 1)) + 1);
            ct_2.degree.0 = degree;
        }

        let ct1 = wopbs_key.keyswitch_to_wopbs_params(&sks, &ct1);
        let ct2 = wopbs_key.keyswitch_to_wopbs_params(&sks, &ct2);
        let lut = wopbs_key.generate_lut_bivariate_crt(&ct1, &ct2, |x, y| (x * y) + y);
        let ct_res = wopbs_key.bivariate_wopbs_with_degree(&ct1, &ct2, &lut);
        let ct_res = wopbs_key.keyswitch_to_pbs_params(&ct_res);

        let res = cks.decrypt_crt(&ct_res);
        assert_eq!(res, ((clear1 * clear2) + clear2) % msg_space);
    }
}
