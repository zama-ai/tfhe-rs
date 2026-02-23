#![allow(unused)]

use crate::integer::keycache::{KEY_CACHE, KEY_CACHE_WOPBS};
use crate::integer::parameters::*;
use crate::integer::server_key::crt::make_basis;
use crate::integer::wopbs::{encode_radix, WopbsKey};
use crate::integer::{gen_keys, IntegerKeyKind};
use crate::shortint::ciphertext::Degree;
use crate::shortint::parameters::parameters_wopbs::*;
use crate::shortint::parameters::test_params::*;
use crate::shortint::parameters::*;
use paste::paste;
use rand::Rng;
use std::cmp::max;

#[cfg(not(tarpaulin))]
const NB_TESTS: usize = 10;
// Use lower numbers for coverage to ensure fast tests to counter balance slowdown due to code
// instrumentation
#[cfg(tarpaulin)]
const NB_TESTS: usize = 1;

macro_rules! create_parameterized_test{    (
        $name:ident {
            $($(#[$cfg:meta])* ($sks_param:ident, $wopbs_param:ident)),*
            $(,)?
        }
    ) => {
        ::paste::paste! {
            $(
                #[test]
                $(#[$cfg])*
                fn [<test_ $name _ $wopbs_param:lower>]() {
                    $name(($sks_param, $wopbs_param))
                }
            )*
        }
    };
    ($name:ident)=> {
        create_parameterized_test!($name
        {
            (TEST_PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64, LEGACY_WOPBS_PARAM_MESSAGE_2_CARRY_2_KS_PBS),
            #[cfg(not(tarpaulin))]
            (TEST_PARAM_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M64, LEGACY_WOPBS_PARAM_MESSAGE_3_CARRY_3_KS_PBS),
            #[cfg(not(tarpaulin))]
            (TEST_PARAM_MESSAGE_4_CARRY_4_KS_PBS_GAUSSIAN_2M64, LEGACY_WOPBS_PARAM_MESSAGE_4_CARRY_4_KS_PBS)
        });
    };
}

create_parameterized_test!(wopbs_crt);
create_parameterized_test!(wopbs_crt_non_reg);
create_parameterized_test!(wopbs_bivariate_radix);
create_parameterized_test!(wopbs_bivariate_crt);
create_parameterized_test!(wopbs_radix);

// test wopbs fake crt with different degree for each Ct
pub fn wopbs_crt(params: (ClassicPBSParameters, WopbsParameters)) {
    let mut rng = rand::rng();

    let basis = make_basis(params.1.message_modulus.0);

    let nb_block = basis.len();

    let (cks, sks) = KEY_CACHE.get_from_params(params.0, IntegerKeyKind::Radix);
    let wopbs_key = KEY_CACHE_WOPBS.get_from_params(params);

    let mut msg_space = 1;
    for modulus in basis.iter() {
        msg_space *= modulus;
    }

    let mut tmp = 0;
    for _ in 0..NB_TESTS {
        let clear1 = rng.gen::<u64>() % msg_space;
        let mut ct1 = cks.encrypt_crt(clear1, basis.clone());
        //artificially modify the degree
        for ct in ct1.blocks.iter_mut() {
            let degree = params.0.message_modulus.0
                * ((rng.gen::<u64>() % (params.0.carry_modulus.0 - 1)) + 1);
            ct.degree = Degree::new(degree);
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
        println!("failure rate {tmp:?}/{NB_TESTS:?}");
        panic!()
    }
}

// From https://github.com/zama-ai/tfhe-rs/issues/849
// This checks we do not generate a LUT constant equal to 0, as used to be the case with this
// threshold-like LUT
pub fn wopbs_crt_non_reg(params: (ClassicPBSParameters, WopbsParameters)) {
    let mut rng = rand::rng();

    let basis = make_basis(params.1.message_modulus.0);

    let nb_block = basis.len();

    let (cks, sks) = KEY_CACHE.get_from_params(params.0, IntegerKeyKind::Radix);
    let wopbs_key = KEY_CACHE_WOPBS.get_from_params(params);

    let mut msg_space = 1;
    for modulus in basis.iter() {
        msg_space *= modulus;
    }

    let threshold = msg_space / 2;

    let f = |x| (x > threshold) as u64;

    let mut tmp = 0;
    for _ in 0..NB_TESTS {
        let clear1 = rng.gen::<u64>() % msg_space;
        let mut ct1 = cks.encrypt_crt(clear1, basis.clone());
        //artificially modify the degree
        for ct in ct1.blocks.iter_mut() {
            let degree = params.0.message_modulus.0
                * ((rng.gen::<u64>() % (params.0.carry_modulus.0 - 1)) + 1);
            ct.degree = Degree::new(degree);
        }
        let sanity_dec = cks.decrypt_crt(&ct1);
        assert_eq!(clear1, sanity_dec);

        let ct1 = wopbs_key.keyswitch_to_wopbs_params(&sks, &ct1);
        let lut = wopbs_key.generate_lut_crt(&ct1, f);
        let ct_res = wopbs_key.wopbs(&ct1, &lut);
        let ct_res = wopbs_key.keyswitch_to_pbs_params(&ct_res);

        let res_wop = cks.decrypt_crt(&ct_res);
        if f(clear1) % msg_space != res_wop {
            tmp += 1;
        }
    }
    if tmp != 0 {
        println!("failure rate {tmp:?}/{NB_TESTS:?}");
        panic!()
    }
}

// test wopbs radix with different degree for each Ct
pub fn wopbs_radix(params: (ClassicPBSParameters, WopbsParameters)) {
    let mut rng = rand::rng();

    let nb_block = 2;

    let (cks, sks) = KEY_CACHE.get_from_params(params.0, IntegerKeyKind::Radix);
    let wopbs_key = KEY_CACHE_WOPBS.get_from_params(params);

    let mut msg_space: u64 = params.0.message_modulus.0;
    for modulus in 1..nb_block {
        msg_space *= params.0.message_modulus.0;
    }

    let mut tmp = 0;
    for _ in 0..NB_TESTS {
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
        println!("failure rate {tmp:?}/{NB_TESTS:?}");
        panic!()
    }
}

// test wopbs radix with different degree for each Ct
pub fn wopbs_bivariate_radix(params: (ClassicPBSParameters, WopbsParameters)) {
    let mut rng = rand::rng();

    let nb_block = 2;

    let (cks, sks) = KEY_CACHE.get_from_params(params.0, IntegerKeyKind::Radix);
    let wopbs_key = KEY_CACHE_WOPBS.get_from_params(params);

    let mut msg_space: u64 = params.0.message_modulus.0;
    for modulus in 1..nb_block {
        msg_space *= params.0.message_modulus.0;
    }

    for _ in 0..NB_TESTS {
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
    let mut rng = rand::rng();

    let basis = make_basis(params.1.message_modulus.0);
    let modulus = basis.iter().product::<u64>();

    let (cks, sks) = KEY_CACHE.get_from_params(params.0, IntegerKeyKind::Radix);
    let wopbs_key = KEY_CACHE_WOPBS.get_from_params(params);

    let mut msg_space: u64 = 1;
    for modulus in basis.iter() {
        msg_space *= modulus;
    }

    for _ in 0..NB_TESTS {
        let clear1 = rng.gen::<u64>() % msg_space;
        let clear2 = rng.gen::<u64>() % msg_space;
        let mut ct1 = cks.encrypt_crt(clear1, basis.clone());
        let mut ct2 = cks.encrypt_crt(clear2, basis.clone());
        //artificially modify the degree
        for (ct_1, ct_2) in ct1.blocks.iter_mut().zip(ct2.blocks.iter_mut()) {
            // Do not go too far otherwise we explode the RAM for larger parameters
            ct_1.degree = Degree::new(ct_1.degree.get() * 2);
            ct_1.degree = Degree::new(ct_2.degree.get() * 2);
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

// Previously failing case from https://github.com/zama-ai/tfhe-rs/issues/1010
#[test]
pub fn test_wopbs_non_reg_trivial_0() {
    use crate::integer::{gen_keys_radix, RadixCiphertext, RadixClientKey, ServerKey};

    fn generate_keys() -> (RadixClientKey, ServerKey, WopbsKey) {
        let (ck, sk) = gen_keys_radix(TEST_PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128, 16);
        let wopbs_key =
            WopbsKey::new_wopbs_key(&ck, &sk, &LEGACY_WOPBS_PARAM_MESSAGE_2_CARRY_2_KS_PBS);
        (ck, sk, wopbs_key)
    }

    let (ck, sk, wopbs_key) = generate_keys();
    let ct_max_arg: RadixCiphertext = sk.create_trivial_radix(8u64, 4);
    let f = |x: u64| -> u64 { 5 + x };
    let lut = wopbs_key.generate_lut_radix(&ct_max_arg, f);
    let apply_lut = |encrypted_id: &RadixCiphertext| -> RadixCiphertext {
        let ct = wopbs_key.keyswitch_to_wopbs_params(&sk, encrypted_id);
        let ct_res = wopbs_key.wopbs(&ct, &lut);
        wopbs_key.keyswitch_to_pbs_params(&ct_res)
    };
    let lut_at_2 = apply_lut(&sk.create_trivial_radix(2u64, 4)); // succeeds
    assert_eq!(ck.decrypt::<u64>(&lut_at_2), 7);
    let lut_at_1 = apply_lut(&sk.create_trivial_radix(1u64, 4)); // succeeds
    assert_eq!(ck.decrypt::<u64>(&lut_at_1), 6);
    let lut_at_0 = apply_lut(&sk.create_trivial_radix(0u64, 4)); // used to fail, now fixed
    assert_eq!(ck.decrypt::<u64>(&lut_at_0), 5);
}
