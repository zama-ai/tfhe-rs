use crate::shortint::keycache::KEY_CACHE;
use crate::shortint::parameters::*;
use paste::paste;
use rand::Rng;

/// Number of assert in randomized tests
const NB_TEST: usize = 30;

// Macro to generate tests for all parameter sets
macro_rules! create_parametrized_test{
    ($name:ident { $($param:ident),* }) => {
        paste! {
            $(
            #[test]
            fn [<test_ $name _ $param:lower>]() {
                $name($param)
            }
            )*
        }
    };
     ($name:ident)=> {
        create_parametrized_test!($name
        {
            PARAM_MESSAGE_1_CARRY_1,
            PARAM_MESSAGE_1_CARRY_2,
            PARAM_MESSAGE_1_CARRY_3,
            PARAM_MESSAGE_1_CARRY_4,
            PARAM_MESSAGE_1_CARRY_5,
            PARAM_MESSAGE_1_CARRY_6,
            PARAM_MESSAGE_1_CARRY_7,
            PARAM_MESSAGE_2_CARRY_1,
            PARAM_MESSAGE_2_CARRY_2,
            PARAM_MESSAGE_2_CARRY_3,
            PARAM_MESSAGE_2_CARRY_4,
            PARAM_MESSAGE_2_CARRY_5,
            PARAM_MESSAGE_2_CARRY_6,
            PARAM_MESSAGE_3_CARRY_1,
            PARAM_MESSAGE_3_CARRY_2,
            PARAM_MESSAGE_3_CARRY_3,
            PARAM_MESSAGE_3_CARRY_4,
            PARAM_MESSAGE_3_CARRY_5,
            PARAM_MESSAGE_4_CARRY_1,
            PARAM_MESSAGE_4_CARRY_2,
            PARAM_MESSAGE_4_CARRY_3,
            PARAM_MESSAGE_4_CARRY_4,
            PARAM_MESSAGE_5_CARRY_1,
            PARAM_MESSAGE_5_CARRY_2,
            PARAM_MESSAGE_5_CARRY_3,
            PARAM_MESSAGE_6_CARRY_1,
            PARAM_MESSAGE_6_CARRY_2,
            PARAM_MESSAGE_7_CARRY_1
        });
    };
}

//Macro to generate tests for parameters sets compatible with the bivariate pbs
macro_rules! create_parametrized_test_bivariate_pbs_compliant{
    ($name:ident { $($param:ident),* }) => {
        paste! {
            $(
            #[test]
            fn [<test_ $name _ $param:lower>]() {
                $name($param)
            }
            )*
        }
    };
     ($name:ident)=> {
        create_parametrized_test!($name
        {
            PARAM_MESSAGE_1_CARRY_1,
            PARAM_MESSAGE_1_CARRY_2,
            PARAM_MESSAGE_1_CARRY_3,
            PARAM_MESSAGE_1_CARRY_4,
            PARAM_MESSAGE_1_CARRY_5,
            PARAM_MESSAGE_1_CARRY_6,
            PARAM_MESSAGE_1_CARRY_7,
            PARAM_MESSAGE_2_CARRY_2,
            PARAM_MESSAGE_2_CARRY_3,
            PARAM_MESSAGE_2_CARRY_4,
            PARAM_MESSAGE_2_CARRY_5,
            PARAM_MESSAGE_2_CARRY_6,
            PARAM_MESSAGE_3_CARRY_3,
            PARAM_MESSAGE_3_CARRY_4,
            PARAM_MESSAGE_3_CARRY_5,
            PARAM_MESSAGE_4_CARRY_4
        });
    };
}

//These functions are compatible with all parameter sets.
create_parametrized_test!(shortint_encrypt_decrypt);
create_parametrized_test!(shortint_encrypt_with_message_modulus_decrypt);
create_parametrized_test!(shortint_encrypt_decrypt_without_padding);
create_parametrized_test!(shortint_keyswitch_bootstrap);
create_parametrized_test!(shortint_keyswitch_programmable_bootstrap);
create_parametrized_test!(shortint_carry_extract);
create_parametrized_test!(shortint_message_extract);
create_parametrized_test!(shortint_generate_accumulator);
create_parametrized_test!(shortint_unchecked_add);
create_parametrized_test!(shortint_smart_add);
create_parametrized_test!(shortint_smart_mul_lsb);
create_parametrized_test!(shortint_unchecked_neg);
create_parametrized_test!(shortint_smart_neg);
create_parametrized_test!(shortint_unchecked_scalar_add);
create_parametrized_test!(shortint_smart_scalar_add);
create_parametrized_test!(shortint_unchecked_scalar_sub);
create_parametrized_test!(shortint_smart_scalar_sub);
create_parametrized_test!(shortint_unchecked_scalar_mul);
create_parametrized_test!(shortint_smart_scalar_mul);
create_parametrized_test!(shortint_unchecked_right_shift);
create_parametrized_test!(shortint_unchecked_left_shift);
create_parametrized_test!(shortint_unchecked_sub);
create_parametrized_test!(shortint_smart_sub);
create_parametrized_test!(shortint_mul_small_carry);

//These functions are compatible with some parameter sets where the carry modulus is larger than
// the message modulus.
create_parametrized_test_bivariate_pbs_compliant!(shortint_unchecked_bitand);
create_parametrized_test_bivariate_pbs_compliant!(shortint_unchecked_bitor);
create_parametrized_test_bivariate_pbs_compliant!(shortint_unchecked_bitxor);
create_parametrized_test_bivariate_pbs_compliant!(shortint_unchecked_greater);
create_parametrized_test_bivariate_pbs_compliant!(shortint_unchecked_greater_or_equal);
create_parametrized_test_bivariate_pbs_compliant!(shortint_unchecked_less);
create_parametrized_test_bivariate_pbs_compliant!(shortint_unchecked_less_or_equal);
create_parametrized_test_bivariate_pbs_compliant!(shortint_unchecked_equal);
create_parametrized_test_bivariate_pbs_compliant!(shortint_smart_bitand);
create_parametrized_test_bivariate_pbs_compliant!(shortint_smart_bitor);
create_parametrized_test_bivariate_pbs_compliant!(shortint_smart_bitxor);
create_parametrized_test_bivariate_pbs_compliant!(shortint_smart_greater);
create_parametrized_test_bivariate_pbs_compliant!(shortint_smart_greater_or_equal);
create_parametrized_test_bivariate_pbs_compliant!(shortint_smart_less);
create_parametrized_test_bivariate_pbs_compliant!(shortint_smart_less_or_equal);
create_parametrized_test_bivariate_pbs_compliant!(shortint_smart_equal);
create_parametrized_test_bivariate_pbs_compliant!(shortint_smart_scalar_equal);
create_parametrized_test_bivariate_pbs_compliant!(shortint_smart_scalar_less);
create_parametrized_test_bivariate_pbs_compliant!(shortint_smart_scalar_less_or_equal);
create_parametrized_test_bivariate_pbs_compliant!(shortint_smart_scalar_greater);
create_parametrized_test_bivariate_pbs_compliant!(shortint_smart_scalar_greater_or_equal);
create_parametrized_test_bivariate_pbs_compliant!(shortint_unchecked_div);
create_parametrized_test_bivariate_pbs_compliant!(shortint_unchecked_scalar_div);
create_parametrized_test_bivariate_pbs_compliant!(shortint_unchecked_mod);
create_parametrized_test_bivariate_pbs_compliant!(shortint_unchecked_mul_lsb);
create_parametrized_test_bivariate_pbs_compliant!(shortint_unchecked_mul_msb);
create_parametrized_test_bivariate_pbs_compliant!(shortint_smart_mul_msb);
create_parametrized_test_bivariate_pbs_compliant!(
    shortint_keyswitch_bivariate_programmable_bootstrap
);
create_parametrized_test_bivariate_pbs_compliant!(
    shortint_encrypt_with_message_modulus_smart_add_and_mul
);

/// test encryption and decryption with the LWE client key
fn shortint_encrypt_decrypt(param: Parameters) {
    let keys = KEY_CACHE.get_from_param(param);
    let cks = keys.client_key();

    let mut rng = rand::thread_rng();

    let modulus = cks.parameters.message_modulus.0 as u64;

    for _ in 0..NB_TEST {
        let clear = rng.gen::<u64>() % modulus;

        let ct = cks.encrypt(clear);

        // decryption of ct_zero
        let dec = cks.decrypt(&ct);

        // assert
        assert_eq!(clear, dec);
    }
}

/// test encryption and decryption with the LWE client key
fn shortint_encrypt_with_message_modulus_decrypt(param: Parameters) {
    let keys = KEY_CACHE.get_from_param(param);
    let cks = keys.client_key();

    let mut rng = rand::thread_rng();

    for _ in 0..NB_TEST {
        let mut modulus = rng.gen::<u64>() % cks.parameters.message_modulus.0 as u64;
        while modulus == 0 {
            modulus = rng.gen::<u64>() % cks.parameters.message_modulus.0 as u64;
        }

        let clear = rng.gen::<u64>() % modulus;

        let ct = cks.encrypt_with_message_modulus(clear, MessageModulus(modulus as usize));

        // decryption of ct_zero
        let dec = cks.decrypt(&ct);

        // assert
        assert_eq!(clear, dec);
    }
}

fn shortint_encrypt_decrypt_without_padding(param: Parameters) {
    let keys = KEY_CACHE.get_from_param(param);
    let cks = keys.client_key();

    let mut rng = rand::thread_rng();

    // We assume that the modulus is the largest possible without padding bit
    let modulus = (cks.parameters.message_modulus.0 * cks.parameters.carry_modulus.0) as u64;

    for _ in 0..NB_TEST {
        let clear = rng.gen::<u64>() % modulus;

        let ct = cks.encrypt_without_padding(clear);

        // decryption of ct_zero
        let dec = cks.decrypt_message_and_carry_without_padding(&ct);

        // assert
        assert_eq!(clear, dec);
    }
}

fn shortint_keyswitch_bootstrap(param: Parameters) {
    let keys = KEY_CACHE.get_from_param(param);
    let (cks, sks) = (keys.client_key(), keys.server_key());

    //RNG
    let mut rng = rand::thread_rng();

    let modulus = cks.parameters.message_modulus.0 as u64;
    let mut failures = 0;

    for _ in 0..NB_TEST {
        let clear_0 = rng.gen::<u64>() % modulus;

        // encryption of an integer
        let ctxt_0 = cks.encrypt(clear_0);

        // keyswitch and bootstrap
        let ct_res = sks.keyswitch_bootstrap(&ctxt_0);

        // decryption of ct_res
        let dec_res = cks.decrypt(&ct_res);

        if clear_0 != dec_res {
            failures += 1;
        }
        // assert
        // assert_eq!(clear_0, dec_res);
    }

    println!("fail_rate = {}/{}", failures, 100);
    assert_eq!(0, failures);
}

fn shortint_keyswitch_programmable_bootstrap(param: Parameters) {
    let keys = KEY_CACHE.get_from_param(param);
    let (cks, sks) = (keys.client_key(), keys.server_key());
    //RNG
    let mut rng = rand::thread_rng();

    let modulus = cks.parameters.message_modulus.0 as u64;

    for _ in 0..NB_TEST {
        let clear_0 = rng.gen::<u64>() % modulus;

        // encryption of an integer
        let ctxt_0 = cks.encrypt(clear_0);

        //define the accumulator as identity
        let acc = sks.generate_accumulator(|n| n % modulus);
        // add the two ciphertexts
        let ct_res = sks.keyswitch_programmable_bootstrap(&ctxt_0, &acc);

        // decryption of ct_res
        let dec_res = cks.decrypt(&ct_res);

        // assert
        assert_eq!(clear_0, dec_res);
    }
}

fn shortint_keyswitch_bivariate_programmable_bootstrap(param: Parameters) {
    let keys = KEY_CACHE.get_from_param(param);
    let (cks, sks) = (keys.client_key(), keys.server_key());
    //RNG
    let mut rng = rand::thread_rng();

    let modulus = cks.parameters.message_modulus.0 as u64;

    for _ in 0..NB_TEST {
        let clear_0 = rng.gen::<u64>() % modulus;
        let clear_1 = rng.gen::<u64>() % modulus;

        // encryption of an integer
        let ctxt_0 = cks.encrypt(clear_0);
        let ctxt_1 = cks.encrypt(clear_1);
        //define the accumulator as identity
        let acc = sks.generate_accumulator_bivariate(|x, y| x * 2 * y % modulus);
        // add the two ciphertexts
        let ct_res = sks.keyswitch_programmable_bootstrap_bivariate(&ctxt_0, &ctxt_1, &acc);

        // decryption of ct_res
        let dec_res = cks.decrypt(&ct_res);

        // assert
        assert_eq!((2 * clear_0 * clear_1) % modulus, dec_res);
    }
}

/// test extraction of a carry
fn shortint_carry_extract(param: Parameters) {
    let keys = KEY_CACHE.get_from_param(param);
    let (cks, sks) = (keys.client_key(), keys.server_key());
    //RNG
    let mut rng = rand::thread_rng();

    let full_modulus =
        cks.parameters.message_modulus.0 as u64 + cks.parameters.carry_modulus.0 as u64;
    let msg_modulus = cks.parameters.message_modulus.0 as u64;

    for _ in 0..NB_TEST {
        // shift to the carry bits
        let clear = rng.gen::<u64>() % full_modulus;

        // unchecked encryption of the message to have a larger message encrypted.
        let ctxt = cks.unchecked_encrypt(clear);

        // extract the carry
        let ct_carry = sks.carry_extract(&ctxt);

        // decryption of message and carry
        let dec = cks.decrypt_message_and_carry(&ct_carry);

        // assert
        println!(
            "msg = {}, modulus = {}, msg/modulus = {}",
            clear,
            msg_modulus,
            clear / msg_modulus
        );
        assert_eq!(clear / msg_modulus, dec);
    }
}

/// test extraction of a message
fn shortint_message_extract(param: Parameters) {
    let keys = KEY_CACHE.get_from_param(param);
    let (cks, sks) = (keys.client_key(), keys.server_key());
    //RNG
    let mut rng = rand::thread_rng();

    let modulus_sup = (param.message_modulus.0 * param.carry_modulus.0) as u64;

    let modulus = param.message_modulus.0 as u64;

    for _ in 0..NB_TEST {
        let clear = rng.gen::<u64>() % modulus_sup;

        // encryption of an integer
        let ctxt = cks.unchecked_encrypt(clear);

        // message extraction
        let ct_msg = sks.message_extract(&ctxt);

        // decryption of ct_msg
        let dec = cks.decrypt(&ct_msg);

        // assert
        assert_eq!(clear % modulus, dec);
    }
}

/// test multiplication with the LWE server key
fn shortint_generate_accumulator(param: Parameters) {
    let keys = KEY_CACHE.get_from_param(param);
    let (cks, sks) = (keys.client_key(), keys.server_key());
    let double = |x| 2 * x;
    let acc = sks.generate_accumulator(double);

    //RNG
    let mut rng = rand::thread_rng();

    let modulus = cks.parameters.message_modulus.0 as u64;

    for _ in 0..NB_TEST {
        let clear = rng.gen::<u64>() % modulus;

        // encryption of an integer
        let ct = cks.encrypt(clear);

        let ct_res = sks.keyswitch_programmable_bootstrap(&ct, &acc);

        // decryption of ct_res
        let dec_res = cks.decrypt(&ct_res);

        // assert
        assert_eq!((clear * 2) % modulus, dec_res);
    }
}

/// test addition with the LWE server key
fn shortint_unchecked_add(param: Parameters) {
    let keys = KEY_CACHE.get_from_param(param);
    let (cks, sks) = (keys.client_key(), keys.server_key());
    //RNG
    let mut rng = rand::thread_rng();

    let modulus = cks.parameters.message_modulus.0 as u64;

    for _ in 0..NB_TEST {
        let clear_0 = rng.gen::<u64>() % modulus;
        let clear_1 = rng.gen::<u64>() % modulus;

        // encryption of an integer
        let ctxt_0 = cks.encrypt(clear_0);

        // encryption of an integer
        let ctxt_1 = cks.encrypt(clear_1);

        // add the two ciphertexts
        let ct_res = sks.unchecked_add(&ctxt_0, &ctxt_1);

        // decryption of ct_res
        let dec_res = cks.decrypt(&ct_res);

        // assert
        println!(
            "The parameters set is CARRY_{}_MESSAGE_{}",
            cks.parameters.carry_modulus.0, cks.parameters.message_modulus.0
        );
        assert_eq!((clear_0 + clear_1) % modulus, dec_res);
    }
}

/// test addition with the LWE server key
fn shortint_smart_add(param: Parameters) {
    let keys = KEY_CACHE.get_from_param(param);
    let (cks, sks) = (keys.client_key(), keys.server_key());

    //RNG
    let mut rng = rand::thread_rng();

    let modulus = cks.parameters.message_modulus.0 as u64;

    for _ in 0..10 {
        let clear_0 = rng.gen::<u64>() % modulus;

        let clear_1 = rng.gen::<u64>() % modulus;

        // encryption of an integer
        let mut ctxt_0 = cks.encrypt(clear_0);

        // encryption of an integer
        let mut ctxt_1 = cks.encrypt(clear_1);

        // add the two ciphertexts
        let mut ct_res = sks.smart_add(&mut ctxt_0, &mut ctxt_1);
        let mut clear = clear_0 + clear_1;

        //add multiple times to raise the degree and test the smart operation
        for _ in 0..40 {
            ct_res = sks.smart_add(&mut ct_res, &mut ctxt_0);
            clear += clear_0;

            // decryption of ct_res
            let dec_res = cks.decrypt(&ct_res);

            // assert
            assert_eq!(clear % modulus, dec_res);
        }
    }
}

/// test bitwise 'and' with the LWE server key
fn shortint_unchecked_bitand(param: Parameters) {
    let keys = KEY_CACHE.get_from_param(param);
    let (cks, sks) = (keys.client_key(), keys.server_key());
    //RNG
    let mut rng = rand::thread_rng();

    let modulus = cks.parameters.message_modulus.0 as u64;

    for _ in 0..NB_TEST {
        let clear_0 = rng.gen::<u64>() % modulus;
        let clear_1 = rng.gen::<u64>() % modulus;

        // encryption of an integer
        let ctxt_0 = cks.encrypt(clear_0);

        // encryption of an integer
        let ctxt_1 = cks.encrypt(clear_1);

        // add the two ciphertexts
        let ct_res = sks.unchecked_bitand(&ctxt_0, &ctxt_1);

        // decryption of ct_res
        let dec_res = cks.decrypt(&ct_res);

        // assert
        assert_eq!(clear_0 & clear_1, dec_res);
    }
}

/// test bitwise 'or' with the LWE server key
fn shortint_unchecked_bitor(param: Parameters) {
    let keys = KEY_CACHE.get_from_param(param);
    let (cks, sks) = (keys.client_key(), keys.server_key());
    //RNG
    let mut rng = rand::thread_rng();

    let modulus = cks.parameters.message_modulus.0 as u64;

    for _ in 0..NB_TEST {
        let clear_0 = rng.gen::<u64>() % modulus;
        let clear_1 = rng.gen::<u64>() % modulus;

        // encryption of an integer
        let ctxt_0 = cks.encrypt(clear_0);

        // encryption of an integer
        let ctxt_1 = cks.encrypt(clear_1);

        // add the two ciphertexts
        let ct_res = sks.unchecked_bitor(&ctxt_0, &ctxt_1);

        // decryption of ct_res
        let dec_res = cks.decrypt(&ct_res);

        // assert
        assert_eq!(clear_0 | clear_1, dec_res);
    }
}

/// test bitwise 'xor' with the LWE server key
fn shortint_unchecked_bitxor(param: Parameters) {
    let keys = KEY_CACHE.get_from_param(param);
    let (cks, sks) = (keys.client_key(), keys.server_key());
    //RNG
    let mut rng = rand::thread_rng();

    let modulus = cks.parameters.message_modulus.0 as u64;

    for _ in 0..NB_TEST {
        let clear_0 = rng.gen::<u64>() % modulus;
        let clear_1 = rng.gen::<u64>() % modulus;

        // encryption of an integer
        let ctxt_0 = cks.encrypt(clear_0);

        // encryption of an integer
        let ctxt_1 = cks.encrypt(clear_1);

        // add the two ciphertexts
        let ct_res = sks.unchecked_bitxor(&ctxt_0, &ctxt_1);

        // decryption of ct_res
        let dec_res = cks.decrypt(&ct_res);

        // assert
        assert_eq!(clear_0 ^ clear_1, dec_res);
    }
}

/// test bitwise 'and' with the LWE server key
fn shortint_smart_bitand(param: Parameters) {
    let keys = KEY_CACHE.get_from_param(param);
    let (cks, sks) = (keys.client_key(), keys.server_key());
    //RNG
    let mut rng = rand::thread_rng();

    let modulus = cks.parameters.message_modulus.0 as u64;
    let mod_scalar = cks.parameters.carry_modulus.0 as u8;

    for _ in 0..NB_TEST {
        let mut clear_0 = rng.gen::<u64>() % modulus;
        let mut clear_1 = rng.gen::<u64>() % modulus;
        let scalar = rng.gen::<u8>() % mod_scalar;

        // encryption of an integer
        let mut ctxt_0 = cks.encrypt(clear_0);

        // encryption of an integer
        let mut ctxt_1 = cks.encrypt(clear_1);

        sks.unchecked_scalar_mul_assign(&mut ctxt_0, scalar);
        sks.unchecked_scalar_mul_assign(&mut ctxt_1, scalar);

        clear_0 *= scalar as u64;
        clear_1 *= scalar as u64;

        // add the two ciphertexts
        let ct_res = sks.smart_bitand(&mut ctxt_0, &mut ctxt_1);

        // decryption of ct_res
        let dec_res = cks.decrypt(&ct_res);

        // assert
        assert_eq!((clear_0 & clear_1) % modulus, dec_res);
    }
}

/// test bitwise 'or' with the LWE server key
fn shortint_smart_bitor(param: Parameters) {
    let keys = KEY_CACHE.get_from_param(param);
    let (cks, sks) = (keys.client_key(), keys.server_key());
    //RNG
    let mut rng = rand::thread_rng();

    let modulus = cks.parameters.message_modulus.0 as u64;
    let mod_scalar = cks.parameters.carry_modulus.0 as u8;

    for _ in 0..NB_TEST {
        let mut clear_0 = rng.gen::<u64>() % modulus;
        let mut clear_1 = rng.gen::<u64>() % modulus;
        let scalar = rng.gen::<u8>() % mod_scalar;

        // encryption of an integer
        let mut ctxt_0 = cks.encrypt(clear_0);

        // encryption of an integer
        let mut ctxt_1 = cks.encrypt(clear_1);

        sks.unchecked_scalar_mul_assign(&mut ctxt_0, scalar);
        sks.unchecked_scalar_mul_assign(&mut ctxt_1, scalar);

        clear_0 *= scalar as u64;
        clear_1 *= scalar as u64;

        // add the two ciphertexts
        let ct_res = sks.smart_bitor(&mut ctxt_0, &mut ctxt_1);

        // decryption of ct_res
        let dec_res = cks.decrypt(&ct_res);

        // assert
        assert_eq!((clear_0 | clear_1) % modulus, dec_res);
    }
}

/// test bitwise 'xor' with the LWE server key
fn shortint_smart_bitxor(param: Parameters) {
    let keys = KEY_CACHE.get_from_param(param);
    let (cks, sks) = (keys.client_key(), keys.server_key());
    //RNG
    let mut rng = rand::thread_rng();

    let modulus = cks.parameters.message_modulus.0 as u64;
    let mod_scalar = cks.parameters.carry_modulus.0 as u8;

    for _ in 0..NB_TEST {
        let mut clear_0 = rng.gen::<u64>() % modulus;
        let mut clear_1 = rng.gen::<u64>() % modulus;
        let scalar = rng.gen::<u8>() % mod_scalar;

        // encryption of an integer
        let mut ctxt_0 = cks.encrypt(clear_0);

        // encryption of an integer
        let mut ctxt_1 = cks.encrypt(clear_1);

        sks.unchecked_scalar_mul_assign(&mut ctxt_0, scalar);
        sks.unchecked_scalar_mul_assign(&mut ctxt_1, scalar);

        clear_0 *= scalar as u64;
        clear_1 *= scalar as u64;

        // add the two ciphertexts
        let ct_res = sks.smart_bitxor(&mut ctxt_0, &mut ctxt_1);

        // decryption of ct_res
        let dec_res = cks.decrypt(&ct_res);

        // assert
        assert_eq!((clear_0 ^ clear_1) % modulus, dec_res);
    }
}

/// test '>' with the LWE server key
fn shortint_unchecked_greater(param: Parameters) {
    let keys = KEY_CACHE.get_from_param(param);
    let (cks, sks) = (keys.client_key(), keys.server_key());
    //RNG
    let mut rng = rand::thread_rng();

    let modulus = cks.parameters.message_modulus.0 as u64;

    for _ in 0..NB_TEST {
        let clear_0 = rng.gen::<u64>() % modulus;
        let clear_1 = rng.gen::<u64>() % modulus;

        // encryption of an integer
        let ctxt_0 = cks.encrypt(clear_0);

        // encryption of an integer
        let ctxt_1 = cks.encrypt(clear_1);

        // add the two ciphertexts
        let ct_res = sks.unchecked_greater(&ctxt_0, &ctxt_1);

        // decryption of ct_res
        let dec_res = cks.decrypt(&ct_res);

        // assert
        assert_eq!((clear_0 > clear_1) as u64, dec_res);
    }
}

/// test '>' with the LWE server key
fn shortint_smart_greater(param: Parameters) {
    let keys = KEY_CACHE.get_from_param(param);
    let (cks, sks) = (keys.client_key(), keys.server_key());
    //RNG
    let mut rng = rand::thread_rng();

    let modulus = cks.parameters.message_modulus.0 as u64;

    for _ in 0..NB_TEST {
        let clear_0 = rng.gen::<u64>() % modulus;
        let clear_1 = rng.gen::<u64>() % modulus;

        // encryption of an integer
        let mut ctxt_0 = cks.encrypt(clear_0);

        // encryption of an integer
        let mut ctxt_1 = cks.encrypt(clear_1);

        // add the two ciphertexts
        let ct_res = sks.smart_greater(&mut ctxt_0, &mut ctxt_1);

        // decryption of ct_res
        let dec_res = cks.decrypt(&ct_res);

        // assert
        assert_eq!((clear_0 > clear_1) as u64, dec_res);
    }
}

/// test '>=' with the LWE server key
fn shortint_unchecked_greater_or_equal(param: Parameters) {
    let keys = KEY_CACHE.get_from_param(param);
    let (cks, sks) = (keys.client_key(), keys.server_key());
    //RNG
    let mut rng = rand::thread_rng();

    let modulus = cks.parameters.message_modulus.0 as u64;

    for _ in 0..NB_TEST {
        let clear_0 = rng.gen::<u64>() % modulus;
        let clear_1 = rng.gen::<u64>() % modulus;

        // encryption of an integer
        let ctxt_0 = cks.encrypt(clear_0);

        // encryption of an integer
        let ctxt_1 = cks.encrypt(clear_1);

        // add the two ciphertexts
        let ct_res = sks.unchecked_greater_or_equal(&ctxt_0, &ctxt_1);

        // decryption of ct_res
        let dec_res = cks.decrypt(&ct_res);

        // assert
        assert_eq!((clear_0 >= clear_1) as u64, dec_res);
    }
}

/// test '>=' with the LWE server key
fn shortint_smart_greater_or_equal(param: Parameters) {
    let keys = KEY_CACHE.get_from_param(param);
    let (cks, sks) = (keys.client_key(), keys.server_key());
    //RNG
    let mut rng = rand::thread_rng();

    let modulus = cks.parameters.message_modulus.0 as u64;
    let mod_scalar = cks.parameters.carry_modulus.0 as u8;

    for _ in 0..NB_TEST {
        let mut clear_0 = rng.gen::<u64>() % modulus;
        let mut clear_1 = rng.gen::<u64>() % modulus;
        let scalar = rng.gen::<u8>() % mod_scalar;

        // encryption of an integer
        let mut ctxt_0 = cks.encrypt(clear_0);

        // encryption of an integer
        let mut ctxt_1 = cks.encrypt(clear_1);

        sks.unchecked_scalar_mul_assign(&mut ctxt_0, scalar);
        sks.unchecked_scalar_mul_assign(&mut ctxt_1, scalar);

        clear_0 = (clear_0 * scalar as u64) % modulus;
        clear_1 = (clear_1 * scalar as u64) % modulus;

        // add the two ciphertexts
        let ct_res = sks.smart_greater_or_equal(&mut ctxt_0, &mut ctxt_1);

        // decryption of ct_res
        let dec_res = cks.decrypt(&ct_res);

        // assert
        assert_eq!((clear_0 >= clear_1) as u64, dec_res);
    }
}

/// test '<' with the LWE server key
fn shortint_unchecked_less(param: Parameters) {
    let keys = KEY_CACHE.get_from_param(param);
    let (cks, sks) = (keys.client_key(), keys.server_key());
    //RNG
    let mut rng = rand::thread_rng();

    let modulus = cks.parameters.message_modulus.0 as u64;

    for _ in 0..NB_TEST {
        let clear_0 = rng.gen::<u64>() % modulus;
        let clear_1 = rng.gen::<u64>() % modulus;

        // encryption of an integer
        let ctxt_0 = cks.encrypt(clear_0);

        // encryption of an integer
        let ctxt_1 = cks.encrypt(clear_1);

        // add the two ciphertexts
        let ct_res = sks.unchecked_less(&ctxt_0, &ctxt_1);

        // decryption of ct_res
        let dec_res = cks.decrypt(&ct_res);

        // assert
        assert_eq!((clear_0 < clear_1) as u64, dec_res);
    }
}

/// test '<' with the LWE server key
fn shortint_smart_less(param: Parameters) {
    let keys = KEY_CACHE.get_from_param(param);
    let (cks, sks) = (keys.client_key(), keys.server_key());
    //RNG
    let mut rng = rand::thread_rng();

    let modulus = cks.parameters.message_modulus.0 as u64;
    let mod_scalar = cks.parameters.carry_modulus.0 as u8;

    for _ in 0..NB_TEST {
        let mut clear_0 = rng.gen::<u64>() % modulus;
        let mut clear_1 = rng.gen::<u64>() % modulus;
        let scalar = rng.gen::<u8>() % mod_scalar;

        // encryption of an integer
        let mut ctxt_0 = cks.encrypt(clear_0);

        // encryption of an integer
        let mut ctxt_1 = cks.encrypt(clear_1);

        sks.unchecked_scalar_mul_assign(&mut ctxt_0, scalar);
        sks.unchecked_scalar_mul_assign(&mut ctxt_1, scalar);

        clear_0 = (clear_0 * scalar as u64) % modulus;
        clear_1 = (clear_1 * scalar as u64) % modulus;

        // add the two ciphertexts
        let ct_res = sks.smart_less(&mut ctxt_0, &mut ctxt_1);

        // decryption of ct_res
        let dec_res = cks.decrypt(&ct_res);

        // assert
        assert_eq!((clear_0 < clear_1) as u64, dec_res);
    }
}

/// test '<=' with the LWE server key
fn shortint_unchecked_less_or_equal(param: Parameters) {
    let keys = KEY_CACHE.get_from_param(param);
    let (cks, sks) = (keys.client_key(), keys.server_key());
    //RNG
    let mut rng = rand::thread_rng();

    let modulus = cks.parameters.message_modulus.0 as u64;

    for _ in 0..NB_TEST {
        let clear_0 = rng.gen::<u64>() % modulus;
        let clear_1 = rng.gen::<u64>() % modulus;

        // encryption of an integer
        let ctxt_0 = cks.encrypt(clear_0);

        // encryption of an integer
        let ctxt_1 = cks.encrypt(clear_1);

        // add the two ciphertexts
        let ct_res = sks.unchecked_less_or_equal(&ctxt_0, &ctxt_1);

        // decryption of ct_res
        let dec_res = cks.decrypt(&ct_res);

        // assert
        assert_eq!((clear_0 <= clear_1) as u64, dec_res);
    }
}

/// test '<=' with the LWE server key
fn shortint_smart_less_or_equal(param: Parameters) {
    let keys = KEY_CACHE.get_from_param(param);
    let (cks, sks) = (keys.client_key(), keys.server_key());
    //RNG
    let mut rng = rand::thread_rng();

    let modulus = cks.parameters.message_modulus.0 as u64;
    let mod_scalar = cks.parameters.carry_modulus.0 as u8;

    for _ in 0..NB_TEST {
        let mut clear_0 = rng.gen::<u64>() % modulus;
        let mut clear_1 = rng.gen::<u64>() % modulus;
        let scalar = rng.gen::<u8>() % mod_scalar;

        // encryption of an integer
        let mut ctxt_0 = cks.encrypt(clear_0);

        // encryption of an integer
        let mut ctxt_1 = cks.encrypt(clear_1);

        sks.unchecked_scalar_mul_assign(&mut ctxt_0, scalar);
        sks.unchecked_scalar_mul_assign(&mut ctxt_1, scalar);

        clear_0 *= scalar as u64;
        clear_1 *= scalar as u64;

        // add the two ciphertexts
        let ct_res = sks.smart_less_or_equal(&mut ctxt_0, &mut ctxt_1);

        // decryption of ct_res
        let dec_res = cks.decrypt(&ct_res);

        // assert
        assert_eq!(((clear_0 % modulus) <= (clear_1 % modulus)) as u64, dec_res);
    }
}

fn shortint_unchecked_equal(param: Parameters) {
    let keys = KEY_CACHE.get_from_param(param);
    let (cks, sks) = (keys.client_key(), keys.server_key());
    //RNG
    let mut rng = rand::thread_rng();

    let modulus = cks.parameters.message_modulus.0 as u64;

    for _ in 0..NB_TEST {
        let clear_0 = rng.gen::<u64>() % modulus;
        let clear_1 = rng.gen::<u64>() % modulus;

        // encryption of an integer
        let ctxt_0 = cks.encrypt(clear_0);

        // encryption of an integer
        let ctxt_1 = cks.encrypt(clear_1);

        // add the two ciphertexts
        let ct_res = sks.unchecked_equal(&ctxt_0, &ctxt_1);

        // decryption of ct_res
        let dec_res = cks.decrypt(&ct_res);

        // assert
        assert_eq!((clear_0 == clear_1) as u64, dec_res);
    }
}

/// test '==' with the LWE server key
fn shortint_smart_equal(param: Parameters) {
    let keys = KEY_CACHE.get_from_param(param);
    let (cks, sks) = (keys.client_key(), keys.server_key());
    //RNG
    let mut rng = rand::thread_rng();

    let modulus = cks.parameters.message_modulus.0 as u64;
    let mod_scalar = cks.parameters.carry_modulus.0 as u8;

    for _ in 0..NB_TEST {
        let mut clear_0 = rng.gen::<u64>() % modulus;
        let mut clear_1 = rng.gen::<u64>() % modulus;
        let scalar = rng.gen::<u8>() % mod_scalar;

        // encryption of an integer
        let mut ctxt_0 = cks.encrypt(clear_0);

        // encryption of an integer
        let mut ctxt_1 = cks.encrypt(clear_1);

        sks.unchecked_scalar_mul_assign(&mut ctxt_0, scalar);
        sks.unchecked_scalar_mul_assign(&mut ctxt_1, scalar);

        clear_0 *= scalar as u64;
        clear_1 *= scalar as u64;

        // add the two ciphertexts
        let ct_res = sks.smart_equal(&mut ctxt_0, &mut ctxt_1);

        // decryption of ct_res
        let dec_res = cks.decrypt(&ct_res);

        // assert
        assert_eq!(((clear_0 % modulus) == (clear_1 % modulus)) as u64, dec_res);
    }
}

/// test '==' with the LWE server key
fn shortint_smart_scalar_equal(param: Parameters) {
    let keys = KEY_CACHE.get_from_param(param);
    let (cks, sks) = (keys.client_key(), keys.server_key());
    //RNG
    let mut rng = rand::thread_rng();

    let msg_modulus = cks.parameters.message_modulus.0 as u64;
    let modulus = (cks.parameters.message_modulus.0 * cks.parameters.carry_modulus.0) as u64;

    for _ in 0..NB_TEST {
        let clear = rng.gen::<u64>() % msg_modulus;

        let scalar = (rng.gen::<u16>() % modulus as u16) as u8;

        // encryption of an integer
        let ctxt = cks.encrypt(clear);

        // add the two ciphertexts
        let ct_res = sks.smart_scalar_equal(&ctxt, scalar);

        // decryption of ct_res
        let dec_res = cks.decrypt(&ct_res);

        // assert
        assert_eq!((clear == scalar as u64) as u64, dec_res);
    }
}

/// test '<' with the LWE server key
fn shortint_smart_scalar_less(param: Parameters) {
    let keys = KEY_CACHE.get_from_param(param);
    let (cks, sks) = (keys.client_key(), keys.server_key());
    //RNG
    let mut rng = rand::thread_rng();

    let msg_modulus = cks.parameters.message_modulus.0 as u64;
    let modulus = (cks.parameters.message_modulus.0 * cks.parameters.carry_modulus.0) as u64;

    for _ in 0..NB_TEST {
        let clear = rng.gen::<u64>() % msg_modulus;

        let scalar = (rng.gen::<u16>() % modulus as u16) as u8;

        // encryption of an integer
        let ctxt = cks.encrypt(clear);

        // add the two ciphertexts
        let ct_res = sks.smart_scalar_less(&ctxt, scalar);

        // decryption of ct_res
        let dec_res = cks.decrypt(&ct_res);

        // assert
        assert_eq!((clear < scalar as u64) as u64, dec_res);
    }
}

/// test '<=' with the LWE server key
fn shortint_smart_scalar_less_or_equal(param: Parameters) {
    let keys = KEY_CACHE.get_from_param(param);
    let (cks, sks) = (keys.client_key(), keys.server_key());
    //RNG
    let mut rng = rand::thread_rng();

    let msg_modulus = cks.parameters.message_modulus.0 as u64;
    let modulus = (cks.parameters.message_modulus.0 * cks.parameters.carry_modulus.0) as u64;

    for _ in 0..NB_TEST {
        let clear = rng.gen::<u64>() % msg_modulus;

        let scalar = (rng.gen::<u16>() % modulus as u16) as u8;

        // encryption of an integer
        let ctxt = cks.encrypt(clear);

        // add the two ciphertexts
        let ct_res = sks.smart_scalar_less_or_equal(&ctxt, scalar);

        // decryption of ct_res
        let dec_res = cks.decrypt(&ct_res);

        // assert
        assert_eq!((clear <= scalar as u64) as u64, dec_res);
    }
}

/// test '>' with the LWE server key
fn shortint_smart_scalar_greater(param: Parameters) {
    let keys = KEY_CACHE.get_from_param(param);
    let (cks, sks) = (keys.client_key(), keys.server_key());
    //RNG
    let mut rng = rand::thread_rng();

    let msg_modulus = cks.parameters.message_modulus.0 as u64;
    let modulus = (cks.parameters.message_modulus.0 * cks.parameters.carry_modulus.0) as u64;

    for _ in 0..NB_TEST {
        let clear = rng.gen::<u64>() % msg_modulus;

        let scalar = (rng.gen::<u16>() % modulus as u16) as u8;

        // encryption of an integer
        let ctxt = cks.encrypt(clear);

        // add the two ciphertexts
        let ct_res = sks.smart_scalar_greater(&ctxt, scalar);

        // decryption of ct_res
        let dec_res = cks.decrypt(&ct_res);

        // assert
        assert_eq!((clear > scalar as u64) as u64, dec_res);
    }
}

/// test '>' with the LWE server key
fn shortint_smart_scalar_greater_or_equal(param: Parameters) {
    let keys = KEY_CACHE.get_from_param(param);
    let (cks, sks) = (keys.client_key(), keys.server_key());
    //RNG
    let mut rng = rand::thread_rng();

    let msg_modulus = cks.parameters.message_modulus.0 as u64;
    let modulus = (cks.parameters.message_modulus.0 * cks.parameters.carry_modulus.0) as u64;

    for _ in 0..NB_TEST {
        let clear = rng.gen::<u64>() % msg_modulus;

        let scalar = (rng.gen::<u16>() % modulus as u16) as u8;

        // encryption of an integer
        let ctxt = cks.encrypt(clear);

        // add the two ciphertexts
        let ct_res = sks.smart_scalar_greater_or_equal(&ctxt, scalar);

        // decryption of ct_res
        let dec_res = cks.decrypt(&ct_res);

        // assert
        assert_eq!((clear >= scalar as u64) as u64, dec_res);
    }
}

/// test division with the LWE server key
fn shortint_unchecked_div(param: Parameters) {
    let keys = KEY_CACHE.get_from_param(param);
    let (cks, sks) = (keys.client_key(), keys.server_key());
    //RNG
    let mut rng = rand::thread_rng();

    let modulus = cks.parameters.message_modulus.0 as u64;

    for _ in 0..NB_TEST {
        let clear_0 = rng.gen::<u64>() % modulus;
        let clear_1 = (rng.gen::<u64>() % (modulus - 1)) + 1;

        // encryption of an integer
        let ctxt_0 = cks.encrypt(clear_0);

        // encryption of an integer
        let ctxt_1 = cks.encrypt(clear_1);

        // add the two ciphertexts
        let ct_res = sks.unchecked_div(&ctxt_0, &ctxt_1);

        // decryption of ct_res
        let dec_res = cks.decrypt(&ct_res);

        // assert
        assert_eq!(clear_0 / clear_1, dec_res);
    }
}

/// test scalar division with the LWE server key
fn shortint_unchecked_scalar_div(param: Parameters) {
    let keys = KEY_CACHE.get_from_param(param);
    let (cks, sks) = (keys.client_key(), keys.server_key());
    //RNG
    let mut rng = rand::thread_rng();

    let modulus = cks.parameters.message_modulus.0 as u64;

    for _ in 0..NB_TEST {
        let clear_0 = rng.gen::<u64>() % modulus;
        let clear_1 = (rng.gen::<u64>() % (modulus - 1)) + 1;

        // encryption of an integer
        let ctxt_0 = cks.encrypt(clear_0);

        // add the two ciphertexts
        let ct_res = sks.unchecked_scalar_div(&ctxt_0, clear_1 as u8);

        // decryption of ct_res
        let dec_res = cks.decrypt(&ct_res);

        // assert
        assert_eq!(clear_0 / clear_1, dec_res);
    }
}

/// test modulus with the LWE server key
fn shortint_unchecked_mod(param: Parameters) {
    let keys = KEY_CACHE.get_from_param(param);
    let (cks, sks) = (keys.client_key(), keys.server_key());
    //RNG
    let mut rng = rand::thread_rng();

    let modulus = cks.parameters.message_modulus.0 as u64;

    for _ in 0..NB_TEST {
        let clear_0 = rng.gen::<u64>() % modulus;
        let clear_1 = (rng.gen::<u64>() % (modulus - 1)) + 1;

        // encryption of an integer
        let ctxt_0 = cks.encrypt(clear_0);

        // add the two ciphertexts
        let ct_res = sks.unchecked_scalar_mod(&ctxt_0, clear_1 as u8);

        // decryption of ct_res
        let dec_res = cks.decrypt(&ct_res);

        // assert
        assert_eq!(clear_0 % clear_1, dec_res);
    }
}

/// test LSB multiplication with the LWE server key
fn shortint_unchecked_mul_lsb(param: Parameters) {
    let keys = KEY_CACHE.get_from_param(param);
    let (cks, sks) = (keys.client_key(), keys.server_key());
    //RNG
    let mut rng = rand::thread_rng();

    let modulus = cks.parameters.message_modulus.0 as u64;

    for _ in 0..NB_TEST {
        let clear_0 = rng.gen::<u64>() % modulus;
        let clear_1 = rng.gen::<u64>() % modulus;

        // encryption of an integer
        let ctxt_0 = cks.encrypt(clear_0);

        // encryption of an integer
        let ctxt_1 = cks.encrypt(clear_1);

        // add the two ciphertexts
        let ct_res = sks.unchecked_mul_lsb(&ctxt_0, &ctxt_1);

        // decryption of ct_res
        let dec_res = cks.decrypt(&ct_res);

        // assert
        assert_eq!((clear_0 * clear_1) % modulus, dec_res);
    }
}

/// test MSB multiplication with the LWE server key
fn shortint_unchecked_mul_msb(param: Parameters) {
    let keys = KEY_CACHE.get_from_param(param);
    let (cks, sks) = (keys.client_key(), keys.server_key());
    //RNG
    let mut rng = rand::thread_rng();

    let modulus = cks.parameters.message_modulus.0 as u64;

    for _ in 0..NB_TEST {
        let clear_0 = rng.gen::<u64>() % modulus;
        let clear_1 = rng.gen::<u64>() % modulus;

        // encryption of an integer
        let ctxt_0 = cks.encrypt(clear_0);

        // encryption of an integer
        let ctxt_1 = cks.encrypt(clear_1);

        // add the two ciphertexts
        let ct_res = sks.unchecked_mul_msb(&ctxt_0, &ctxt_1);

        // decryption of ct_res
        let dec_res = cks.decrypt(&ct_res);

        // assert
        assert_eq!((clear_0 * clear_1) / modulus, dec_res);
    }
}

/// test LSB multiplication with the LWE server key
fn shortint_smart_mul_lsb(param: Parameters) {
    let keys = KEY_CACHE.get_from_param(param);
    let (cks, sks) = (keys.client_key(), keys.server_key());
    //RNG
    let mut rng = rand::thread_rng();

    let modulus = cks.parameters.message_modulus.0 as u64;

    for _ in 0..10 {
        let clear_0 = rng.gen::<u64>() % modulus;

        let clear_1 = rng.gen::<u64>() % modulus;

        // encryption of an integer
        let mut ctxt_0 = cks.encrypt(clear_0);

        // encryption of an integer
        let mut ctxt_1 = cks.encrypt(clear_1);

        // add the two ciphertexts
        let mut ct_res = sks.smart_mul_lsb(&mut ctxt_0, &mut ctxt_1);

        let mut clear = clear_0 * clear_1;

        //add multiple times to raise the degree
        for _ in 0..30 {
            ct_res = sks.smart_mul_lsb(&mut ct_res, &mut ctxt_0);
            clear = (clear * clear_0) % modulus;

            // decryption of ct_res
            let dec_res = cks.decrypt(&ct_res);

            // assert
            assert_eq!(clear, dec_res);
        }
    }
}

/// test MSB multiplication with the LWE server key
fn shortint_smart_mul_msb(param: Parameters) {
    let keys = KEY_CACHE.get_from_param(param);
    let (cks, sks) = (keys.client_key(), keys.server_key());
    //RNG
    let mut rng = rand::thread_rng();

    let modulus = cks.parameters.message_modulus.0 as u64;

    for _ in 0..10 {
        let clear_0 = rng.gen::<u64>() % modulus;

        let clear_1 = rng.gen::<u64>() % modulus;

        // encryption of an integer
        let mut ctxt_0 = cks.encrypt(clear_0);

        // encryption of an integer
        let mut ctxt_1 = cks.encrypt(clear_1);

        // add the two ciphertexts
        let mut ct_res = sks.smart_mul_msb(&mut ctxt_0, &mut ctxt_1);

        let mut clear = (clear_0 * clear_1) / modulus;

        // let dec_res = cks.decrypt(&ct_res);
        // println!("clear_0 = {}, clear_1 = {}, dec = {}, clear = {}", clear_0, clear_1, dec_res,
        // clear);

        //add multiple times to raise the degree
        for _ in 0..30 {
            ct_res = sks.smart_mul_msb(&mut ct_res, &mut ctxt_0);
            clear = (clear * clear_0) / modulus;

            // decryption of ct_res
            let dec_res = cks.decrypt(&ct_res);

            // assert
            assert_eq!(clear % modulus, dec_res);
        }
    }
}

/// test unchecked negation
fn shortint_unchecked_neg(param: Parameters) {
    let keys = KEY_CACHE.get_from_param(param);
    let (cks, sks) = (keys.client_key(), keys.server_key());
    //RNG
    let mut rng = rand::thread_rng();

    let modulus = cks.parameters.message_modulus.0 as u64;

    for _ in 0..NB_TEST {
        // Define the cleartexts
        let clear = rng.gen::<u64>() % modulus;

        // Encrypt the integers
        let ctxt = cks.encrypt(clear);

        // Negates the ctxt
        let ct_tmp = sks.unchecked_neg(&ctxt);

        // Decrypt the result
        let dec = cks.decrypt(&ct_tmp);

        // Check the correctness
        let clear_result = clear.wrapping_neg() % modulus;

        assert_eq!(clear_result, dec);
    }
}

/// test smart negation
fn shortint_smart_neg(param: Parameters) {
    let keys = KEY_CACHE.get_from_param(param);
    let (cks, sks) = (keys.client_key(), keys.server_key());
    //RNG
    let mut rng = rand::thread_rng();

    let modulus = cks.parameters.message_modulus.0 as u64;

    for _ in 0..10 {
        let clear1 = rng.gen::<u64>() % modulus;

        let mut ct1 = cks.encrypt(clear1);

        let mut ct_res = sks.smart_neg(&mut ct1);

        let mut clear_result = clear1.wrapping_neg() % modulus;

        for _ in 0..30 {
            // scalar multiplication
            ct_res = sks.smart_neg(&mut ct_res);

            clear_result = clear_result.wrapping_neg() % modulus;

            // decryption of ct_res
            let dec_res = cks.decrypt(&ct_res);

            // assert
            assert_eq!(clear_result, dec_res);
        }
    }
}

/// test scalar add
fn shortint_unchecked_scalar_add(param: Parameters) {
    let keys = KEY_CACHE.get_from_param(param);
    let (cks, sks) = (keys.client_key(), keys.server_key());

    let mut rng = rand::thread_rng();

    let message_modulus = param.message_modulus.0 as u8;

    for _ in 0..NB_TEST {
        let clear = rng.gen::<u8>() % message_modulus as u8;

        let scalar = rng.gen::<u8>() % message_modulus as u8;

        // encryption of an integer
        let ct = cks.encrypt(clear as u64);

        // add the two ciphertexts
        let ct_res = sks.unchecked_scalar_add(&ct, scalar);

        // decryption of ct_res
        let dec_res = cks.decrypt(&ct_res);

        // assert
        assert_eq!((clear + scalar) % message_modulus, dec_res as u8);
    }
}

/// test smart scalar add
fn shortint_smart_scalar_add(param: Parameters) {
    let keys = KEY_CACHE.get_from_param(param);
    let (cks, sks) = (keys.client_key(), keys.server_key());
    //RNG
    let mut rng = rand::thread_rng();

    let modulus = cks.parameters.message_modulus.0 as u8;

    for _ in 0..10 {
        let clear_0 = rng.gen::<u8>() % modulus;

        let clear_1 = rng.gen::<u8>() % modulus;

        // encryption of an integer
        let mut ctxt_0 = cks.encrypt(clear_0 as u64);

        // add the two ciphertexts
        let mut ct_res = sks.smart_scalar_add(&mut ctxt_0, clear_1);

        let mut clear = (clear_0 + clear_1) % modulus;

        //add multiple times to raise the degree
        for _ in 0..30 {
            ct_res = sks.smart_scalar_add(&mut ct_res, clear_1);
            clear = (clear + clear_1) % modulus;

            // decryption of ct_res
            let dec_res = cks.decrypt(&ct_res);

            assert_eq!(clear, dec_res as u8);
        }
    }
}

/// test unchecked scalar sub
fn shortint_unchecked_scalar_sub(param: Parameters) {
    let keys = KEY_CACHE.get_from_param(param);
    let (cks, sks) = (keys.client_key(), keys.server_key());

    let mut rng = rand::thread_rng();

    let message_modulus = param.message_modulus.0 as u8;

    for _ in 0..NB_TEST {
        let clear = rng.gen::<u8>() % message_modulus;

        let scalar = rng.gen::<u8>() % message_modulus;

        // encryption of an integer
        let ct = cks.encrypt(clear as u64);

        // add the two ciphertexts
        let ct_res = sks.unchecked_scalar_sub(&ct, scalar);

        // decryption of ct_res
        let dec_res = cks.decrypt(&ct_res);

        // assert
        assert_eq!((clear - scalar) % message_modulus, dec_res as u8);
    }
}

fn shortint_smart_scalar_sub(param: Parameters) {
    let keys = KEY_CACHE.get_from_param(param);
    let (cks, sks) = (keys.client_key(), keys.server_key());
    //RNG
    let mut rng = rand::thread_rng();

    let modulus = cks.parameters.message_modulus.0 as u8;

    for _ in 0..10 {
        let clear_0 = rng.gen::<u8>() % modulus;

        let clear_1 = rng.gen::<u8>() % modulus;

        // encryption of an integer
        let mut ctxt_0 = cks.encrypt(clear_0 as u64);

        // add the two ciphertexts
        let mut ct_res = sks.smart_scalar_sub(&mut ctxt_0, clear_1);

        let mut clear = (clear_0 - clear_1) % modulus;

        // let dec_res = cks.decrypt(&ct_res);
        // println!("clear_0 = {}, clear_1 = {}, dec = {}, clear = {}", clear_0, clear_1, dec_res,
        // clear);

        //add multiple times to raise the degree
        for _ in 0..30 {
            ct_res = sks.smart_scalar_sub(&mut ct_res, clear_1);
            clear = (clear - clear_1) % modulus;

            // decryption of ct_res
            let dec_res = cks.decrypt(&ct_res);

            // println!("clear_1 = {}, dec = {}, clear = {}", clear_1, dec_res, clear);
            // assert
            assert_eq!(clear, dec_res as u8);
        }
    }
}

/// test scalar multiplication with the LWE server key
fn shortint_unchecked_scalar_mul(param: Parameters) {
    let keys = KEY_CACHE.get_from_param(param);
    let (cks, sks) = (keys.client_key(), keys.server_key());

    let mut rng = rand::thread_rng();

    let message_modulus = param.message_modulus.0 as u8;
    let carry_modulus = param.carry_modulus.0 as u8;

    for _ in 0..NB_TEST {
        let clear = rng.gen::<u8>() % message_modulus;

        let scalar = rng.gen::<u8>() % carry_modulus;

        // encryption of an integer
        let ct = cks.encrypt(clear as u64);

        // add the two ciphertexts
        let ct_res = sks.unchecked_scalar_mul(&ct, scalar);

        // decryption of ct_res
        let dec_res = cks.decrypt(&ct_res);

        // assert
        assert_eq!((clear * scalar) % message_modulus, dec_res as u8);
    }
}

/// test smart scalar multiplication with the LWE server key
fn shortint_smart_scalar_mul(param: Parameters) {
    let keys = KEY_CACHE.get_from_param(param);
    let (cks, sks) = (keys.client_key(), keys.server_key());
    //RNG
    let mut rng = rand::thread_rng();

    let modulus = cks.parameters.message_modulus.0 as u8;

    let scalar_modulus = cks.parameters.carry_modulus.0 as u8;

    for _ in 0..10 {
        let clear = rng.gen::<u8>() % modulus;

        let scalar = rng.gen::<u8>() % scalar_modulus;

        // encryption of an integer
        let mut ct = cks.encrypt(clear as u64);

        let mut ct_res = sks.smart_scalar_mul(&mut ct, scalar);

        let mut clear_res = clear * scalar;
        for _ in 0..10 {
            // scalar multiplication
            ct_res = sks.smart_scalar_mul(&mut ct_res, scalar);
            clear_res = (clear_res * scalar) % modulus;
        }

        // decryption of ct_res
        let dec_res = cks.decrypt(&ct_res);

        // assert
        assert_eq!(clear_res, dec_res as u8);
    }
}

/// test unchecked '>>' operation
fn shortint_unchecked_right_shift(param: Parameters) {
    let keys = KEY_CACHE.get_from_param(param);
    let (cks, sks) = (keys.client_key(), keys.server_key());
    //RNG
    let mut rng = rand::thread_rng();

    let modulus = cks.parameters.message_modulus.0 as u64;

    for _ in 0..NB_TEST {
        let clear_0 = rng.gen::<u64>() % modulus;
        let shift = rng.gen::<u64>() % 2;

        // encryption of an integer
        let ctxt_0 = cks.encrypt(clear_0);

        // add the two ciphertexts
        let ct_res = sks.unchecked_scalar_right_shift(&ctxt_0, shift as u8);

        // decryption of ct_res
        let dec_res = cks.decrypt(&ct_res);

        // assert
        assert_eq!(clear_0 >> shift, dec_res);
    }
}

/// test '<<' operation
fn shortint_unchecked_left_shift(param: Parameters) {
    let keys = KEY_CACHE.get_from_param(param);
    let (cks, sks) = (keys.client_key(), keys.server_key());
    //RNG
    let mut rng = rand::thread_rng();

    let modulus = cks.parameters.message_modulus.0 as u64;

    for _ in 0..NB_TEST {
        let clear_0 = rng.gen::<u64>() % modulus;
        let shift = rng.gen::<u64>() % 2;

        // encryption of an integer
        let ctxt_0 = cks.encrypt(clear_0);

        // add the two ciphertexts
        let ct_res = sks.unchecked_scalar_left_shift(&ctxt_0, shift as u8);

        // decryption of ct_res
        let dec_res = cks.decrypt(&ct_res);

        // assert
        assert_eq!((clear_0 << shift) % modulus, dec_res);
    }
}

/// test unchecked subtraction
fn shortint_unchecked_sub(param: Parameters) {
    let keys = KEY_CACHE.get_from_param(param);
    let (cks, sks) = (keys.client_key(), keys.server_key());
    //RNG
    let mut rng = rand::thread_rng();

    let modulus = cks.parameters.message_modulus.0 as u64;
    for _ in 0..NB_TEST {
        // Define the cleartexts
        let clear1 = rng.gen::<u64>() % modulus;
        let clear2 = rng.gen::<u64>() % modulus;

        // Encrypt the integers
        let ctxt_1 = cks.encrypt(clear1);
        let ctxt_2 = cks.encrypt(clear2);

        // Add the ciphertext 1 and 2
        let ct_tmp = sks.unchecked_sub(&ctxt_1, &ctxt_2);

        // Decrypt the result
        let dec = cks.decrypt(&ct_tmp);

        // Check the correctness
        let clear_result = (clear1 - clear2) % modulus;
        assert_eq!(clear_result, dec % modulus);
    }
}

fn shortint_smart_sub(param: Parameters) {
    let keys = KEY_CACHE.get_from_param(param);
    let (cks, sks) = (keys.client_key(), keys.server_key());
    //RNG
    let mut rng = rand::thread_rng();

    let modulus = cks.parameters.message_modulus.0 as u64;

    for _ in 0..10 {
        let clear1 = rng.gen::<u64>() % modulus;
        let clear2 = rng.gen::<u64>() % modulus;

        let mut ct1 = cks.encrypt(clear1);
        let mut ct2 = cks.encrypt(clear2);

        let mut ct_res = sks.smart_sub(&mut ct1, &mut ct2);

        let mut clear_res = (clear1 - clear2) % modulus;
        for _ in 0..10 {
            // scalar multiplication
            ct_res = sks.smart_sub(&mut ct_res, &mut ct2);
            clear_res = (clear_res - clear2) % modulus;
        }
        // decryption of ct_res
        let dec_res = cks.decrypt(&ct_res);

        // assert
        assert_eq!(clear_res, dec_res);
    }
}

/// test multiplication
fn shortint_mul_small_carry(param: Parameters) {
    let keys = KEY_CACHE.get_from_param(param);
    let (cks, sks) = (keys.client_key(), keys.server_key());
    //RNG
    let mut rng = rand::thread_rng();

    let modulus = cks.parameters.message_modulus.0 as u64;

    for _ in 0..50 {
        let clear_0 = rng.gen::<u64>() % modulus;

        let clear_1 = rng.gen::<u64>() % modulus;

        // encryption of an integer
        let mut ctxt_zero = cks.encrypt(clear_0);

        // encryption of an integer
        let mut ctxt_one = cks.encrypt(clear_1);

        // multiply together the two ciphertexts
        let ct_res = sks.unchecked_mul_lsb_small_carry(&mut ctxt_zero, &mut ctxt_one);

        // decryption of ct_res
        let dec_res = cks.decrypt(&ct_res);

        // assert
        assert_eq!((clear_0 * clear_1) % modulus, dec_res % modulus);
    }
}

/// test encryption and decryption with the LWE client key
fn shortint_encrypt_with_message_modulus_smart_add_and_mul(param: Parameters) {
    let keys = KEY_CACHE.get_from_param(param);
    let (cks, sks) = (keys.client_key(), keys.server_key());

    let mut rng = rand::thread_rng();
    let full_mod = (cks.parameters.message_modulus.0 * cks.parameters.carry_modulus.0) / 3;

    for _ in 0..NB_TEST {
        let mut modulus = rng.gen::<u64>() % full_mod as u64;
        while modulus == 0 {
            modulus = rng.gen::<u64>() % full_mod as u64;
        }

        let clear1 = rng.gen::<u64>() % modulus;
        let clear2 = rng.gen::<u64>() % modulus;

        let mut ct1 = cks.encrypt_with_message_modulus(clear1, MessageModulus(modulus as usize));
        let mut ct2 = cks.encrypt_with_message_modulus(clear2, MessageModulus(modulus as usize));

        println!(
            "MUL SMALL CARRY:: clear1 = {}, clear2 = {}, mod = {}",
            clear1, clear2, modulus
        );
        let ct_res = sks.unchecked_mul_lsb_small_carry(&mut ct1, &mut ct2);
        assert_eq!(
            (clear1 * clear2) % modulus,
            cks.decrypt_message_and_carry(&ct_res) % modulus
        );

        println!(
            "ADD:: clear1 = {}, clear2 = {}, mod = {}",
            clear1, clear2, modulus
        );
        let ct_res = sks.unchecked_add(&ct1, &ct2);
        assert_eq!((clear1 + clear2), cks.decrypt_message_and_carry(&ct_res));
    }
}
