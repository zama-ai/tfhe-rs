use crate::shortint::keycache::KEY_CACHE;
use crate::shortint::parameters::*;
use crate::shortint::server_key::tests::parametrized_test::create_parametrized_test;
use rand::Rng;

/// Number of assert in randomized tests
#[cfg(not(tarpaulin))]
const NB_TESTS: usize = 200;
/// Number of iterations in randomized tests for smart operations
#[cfg(not(tarpaulin))]
const NB_TESTS_SMART: usize = 10;
/// Number of sub tests used to increase degree of ciphertexts
#[cfg(not(tarpaulin))]
const NB_SUB_TEST_SMART: usize = 40;

// Use lower numbers for coverage to ensure fast tests to counter balance slowdown due to code
// instrumentation
#[cfg(tarpaulin)]
const NB_TESTS: usize = 1;
/// Number of iterations in randomized tests for smart operations
#[cfg(tarpaulin)]
const NB_TESTS_SMART: usize = 1;
// This constant is tailored to trigger a message extract during operation processing.
// It's applicable for PARAM_MESSAGE_2_CARRY_2_KS_PBS parameters set.
#[cfg(tarpaulin)]
const NB_SUB_TEST_SMART: usize = 5;

//Macro to generate tests for parameters sets compatible with the bivariate pbs
#[cfg(not(tarpaulin))]
macro_rules! create_parametrized_test_bivariate_pbs_compliant{
    ($name:ident { $($param:ident),* }) => {
        ::paste::paste! {
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
            PARAM_MESSAGE_1_CARRY_1_KS_PBS,
            PARAM_MESSAGE_1_CARRY_2_KS_PBS,
            PARAM_MESSAGE_1_CARRY_3_KS_PBS,
            PARAM_MESSAGE_1_CARRY_4_KS_PBS,
            PARAM_MESSAGE_1_CARRY_5_KS_PBS,
            PARAM_MESSAGE_1_CARRY_6_KS_PBS,
            PARAM_MESSAGE_1_CARRY_7_KS_PBS,
            PARAM_MESSAGE_2_CARRY_2_KS_PBS,
            PARAM_MESSAGE_2_CARRY_3_KS_PBS,
            PARAM_MESSAGE_2_CARRY_4_KS_PBS,
            PARAM_MESSAGE_2_CARRY_5_KS_PBS,
            PARAM_MESSAGE_2_CARRY_6_KS_PBS,
            PARAM_MESSAGE_3_CARRY_3_KS_PBS,
            PARAM_MESSAGE_3_CARRY_4_KS_PBS,
            PARAM_MESSAGE_3_CARRY_5_KS_PBS,
            PARAM_MESSAGE_4_CARRY_4_KS_PBS,
            PARAM_MULTI_BIT_MESSAGE_1_CARRY_1_GROUP_2_KS_PBS,
            PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_2_KS_PBS,
            PARAM_MULTI_BIT_MESSAGE_3_CARRY_3_GROUP_2_KS_PBS,
            PARAM_MULTI_BIT_MESSAGE_1_CARRY_1_GROUP_3_KS_PBS,
            PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_3_KS_PBS,
            PARAM_MULTI_BIT_MESSAGE_3_CARRY_3_GROUP_3_KS_PBS
        });
    };
}

// Test against a small subset of parameters to speed up coverage tests
#[cfg(tarpaulin)]
macro_rules! create_parametrized_test_bivariate_pbs_compliant{
    ($name:ident { $($param:ident),* }) => {
        ::paste::paste! {
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
            PARAM_MESSAGE_2_CARRY_2_KS_PBS,
            PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_2_KS_PBS,
            PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_3_KS_PBS
        });
    };
}

// Public key tests are limited to small parameter sets to avoid blowing up memory and large testing
// times. Compressed keygen takes 20 minutes for params 2_2 and for encryption as well.
// 2_2 uncompressed keys take ~2 GB and 3_3 about ~34 GB, hence why we stop at 2_2.
#[cfg(not(tarpaulin))]
#[test]
fn test_shortint_compressed_public_key_smart_add_param_message_1_carry_1_ks_pbs() {
    shortint_compressed_public_key_smart_add(PARAM_MESSAGE_1_CARRY_1_KS_PBS);
}

#[cfg(not(tarpaulin))]
#[test]
fn test_shortint_public_key_smart_add_param_message_1_carry_1_ks_pbs() {
    shortint_public_key_smart_add(PARAM_MESSAGE_1_CARRY_1_KS_PBS);
}

#[cfg(not(tarpaulin))]
#[test]
fn test_shortint_public_key_smart_add_param_message_2_carry_2_ks_pbs() {
    shortint_public_key_smart_add(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
}

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
create_parametrized_test_bivariate_pbs_compliant!(shortint_default_bitand);
create_parametrized_test_bivariate_pbs_compliant!(shortint_smart_bitor);
create_parametrized_test_bivariate_pbs_compliant!(shortint_default_bitor);
create_parametrized_test_bivariate_pbs_compliant!(shortint_smart_bitxor);
create_parametrized_test_bivariate_pbs_compliant!(shortint_default_bitxor);
create_parametrized_test_bivariate_pbs_compliant!(shortint_smart_greater);
create_parametrized_test_bivariate_pbs_compliant!(shortint_default_greater);
create_parametrized_test_bivariate_pbs_compliant!(shortint_smart_greater_or_equal);
create_parametrized_test_bivariate_pbs_compliant!(shortint_default_greater_or_equal);
create_parametrized_test_bivariate_pbs_compliant!(shortint_smart_less);
create_parametrized_test_bivariate_pbs_compliant!(shortint_default_less);
create_parametrized_test_bivariate_pbs_compliant!(shortint_smart_less_or_equal);
create_parametrized_test_bivariate_pbs_compliant!(shortint_default_less_or_equal);
create_parametrized_test_bivariate_pbs_compliant!(shortint_smart_equal);
create_parametrized_test_bivariate_pbs_compliant!(shortint_default_equal);
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
create_parametrized_test_bivariate_pbs_compliant!(shortint_default_mul_msb);
create_parametrized_test_bivariate_pbs_compliant!(
    shortint_keyswitch_bivariate_programmable_bootstrap
);
create_parametrized_test_bivariate_pbs_compliant!(shortint_unchecked_less_or_equal_trivial);

fn shortint_keyswitch_bivariate_programmable_bootstrap<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let keys = KEY_CACHE.get_from_param(param);
    let (cks, sks) = (keys.client_key(), keys.server_key());
    //RNG
    let mut rng = rand::thread_rng();

    let modulus = cks.parameters.message_modulus().0 as u64;

    for _ in 0..NB_TESTS {
        let clear_0 = rng.gen::<u64>() % modulus;
        let clear_1 = rng.gen::<u64>() % modulus;

        // encryption of an integer
        let ctxt_0 = cks.encrypt(clear_0);
        let ctxt_1 = cks.encrypt(clear_1);
        //define the lookup_table as identity
        let acc = sks.generate_lookup_table_bivariate(|x, y| (x * 2 * y) % modulus);
        // add the two ciphertexts
        let ct_res = sks.unchecked_apply_lookup_table_bivariate(&ctxt_0, &ctxt_1, &acc);

        // decryption of ct_res
        let dec_res = cks.decrypt(&ct_res);

        // assert
        assert_eq!((2 * clear_0 * clear_1) % modulus, dec_res);
    }
}

/// test addition with the LWE server key using the a public key for encryption
fn shortint_compressed_public_key_smart_add<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let keys = KEY_CACHE.get_from_param(param);
    let (cks, sks) = (keys.client_key(), keys.server_key());
    let pk = crate::shortint::CompressedPublicKey::new(cks);

    //RNG
    let mut rng = rand::thread_rng();

    let modulus = cks.parameters.message_modulus().0 as u64;

    for _ in 0..NB_TESTS_SMART {
        let clear_0 = rng.gen::<u64>() % modulus;

        let clear_1 = rng.gen::<u64>() % modulus;

        // encryption of an integer
        let mut ctxt_0 = pk.encrypt(clear_0);

        // encryption of an integer
        let mut ctxt_1 = pk.encrypt(clear_1);

        // add the two ciphertexts
        let mut ct_res = sks.smart_add(&mut ctxt_0, &mut ctxt_1);
        let mut clear = clear_0 + clear_1;

        // add multiple times to raise the degree and test the smart operation
        for _ in 0..NB_SUB_TEST_SMART {
            ct_res = sks.smart_add(&mut ct_res, &mut ctxt_0);
            clear += clear_0;

            // decryption of ct_res
            let dec_res = cks.decrypt(&ct_res);

            // assert
            assert_eq!(clear % modulus, dec_res);
        }
    }
}

/// test addition with the LWE server key using the a public key for encryption
fn shortint_public_key_smart_add<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let keys = KEY_CACHE.get_from_param(param);
    let (cks, sks) = (keys.client_key(), keys.server_key());
    let pk = crate::shortint::PublicKey::new(cks);

    //RNG
    let mut rng = rand::thread_rng();

    let modulus = cks.parameters.message_modulus().0 as u64;

    for _ in 0..NB_TESTS_SMART {
        let clear_0 = rng.gen::<u64>() % modulus;

        let clear_1 = rng.gen::<u64>() % modulus;

        // encryption of an integer
        let mut ctxt_0 = pk.encrypt(clear_0);

        // encryption of an integer
        let mut ctxt_1 = pk.encrypt(clear_1);

        // add the two ciphertexts
        let mut ct_res = sks.smart_add(&mut ctxt_0, &mut ctxt_1);
        let mut clear = clear_0 + clear_1;

        // add multiple times to raise the degree and test the smart operation
        for _ in 0..NB_SUB_TEST_SMART {
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
fn shortint_unchecked_bitand<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let keys = KEY_CACHE.get_from_param(param);
    let (cks, sks) = (keys.client_key(), keys.server_key());
    let mut rng = rand::thread_rng();

    let modulus = cks.parameters.message_modulus().0 as u64;

    for _ in 0..NB_TESTS {
        let clear_0 = rng.gen::<u64>() % modulus;
        let clear_1 = rng.gen::<u64>() % modulus;

        // encryption of an integer
        let ctxt_0 = cks.encrypt(clear_0);

        // encryption of an integer
        let ctxt_1 = cks.encrypt(clear_1);

        // add the two ciphertexts
        let ct_res = sks.unchecked_bitand(&ctxt_0, &ctxt_1);
        assert_eq!(ct_res.degree, ctxt_0.degree.after_bitand(ctxt_1.degree));

        // decryption of ct_res
        let dec_res = cks.decrypt(&ct_res);

        // assert
        assert_eq!(clear_0 & clear_1, dec_res);
    }
}

/// test bitwise 'or' with the LWE server key
fn shortint_unchecked_bitor<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let keys = KEY_CACHE.get_from_param(param);
    let (cks, sks) = (keys.client_key(), keys.server_key());
    //RNG
    let mut rng = rand::thread_rng();

    let modulus = cks.parameters.message_modulus().0 as u64;

    for _ in 0..NB_TESTS {
        let clear_0 = rng.gen::<u64>() % modulus;
        let clear_1 = rng.gen::<u64>() % modulus;

        // encryption of an integer
        let ctxt_0 = cks.encrypt(clear_0);

        // encryption of an integer
        let ctxt_1 = cks.encrypt(clear_1);

        // add the two ciphertexts
        let ct_res = sks.unchecked_bitor(&ctxt_0, &ctxt_1);
        assert_eq!(ct_res.degree, ctxt_0.degree.after_bitor(ctxt_1.degree));

        // decryption of ct_res
        let dec_res = cks.decrypt(&ct_res);

        // assert
        assert_eq!(clear_0 | clear_1, dec_res);
    }
}

/// test bitwise 'xor' with the LWE server key
fn shortint_unchecked_bitxor<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let keys = KEY_CACHE.get_from_param(param);
    let (cks, sks) = (keys.client_key(), keys.server_key());
    //RNG
    let mut rng = rand::thread_rng();

    let modulus = cks.parameters.message_modulus().0 as u64;

    for _ in 0..NB_TESTS {
        let clear_0 = rng.gen::<u64>() % modulus;
        let clear_1 = rng.gen::<u64>() % modulus;

        // encryption of an integer
        let ctxt_0 = cks.encrypt(clear_0);

        // encryption of an integer
        let ctxt_1 = cks.encrypt(clear_1);

        // add the two ciphertexts
        let ct_res = sks.unchecked_bitxor(&ctxt_0, &ctxt_1);
        assert_eq!(ct_res.degree, ctxt_0.degree.after_bitxor(ctxt_1.degree));

        // decryption of ct_res
        let dec_res = cks.decrypt(&ct_res);

        // assert
        assert_eq!(clear_0 ^ clear_1, dec_res);
    }
}

/// test bitwise 'and' with the LWE server key
fn shortint_smart_bitand<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let keys = KEY_CACHE.get_from_param(param);
    let (cks, sks) = (keys.client_key(), keys.server_key());
    //RNG
    let mut rng = rand::thread_rng();

    let modulus = cks.parameters.message_modulus().0 as u64;
    let mod_scalar = cks.parameters.carry_modulus().0 as u8;

    for _ in 0..NB_TESTS {
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

/// test default bitwise 'and' with the LWE server key
fn shortint_default_bitand<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let keys = KEY_CACHE.get_from_param(param);
    let (cks, sks) = (keys.client_key(), keys.server_key());
    //RNG
    let mut rng = rand::thread_rng();

    let modulus = cks.parameters.message_modulus().0 as u64;
    let mod_scalar = cks.parameters.carry_modulus().0 as u8;

    for _ in 0..NB_TESTS {
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
        let ct_res = sks.bitand(&ctxt_0, &ctxt_1);

        // decryption of ct_res
        let dec_res = cks.decrypt(&ct_res);

        // assert
        assert_eq!((clear_0 & clear_1) % modulus, dec_res);
    }
}

/// test bitwise 'or' with the LWE server key
fn shortint_smart_bitor<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let keys = KEY_CACHE.get_from_param(param);
    let (cks, sks) = (keys.client_key(), keys.server_key());
    //RNG
    let mut rng = rand::thread_rng();

    let modulus = cks.parameters.message_modulus().0 as u64;
    let mod_scalar = cks.parameters.carry_modulus().0 as u8;

    for _ in 0..NB_TESTS {
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

/// test default bitwise 'or' with the LWE server key
fn shortint_default_bitor<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let keys = KEY_CACHE.get_from_param(param);
    let (cks, sks) = (keys.client_key(), keys.server_key());
    //RNG
    let mut rng = rand::thread_rng();

    let modulus = cks.parameters.message_modulus().0 as u64;
    let mod_scalar = cks.parameters.carry_modulus().0 as u8;

    for _ in 0..NB_TESTS {
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
        let ct_res = sks.bitor(&ctxt_0, &ctxt_1);

        // decryption of ct_res
        let dec_res = cks.decrypt(&ct_res);

        // assert
        assert_eq!((clear_0 | clear_1) % modulus, dec_res);
    }
}

/// test bitwise 'xor' with the LWE server key
fn shortint_smart_bitxor<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let keys = KEY_CACHE.get_from_param(param);
    let (cks, sks) = (keys.client_key(), keys.server_key());
    //RNG
    let mut rng = rand::thread_rng();

    let modulus = cks.parameters.message_modulus().0 as u64;
    let mod_scalar = cks.parameters.carry_modulus().0 as u8;

    for _ in 0..NB_TESTS {
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

/// test default bitwise 'xor' with the LWE server key
fn shortint_default_bitxor<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let keys = KEY_CACHE.get_from_param(param);
    let (cks, sks) = (keys.client_key(), keys.server_key());
    //RNG
    let mut rng = rand::thread_rng();

    let modulus = cks.parameters.message_modulus().0 as u64;
    let mod_scalar = cks.parameters.carry_modulus().0 as u8;

    for _ in 0..NB_TESTS {
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
        let ct_res = sks.bitxor(&ctxt_0, &ctxt_1);

        // decryption of ct_res
        let dec_res = cks.decrypt(&ct_res);

        // assert
        assert_eq!((clear_0 ^ clear_1) % modulus, dec_res);
    }
}

/// test '>' with the LWE server key
fn shortint_unchecked_greater<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let keys = KEY_CACHE.get_from_param(param);
    let (cks, sks) = (keys.client_key(), keys.server_key());
    //RNG
    let mut rng = rand::thread_rng();

    let modulus = cks.parameters.message_modulus().0 as u64;

    for _ in 0..NB_TESTS {
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
fn shortint_smart_greater<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let keys = KEY_CACHE.get_from_param(param);
    let (cks, sks) = (keys.client_key(), keys.server_key());
    //RNG
    let mut rng = rand::thread_rng();

    let modulus = cks.parameters.message_modulus().0 as u64;

    for _ in 0..NB_TESTS {
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

/// test default '>' with the LWE server key
fn shortint_default_greater<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let keys = KEY_CACHE.get_from_param(param);
    let (cks, sks) = (keys.client_key(), keys.server_key());
    //RNG
    let mut rng = rand::thread_rng();

    let modulus = cks.parameters.message_modulus().0 as u64;

    for _ in 0..NB_TESTS {
        let clear_0 = rng.gen::<u64>() % modulus;
        let clear_1 = rng.gen::<u64>() % modulus;

        // encryption of an integer
        let ctxt_0 = cks.encrypt(clear_0);

        // encryption of an integer
        let ctxt_1 = cks.encrypt(clear_1);

        // add the two ciphertexts
        let ct_res = sks.greater(&ctxt_0, &ctxt_1);

        // decryption of ct_res
        let dec_res = cks.decrypt(&ct_res);

        // assert
        assert_eq!((clear_0 > clear_1) as u64, dec_res);
    }
}

/// test '>=' with the LWE server key
fn shortint_unchecked_greater_or_equal<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let keys = KEY_CACHE.get_from_param(param);
    let (cks, sks) = (keys.client_key(), keys.server_key());
    //RNG
    let mut rng = rand::thread_rng();

    let modulus = cks.parameters.message_modulus().0 as u64;

    for _ in 0..NB_TESTS {
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
fn shortint_smart_greater_or_equal<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let keys = KEY_CACHE.get_from_param(param);
    let (cks, sks) = (keys.client_key(), keys.server_key());
    //RNG
    let mut rng = rand::thread_rng();

    let modulus = cks.parameters.message_modulus().0 as u64;
    let mod_scalar = cks.parameters.carry_modulus().0 as u8;

    for _ in 0..NB_TESTS {
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

/// test default '>=' with the LWE server key
fn shortint_default_greater_or_equal<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let keys = KEY_CACHE.get_from_param(param);
    let (cks, sks) = (keys.client_key(), keys.server_key());
    //RNG
    let mut rng = rand::thread_rng();

    let modulus = cks.parameters.message_modulus().0 as u64;
    let mod_scalar = cks.parameters.carry_modulus().0 as u8;

    for _ in 0..NB_TESTS {
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
        let ct_res = sks.greater_or_equal(&ctxt_0, &ctxt_1);

        // decryption of ct_res
        let dec_res = cks.decrypt(&ct_res);

        // assert
        assert_eq!((clear_0 >= clear_1) as u64, dec_res);
    }
}

/// test '<' with the LWE server key
fn shortint_unchecked_less<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let keys = KEY_CACHE.get_from_param(param);
    let (cks, sks) = (keys.client_key(), keys.server_key());
    //RNG
    let mut rng = rand::thread_rng();

    let modulus = cks.parameters.message_modulus().0 as u64;

    for _ in 0..NB_TESTS {
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
fn shortint_smart_less<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let keys = KEY_CACHE.get_from_param(param);
    let (cks, sks) = (keys.client_key(), keys.server_key());
    //RNG
    let mut rng = rand::thread_rng();

    let modulus = cks.parameters.message_modulus().0 as u64;
    let mod_scalar = cks.parameters.carry_modulus().0 as u8;

    for _ in 0..NB_TESTS {
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

/// test default '<' with the LWE server key
fn shortint_default_less<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let keys = KEY_CACHE.get_from_param(param);
    let (cks, sks) = (keys.client_key(), keys.server_key());
    //RNG
    let mut rng = rand::thread_rng();

    let modulus = cks.parameters.message_modulus().0 as u64;
    let mod_scalar = cks.parameters.carry_modulus().0 as u8;

    for _ in 0..NB_TESTS {
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
        let ct_res = sks.less(&ctxt_0, &ctxt_1);

        // decryption of ct_res
        let dec_res = cks.decrypt(&ct_res);

        // assert
        assert_eq!((clear_0 < clear_1) as u64, dec_res);
    }
}

/// test '<=' with the LWE server key
fn shortint_unchecked_less_or_equal<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let keys = KEY_CACHE.get_from_param(param);
    let (cks, sks) = (keys.client_key(), keys.server_key());
    //RNG
    let mut rng = rand::thread_rng();

    let modulus = cks.parameters.message_modulus().0 as u64;

    for _ in 0..NB_TESTS {
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
fn shortint_unchecked_less_or_equal_trivial<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let keys = KEY_CACHE.get_from_param(param);
    let (cks, sks) = (keys.client_key(), keys.server_key());
    //RNG
    let mut rng = rand::thread_rng();

    let modulus = cks.parameters.message_modulus().0 as u64;

    for _ in 0..NB_TESTS {
        let clear_0 = rng.gen::<u64>() % modulus;
        let clear_1 = rng.gen::<u64>() % modulus;

        // encryption of an integer
        let ctxt_0 = sks.create_trivial(clear_0);

        // encryption of an integer
        let ctxt_1 = sks.create_trivial(clear_1);

        // add the two ciphertexts
        let ct_res = sks.unchecked_less_or_equal(&ctxt_0, &ctxt_1);

        // decryption of ct_res
        let dec_res = cks.decrypt(&ct_res);

        // assert
        assert_eq!((clear_0 <= clear_1) as u64, dec_res);
    }
}

/// test '<=' with the LWE server key
fn shortint_smart_less_or_equal<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let keys = KEY_CACHE.get_from_param(param);
    let (cks, sks) = (keys.client_key(), keys.server_key());
    //RNG
    let mut rng = rand::thread_rng();

    let modulus = cks.parameters.message_modulus().0 as u64;
    let mod_scalar = cks.parameters.carry_modulus().0 as u8;

    for _ in 0..NB_TESTS {
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

/// test default '<=' with the LWE server key
fn shortint_default_less_or_equal<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let keys = KEY_CACHE.get_from_param(param);
    let (cks, sks) = (keys.client_key(), keys.server_key());
    //RNG
    let mut rng = rand::thread_rng();

    let modulus = cks.parameters.message_modulus().0 as u64;
    let mod_scalar = cks.parameters.carry_modulus().0 as u8;

    for _ in 0..NB_TESTS {
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
        let ct_res = sks.less_or_equal(&ctxt_0, &ctxt_1);

        // decryption of ct_res
        let dec_res = cks.decrypt(&ct_res);

        // assert
        assert_eq!(((clear_0 % modulus) <= (clear_1 % modulus)) as u64, dec_res);
    }
}

fn shortint_unchecked_equal<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let keys = KEY_CACHE.get_from_param(param);
    let (cks, sks) = (keys.client_key(), keys.server_key());
    //RNG
    let mut rng = rand::thread_rng();

    let modulus = cks.parameters.message_modulus().0 as u64;

    for _ in 0..NB_TESTS {
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
fn shortint_smart_equal<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let keys = KEY_CACHE.get_from_param(param);
    let (cks, sks) = (keys.client_key(), keys.server_key());
    //RNG
    let mut rng = rand::thread_rng();

    let modulus = cks.parameters.message_modulus().0 as u64;
    let mod_scalar = cks.parameters.carry_modulus().0 as u8;

    for _ in 0..NB_TESTS {
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

/// test default '==' with the LWE server key
fn shortint_default_equal<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let keys = KEY_CACHE.get_from_param(param);
    let (cks, sks) = (keys.client_key(), keys.server_key());
    //RNG
    let mut rng = rand::thread_rng();

    let modulus = cks.parameters.message_modulus().0 as u64;
    let mod_scalar = cks.parameters.carry_modulus().0 as u8;

    for _ in 0..NB_TESTS {
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
        let ct_res = sks.equal(&ctxt_0, &ctxt_1);

        // decryption of ct_res
        let dec_res = cks.decrypt(&ct_res);

        // assert
        assert_eq!(((clear_0 % modulus) == (clear_1 % modulus)) as u64, dec_res);
    }
}

/// test '==' with the LWE server key
fn shortint_smart_scalar_equal<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let keys = KEY_CACHE.get_from_param(param);
    let (cks, sks) = (keys.client_key(), keys.server_key());
    //RNG
    let mut rng = rand::thread_rng();

    let msg_modulus = cks.parameters.message_modulus().0 as u64;
    let modulus = (cks.parameters.message_modulus().0 * cks.parameters.carry_modulus().0) as u64;

    for _ in 0..NB_TESTS {
        let clear = rng.gen::<u64>() % msg_modulus;

        let scalar = (rng.gen::<u16>() % modulus as u16) as u8;

        // encryption of an integer
        let mut ctxt = cks.encrypt(clear);

        // add the two ciphertexts
        let ct_res = sks.smart_scalar_equal(&mut ctxt, scalar);

        // decryption of ct_res
        let dec_res = cks.decrypt(&ct_res);

        // assert
        assert_eq!((clear == scalar as u64) as u64, dec_res);
    }
}

/// test '<' with the LWE server key
fn shortint_smart_scalar_less<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let keys = KEY_CACHE.get_from_param(param);
    let (cks, sks) = (keys.client_key(), keys.server_key());
    //RNG
    let mut rng = rand::thread_rng();

    let msg_modulus = cks.parameters.message_modulus().0 as u64;
    let modulus = (cks.parameters.message_modulus().0 * cks.parameters.carry_modulus().0) as u64;

    for _ in 0..NB_TESTS {
        let clear = rng.gen::<u64>() % msg_modulus;

        let scalar = (rng.gen::<u16>() % modulus as u16) as u8;

        // encryption of an integer
        let mut ctxt = cks.encrypt(clear);

        // add the two ciphertexts
        let ct_res = sks.smart_scalar_less(&mut ctxt, scalar);

        // decryption of ct_res
        let dec_res = cks.decrypt(&ct_res);

        // assert
        assert_eq!((clear < scalar as u64) as u64, dec_res);
    }
}

/// test '<=' with the LWE server key
fn shortint_smart_scalar_less_or_equal<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let keys = KEY_CACHE.get_from_param(param);
    let (cks, sks) = (keys.client_key(), keys.server_key());
    //RNG
    let mut rng = rand::thread_rng();

    let msg_modulus = cks.parameters.message_modulus().0 as u64;
    let modulus = (cks.parameters.message_modulus().0 * cks.parameters.carry_modulus().0) as u64;

    for _ in 0..NB_TESTS {
        let clear = rng.gen::<u64>() % msg_modulus;

        let scalar = (rng.gen::<u16>() % modulus as u16) as u8;

        // encryption of an integer
        let mut ctxt = cks.encrypt(clear);

        // add the two ciphertexts
        let ct_res = sks.smart_scalar_less_or_equal(&mut ctxt, scalar);

        // decryption of ct_res
        let dec_res = cks.decrypt(&ct_res);

        // assert
        assert_eq!((clear <= scalar as u64) as u64, dec_res);
    }
}

/// test '>' with the LWE server key
fn shortint_smart_scalar_greater<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let keys = KEY_CACHE.get_from_param(param);
    let (cks, sks) = (keys.client_key(), keys.server_key());
    //RNG
    let mut rng = rand::thread_rng();

    let msg_modulus = cks.parameters.message_modulus().0 as u64;
    let modulus = (cks.parameters.message_modulus().0 * cks.parameters.carry_modulus().0) as u64;

    for _ in 0..NB_TESTS {
        let clear = rng.gen::<u64>() % msg_modulus;

        let scalar = (rng.gen::<u16>() % modulus as u16) as u8;

        // encryption of an integer
        let mut ctxt = cks.encrypt(clear);

        // add the two ciphertexts
        let ct_res = sks.smart_scalar_greater(&mut ctxt, scalar);

        // decryption of ct_res
        let dec_res = cks.decrypt(&ct_res);

        // assert
        assert_eq!((clear > scalar as u64) as u64, dec_res);
    }
}

/// test '>' with the LWE server key
fn shortint_smart_scalar_greater_or_equal<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let keys = KEY_CACHE.get_from_param(param);
    let (cks, sks) = (keys.client_key(), keys.server_key());
    //RNG
    let mut rng = rand::thread_rng();

    let msg_modulus = cks.parameters.message_modulus().0 as u64;
    let modulus = (cks.parameters.message_modulus().0 * cks.parameters.carry_modulus().0) as u64;

    for _ in 0..NB_TESTS {
        let clear = rng.gen::<u64>() % msg_modulus;

        let scalar = (rng.gen::<u16>() % modulus as u16) as u8;

        // encryption of an integer
        let mut ctxt = cks.encrypt(clear);

        // add the two ciphertexts
        let ct_res = sks.smart_scalar_greater_or_equal(&mut ctxt, scalar);

        // decryption of ct_res
        let dec_res = cks.decrypt(&ct_res);

        // assert
        assert_eq!((clear >= scalar as u64) as u64, dec_res);
    }
}

/// test division with the LWE server key
fn shortint_unchecked_div<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let keys = KEY_CACHE.get_from_param(param);
    let (cks, sks) = (keys.client_key(), keys.server_key());
    //RNG
    let mut rng = rand::thread_rng();

    let modulus = cks.parameters.message_modulus().0 as u64;

    // check div by 0 result
    {
        let numerator = 1u64;
        let denominator = 0u64;

        let ct_num = cks.encrypt(numerator);
        let ct_denom = cks.encrypt(denominator);
        let ct_res = sks.unchecked_div(&ct_num, &ct_denom);

        let res = cks.decrypt(&ct_res);
        assert_eq!(res, (ct_num.message_modulus.0 - 1) as u64);
    }

    for _ in 0..NB_TESTS {
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
fn shortint_unchecked_scalar_div<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let keys = KEY_CACHE.get_from_param(param);
    let (cks, sks) = (keys.client_key(), keys.server_key());
    //RNG
    let mut rng = rand::thread_rng();

    let modulus = cks.parameters.message_modulus().0 as u64;

    for _ in 0..NB_TESTS {
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
fn shortint_unchecked_mod<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let keys = KEY_CACHE.get_from_param(param);
    let (cks, sks) = (keys.client_key(), keys.server_key());
    //RNG
    let mut rng = rand::thread_rng();

    let modulus = cks.parameters.message_modulus().0 as u64;

    for _ in 0..NB_TESTS {
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
fn shortint_unchecked_mul_lsb<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let keys = KEY_CACHE.get_from_param(param);
    let (cks, sks) = (keys.client_key(), keys.server_key());
    //RNG
    let mut rng = rand::thread_rng();

    let modulus = cks.parameters.message_modulus().0 as u64;

    for _ in 0..NB_TESTS {
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
fn shortint_unchecked_mul_msb<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let keys = KEY_CACHE.get_from_param(param);
    let (cks, sks) = (keys.client_key(), keys.server_key());
    //RNG
    let mut rng = rand::thread_rng();

    let modulus = cks.parameters.message_modulus().0 as u64;

    for _ in 0..NB_TESTS {
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

/// test MSB multiplication with the LWE server key
fn shortint_smart_mul_msb<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let keys = KEY_CACHE.get_from_param(param);
    let (cks, sks) = (keys.client_key(), keys.server_key());
    //RNG
    let mut rng = rand::thread_rng();

    let modulus = cks.parameters.message_modulus().0 as u64;

    for _ in 0..NB_TESTS_SMART {
        let clear_0 = rng.gen::<u64>() % modulus;

        let clear_1 = rng.gen::<u64>() % modulus;

        // encryption of an integer
        let mut ctxt_0 = cks.encrypt(clear_0);

        // encryption of an integer
        let mut ctxt_1 = cks.encrypt(clear_1);

        // add the two ciphertexts
        let mut ct_res = sks.smart_mul_msb(&mut ctxt_0, &mut ctxt_1);

        let mut clear = (clear_0 * clear_1) / modulus;

        let dec_res = cks.decrypt(&ct_res);

        assert_eq!(clear % modulus, dec_res);

        // multiply several times to raise the degree
        for _ in 0..NB_SUB_TEST_SMART {
            ct_res = sks.smart_mul_msb(&mut ct_res, &mut ctxt_0);
            clear = (clear * clear_0) / modulus;

            // decryption of ct_res
            let dec_res = cks.decrypt(&ct_res);

            // assert
            assert_eq!(clear % modulus, dec_res);
        }
    }
}

/// test default MSB multiplication with the LWE server key
fn shortint_default_mul_msb<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let keys = KEY_CACHE.get_from_param(param);
    let (cks, sks) = (keys.client_key(), keys.server_key());
    //RNG
    let mut rng = rand::thread_rng();

    let modulus = cks.parameters.message_modulus().0 as u64;

    for _ in 0..NB_TESTS {
        let clear_0 = rng.gen::<u64>() % modulus;

        let clear_1 = rng.gen::<u64>() % modulus;

        // encryption of an integer
        let ctxt_0 = cks.encrypt(clear_0);

        // encryption of an integer
        let ctxt_1 = cks.encrypt(clear_1);

        // add the two ciphertexts
        let ct_res = sks.mul_msb(&ctxt_0, &ctxt_1);

        let clear = (clear_0 * clear_1) / modulus;

        let dec_res = cks.decrypt(&ct_res);

        assert_eq!(clear % modulus, dec_res);
    }
}
