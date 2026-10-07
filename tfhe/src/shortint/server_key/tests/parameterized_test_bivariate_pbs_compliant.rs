#![allow(
    clippy::eq_op,
    reason = "explicitly test that clear and fhe op give the same result in the equality case"
)]

use crate::shortint::keycache::KEY_CACHE;
use crate::shortint::parameters::test_params::*;
use crate::shortint::server_key::tests::parameterized_test::create_parameterized_test;
use rand::Rng;

/// Number of assert in randomized tests
#[cfg(not(tarpaulin))]
const NB_TESTS: usize = 200;

// Use lower numbers for coverage to ensure fast tests to counter balance slowdown due to code
// instrumentation
#[cfg(tarpaulin)]
const NB_TESTS: usize = 1;

//Macro to generate tests for parameters sets compatible with the bivariate pbs
#[cfg(not(tarpaulin))]
macro_rules! create_parameterized_test_bivariate_pbs_compliant{
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
        create_parameterized_test!($name
        {
            TEST_PARAM_MESSAGE_1_CARRY_1_KS_PBS_GAUSSIAN_2M128,
            TEST_PARAM_MESSAGE_1_CARRY_2_KS_PBS_GAUSSIAN_2M128,
            TEST_PARAM_MESSAGE_1_CARRY_3_KS_PBS_GAUSSIAN_2M128,
            TEST_PARAM_MESSAGE_1_CARRY_4_KS_PBS_GAUSSIAN_2M128,
            TEST_PARAM_MESSAGE_1_CARRY_5_KS_PBS_GAUSSIAN_2M128,
            TEST_PARAM_MESSAGE_1_CARRY_6_KS_PBS_GAUSSIAN_2M128,
            TEST_PARAM_MESSAGE_1_CARRY_7_KS_PBS_GAUSSIAN_2M128,
            TEST_PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128,
            TEST_PARAM_MESSAGE_2_CARRY_3_KS_PBS_GAUSSIAN_2M128,
            TEST_PARAM_MESSAGE_2_CARRY_4_KS_PBS_GAUSSIAN_2M128,
            TEST_PARAM_MESSAGE_2_CARRY_5_KS_PBS_GAUSSIAN_2M128,
            TEST_PARAM_MESSAGE_2_CARRY_6_KS_PBS_GAUSSIAN_2M128,
            TEST_PARAM_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M128,
            TEST_PARAM_MESSAGE_3_CARRY_4_KS_PBS_GAUSSIAN_2M128,
            TEST_PARAM_MESSAGE_3_CARRY_5_KS_PBS_GAUSSIAN_2M128,
            // 2M128 are 2x slower and killing tests
            TEST_PARAM_MESSAGE_4_CARRY_4_KS_PBS_GAUSSIAN_2M64,
            TEST_PARAM_MULTI_BIT_GROUP_2_MESSAGE_1_CARRY_1_KS_PBS_GAUSSIAN_2M64,
            TEST_PARAM_MULTI_BIT_GROUP_2_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64,
            TEST_PARAM_MULTI_BIT_GROUP_2_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M64,
            TEST_PARAM_MULTI_BIT_GROUP_3_MESSAGE_1_CARRY_1_KS_PBS_GAUSSIAN_2M64,
            TEST_PARAM_MULTI_BIT_GROUP_3_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64,
            TEST_PARAM_MULTI_BIT_GROUP_3_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M64
        });
    };
}

// Test against a small subset of parameters to speed up coverage tests
#[cfg(tarpaulin)]
macro_rules! create_parameterized_test_bivariate_pbs_compliant{
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
        create_parameterized_test!($name
        {
            TEST_PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128,
            TEST_PARAM_MULTI_BIT_GROUP_2_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64,
            TEST_PARAM_MULTI_BIT_GROUP_3_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64
        });
    };
}

//These functions are compatible with some parameter sets where the carry modulus is larger than
// the message modulus.
create_parameterized_test_bivariate_pbs_compliant!(shortint_unchecked_bitand);
create_parameterized_test_bivariate_pbs_compliant!(shortint_unchecked_bitor);
create_parameterized_test_bivariate_pbs_compliant!(shortint_unchecked_bitxor);
create_parameterized_test_bivariate_pbs_compliant!(shortint_unchecked_greater);
create_parameterized_test_bivariate_pbs_compliant!(shortint_unchecked_greater_or_equal);
create_parameterized_test_bivariate_pbs_compliant!(shortint_unchecked_less);
create_parameterized_test_bivariate_pbs_compliant!(shortint_unchecked_less_or_equal);
create_parameterized_test_bivariate_pbs_compliant!(shortint_unchecked_equal);
create_parameterized_test_bivariate_pbs_compliant!(shortint_default_bitand);
create_parameterized_test_bivariate_pbs_compliant!(shortint_default_bitor);
create_parameterized_test_bivariate_pbs_compliant!(shortint_default_bitxor);
create_parameterized_test_bivariate_pbs_compliant!(shortint_default_greater);
create_parameterized_test_bivariate_pbs_compliant!(shortint_default_greater_or_equal);
create_parameterized_test_bivariate_pbs_compliant!(shortint_default_less);
create_parameterized_test_bivariate_pbs_compliant!(shortint_default_less_or_equal);
create_parameterized_test_bivariate_pbs_compliant!(shortint_default_equal);
create_parameterized_test_bivariate_pbs_compliant!(shortint_unchecked_div);
create_parameterized_test_bivariate_pbs_compliant!(shortint_unchecked_scalar_div);
create_parameterized_test_bivariate_pbs_compliant!(shortint_unchecked_mod);
create_parameterized_test_bivariate_pbs_compliant!(shortint_unchecked_mul_lsb);
create_parameterized_test_bivariate_pbs_compliant!(shortint_unchecked_mul_msb);
create_parameterized_test_bivariate_pbs_compliant!(shortint_default_mul_msb);
create_parameterized_test_bivariate_pbs_compliant!(
    shortint_keyswitch_bivariate_programmable_bootstrap
);
create_parameterized_test_bivariate_pbs_compliant!(shortint_unchecked_less_or_equal_trivial);

fn shortint_keyswitch_bivariate_programmable_bootstrap<P>(param: P)
where
    P: Into<TestParameters>,
{
    let keys = KEY_CACHE.get_from_param(param);
    let (cks, sks) = (keys.client_key(), keys.server_key());

    let mut rng = rand::thread_rng();

    let modulus = cks.parameters().message_modulus().0;

    for _ in 0..NB_TESTS {
        let clear_0 = rng.gen::<u64>() % modulus;
        let clear_1 = rng.gen::<u64>() % modulus;

        let ctxt_0 = cks.encrypt(clear_0);
        let ctxt_1 = cks.encrypt(clear_1);

        let acc = sks.generate_lookup_table_bivariate(|x, y| (x * 2 * y) % modulus);

        let ct_res = sks.unchecked_apply_lookup_table_bivariate(&ctxt_0, &ctxt_1, &acc);

        let dec_res = cks.decrypt(&ct_res);

        assert_eq!((2 * clear_0 * clear_1) % modulus, dec_res);
    }
}

fn shortint_unchecked_bitand<P>(param: P)
where
    P: Into<TestParameters>,
{
    let keys = KEY_CACHE.get_from_param(param);
    let (cks, sks) = (keys.client_key(), keys.server_key());
    let mut rng = rand::thread_rng();

    let modulus = cks.parameters().message_modulus().0;

    for _ in 0..NB_TESTS {
        let clear_0 = rng.gen::<u64>() % modulus;
        let clear_1 = rng.gen::<u64>() % modulus;

        let ctxt_0 = cks.encrypt(clear_0);

        let ctxt_1 = cks.encrypt(clear_1);

        let ct_res = sks.unchecked_bitand(&ctxt_0, &ctxt_1);
        assert_eq!(ct_res.degree, ctxt_0.degree.after_bitand(ctxt_1.degree));

        let dec_res = cks.decrypt(&ct_res);

        assert_eq!(clear_0 & clear_1, dec_res);
    }
}

fn shortint_unchecked_bitor<P>(param: P)
where
    P: Into<TestParameters>,
{
    let keys = KEY_CACHE.get_from_param(param);
    let (cks, sks) = (keys.client_key(), keys.server_key());

    let mut rng = rand::thread_rng();

    let modulus = cks.parameters().message_modulus().0;

    for _ in 0..NB_TESTS {
        let clear_0 = rng.gen::<u64>() % modulus;
        let clear_1 = rng.gen::<u64>() % modulus;

        let ctxt_0 = cks.encrypt(clear_0);

        let ctxt_1 = cks.encrypt(clear_1);

        let ct_res = sks.unchecked_bitor(&ctxt_0, &ctxt_1);
        assert_eq!(ct_res.degree, ctxt_0.degree.after_bitor(ctxt_1.degree));

        let dec_res = cks.decrypt(&ct_res);

        assert_eq!(clear_0 | clear_1, dec_res);
    }
}

fn shortint_unchecked_bitxor<P>(param: P)
where
    P: Into<TestParameters>,
{
    let keys = KEY_CACHE.get_from_param(param);
    let (cks, sks) = (keys.client_key(), keys.server_key());

    let mut rng = rand::thread_rng();

    let modulus = cks.parameters().message_modulus().0;

    for _ in 0..NB_TESTS {
        let clear_0 = rng.gen::<u64>() % modulus;
        let clear_1 = rng.gen::<u64>() % modulus;

        let ctxt_0 = cks.encrypt(clear_0);

        let ctxt_1 = cks.encrypt(clear_1);

        let ct_res = sks.unchecked_bitxor(&ctxt_0, &ctxt_1);
        assert_eq!(ct_res.degree, ctxt_0.degree.after_bitxor(ctxt_1.degree));

        let dec_res = cks.decrypt(&ct_res);

        assert_eq!(clear_0 ^ clear_1, dec_res);
    }
}

fn shortint_default_bitand<P>(param: P)
where
    P: Into<TestParameters>,
{
    let keys = KEY_CACHE.get_from_param(param);
    let (cks, sks) = (keys.client_key(), keys.server_key());

    let mut rng = rand::thread_rng();

    let modulus = cks.parameters().message_modulus().0;
    let mod_scalar = cks.parameters().carry_modulus().0 as u8;

    for _ in 0..NB_TESTS {
        let mut clear_0 = rng.gen::<u64>() % modulus;
        let mut clear_1 = rng.gen::<u64>() % modulus;
        let scalar = rng.gen::<u8>() % mod_scalar;

        let mut ctxt_0 = cks.encrypt(clear_0);

        let mut ctxt_1 = cks.encrypt(clear_1);

        sks.unchecked_scalar_mul_assign(&mut ctxt_0, scalar);
        sks.unchecked_scalar_mul_assign(&mut ctxt_1, scalar);

        clear_0 *= scalar as u64;
        clear_1 *= scalar as u64;

        let ct_res = sks.bitand(&ctxt_0, &ctxt_1);

        let dec_res = cks.decrypt(&ct_res);

        assert_eq!((clear_0 & clear_1) % modulus, dec_res);
    }
}

fn shortint_default_bitor<P>(param: P)
where
    P: Into<TestParameters>,
{
    let keys = KEY_CACHE.get_from_param(param);
    let (cks, sks) = (keys.client_key(), keys.server_key());

    let mut rng = rand::thread_rng();

    let modulus = cks.parameters().message_modulus().0;
    let mod_scalar = cks.parameters().carry_modulus().0 as u8;

    for _ in 0..NB_TESTS {
        let mut clear_0 = rng.gen::<u64>() % modulus;
        let mut clear_1 = rng.gen::<u64>() % modulus;
        let scalar = rng.gen::<u8>() % mod_scalar;

        let mut ctxt_0 = cks.encrypt(clear_0);

        let mut ctxt_1 = cks.encrypt(clear_1);

        sks.unchecked_scalar_mul_assign(&mut ctxt_0, scalar);
        sks.unchecked_scalar_mul_assign(&mut ctxt_1, scalar);

        clear_0 *= scalar as u64;
        clear_1 *= scalar as u64;

        let ct_res = sks.bitor(&ctxt_0, &ctxt_1);

        let dec_res = cks.decrypt(&ct_res);

        assert_eq!((clear_0 | clear_1) % modulus, dec_res);
    }
}

fn shortint_default_bitxor<P>(param: P)
where
    P: Into<TestParameters>,
{
    let keys = KEY_CACHE.get_from_param(param);
    let (cks, sks) = (keys.client_key(), keys.server_key());

    let mut rng = rand::thread_rng();

    let modulus = cks.parameters().message_modulus().0;
    let mod_scalar = cks.parameters().carry_modulus().0 as u8;

    for _ in 0..NB_TESTS {
        let mut clear_0 = rng.gen::<u64>() % modulus;
        let mut clear_1 = rng.gen::<u64>() % modulus;
        let scalar = rng.gen::<u8>() % mod_scalar;

        let mut ctxt_0 = cks.encrypt(clear_0);

        let mut ctxt_1 = cks.encrypt(clear_1);

        sks.unchecked_scalar_mul_assign(&mut ctxt_0, scalar);
        sks.unchecked_scalar_mul_assign(&mut ctxt_1, scalar);

        clear_0 *= scalar as u64;
        clear_1 *= scalar as u64;

        let ct_res = sks.bitxor(&ctxt_0, &ctxt_1);

        let dec_res = cks.decrypt(&ct_res);

        assert_eq!((clear_0 ^ clear_1) % modulus, dec_res);
    }
}

fn shortint_unchecked_greater<P>(param: P)
where
    P: Into<TestParameters>,
{
    let keys = KEY_CACHE.get_from_param(param);
    let (cks, sks) = (keys.client_key(), keys.server_key());

    let mut rng = rand::thread_rng();

    let modulus = cks.parameters().message_modulus().0;

    for _ in 0..NB_TESTS {
        let clear_0 = rng.gen::<u64>() % modulus;
        let clear_1 = rng.gen::<u64>() % modulus;

        let ctxt_0 = cks.encrypt(clear_0);

        let ctxt_1 = cks.encrypt(clear_1);

        let ct_res = sks.unchecked_greater(&ctxt_0, &ctxt_1);

        let dec_res = cks.decrypt(&ct_res);

        assert_eq!((clear_0 > clear_1) as u64, dec_res);
    }
}

fn shortint_default_greater<P>(param: P)
where
    P: Into<TestParameters>,
{
    let keys = KEY_CACHE.get_from_param(param);
    let (cks, sks) = (keys.client_key(), keys.server_key());

    let mut rng = rand::thread_rng();

    let modulus = cks.parameters().message_modulus().0;

    for _ in 0..NB_TESTS {
        let clear_0 = rng.gen::<u64>() % modulus;
        let clear_1 = rng.gen::<u64>() % modulus;

        let ctxt_0 = cks.encrypt(clear_0);

        let ctxt_1 = cks.encrypt(clear_1);

        let ct_res = sks.greater(&ctxt_0, &ctxt_1);

        let dec_res = cks.decrypt(&ct_res);

        assert_eq!((clear_0 > clear_1) as u64, dec_res);
    }
}

fn shortint_unchecked_greater_or_equal<P>(param: P)
where
    P: Into<TestParameters>,
{
    let keys = KEY_CACHE.get_from_param(param);
    let (cks, sks) = (keys.client_key(), keys.server_key());

    let mut rng = rand::thread_rng();

    let modulus = cks.parameters().message_modulus().0;

    for _ in 0..NB_TESTS {
        let clear_0 = rng.gen::<u64>() % modulus;
        let clear_1 = rng.gen::<u64>() % modulus;

        let ctxt_0 = cks.encrypt(clear_0);

        let ctxt_1 = cks.encrypt(clear_1);

        let ct_res = sks.unchecked_greater_or_equal(&ctxt_0, &ctxt_1);

        let dec_res = cks.decrypt(&ct_res);

        assert_eq!((clear_0 >= clear_1) as u64, dec_res);
    }
}

fn shortint_default_greater_or_equal<P>(param: P)
where
    P: Into<TestParameters>,
{
    let keys = KEY_CACHE.get_from_param(param);
    let (cks, sks) = (keys.client_key(), keys.server_key());

    let mut rng = rand::thread_rng();

    let modulus = cks.parameters().message_modulus().0;
    let mod_scalar = cks.parameters().carry_modulus().0 as u8;

    for _ in 0..NB_TESTS {
        let mut clear_0 = rng.gen::<u64>() % modulus;
        let mut clear_1 = rng.gen::<u64>() % modulus;
        let scalar = rng.gen::<u8>() % mod_scalar;

        let mut ctxt_0 = cks.encrypt(clear_0);

        let mut ctxt_1 = cks.encrypt(clear_1);

        sks.unchecked_scalar_mul_assign(&mut ctxt_0, scalar);
        sks.unchecked_scalar_mul_assign(&mut ctxt_1, scalar);

        clear_0 = (clear_0 * scalar as u64) % modulus;
        clear_1 = (clear_1 * scalar as u64) % modulus;

        let ct_res = sks.greater_or_equal(&ctxt_0, &ctxt_1);

        let dec_res = cks.decrypt(&ct_res);

        assert_eq!((clear_0 >= clear_1) as u64, dec_res);
    }
}

fn shortint_unchecked_less<P>(param: P)
where
    P: Into<TestParameters>,
{
    let keys = KEY_CACHE.get_from_param(param);
    let (cks, sks) = (keys.client_key(), keys.server_key());

    let mut rng = rand::thread_rng();

    let modulus = cks.parameters().message_modulus().0;

    for _ in 0..NB_TESTS {
        let clear_0 = rng.gen::<u64>() % modulus;
        let clear_1 = rng.gen::<u64>() % modulus;

        let ctxt_0 = cks.encrypt(clear_0);

        let ctxt_1 = cks.encrypt(clear_1);

        let ct_res = sks.unchecked_less(&ctxt_0, &ctxt_1);

        let dec_res = cks.decrypt(&ct_res);

        assert_eq!((clear_0 < clear_1) as u64, dec_res);
    }
}

fn shortint_default_less<P>(param: P)
where
    P: Into<TestParameters>,
{
    let keys = KEY_CACHE.get_from_param(param);
    let (cks, sks) = (keys.client_key(), keys.server_key());

    let mut rng = rand::thread_rng();

    let modulus = cks.parameters().message_modulus().0;
    let mod_scalar = cks.parameters().carry_modulus().0 as u8;

    for _ in 0..NB_TESTS {
        let mut clear_0 = rng.gen::<u64>() % modulus;
        let mut clear_1 = rng.gen::<u64>() % modulus;
        let scalar = rng.gen::<u8>() % mod_scalar;

        let mut ctxt_0 = cks.encrypt(clear_0);

        let mut ctxt_1 = cks.encrypt(clear_1);

        sks.unchecked_scalar_mul_assign(&mut ctxt_0, scalar);
        sks.unchecked_scalar_mul_assign(&mut ctxt_1, scalar);

        clear_0 = (clear_0 * scalar as u64) % modulus;
        clear_1 = (clear_1 * scalar as u64) % modulus;

        let ct_res = sks.less(&ctxt_0, &ctxt_1);

        let dec_res = cks.decrypt(&ct_res);

        assert_eq!((clear_0 < clear_1) as u64, dec_res);
    }
}

fn shortint_unchecked_less_or_equal<P>(param: P)
where
    P: Into<TestParameters>,
{
    let keys = KEY_CACHE.get_from_param(param);
    let (cks, sks) = (keys.client_key(), keys.server_key());

    let mut rng = rand::thread_rng();

    let modulus = cks.parameters().message_modulus().0;

    for _ in 0..NB_TESTS {
        let clear_0 = rng.gen::<u64>() % modulus;
        let clear_1 = rng.gen::<u64>() % modulus;

        let ctxt_0 = cks.encrypt(clear_0);

        let ctxt_1 = cks.encrypt(clear_1);

        let ct_res = sks.unchecked_less_or_equal(&ctxt_0, &ctxt_1);

        let dec_res = cks.decrypt(&ct_res);

        assert_eq!((clear_0 <= clear_1) as u64, dec_res);
    }
}

fn shortint_unchecked_less_or_equal_trivial<P>(param: P)
where
    P: Into<TestParameters>,
{
    let keys = KEY_CACHE.get_from_param(param);
    let (cks, sks) = (keys.client_key(), keys.server_key());

    let mut rng = rand::thread_rng();

    let modulus = cks.parameters().message_modulus().0;

    for _ in 0..NB_TESTS {
        let clear_0 = rng.gen::<u64>() % modulus;
        let clear_1 = rng.gen::<u64>() % modulus;

        let ctxt_0 = sks.create_trivial(clear_0);

        let ctxt_1 = sks.create_trivial(clear_1);

        let ct_res = sks.unchecked_less_or_equal(&ctxt_0, &ctxt_1);

        let dec_res = cks.decrypt(&ct_res);

        assert_eq!((clear_0 <= clear_1) as u64, dec_res);
    }
}

fn shortint_default_less_or_equal<P>(param: P)
where
    P: Into<TestParameters>,
{
    let keys = KEY_CACHE.get_from_param(param);
    let (cks, sks) = (keys.client_key(), keys.server_key());

    let mut rng = rand::thread_rng();

    let modulus = cks.parameters().message_modulus().0;
    let mod_scalar = cks.parameters().carry_modulus().0 as u8;

    for _ in 0..NB_TESTS {
        let mut clear_0 = rng.gen::<u64>() % modulus;
        let mut clear_1 = rng.gen::<u64>() % modulus;
        let scalar = rng.gen::<u8>() % mod_scalar;

        let mut ctxt_0 = cks.encrypt(clear_0);

        let mut ctxt_1 = cks.encrypt(clear_1);

        sks.unchecked_scalar_mul_assign(&mut ctxt_0, scalar);
        sks.unchecked_scalar_mul_assign(&mut ctxt_1, scalar);

        clear_0 *= scalar as u64;
        clear_1 *= scalar as u64;

        let ct_res = sks.less_or_equal(&ctxt_0, &ctxt_1);

        let dec_res = cks.decrypt(&ct_res);

        assert_eq!(((clear_0 % modulus) <= (clear_1 % modulus)) as u64, dec_res);
    }
}

fn shortint_unchecked_equal<P>(param: P)
where
    P: Into<TestParameters>,
{
    let keys = KEY_CACHE.get_from_param(param);
    let (cks, sks) = (keys.client_key(), keys.server_key());

    let mut rng = rand::thread_rng();

    let modulus = cks.parameters().message_modulus().0;

    for _ in 0..NB_TESTS {
        let clear_0 = rng.gen::<u64>() % modulus;
        let clear_1 = rng.gen::<u64>() % modulus;

        let ctxt_0 = cks.encrypt(clear_0);

        let ctxt_1 = cks.encrypt(clear_1);

        let ct_res = sks.unchecked_equal(&ctxt_0, &ctxt_1);

        let dec_res = cks.decrypt(&ct_res);

        assert_eq!((clear_0 == clear_1) as u64, dec_res);
    }
}

fn shortint_default_equal<P>(param: P)
where
    P: Into<TestParameters>,
{
    let keys = KEY_CACHE.get_from_param(param);
    let (cks, sks) = (keys.client_key(), keys.server_key());

    let mut rng = rand::thread_rng();

    let modulus = cks.parameters().message_modulus().0;
    let mod_scalar = cks.parameters().carry_modulus().0 as u8;

    for _ in 0..NB_TESTS {
        let mut clear_0 = rng.gen::<u64>() % modulus;
        let mut clear_1 = rng.gen::<u64>() % modulus;
        let scalar = rng.gen::<u8>() % mod_scalar;

        let mut ctxt_0 = cks.encrypt(clear_0);

        let mut ctxt_1 = cks.encrypt(clear_1);

        sks.unchecked_scalar_mul_assign(&mut ctxt_0, scalar);
        sks.unchecked_scalar_mul_assign(&mut ctxt_1, scalar);

        clear_0 *= scalar as u64;
        clear_1 *= scalar as u64;

        let ct_res = sks.equal(&ctxt_0, &ctxt_1);

        let dec_res = cks.decrypt(&ct_res);

        assert_eq!(((clear_0 % modulus) == (clear_1 % modulus)) as u64, dec_res);
    }
}

fn shortint_unchecked_div<P>(param: P)
where
    P: Into<TestParameters>,
{
    let keys = KEY_CACHE.get_from_param(param);
    let (cks, sks) = (keys.client_key(), keys.server_key());

    let mut rng = rand::thread_rng();

    let modulus = cks.parameters().message_modulus().0;

    {
        let numerator = 1u64;
        let denominator = 0u64;

        let ct_num = cks.encrypt(numerator);
        let ct_denom = cks.encrypt(denominator);
        let ct_res = sks.unchecked_div(&ct_num, &ct_denom);

        let res = cks.decrypt(&ct_res);
        assert_eq!(res, ct_num.message_modulus.0 - 1);
    }

    for _ in 0..NB_TESTS {
        let clear_0 = rng.gen::<u64>() % modulus;
        let clear_1 = (rng.gen::<u64>() % (modulus - 1)) + 1;

        let ctxt_0 = cks.encrypt(clear_0);

        let ctxt_1 = cks.encrypt(clear_1);

        let ct_res = sks.unchecked_div(&ctxt_0, &ctxt_1);

        let dec_res = cks.decrypt(&ct_res);

        assert_eq!(clear_0 / clear_1, dec_res);
    }
}

fn shortint_unchecked_scalar_div<P>(param: P)
where
    P: Into<TestParameters>,
{
    let keys = KEY_CACHE.get_from_param(param);
    let (cks, sks) = (keys.client_key(), keys.server_key());

    let mut rng = rand::thread_rng();

    let modulus = cks.parameters().message_modulus().0;

    for _ in 0..NB_TESTS {
        let clear_0 = rng.gen::<u64>() % modulus;
        let clear_1 = (rng.gen::<u64>() % (modulus - 1)) + 1;

        let ctxt_0 = cks.encrypt(clear_0);

        let ct_res = sks.unchecked_scalar_div(&ctxt_0, clear_1 as u8);

        let dec_res = cks.decrypt(&ct_res);

        assert_eq!(clear_0 / clear_1, dec_res);
    }
}

fn shortint_unchecked_mod<P>(param: P)
where
    P: Into<TestParameters>,
{
    let keys = KEY_CACHE.get_from_param(param);
    let (cks, sks) = (keys.client_key(), keys.server_key());

    let mut rng = rand::thread_rng();

    let modulus = cks.parameters().message_modulus().0;

    for _ in 0..NB_TESTS {
        let clear_0 = rng.gen::<u64>() % modulus;
        let clear_1 = (rng.gen::<u64>() % (modulus - 1)) + 1;

        let ctxt_0 = cks.encrypt(clear_0);

        let ct_res = sks.unchecked_scalar_mod(&ctxt_0, clear_1 as u8);

        let dec_res = cks.decrypt(&ct_res);

        assert_eq!(clear_0 % clear_1, dec_res);
    }
}

fn shortint_unchecked_mul_lsb<P>(param: P)
where
    P: Into<TestParameters>,
{
    let keys = KEY_CACHE.get_from_param(param);
    let (cks, sks) = (keys.client_key(), keys.server_key());

    let mut rng = rand::thread_rng();

    let modulus = cks.parameters().message_modulus().0;

    for _ in 0..NB_TESTS {
        let clear_0 = rng.gen::<u64>() % modulus;
        let clear_1 = rng.gen::<u64>() % modulus;

        let ctxt_0 = cks.encrypt(clear_0);

        let ctxt_1 = cks.encrypt(clear_1);

        let ct_res = sks.unchecked_mul_lsb(&ctxt_0, &ctxt_1);

        let dec_res = cks.decrypt(&ct_res);

        assert_eq!((clear_0 * clear_1) % modulus, dec_res);
    }
}

fn shortint_unchecked_mul_msb<P>(param: P)
where
    P: Into<TestParameters>,
{
    let keys = KEY_CACHE.get_from_param(param);
    let (cks, sks) = (keys.client_key(), keys.server_key());

    let mut rng = rand::thread_rng();

    let modulus = cks.parameters().message_modulus().0;

    for _ in 0..NB_TESTS {
        let clear_0 = rng.gen::<u64>() % modulus;
        let clear_1 = rng.gen::<u64>() % modulus;

        let ctxt_0 = cks.encrypt(clear_0);

        let ctxt_1 = cks.encrypt(clear_1);

        let ct_res = sks.unchecked_mul_msb(&ctxt_0, &ctxt_1);

        let dec_res = cks.decrypt(&ct_res);

        assert_eq!((clear_0 * clear_1) / modulus, dec_res);
    }
}

fn shortint_default_mul_msb<P>(param: P)
where
    P: Into<TestParameters>,
{
    let keys = KEY_CACHE.get_from_param(param);
    let (cks, sks) = (keys.client_key(), keys.server_key());

    let mut rng = rand::thread_rng();

    let modulus = cks.parameters().message_modulus().0;

    for _ in 0..NB_TESTS {
        let clear_0 = rng.gen::<u64>() % modulus;

        let clear_1 = rng.gen::<u64>() % modulus;

        let ctxt_0 = cks.encrypt(clear_0);

        let ctxt_1 = cks.encrypt(clear_1);

        let ct_res = sks.mul_msb(&ctxt_0, &ctxt_1);

        let clear = (clear_0 * clear_1) / modulus;

        let dec_res = cks.decrypt(&ct_res);

        assert_eq!(clear % modulus, dec_res);
    }
}
