use super::{NB_SUB_TEST_SMART, NB_TESTS, NB_TESTS_SMART};
use crate::shortint::keycache::KEY_CACHE;
use crate::shortint::parameters::test_params::*;
use crate::shortint::parameters::*;
use crate::shortint::server_key::{LookupTableOwned, ManyLookupTableOwned};
use rand::Rng;

// Macro to generate tests for all parameter sets
#[cfg(not(tarpaulin))]
macro_rules! create_parameterized_test{
    // Variant with explicit test name suffixes for each parameter (useful for MetaParameters)
    ($func_name:ident { $(($param:expr, $suffix:ident)),* $(,)? }) => {
        ::paste::paste! {
            $(
            #[test]
            fn [<test_ $func_name _ $suffix:lower>]() {
                $func_name($param)
            }
            )*
        }
    };
    // Variant that derives test names from parameter identifiers
    ($func_name:ident { $($param:ident),* $(,)? }) => {
        ::paste::paste! {
            $(
            #[test]
            fn [<test_ $func_name _ $param:lower>]() {
                $func_name($param)
            }
            )*
        }
    };
    ($func_name:ident)=> {
        create_parameterized_test!($func_name
        {
            TEST_PARAM_MESSAGE_1_CARRY_1_KS_PBS_GAUSSIAN_2M128,
            TEST_PARAM_MESSAGE_1_CARRY_2_KS_PBS_GAUSSIAN_2M128,
            TEST_PARAM_MESSAGE_1_CARRY_3_KS_PBS_GAUSSIAN_2M128,
            TEST_PARAM_MESSAGE_1_CARRY_4_KS_PBS_GAUSSIAN_2M128,
            TEST_PARAM_MESSAGE_1_CARRY_5_KS_PBS_GAUSSIAN_2M128,
            TEST_PARAM_MESSAGE_1_CARRY_6_KS_PBS_GAUSSIAN_2M128,
            TEST_PARAM_MESSAGE_1_CARRY_7_KS_PBS_GAUSSIAN_2M128,
            TEST_PARAM_MESSAGE_2_CARRY_1_KS_PBS_GAUSSIAN_2M128,
            TEST_PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128,
            TEST_PARAM_MESSAGE_2_CARRY_3_KS_PBS_GAUSSIAN_2M128,
            TEST_PARAM_MESSAGE_2_CARRY_4_KS_PBS_GAUSSIAN_2M128,
            TEST_PARAM_MESSAGE_2_CARRY_5_KS_PBS_GAUSSIAN_2M128,
            TEST_PARAM_MESSAGE_2_CARRY_6_KS_PBS_GAUSSIAN_2M128,
            TEST_PARAM_MESSAGE_3_CARRY_1_KS_PBS_GAUSSIAN_2M128,
            TEST_PARAM_MESSAGE_3_CARRY_2_KS_PBS_GAUSSIAN_2M128,
            TEST_PARAM_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M128,
            TEST_PARAM_MESSAGE_3_CARRY_4_KS_PBS_GAUSSIAN_2M128,
            TEST_PARAM_MESSAGE_3_CARRY_5_KS_PBS_GAUSSIAN_2M128,
            TEST_PARAM_MESSAGE_4_CARRY_1_KS_PBS_GAUSSIAN_2M128,
            TEST_PARAM_MESSAGE_4_CARRY_2_KS_PBS_GAUSSIAN_2M128,
            TEST_PARAM_MESSAGE_4_CARRY_3_KS_PBS_GAUSSIAN_2M128,
            // 2M128 are 2x slower and killing tests
            TEST_PARAM_MESSAGE_4_CARRY_4_KS_PBS_GAUSSIAN_2M64,
            TEST_PARAM_MESSAGE_5_CARRY_1_KS_PBS_GAUSSIAN_2M128,
            TEST_PARAM_MESSAGE_5_CARRY_2_KS_PBS_GAUSSIAN_2M128,
            TEST_PARAM_MESSAGE_5_CARRY_3_KS_PBS_GAUSSIAN_2M128,
            TEST_PARAM_MESSAGE_6_CARRY_1_KS_PBS_GAUSSIAN_2M128,
            TEST_PARAM_MESSAGE_6_CARRY_2_KS_PBS_GAUSSIAN_2M128,
            TEST_PARAM_MESSAGE_7_CARRY_1_KS_PBS_GAUSSIAN_2M128,
            TEST_PARAM_MULTI_BIT_GROUP_2_MESSAGE_1_CARRY_1_KS_PBS_GAUSSIAN_2M64,
            TEST_PARAM_MULTI_BIT_GROUP_2_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64,
            TEST_PARAM_MULTI_BIT_GROUP_2_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M64,
            TEST_PARAM_MULTI_BIT_GROUP_3_MESSAGE_1_CARRY_1_KS_PBS_GAUSSIAN_2M64,
            TEST_PARAM_MULTI_BIT_GROUP_3_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64,
            TEST_PARAM_MULTI_BIT_GROUP_3_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M64,
            TEST_PARAM_MESSAGE_2_CARRY_2_KS32_PBS_TUNIFORM_2M128,
            // To still be able to test prod
            TEST_PARAM_PROD_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128
        });
    };
}

// Test against a small subset of parameters to speed up coverage tests
#[cfg(tarpaulin)]
macro_rules! create_parameterized_test{
    // Variant with explicit test name suffixes for each parameter (useful for MetaParameters)
    ($func_name:ident { $(($param:expr, $suffix:ident)),* $(,)? }) => {
        ::paste::paste! {
            $(
            #[test]
            fn [<test_ $func_name _ $suffix:lower>]() {
                $func_name($param)
            }
            )*
        }
    };
    // Variant that derives test names from parameter identifiers
    ($func_name:ident { $($param:ident),*$(,)? }) => {
        ::paste::paste! {
            $(
            #[test]
            fn [<test_ $func_name _ $param:lower>]() {
                $func_name($param)
            }
            )*
        }
    };
    ($func_name:ident)=> {
        create_parameterized_test!($func_name
        {
            TEST_PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128,
            TEST_PARAM_MULTI_BIT_GROUP_2_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64,
            TEST_PARAM_MULTI_BIT_GROUP_3_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64
        });
    };
}

pub(crate) use create_parameterized_test;

//These functions are compatible with all parameter sets.
create_parameterized_test!(shortint_encrypt_decrypt);
create_parameterized_test!(shortint_encrypt_with_message_modulus_decrypt);
create_parameterized_test!(shortint_encrypt_decrypt_without_padding);
create_parameterized_test!(shortint_keyswitch_bootstrap);
create_parameterized_test!(shortint_keyswitch_programmable_bootstrap);
create_parameterized_test!(shortint_keyswitch_programmable_bootstrap_many_lut);
create_parameterized_test!(shortint_carry_extract);
create_parameterized_test!(shortint_message_extract);
create_parameterized_test!(shortint_generate_lookup_table);
create_parameterized_test!(shortint_unchecked_add);
create_parameterized_test!(shortint_smart_add);
create_parameterized_test!(shortint_default_add);
create_parameterized_test!(shortint_smart_mul_lsb);
create_parameterized_test!(shortint_default_mul_lsb);
create_parameterized_test!(shortint_unchecked_neg);
create_parameterized_test!(shortint_smart_neg);
create_parameterized_test!(shortint_default_neg);
create_parameterized_test!(shortint_unchecked_scalar_add);
create_parameterized_test!(shortint_smart_scalar_add);
create_parameterized_test!(shortint_default_scalar_add);
create_parameterized_test!(shortint_unchecked_scalar_sub);
create_parameterized_test!(shortint_smart_scalar_sub);
create_parameterized_test!(shortint_default_scalar_sub);
create_parameterized_test!(shortint_unchecked_scalar_mul);
create_parameterized_test!(shortint_smart_scalar_mul);
create_parameterized_test!(shortint_default_scalar_mul);
create_parameterized_test!(shortint_unchecked_right_shift);
create_parameterized_test!(shortint_default_right_shift);
create_parameterized_test!(shortint_unchecked_left_shift);
create_parameterized_test!(shortint_default_left_shift);
create_parameterized_test!(shortint_unchecked_sub);
create_parameterized_test!(shortint_smart_sub);
create_parameterized_test!(shortint_default_sub);
create_parameterized_test!(shortint_mul_small_carry);
create_parameterized_test!(shortint_mux);
create_parameterized_test!(shortint_unchecked_scalar_bitand);
create_parameterized_test!(shortint_unchecked_scalar_bitor);
create_parameterized_test!(shortint_unchecked_scalar_bitxor);
create_parameterized_test!(shortint_smart_scalar_bitand);
create_parameterized_test!(shortint_smart_scalar_bitor);
create_parameterized_test!(shortint_smart_scalar_bitxor);
create_parameterized_test!(shortint_default_scalar_bitand);
create_parameterized_test!(shortint_default_scalar_bitor);
create_parameterized_test!(shortint_default_scalar_bitxor);
create_parameterized_test!(shortint_trivial_pbs);
create_parameterized_test!(shortint_trivial_pbs_many_lut);
create_parameterized_test!(
    shortint_encrypt_with_message_modulus_unchecked_mul_lsb_small_carry_and_add
);
create_parameterized_test!(
    shortint_encrypt_with_message_and_carry_modulus_unchecked_mul_lsb_small_carry_and_add
);

// Public key tests are limited to small parameter sets to avoid blowing up memory and large testing
// times. Compressed keygen takes 20 minutes for params 2_2 and for encryption as well.
// 2_2 uncompressed keys take ~2 GB and 3_3 about ~34 GB, hence why we stop at 2_2.
#[cfg(not(tarpaulin))]
#[test]
fn test_shortint_compressed_public_key_smart_add_param_message_1_carry_1_ks_pbs() {
    shortint_compressed_public_key_smart_add(TEST_PARAM_MESSAGE_1_CARRY_1_KS_PBS_GAUSSIAN_2M128);
}

#[cfg(not(tarpaulin))]
#[test]
fn test_shortint_public_key_smart_add_param_message_1_carry_1_ks_pbs() {
    shortint_public_key_smart_add(TEST_PARAM_MESSAGE_1_CARRY_1_KS_PBS_GAUSSIAN_2M128);
}

#[cfg(not(tarpaulin))]
#[test]
fn test_shortint_public_key_smart_add_param_message_2_carry_2_ks_pbs() {
    shortint_public_key_smart_add(TEST_PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128);
}

#[test]
fn test_shortint_keyswitch_programmable_bootstrap_pbs_ks_ci_run_filter() {
    shortint_keyswitch_programmable_bootstrap(TEST_PARAM_MESSAGE_2_CARRY_2_PBS_KS_GAUSSIAN_2M128);
}

#[test]
fn test_shortint_keyswitch_programmable_bootstrap_many_lut_pbs_ks_ci_run_filter() {
    shortint_keyswitch_programmable_bootstrap_many_lut(
        TEST_PARAM_MESSAGE_2_CARRY_2_PBS_KS_GAUSSIAN_2M128,
    );
}

fn shortint_encrypt_decrypt<P>(param: P)
where
    P: Into<TestParameters>,
{
    let keys = KEY_CACHE.get_from_param(param);
    let cks = keys.client_key();

    let mut rng = rand::thread_rng();

    let modulus = cks.parameters().message_modulus().0;

    for _ in 0..NB_TESTS {
        let clear = rng.gen::<u64>() % modulus;

        let ct = cks.encrypt(clear);

        let dec = cks.decrypt(&ct);

        assert_eq!(clear, dec);
    }
}

fn shortint_encrypt_with_message_modulus_decrypt<P>(param: P)
where
    P: Into<TestParameters>,
{
    let keys = KEY_CACHE.get_from_param(param);
    let cks = keys.client_key();

    let mut rng = rand::thread_rng();

    for _ in 0..NB_TESTS {
        let mut modulus = rng.gen::<u64>() % cks.parameters().message_modulus().0;
        while modulus == 0 {
            modulus = rng.gen::<u64>() % cks.parameters().message_modulus().0;
        }

        let clear = rng.gen::<u64>() % modulus;

        let ct = cks.encrypt_with_message_modulus(clear, MessageModulus(modulus));

        let dec = cks.decrypt(&ct);

        assert_eq!(clear, dec);
    }
}

fn shortint_encrypt_decrypt_without_padding<P>(param: P)
where
    P: Into<TestParameters>,
{
    let keys = KEY_CACHE.get_from_param(param);
    let cks = keys.client_key();

    let mut rng = rand::thread_rng();

    // We assume that the modulus is the largest possible without padding bit
    let modulus = cks.parameters().message_modulus().0 * cks.parameters().carry_modulus().0;

    for _ in 0..NB_TESTS {
        let clear = rng.gen::<u64>() % modulus;

        let ct = cks.encrypt_without_padding(clear);

        let dec = cks.decrypt_message_and_carry_without_padding(&ct);

        assert_eq!(clear, dec);
    }
}

fn shortint_keyswitch_bootstrap<P>(param: P)
where
    P: Into<TestParameters>,
{
    let keys = KEY_CACHE.get_from_param(param);
    let (cks, sks) = (keys.client_key(), keys.server_key());

    let mut rng = rand::thread_rng();

    let modulus = cks.parameters().message_modulus().0;
    let mut failures = 0;

    for _ in 0..NB_TESTS {
        let clear_0 = rng.gen::<u64>() % modulus;

        let ctxt_0 = cks.encrypt(clear_0);

        let ct_res = sks.message_extract(&ctxt_0);

        let dec_res = cks.decrypt(&ct_res);

        if clear_0 != dec_res {
            failures += 1;
        }
    }

    println!("fail_rate = {failures}/{NB_TESTS}");
    assert_eq!(0, failures);
}

fn shortint_keyswitch_programmable_bootstrap<P>(param: P)
where
    P: Into<TestParameters>,
{
    let keys = KEY_CACHE.get_from_param(param);
    let (cks, sks) = (keys.client_key(), keys.server_key());

    let mut rng = rand::thread_rng();

    let modulus = cks.parameters().message_modulus().0;

    for _ in 0..NB_TESTS {
        let clear_0 = rng.gen::<u64>() % modulus;

        let ctxt_0 = cks.encrypt(clear_0);

        let acc = sks.generate_msg_lookup_table(|n| n, cks.parameters().message_modulus());

        let ct_res = sks.apply_lookup_table(&ctxt_0, &acc);

        let dec_res = cks.decrypt(&ct_res);

        assert_eq!(clear_0, dec_res);
    }
}

fn shortint_keyswitch_programmable_bootstrap_many_lut<P>(param: P)
where
    P: Into<TestParameters>,
{
    let keys = KEY_CACHE.get_from_param(param);
    let (cks, sks) = (keys.client_key(), keys.server_key());

    let mut rng = rand::thread_rng();

    let msg_modulus = cks.parameters().message_modulus().0;
    let carry_modulus = cks.parameters().carry_modulus().0;
    let modulus_sup = msg_modulus * carry_modulus;

    let f1 = |x: u64| x * x % msg_modulus;
    let f2 = |x: u64| (x.count_ones() as u64) % msg_modulus;
    let f3 = |x: u64| (x.wrapping_add(1)) % msg_modulus;
    let f4 = |x: u64| (x.wrapping_sub(1)) % msg_modulus;
    let f5 = |x: u64| (x * 2) % msg_modulus;
    let f6 = |x: u64| (x * 3) % msg_modulus;
    let f7 = |x: u64| (x / 2) % msg_modulus;
    let f8 = |x: u64| (x / 3) % msg_modulus;

    let functions: &[&dyn Fn(u64) -> u64] = &[&f1, &f2, &f3, &f4, &f5, &f6, &f7, &f8];
    let max_fn_count = functions.len().min(modulus_sup as usize / 2);
    let per_fn_tests = (NB_TESTS / max_fn_count).max(1);
    for fn_count in 1..=max_fn_count {
        let functions = &functions[..fn_count];

        // Depending on how many functions we are evaluating the maximum valid message modulus is
        // lower than what the parameters support
        let effective_msg_modulus = msg_modulus.min(modulus_sup / fn_count as u64);

        // Generate the many lut once for the current set of functions
        let acc = sks.generate_many_lookup_table(functions);
        for _ in 0..per_fn_tests {
            let clear_0 = rng.gen::<u64>() % effective_msg_modulus;

            // Test on real ciphertext
            {
                #[cfg(feature = "pbs-stats")]
                crate::reset_pbs_count();

                let ctxt_0 = cks.encrypt(clear_0);
                let vec_res = sks.apply_many_lookup_table(&ctxt_0, &acc);

                for (fn_idx, (res, function)) in vec_res.iter().zip(functions).enumerate() {
                    let dec = cks.decrypt(res);
                    let function_eval = function(clear_0);

                    assert_eq!(
                        dec, function_eval,
                        "Evaluation of function #{fn_idx} on {clear_0} failed, \
                        got {dec}, expected {function_eval}",
                    );
                }

                #[cfg(feature = "pbs-stats")]
                assert_eq!(crate::get_pbs_count(), 1, "Invalid PBS Count");
            }

            // Test on a trivial
            {
                #[cfg(feature = "pbs-stats")]
                crate::reset_pbs_count();

                let ctxt_0 = sks.create_trivial(clear_0);
                let vec_res = sks.apply_many_lookup_table(&ctxt_0, &acc);

                for (fn_idx, (res, function)) in vec_res.iter().zip(functions).enumerate() {
                    let dec = cks.decrypt(res);
                    let function_eval = function(clear_0);

                    assert_eq!(
                        dec, function_eval,
                        "Evaluation of function #{fn_idx} on {clear_0} failed, \
                        got {dec}, expected {function_eval}",
                    );
                }

                #[cfg(feature = "pbs-stats")]
                assert_eq!(crate::get_pbs_count(), 1, "Invalid PBS Count");
            }
        }
    }
}

fn shortint_carry_extract<P>(param: P)
where
    P: Into<TestParameters>,
{
    let keys = KEY_CACHE.get_from_param(param);
    let (cks, sks) = (keys.client_key(), keys.server_key());

    let mut rng = rand::thread_rng();

    let full_modulus = cks.parameters().message_modulus().0 * cks.parameters().carry_modulus().0;

    let msg_modulus = cks.parameters().message_modulus().0;

    for _ in 0..NB_TESTS {
        let clear = rng.gen::<u64>() % full_modulus;

        let ctxt = cks.unchecked_encrypt(clear);

        let ct_carry = sks.carry_extract(&ctxt);

        let dec = cks.decrypt_message_and_carry(&ct_carry);

        println!(
            "msg = {clear}, modulus = {msg_modulus}, msg/modulus = {}",
            clear / msg_modulus
        );
        assert_eq!(clear / msg_modulus, dec);
    }
}

fn shortint_message_extract<P>(param: P)
where
    P: Into<TestParameters>,
{
    let keys = KEY_CACHE.get_from_param(param);
    let (cks, sks) = (keys.client_key(), keys.server_key());

    let mut rng = rand::thread_rng();

    let full_modulus = cks.parameters().message_modulus().0 * cks.parameters().carry_modulus().0;

    let msg_modulus = cks.parameters().message_modulus().0;

    for _ in 0..NB_TESTS {
        let clear = rng.gen::<u64>() % full_modulus;

        let ctxt = cks.unchecked_encrypt(clear);

        let ct_msg = sks.message_extract(&ctxt);

        let dec = cks.decrypt(&ct_msg);

        assert_eq!(clear % msg_modulus, dec);
    }
}

fn shortint_generate_lookup_table<P>(param: P)
where
    P: Into<TestParameters>,
{
    let keys = KEY_CACHE.get_from_param(param);
    let (cks, sks) = (keys.client_key(), keys.server_key());
    let double = |x| (2 * x) % sks.message_modulus.0;
    let acc = sks.generate_lookup_table(double);

    let mut rng = rand::thread_rng();

    let modulus = cks.parameters().message_modulus().0;

    for _ in 0..NB_TESTS {
        let clear = rng.gen::<u64>() % modulus;

        let ct = cks.encrypt(clear);

        let ct_res = sks.apply_lookup_table(&ct, &acc);

        let dec_res = cks.decrypt(&ct_res);

        assert_eq!((clear * 2) % modulus, dec_res);
    }
}

fn shortint_unchecked_add<P>(param: P)
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

        let ct_res = sks.unchecked_add(&ctxt_0, &ctxt_1);

        let dec_res = cks.decrypt(&ct_res);

        println!(
            "The parameters set is CARRY_{}_MESSAGE_{}",
            cks.parameters().carry_modulus().0,
            cks.parameters().message_modulus().0
        );
        assert_eq!((clear_0 + clear_1) % modulus, dec_res);
    }
}

fn shortint_smart_add<P>(param: P)
where
    P: Into<TestParameters>,
{
    let keys = KEY_CACHE.get_from_param(param);
    let (cks, sks) = (keys.client_key(), keys.server_key());

    let mut rng = rand::thread_rng();

    let modulus = cks.parameters().message_modulus().0;

    for _ in 0..NB_TESTS_SMART {
        let clear_0 = rng.gen::<u64>() % modulus;

        let clear_1 = rng.gen::<u64>() % modulus;

        let mut ctxt_0 = cks.encrypt(clear_0);

        let mut ctxt_1 = cks.encrypt(clear_1);

        let mut ct_res = sks.smart_add(&mut ctxt_0, &mut ctxt_1);
        let mut clear = clear_0 + clear_1;

        for _ in 0..NB_SUB_TEST_SMART {
            println!("SUB TEST");
            ct_res = sks.smart_add(&mut ct_res, &mut ctxt_0);
            clear += clear_0;

            let dec_res = cks.decrypt(&ct_res);

            assert_eq!(clear % modulus, dec_res);
        }
    }
}

fn shortint_default_add<P>(param: P)
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

        let ct_res = sks.add(&ctxt_0, &ctxt_1);
        let clear_res = clear_0 + clear_1;

        let dec_res = cks.decrypt(&ct_res);

        assert_eq!(clear_res % modulus, dec_res);
    }
}

fn shortint_compressed_public_key_smart_add<P>(param: P)
where
    P: Into<TestParameters>,
{
    let keys = KEY_CACHE.get_from_param(param);
    let (cks, sks) = (keys.client_key(), keys.server_key());
    let pk = crate::shortint::CompressedPublicKey::new(cks);

    let mut rng = rand::thread_rng();

    let modulus = cks.parameters().message_modulus().0;

    for _ in 0..NB_TESTS_SMART {
        let clear_0 = rng.gen::<u64>() % modulus;

        let clear_1 = rng.gen::<u64>() % modulus;

        let mut ctxt_0 = pk.encrypt(clear_0);

        let mut ctxt_1 = pk.encrypt(clear_1);

        let mut ct_res = sks.smart_add(&mut ctxt_0, &mut ctxt_1);
        let mut clear = clear_0 + clear_1;

        for _ in 0..NB_SUB_TEST_SMART {
            ct_res = sks.smart_add(&mut ct_res, &mut ctxt_0);
            clear += clear_0;

            let dec_res = cks.decrypt(&ct_res);

            assert_eq!(clear % modulus, dec_res);
        }
    }
}

fn shortint_public_key_smart_add<P>(param: P)
where
    P: Into<TestParameters>,
{
    let keys = KEY_CACHE.get_from_param(param);
    let (cks, sks) = (keys.client_key(), keys.server_key());
    let pk = crate::shortint::PublicKey::new(cks);

    let mut rng = rand::thread_rng();

    let modulus = cks.parameters().message_modulus().0;

    for _ in 0..NB_TESTS_SMART {
        let clear_0 = rng.gen::<u64>() % modulus;

        let clear_1 = rng.gen::<u64>() % modulus;

        let mut ctxt_0 = pk.encrypt(clear_0);

        let mut ctxt_1 = pk.encrypt(clear_1);

        let mut ct_res = sks.smart_add(&mut ctxt_0, &mut ctxt_1);
        let mut clear = clear_0 + clear_1;

        for _ in 0..NB_SUB_TEST_SMART {
            ct_res = sks.smart_add(&mut ct_res, &mut ctxt_0);
            clear += clear_0;

            let dec_res = cks.decrypt(&ct_res);

            assert_eq!(clear % modulus, dec_res);
        }
    }
}

fn shortint_unchecked_scalar_bitxor<P>(param: P)
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

        let ct_res = sks.unchecked_scalar_bitxor(&ctxt_0, clear_1 as u8);
        assert_eq!(
            ct_res.degree,
            ctxt_0.degree.after_bitxor(Degree::new(clear_1))
        );

        let dec_res = cks.decrypt(&ct_res);

        assert_eq!(clear_0 ^ clear_1, dec_res);
    }
}

fn shortint_unchecked_scalar_bitor<P>(param: P)
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

        let ct_res = sks.unchecked_scalar_bitor(&ctxt_0, clear_1 as u8);
        assert_eq!(
            ct_res.degree,
            ctxt_0.degree.after_bitor(Degree::new(clear_1))
        );

        let dec_res = cks.decrypt(&ct_res);

        assert_eq!(clear_0 | clear_1, dec_res);
    }
}

fn shortint_unchecked_scalar_bitand<P>(param: P)
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

        let ct_res = sks.unchecked_scalar_bitand(&ctxt_0, clear_1 as u8);
        assert_eq!(
            ct_res.degree,
            ctxt_0.degree.after_bitand(Degree::new(clear_1))
        );

        let dec_res = cks.decrypt(&ct_res);

        assert_eq!(clear_0 & clear_1, dec_res);
    }
}

fn shortint_smart_scalar_bitand<P>(param: P)
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
        let clear_1 = rng.gen::<u64>() % modulus;
        let scalar = rng.gen::<u8>() % mod_scalar;

        let mut ctxt_0 = cks.encrypt(clear_0);

        sks.unchecked_scalar_mul_assign(&mut ctxt_0, scalar);

        clear_0 *= scalar as u64;

        let ct_res = sks.smart_scalar_bitand(&mut ctxt_0, clear_1 as u8);

        let dec_res = cks.decrypt(&ct_res);

        assert_eq!(clear_0 & clear_1, dec_res);
    }
}

fn shortint_default_scalar_bitand<P>(param: P)
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
        let clear_1 = rng.gen::<u64>() % modulus;
        let scalar = rng.gen::<u8>() % mod_scalar;

        let mut ctxt_0 = cks.encrypt(clear_0);

        sks.unchecked_scalar_mul_assign(&mut ctxt_0, scalar);

        clear_0 *= scalar as u64;

        let ct_res = sks.scalar_bitand(&ctxt_0, clear_1 as u8);

        let dec_res = cks.decrypt(&ct_res);

        assert_eq!(clear_0 & clear_1, dec_res);
    }
}

fn shortint_smart_scalar_bitor<P>(param: P)
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
        let clear_1 = rng.gen::<u64>() % modulus;
        let scalar = rng.gen::<u8>() % mod_scalar;

        let mut ctxt_0 = cks.encrypt(clear_0);

        sks.unchecked_scalar_mul_assign(&mut ctxt_0, scalar);

        clear_0 *= scalar as u64;

        let ct_res = sks.smart_scalar_bitor(&mut ctxt_0, clear_1 as u8);

        let dec_res = cks.decrypt(&ct_res);

        assert_eq!((clear_0 | clear_1) % modulus, dec_res);
    }
}

fn shortint_default_scalar_bitor<P>(param: P)
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
        let clear_1 = rng.gen::<u64>() % modulus;
        let scalar = rng.gen::<u8>() % mod_scalar;

        let mut ctxt_0 = cks.encrypt(clear_0);

        sks.unchecked_scalar_mul_assign(&mut ctxt_0, scalar);

        clear_0 *= scalar as u64;

        let ct_res = sks.scalar_bitor(&ctxt_0, clear_1 as u8);

        let dec_res = cks.decrypt(&ct_res);

        assert_eq!((clear_0 | clear_1) % modulus, dec_res);
    }
}

fn shortint_smart_scalar_bitxor<P>(param: P)
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
        let clear_1 = rng.gen::<u64>() % modulus;
        let scalar = rng.gen::<u8>() % mod_scalar;

        let mut ctxt_0 = cks.encrypt(clear_0);

        sks.unchecked_scalar_mul_assign(&mut ctxt_0, scalar);

        clear_0 *= scalar as u64;

        let ct_res = sks.smart_scalar_bitxor(&mut ctxt_0, clear_1 as u8);

        let dec_res = cks.decrypt(&ct_res);

        assert_eq!((clear_0 ^ clear_1) % modulus, dec_res);
    }
}

fn shortint_default_scalar_bitxor<P>(param: P)
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
        let clear_1 = rng.gen::<u64>() % modulus;
        let scalar = rng.gen::<u8>() % mod_scalar;

        let mut ctxt_0 = cks.encrypt(clear_0);

        sks.unchecked_scalar_mul_assign(&mut ctxt_0, scalar);

        clear_0 *= scalar as u64;

        let ct_res = sks.scalar_bitxor(&ctxt_0, clear_1 as u8);

        let dec_res = cks.decrypt(&ct_res);

        assert_eq!((clear_0 ^ clear_1) % modulus, dec_res);
    }
}

fn shortint_smart_mul_lsb<P>(param: P)
where
    P: Into<TestParameters>,
{
    let keys = KEY_CACHE.get_from_param(param);
    let (cks, sks) = (keys.client_key(), keys.server_key());

    let mut rng = rand::thread_rng();

    let modulus = cks.parameters().message_modulus().0;

    for _ in 0..NB_TESTS_SMART {
        let clear_0 = rng.gen::<u64>() % modulus;

        let clear_1 = rng.gen::<u64>() % modulus;

        let mut ctxt_0 = cks.encrypt(clear_0);

        let mut ctxt_1 = cks.encrypt(clear_1);

        let mut ct_res = sks.smart_mul_lsb(&mut ctxt_0, &mut ctxt_1);

        let mut clear = clear_0 * clear_1;

        let dec_res = cks.decrypt(&ct_res);

        assert_eq!(clear % modulus, dec_res);

        for _ in 0..NB_SUB_TEST_SMART {
            ct_res = sks.smart_mul_lsb(&mut ct_res, &mut ctxt_0);
            clear = (clear * clear_0) % modulus;

            let dec_res = cks.decrypt(&ct_res);

            assert_eq!(clear, dec_res);
        }
    }
}

fn shortint_default_mul_lsb<P>(param: P)
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

        let ct_res = sks.mul_lsb(&ctxt_0, &ctxt_1);

        let clear = clear_0 * clear_1;

        let dec_res = cks.decrypt(&ct_res);

        assert_eq!(clear % modulus, dec_res);
    }
}

fn shortint_unchecked_neg<P>(param: P)
where
    P: Into<TestParameters>,
{
    let keys = KEY_CACHE.get_from_param(param);
    let (cks, sks) = (keys.client_key(), keys.server_key());

    let mut rng = rand::thread_rng();

    let modulus = cks.parameters().message_modulus().0;

    for _ in 0..NB_TESTS {
        let clear = rng.gen::<u64>() % modulus;

        let ctxt = cks.encrypt(clear);

        let ct_tmp = sks.unchecked_neg(&ctxt);

        let dec = cks.decrypt(&ct_tmp);

        let clear_result = clear.wrapping_neg() % modulus;

        assert_eq!(clear_result, dec);
    }
}

fn shortint_smart_neg<P>(param: P)
where
    P: Into<TestParameters>,
{
    let keys = KEY_CACHE.get_from_param(param);
    let (cks, sks) = (keys.client_key(), keys.server_key());

    let mut rng = rand::thread_rng();

    let modulus = cks.parameters().message_modulus().0;

    for _ in 0..NB_TESTS_SMART {
        let clear1 = rng.gen::<u64>() % modulus;

        let mut ct1 = cks.encrypt(clear1);

        let mut ct_res = sks.smart_neg(&mut ct1);

        let mut clear_result = clear1.wrapping_neg() % modulus;

        for _ in 0..NB_SUB_TEST_SMART {
            ct_res = sks.smart_neg(&mut ct_res);

            clear_result = clear_result.wrapping_neg() % modulus;

            let dec_res = cks.decrypt(&ct_res);

            assert_eq!(clear_result, dec_res);
        }
    }
}

fn shortint_default_neg<P>(param: P)
where
    P: Into<TestParameters>,
{
    let keys = KEY_CACHE.get_from_param(param);
    let (cks, sks) = (keys.client_key(), keys.server_key());

    let mut rng = rand::thread_rng();

    let modulus = cks.parameters().message_modulus().0;

    for _ in 0..NB_TESTS {
        let clear1 = rng.gen::<u64>() % modulus;

        let ct1 = cks.encrypt(clear1);

        let ct_res = sks.neg(&ct1);

        let clear_result = clear1.wrapping_neg() % modulus;

        let dec_res = cks.decrypt(&ct_res);

        assert_eq!(clear_result, dec_res);
    }
}

fn shortint_unchecked_scalar_add<P>(param: P)
where
    P: Into<TestParameters>,
{
    let keys = KEY_CACHE.get_from_param(param);
    let (cks, sks) = (keys.client_key(), keys.server_key());

    let mut rng = rand::thread_rng();

    let message_modulus = cks.parameters().message_modulus().0 as u8;

    for _ in 0..NB_TESTS {
        let clear = rng.gen::<u8>() % message_modulus;

        let scalar = rng.gen::<u8>() % message_modulus;

        let ct = cks.encrypt(clear as u64);

        let ct_res = sks.unchecked_scalar_add(&ct, scalar);

        let dec_res = cks.decrypt(&ct_res);

        assert_eq!((clear + scalar) % message_modulus, dec_res as u8);
    }
}

fn shortint_smart_scalar_add<P>(param: P)
where
    P: Into<TestParameters>,
{
    let keys = KEY_CACHE.get_from_param(param);
    let (cks, sks) = (keys.client_key(), keys.server_key());

    let mut rng = rand::thread_rng();

    let modulus = cks.parameters().message_modulus().0 as u8;

    for _ in 0..NB_TESTS_SMART {
        let clear_0 = rng.gen::<u8>() % modulus;

        let clear_1 = rng.gen::<u8>() % modulus;

        let mut ctxt_0 = cks.encrypt(clear_0 as u64);

        let mut ct_res = sks.smart_scalar_add(&mut ctxt_0, clear_1);

        let mut clear = (clear_0 + clear_1) % modulus;

        for _ in 0..NB_SUB_TEST_SMART {
            ct_res = sks.smart_scalar_add(&mut ct_res, clear_1);
            clear = (clear + clear_1) % modulus;

            let dec_res = cks.decrypt(&ct_res);

            assert_eq!(clear, dec_res as u8);
        }
    }
}

fn shortint_default_scalar_add<P>(param: P)
where
    P: Into<TestParameters>,
{
    let keys = KEY_CACHE.get_from_param(param);
    let (cks, sks) = (keys.client_key(), keys.server_key());

    let mut rng = rand::thread_rng();

    let modulus = cks.parameters().message_modulus().0 as u8;

    for _ in 0..NB_TESTS {
        let clear_0 = rng.gen::<u8>() % modulus;

        let clear_1 = rng.gen::<u8>() % modulus;

        let ctxt_0 = cks.encrypt(clear_0 as u64);

        let ct_res = sks.scalar_add(&ctxt_0, clear_1);

        let clear = (clear_0 + clear_1) % modulus;

        let dec_res = cks.decrypt(&ct_res);

        assert_eq!(clear, dec_res as u8);
    }
}

fn shortint_unchecked_scalar_sub<P>(param: P)
where
    P: Into<TestParameters>,
{
    let keys = KEY_CACHE.get_from_param(param);
    let (cks, sks) = (keys.client_key(), keys.server_key());

    let mut rng = rand::thread_rng();

    let message_modulus = cks.parameters().message_modulus().0 as u8;

    for _ in 0..NB_TESTS {
        let clear = rng.gen::<u8>() % message_modulus;

        let scalar = rng.gen::<u8>() % message_modulus;

        let ct = cks.encrypt(clear as u64);

        let ct_res = sks.unchecked_scalar_sub(&ct, scalar);

        let dec_res = cks.decrypt(&ct_res);

        assert_eq!(clear.wrapping_sub(scalar) % message_modulus, dec_res as u8);
    }
}

fn shortint_smart_scalar_sub<P>(param: P)
where
    P: Into<TestParameters>,
{
    let keys = KEY_CACHE.get_from_param(param);
    let (cks, sks) = (keys.client_key(), keys.server_key());

    let mut rng = rand::thread_rng();

    let modulus = cks.parameters().message_modulus().0 as u8;

    for _ in 0..NB_TESTS_SMART {
        let clear_0 = rng.gen::<u8>() % modulus;

        let clear_1 = rng.gen::<u8>() % modulus;

        let mut ctxt_0 = cks.encrypt(clear_0 as u64);

        let mut ct_res = sks.smart_scalar_sub(&mut ctxt_0, clear_1);

        let mut clear = clear_0.wrapping_sub(clear_1) % modulus;

        for _ in 0..NB_SUB_TEST_SMART {
            ct_res = sks.smart_scalar_sub(&mut ct_res, clear_1);
            clear = clear.wrapping_sub(clear_1) % modulus;

            let dec_res = cks.decrypt(&ct_res);

            assert_eq!(clear, dec_res as u8);
        }
    }
}

fn shortint_default_scalar_sub<P>(param: P)
where
    P: Into<TestParameters>,
{
    let keys = KEY_CACHE.get_from_param(param);
    let (cks, sks) = (keys.client_key(), keys.server_key());

    let mut rng = rand::thread_rng();

    let modulus = cks.parameters().message_modulus().0 as u8;

    for _ in 0..NB_TESTS {
        let clear_0 = rng.gen::<u8>() % modulus;

        let clear_1 = rng.gen::<u8>() % modulus;

        let ctxt_0 = cks.encrypt(clear_0 as u64);

        let ct_res = sks.scalar_sub(&ctxt_0, clear_1);

        let clear = (clear_0.wrapping_sub(clear_1)) % modulus;

        let dec_res = cks.decrypt(&ct_res);

        assert_eq!(clear, dec_res as u8);
    }
}

fn shortint_unchecked_scalar_mul<P>(param: P)
where
    P: Into<TestParameters>,
{
    let keys = KEY_CACHE.get_from_param(param);
    let (cks, sks) = (keys.client_key(), keys.server_key());

    let mut rng = rand::thread_rng();

    let message_modulus = cks.parameters().message_modulus().0 as u8;
    let carry_modulus = cks.parameters().carry_modulus().0 as u8;

    for _ in 0..NB_TESTS {
        let clear = rng.gen::<u8>() % message_modulus;

        let scalar = rng.gen::<u8>() % carry_modulus;

        let ct = cks.encrypt(clear as u64);

        let ct_res = sks.unchecked_scalar_mul(&ct, scalar);

        let dec_res = cks.decrypt(&ct_res);

        assert_eq!((clear * scalar) % message_modulus, dec_res as u8);
    }
}

fn shortint_smart_scalar_mul<P>(param: P)
where
    P: Into<TestParameters>,
{
    let keys = KEY_CACHE.get_from_param(param);
    let (cks, sks) = (keys.client_key(), keys.server_key());

    let mut rng = rand::thread_rng();

    let modulus = cks.parameters().message_modulus().0 as u8;

    let scalar_modulus = cks.parameters().carry_modulus().0 as u8;

    for _ in 0..NB_TESTS_SMART {
        let clear = rng.gen::<u8>() % modulus;

        let scalar = rng.gen::<u8>() % scalar_modulus;

        let mut ct = cks.encrypt(clear as u64);

        let mut ct_res = sks.smart_scalar_mul(&mut ct, scalar);

        let mut clear_res = clear * scalar;
        for _ in 0..NB_SUB_TEST_SMART {
            ct_res = sks.smart_scalar_mul(&mut ct_res, scalar);
            clear_res = (clear_res * scalar) % modulus;
        }

        let dec_res = cks.decrypt(&ct_res);

        assert_eq!(clear_res, dec_res as u8);
    }
}

fn shortint_default_scalar_mul<P>(param: P)
where
    P: Into<TestParameters>,
{
    let keys = KEY_CACHE.get_from_param(param);
    let (cks, sks) = (keys.client_key(), keys.server_key());

    let mut rng = rand::thread_rng();

    let modulus = cks.parameters().message_modulus().0 as u8;

    let scalar_modulus = cks.parameters().carry_modulus().0 as u8;

    for _ in 0..NB_TESTS {
        let clear = rng.gen::<u8>() % modulus;

        let scalar = rng.gen::<u8>() % scalar_modulus;

        let ct = cks.encrypt(clear as u64);

        let ct_res = sks.scalar_mul(&ct, scalar);

        let clear_res = (clear * scalar) % modulus;

        let dec_res = cks.decrypt(&ct_res);

        assert_eq!(clear_res, dec_res as u8);
    }
}

fn shortint_unchecked_right_shift<P>(param: P)
where
    P: Into<TestParameters>,
{
    let keys = KEY_CACHE.get_from_param(param);
    let (cks, sks) = (keys.client_key(), keys.server_key());

    let mut rng = rand::thread_rng();

    let modulus = cks.parameters().message_modulus().0;

    for _ in 0..NB_TESTS {
        let clear_0 = rng.gen::<u64>() % modulus;
        let shift = rng.gen::<u64>() % 2;

        let ctxt_0 = cks.encrypt(clear_0);

        let ct_res = sks.unchecked_scalar_right_shift(&ctxt_0, shift as u8);

        let dec_res = cks.decrypt(&ct_res);

        assert_eq!(clear_0 >> shift, dec_res);
    }
}

fn shortint_default_right_shift<P>(param: P)
where
    P: Into<TestParameters>,
{
    let keys = KEY_CACHE.get_from_param(param);
    let (cks, sks) = (keys.client_key(), keys.server_key());

    let mut rng = rand::thread_rng();

    let modulus = cks.parameters().message_modulus().0;

    for _ in 0..NB_TESTS {
        let clear_0 = rng.gen::<u64>() % modulus;
        let shift = rng.gen::<u64>() % 2;

        let ctxt_0 = cks.encrypt(clear_0);

        let ct_res = sks.scalar_right_shift(&ctxt_0, shift as u8);

        let dec_res = cks.decrypt(&ct_res);

        assert_eq!(clear_0 >> shift, dec_res);
    }
}

fn shortint_unchecked_left_shift<P>(param: P)
where
    P: Into<TestParameters>,
{
    let keys = KEY_CACHE.get_from_param(param);
    let (cks, sks) = (keys.client_key(), keys.server_key());

    let mut rng = rand::thread_rng();

    let modulus = cks.parameters().message_modulus().0;

    for _ in 0..NB_TESTS {
        let clear_0 = rng.gen::<u64>() % modulus;
        let shift = rng.gen::<u64>() % 2;

        let ctxt_0 = cks.encrypt(clear_0);

        let ct_res = sks.unchecked_scalar_left_shift(&ctxt_0, shift as u8);

        let dec_res = cks.decrypt(&ct_res);

        assert_eq!((clear_0 << shift) % modulus, dec_res);
    }
}

fn shortint_default_left_shift<P>(param: P)
where
    P: Into<TestParameters>,
{
    let keys = KEY_CACHE.get_from_param(param);
    let (cks, sks) = (keys.client_key(), keys.server_key());

    let mut rng = rand::thread_rng();

    let modulus = cks.parameters().message_modulus().0;

    for _ in 0..NB_TESTS {
        let clear_0 = rng.gen::<u64>() % modulus;
        let shift = rng.gen::<u64>() % 2;

        let ctxt_0 = cks.encrypt(clear_0);

        let ct_res = sks.scalar_left_shift(&ctxt_0, shift as u8);

        let dec_res = cks.decrypt(&ct_res);

        assert_eq!((clear_0 << shift) % modulus, dec_res);
    }
}

fn shortint_unchecked_sub<P>(param: P)
where
    P: Into<TestParameters>,
{
    let keys = KEY_CACHE.get_from_param(param);
    let (cks, sks) = (keys.client_key(), keys.server_key());

    let mut rng = rand::thread_rng();

    let modulus = cks.parameters().message_modulus().0;
    for _ in 0..NB_TESTS {
        let clear1 = rng.gen::<u64>() % modulus;
        let clear2 = rng.gen::<u64>() % modulus;

        let ctxt_1 = cks.encrypt(clear1);
        let ctxt_2 = cks.encrypt(clear2);

        let ct_tmp = sks.unchecked_sub(&ctxt_1, &ctxt_2);

        let dec = cks.decrypt(&ct_tmp);

        let clear_result = clear1.wrapping_sub(clear2) % modulus;
        assert_eq!(clear_result, dec % modulus);
    }
}

fn shortint_smart_sub<P>(param: P)
where
    P: Into<TestParameters>,
{
    let keys = KEY_CACHE.get_from_param(param);
    let (cks, sks) = (keys.client_key(), keys.server_key());

    let mut rng = rand::thread_rng();

    let modulus = cks.parameters().message_modulus().0;

    for _ in 0..NB_TESTS_SMART {
        let clear1 = rng.gen::<u64>() % modulus;
        let clear2 = rng.gen::<u64>() % modulus;

        let mut ct1 = cks.encrypt(clear1);
        let mut ct2 = cks.encrypt(clear2);

        let mut ct_res = sks.smart_sub(&mut ct1, &mut ct2);

        let mut clear_res = clear1.wrapping_sub(clear2) % modulus;
        for _ in 0..NB_SUB_TEST_SMART {
            ct_res = sks.smart_sub(&mut ct_res, &mut ct2);
            clear_res = clear_res.wrapping_sub(clear2) % modulus;
        }

        let dec_res = cks.decrypt(&ct_res);

        assert_eq!(clear_res, dec_res);
    }
}

fn shortint_default_sub<P>(param: P)
where
    P: Into<TestParameters>,
{
    let keys = KEY_CACHE.get_from_param(param);
    let (cks, sks) = (keys.client_key(), keys.server_key());

    let mut rng = rand::thread_rng();

    let modulus = cks.parameters().message_modulus().0;

    for _ in 0..NB_TESTS {
        let clear1 = rng.gen::<u64>() % modulus;
        let clear2 = rng.gen::<u64>() % modulus;

        let ct1 = cks.encrypt(clear1);
        let ct2 = cks.encrypt(clear2);

        let ct_res = sks.sub(&ct1, &ct2);

        let clear_res = (clear1.wrapping_sub(clear2)) % modulus;

        let dec_res = cks.decrypt(&ct_res);

        assert_eq!(clear_res, dec_res);
    }
}

fn shortint_mul_small_carry<P>(param: P)
where
    P: Into<TestParameters>,
{
    let keys = KEY_CACHE.get_from_param(param);
    let (cks, sks) = (keys.client_key(), keys.server_key());

    let mut rng = rand::thread_rng();

    let modulus = cks.parameters().message_modulus().0;

    for _ in 0..50 {
        let clear_0 = rng.gen::<u64>() % modulus;

        let clear_1 = rng.gen::<u64>() % modulus;

        let ctxt_zero = cks.encrypt(clear_0);

        let ctxt_one = cks.encrypt(clear_1);

        let ct_res = sks.unchecked_mul_lsb_small_carry(&ctxt_zero, &ctxt_one);

        let dec_res = cks.decrypt(&ct_res);

        assert_eq!((clear_0 * clear_1) % modulus, dec_res % modulus);
    }
}

fn shortint_encrypt_with_message_modulus_unchecked_mul_lsb_small_carry_and_add<P>(param: P)
where
    P: Into<TestParameters>,
{
    let keys = KEY_CACHE.get_from_param(param);
    let (cks, sks) = (keys.client_key(), keys.server_key());

    let mut rng = rand::thread_rng();
    let full_mod = cks.parameters().message_modulus().0 * cks.parameters().carry_modulus().0;

    for _ in 0..NB_TESTS {
        let modulus = rng.gen_range(1..full_mod / 2);

        let clear1 = rng.gen::<u64>() % modulus;
        let clear2 = rng.gen::<u64>() % modulus;

        let ct1 = cks.encrypt_with_message_modulus(clear1, MessageModulus(modulus));
        let ct2 = cks.encrypt_with_message_modulus(clear2, MessageModulus(modulus));

        println!("MUL SMALL CARRY:: clear1 = {clear1}, clear2 = {clear2}, mod = {modulus}");
        let ct_res = sks.unchecked_mul_lsb_small_carry(&ct1, &ct2);
        assert_eq!(
            (clear1 * clear2) % modulus,
            cks.decrypt_message_and_carry(&ct_res) % modulus
        );

        println!("ADD:: clear1 = {clear1}, clear2 = {clear2}, mod = {modulus}");
        let ct_res = sks.unchecked_add(&ct1, &ct2);
        assert_eq!((clear1 + clear2), cks.decrypt_message_and_carry(&ct_res));
    }
}

fn shortint_encrypt_with_message_and_carry_modulus_unchecked_mul_lsb_small_carry_and_add<P>(
    param: P,
) where
    P: Into<TestParameters>,
{
    let keys = KEY_CACHE.get_from_param(param);
    let (cks, sks) = (keys.client_key(), keys.server_key());

    let mut rng = rand::thread_rng();

    let param_msg_mod = cks.parameters().message_modulus().0;
    let param_carry_mod = cks.parameters().carry_modulus().0;

    for _ in 0..NB_TESTS {
        let msg_modulus = rng.gen_range(2u64..=param_msg_mod);
        let carry_modulus = rng.gen_range(2u64..=param_carry_mod);

        let modulus = msg_modulus * carry_modulus;

        let clear1 = rng.gen::<u64>() % msg_modulus;
        let clear2 = rng.gen::<u64>() % msg_modulus;

        let ct1 = cks.encrypt_with_message_and_carry_modulus(
            clear1,
            MessageModulus(msg_modulus),
            CarryModulus(carry_modulus),
        );
        let ct2 = cks.encrypt_with_message_and_carry_modulus(
            clear2,
            MessageModulus(msg_modulus),
            CarryModulus(carry_modulus),
        );

        println!("MUL SMALL CARRY:: clear1 = {clear1}, clear2 = {clear2}, msg_mod = {msg_modulus}, carry_mod = {carry_modulus}");
        let ct_res = sks.unchecked_mul_lsb_small_carry(&ct1, &ct2);
        assert_eq!(
            (clear1 * clear2) % msg_modulus,
            cks.decrypt_message_and_carry(&ct_res) % msg_modulus
        );

        println!("ADD:: clear1 = {clear1}, clear2 = {clear2}, msg_mod = {msg_modulus}, carry_mod = {carry_modulus}");
        let ct_res = sks.unchecked_add(&ct1, &ct2);
        assert_eq!(
            (clear1 + clear2) % modulus,
            cks.decrypt_message_and_carry(&ct_res) % modulus
        );
    }
}

fn shortint_mux<P>(param: P)
where
    P: Into<TestParameters>,
{
    let keys = KEY_CACHE.get_from_param(param);
    let (cks, sks) = (keys.client_key(), keys.server_key());

    let mut rng = rand::thread_rng();
    let modulus = cks.parameters().message_modulus().0;

    let msg_true = rng.gen::<u64>() % modulus;
    let msg_false = rng.gen::<u64>() % modulus;
    let control_bit = rng.gen::<u64>() % 2;

    let mut ct_true = cks.encrypt(msg_true);
    let mut ct_false = cks.encrypt(msg_false);
    let mut ct_control = cks.encrypt(control_bit);

    let mut res = sks.smart_sub(&mut ct_true, &mut ct_false);
    sks.smart_mul_lsb_assign(&mut res, &mut ct_control);
    sks.smart_add_assign(&mut res, &mut ct_false);

    let dec_res = cks.decrypt(&res);

    let clear_mux = (msg_true.wrapping_sub(msg_false) * control_bit).wrapping_add(msg_false);
    println!("(msg_true - msg_false) * control_bit  + msg_false = {clear_mux}, res = {dec_res}");
    assert_eq!(clear_mux, dec_res);
}

fn shortint_trivial_pbs<P>(param: P)
where
    P: Into<TestParameters>,
{
    let param = param.into();
    let full_modulus = param.message_modulus().0 * param.carry_modulus().0;
    let keys = KEY_CACHE.get_from_param(param);
    let (cks, sks) = (keys.client_key(), keys.server_key());

    let check_trivial_bootstrap = |clear, lut: &LookupTableOwned| {
        let trivial_ct = sks.unchecked_create_trivial(clear);
        let non_trivial_ct = cks.unchecked_encrypt(clear);

        let trivial_res = sks.apply_lookup_table(&trivial_ct, lut);
        let non_trivial_res = sks.apply_lookup_table(&non_trivial_ct, lut);
        assert!(trivial_res.is_trivial());
        assert!(!non_trivial_res.is_trivial());
        assert_eq!(non_trivial_res.noise_level(), NoiseLevel::NOMINAL);

        let trivial_res = cks.decrypt_message_and_carry(&trivial_res);
        let non_trivial_res = cks.decrypt_message_and_carry(&non_trivial_res);
        assert_eq!(
            trivial_res, non_trivial_res,
            "Invalid trivial PBS result expected '{non_trivial_res}', got '{trivial_res}'"
        );
    };

    let functions = [
        Box::new(|x| x) as Box<dyn Fn(u64) -> u64>,
        Box::new(|x| x % sks.message_modulus.0) as Box<dyn Fn(u64) -> u64>,
        Box::new(|x| x / sks.message_modulus.0) as Box<dyn Fn(u64) -> u64>,
    ];

    if full_modulus >= 64 {
        let mut rng = rand::thread_rng();

        for _ in 0..(NB_TESTS / functions.len()).max(1) {
            for f in &functions {
                let lut = sks.generate_lookup_table(f);

                let clear_with_clean_padding_bit = rng.gen_range(0..full_modulus);
                check_trivial_bootstrap(clear_with_clean_padding_bit, &lut);

                let clear_with_dirty_padding_bit = rng.gen_range(full_modulus..2 * full_modulus);
                check_trivial_bootstrap(clear_with_dirty_padding_bit, &lut);
            }
        }
    } else {
        for f in functions {
            let lut = sks.generate_lookup_table(f);

            for clear_with_clean_padding_bit in 0..full_modulus {
                check_trivial_bootstrap(clear_with_clean_padding_bit, &lut);
            }

            for clear_with_dirty_padding_bit in full_modulus..(full_modulus * 2) {
                check_trivial_bootstrap(clear_with_dirty_padding_bit, &lut);
            }
        }
    }
}

fn shortint_trivial_pbs_many_lut<P>(param: P)
where
    P: Into<TestParameters>,
{
    let param = param.into();
    let msg_modulus = param.message_modulus().0;
    let full_modulus = param.message_modulus().0 * param.carry_modulus().0;
    let keys = KEY_CACHE.get_from_param(param);
    let (cks, sks) = (keys.client_key(), keys.server_key());

    let check_trivial_bootstrap = |clear, lut: &ManyLookupTableOwned| {
        let trivial_ct = sks.unchecked_create_trivial(clear);
        let non_trivial_ct = cks.unchecked_encrypt(clear);

        let trivial_res = sks.apply_many_lookup_table(&trivial_ct, lut);
        let non_trivial_res = sks.apply_many_lookup_table(&non_trivial_ct, lut);
        assert!(trivial_res
            .iter()
            .all(crate::shortint::ciphertext::Ciphertext::is_trivial));
        assert!(non_trivial_res
            .iter()
            .all(|ct| !ct.is_trivial() && ct.noise_level() == NoiseLevel::NOMINAL));

        for (fn_idx, (trivial, non_trivial)) in
            trivial_res.iter().zip(non_trivial_res.iter()).enumerate()
        {
            let trivial = cks.decrypt_message_and_carry(trivial);
            let non_trivial = cks.decrypt_message_and_carry(non_trivial);
            assert_eq!(
                trivial, non_trivial,
                "Invalid trivial PBS result got '{trivial}', got non trivial '{non_trivial}' \
                for input {clear} evaluating function #{fn_idx}"
            );
        }
    };

    let f1 = |x: u64| x * x % msg_modulus;
    let f2 = |x: u64| (x.count_ones() as u64) % msg_modulus;
    let f3 = |x: u64| (x.wrapping_add(1)) % msg_modulus;
    let f4 = |x: u64| (x.wrapping_sub(1)) % msg_modulus;
    let f5 = |x: u64| (x * 2) % msg_modulus;
    let f6 = |x: u64| (x * 3) % msg_modulus;
    let f7 = |x: u64| (x / 2) % msg_modulus;
    let f8 = |x: u64| (x / 3) % msg_modulus;

    let functions: &[&dyn Fn(u64) -> u64] = &[&f1, &f2, &f3, &f4, &f5, &f6, &f7, &f8];
    let max_fn_count = functions.len().min(full_modulus as usize / 2);

    if full_modulus >= 64 {
        let mut rng = rand::thread_rng();

        for _ in 0..(NB_TESTS / max_fn_count).max(1) {
            for fn_count in 1..=max_fn_count {
                let functions = &functions[..fn_count];
                let lut = sks.generate_many_lookup_table(functions);

                let clear_with_clean_padding_bit = rng.gen_range(0..full_modulus);
                check_trivial_bootstrap(clear_with_clean_padding_bit, &lut);

                let clear_with_dirty_padding_bit = rng.gen_range(full_modulus..2 * full_modulus);
                check_trivial_bootstrap(clear_with_dirty_padding_bit, &lut);
            }
        }
    } else {
        for fn_count in 1..=max_fn_count {
            let functions = &functions[..fn_count];
            let lut = sks.generate_many_lookup_table(functions);

            for clear_with_clean_padding_bit in 0..full_modulus {
                check_trivial_bootstrap(clear_with_clean_padding_bit, &lut);
            }

            for clear_with_dirty_padding_bit in full_modulus..(full_modulus * 2) {
                check_trivial_bootstrap(clear_with_dirty_padding_bit, &lut);
            }
        }
    }
}
