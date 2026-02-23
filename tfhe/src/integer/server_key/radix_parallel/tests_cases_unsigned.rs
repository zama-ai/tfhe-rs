use super::tests_unsigned::{
    nb_tests_for_params, nb_tests_smaller_for_params, overflowing_add_under_modulus,
    overflowing_mul_under_modulus, overflowing_sub_under_modulus, random_non_zero_value,
    MAX_NB_CTXT,
};
use crate::integer::block_decomposition::BlockDecomposer;
use crate::integer::ciphertext::boolean_value::BooleanBlock;
use crate::integer::keycache::KEY_CACHE;
use crate::integer::{
    IntegerKeyKind, IntegerRadixCiphertext, RadixCiphertext, RadixClientKey, ServerKey,
};
use crate::shortint::parameters::*;
use rand::Rng;
use std::sync::Arc;

#[cfg(not(tarpaulin))]
pub(crate) const NB_CTXT: usize = 4;
#[cfg(tarpaulin)]
pub(crate) const NB_CTXT: usize = 2;

/// This trait is to be implemented by a struct that is capable
/// of executing a particular function to be tested.
pub(crate) trait FunctionExecutor<TestInput, TestOutput> {
    /// Setups the executor
    ///
    /// Implementers are expected to be fully functional after this
    /// function has been called.
    fn setup(&mut self, cks: &RadixClientKey, sks: Arc<ServerKey>);

    /// Executes the function
    ///
    /// The function receives some inputs and return some output.
    /// Implementers may have to do more than just calling the function
    /// that is being tested (for example input/output may need to be converted)
    ///
    /// Look at the test case function to know what are the expected inputs and outputs.
    fn execute(&mut self, input: TestInput) -> TestOutput;
}

pub(crate) use crate::integer::server_key::radix_parallel::tests_unsigned::test_add::unchecked_add_test;
#[cfg(feature = "gpu")]
pub(crate) use crate::integer::server_key::radix_parallel::tests_unsigned::test_add::{
    default_add_test, unchecked_add_assign_test,
};
#[cfg(feature = "gpu")]
pub(crate) use crate::integer::server_key::radix_parallel::tests_unsigned::test_aes::{
    aes_dynamic_parallelism_many_inputs_test, aes_fixed_parallelism_1_input_test,
    aes_fixed_parallelism_2_inputs_test,
};
#[cfg(feature = "gpu")]
pub(crate) use crate::integer::server_key::radix_parallel::tests_unsigned::test_aes256::{
    aes_256_dynamic_parallelism_many_inputs_test, aes_256_fixed_parallelism_1_input_test,
    aes_256_fixed_parallelism_2_inputs_test,
};
#[cfg(feature = "gpu")]
pub(crate) use crate::integer::server_key::radix_parallel::tests_unsigned::test_neg::default_neg_test;
pub(crate) use crate::integer::server_key::radix_parallel::tests_unsigned::test_neg::unchecked_neg_test;
#[cfg(feature = "gpu")]
pub(crate) use crate::integer::server_key::radix_parallel::tests_unsigned::test_sub::default_sub_test;
pub(crate) use crate::integer::server_key::radix_parallel::tests_unsigned::test_sub::unchecked_sub_test;
#[cfg(feature = "gpu")]
pub(crate) use crate::integer::server_key::radix_parallel::tests_unsigned::test_sum::default_sum_ciphertexts_vec_test;
#[cfg(feature = "gpu")]
pub(crate) use crate::integer::server_key::radix_parallel::tests_unsigned::test_vector_find::{
    default_contains_clear_test_case, default_contains_test_case,
    default_first_index_in_clears_test_case, default_first_index_of_clear_test_case,
    default_first_index_of_test_case, default_index_in_clears_test_case,
    default_index_of_clear_test_case, default_index_of_test_case, default_is_in_clears_test_case,
    default_match_value_or_test_case, default_match_value_test_case,
    unchecked_contains_clear_test_case, unchecked_contains_test_case,
    unchecked_first_index_in_clears_test_case, unchecked_first_index_of_clear_test_case,
    unchecked_first_index_of_test_case, unchecked_index_in_clears_test_case,
    unchecked_index_of_clear_test_case, unchecked_index_of_test_case,
    unchecked_is_in_clears_test_case, unchecked_match_value_or_test_case,
    unchecked_match_value_test_case,
};
use crate::shortint::server_key::CiphertextNoiseDegree;

//=============================================================================
// Unchecked Tests
//=============================================================================

pub(crate) fn unchecked_mul_test<P, T>(param: P, mut executor: T)
where
    P: Into<TestParameters>,
    T: for<'a> FunctionExecutor<(&'a RadixCiphertext, &'a RadixCiphertext), RadixCiphertext>,
{
    let param = param.into();
    let nb_tests = nb_tests_for_params(param);
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let sks = Arc::new(sks);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    let mut rng = rand::rng();

    // message_modulus^vec_length
    let modulus = cks.parameters().message_modulus().0.pow(NB_CTXT as u32);

    executor.setup(&cks, sks);

    for _ in 0..nb_tests {
        let clear_0 = rng.gen::<u64>() % modulus;
        let clear_1 = rng.gen::<u64>() % modulus;

        let ctxt_0 = cks.encrypt(clear_0);
        let ctxt_1 = cks.encrypt(clear_1);

        let encrypted_result = executor.execute((&ctxt_0, &ctxt_1));
        let decrypted_result: u64 = cks.decrypt(&encrypted_result);

        let expected_result = clear_0.wrapping_mul(clear_1) % modulus;
        assert_eq!(decrypted_result, expected_result);
    }
}

pub(crate) fn unchecked_block_mul_test<P, T>(param: P, mut executor: T)
where
    P: Into<TestParameters>,
    T: for<'a> FunctionExecutor<
        (&'a RadixCiphertext, &'a crate::shortint::Ciphertext, usize),
        RadixCiphertext,
    >,
{
    let param = param.into();
    let nb_tests = nb_tests_for_params(param);
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let sks = Arc::new(sks);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    let mut rng = rand::rng();

    // message_modulus^vec_length
    let modulus = cks.parameters().message_modulus().0.pow(NB_CTXT as u32);

    let block_modulus = cks.parameters().message_modulus().0;

    executor.setup(&cks, sks);

    for _ in 0..nb_tests {
        let clear_0 = rng.gen::<u64>() % modulus;
        let clear_1 = rng.gen::<u64>() % block_modulus;

        let index = rng.gen_range(0..=(NB_CTXT - 1) as u32);
        let multiplier = cks.parameters().message_modulus().0.pow(index) as u64;
        let index = index as usize;

        let ct_zero = cks.encrypt(clear_0);
        let ct_one = cks.encrypt_one_block(clear_1);

        let ct_res = executor.execute((&ct_zero, &ct_one, index));
        let dec_res: u64 = cks.decrypt(&ct_res);

        let expected = clear_0.wrapping_mul(clear_1).wrapping_mul(multiplier) % modulus;
        assert_eq!(expected, dec_res);
    }
}

pub(crate) fn unchecked_mul_corner_cases_test<P, T>(param: P, mut executor: T)
where
    P: Into<TestParameters>,
    T: for<'a> FunctionExecutor<(&'a RadixCiphertext, &'a RadixCiphertext), RadixCiphertext>,
{
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let sks = Arc::new(sks);
    let nb_ct =
        (128f64 / (cks.parameters().message_modulus().0 as f64).log2().ceil()).ceil() as usize;
    let cks = RadixClientKey::from((cks, nb_ct));

    executor.setup(&cks, sks);

    // This example will not pass if the terms reduction is wrong
    // on the chunk size it uses to reduce the 'terms' resulting
    // from blockmuls
    {
        let clear = 307096569525960547621731375222677666984u128;
        let scalar = 5207034748027904122u64;

        // Same thing but with scalar encrypted
        let ct = cks.encrypt(clear);
        let ct2 = cks.encrypt(scalar);
        let ct_res = executor.execute((&ct, &ct2));
        let dec_res: u128 = cks.decrypt(&ct_res);
        assert_eq!(clear.wrapping_mul(scalar as u128), dec_res);
    }

    {
        // Same thing but with scalar encrypted
        let clear = u128::MAX;
        let scalar = u128::MAX;
        let ct = cks.encrypt(clear);
        let ct2 = cks.encrypt(scalar);
        let ct_res = executor.execute((&ct, &ct2));
        let dec_res: u128 = cks.decrypt(&ct_res);
        assert_eq!(clear.wrapping_mul(scalar), dec_res);
    }
}

//=============================================================================
// Unchecked Scalar Tests
//=============================================================================

pub(crate) fn unchecked_scalar_add_test<P, T>(param: P, mut executor: T)
where
    P: Into<TestParameters>,
    T: for<'a> FunctionExecutor<(&'a RadixCiphertext, u64), RadixCiphertext>,
{
    let param = param.into();
    let nb_tests = nb_tests_for_params(param);
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let sks = Arc::new(sks);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    let mut rng = rand::rng();

    // message_modulus^vec_length
    let modulus = cks.parameters().message_modulus().0.pow(NB_CTXT as u32);

    executor.setup(&cks, sks);

    for _ in 0..nb_tests {
        let clear_0 = rng.gen::<u64>() % modulus;
        let clear_1 = rng.gen::<u64>() % modulus;

        let ctxt_0 = cks.encrypt(clear_0);

        let encrypted_result = executor.execute((&ctxt_0, clear_1));
        let decrypted_result: u64 = cks.decrypt(&encrypted_result);

        let expected_result = clear_0.wrapping_add(clear_1) % modulus;
        assert_eq!(
            decrypted_result, expected_result,
            "Invalid add result, expected {clear_0} + {clear_1} \
            to be {expected_result}, but got {decrypted_result}."
        );
    }
}

pub(crate) fn unchecked_scalar_sub_test<P, T>(param: P, mut executor: T)
where
    P: Into<TestParameters>,
    T: for<'a> FunctionExecutor<(&'a RadixCiphertext, u64), RadixCiphertext>,
{
    let param = param.into();
    let nb_tests = nb_tests_for_params(param);
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let sks = Arc::new(sks);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    let mut rng = rand::rng();

    // message_modulus^vec_length
    let modulus = cks.parameters().message_modulus().0.pow(NB_CTXT as u32);

    executor.setup(&cks, sks);

    for _ in 0..nb_tests {
        let clear_0 = rng.gen::<u64>() % modulus;
        let clear_1 = rng.gen::<u64>() % modulus;

        let ctxt_0 = cks.encrypt(clear_0);

        let encrypted_result = executor.execute((&ctxt_0, clear_1));
        let decrypted_result: u64 = cks.decrypt(&encrypted_result);

        let expected_result = clear_0.wrapping_sub(clear_1) % modulus;
        assert_eq!(
            decrypted_result, expected_result,
            "Invalid sub result, expected {clear_0} - {clear_1} \
            to be {expected_result}, but got {decrypted_result}."
        );
    }
}
pub(crate) fn unchecked_scalar_mul_corner_cases_test<P, T>(param: P, mut executor: T)
where
    P: Into<TestParameters>,
    T: for<'a> FunctionExecutor<(&'a RadixCiphertext, u64), RadixCiphertext>,
{
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let sks = Arc::new(sks);
    let nb_ct =
        (128f64 / (cks.parameters().message_modulus().0 as f64).log2().ceil()).ceil() as usize;
    let cks = RadixClientKey::from((cks, nb_ct));

    executor.setup(&cks, sks.clone());

    // This example will not pass if the terms reduction is wrong
    // on the chunk size it uses to reduce the 'terms' resulting
    // from blockmuls
    {
        let clear = 307096569525960547621731375222677666984u128;
        let scalar = 5207034748027904122u64;

        let ct = cks.encrypt(clear);
        let ct_res = executor.execute((&ct, scalar));
        let dec_res: u128 = cks.decrypt(&ct_res);
        assert_eq!(clear.wrapping_mul(scalar as u128), dec_res);

        let clear = u128::MAX;
        let scalar = u64::MAX;

        let ct = cks.encrypt(clear);
        let ct_res = executor.execute((&ct, scalar));
        let dec_res: u128 = cks.decrypt(&ct_res);
        assert_eq!(clear.wrapping_mul(scalar as u128), dec_res);
    }

    // Trying to multiply a ciphertext with a scalar value
    // bigger than the ciphertext modulus should work
    {
        let cks: crate::integer::ClientKey = cks.into();
        let nb_ct =
            (8f64 / (cks.parameters().message_modulus().0 as f64).log2().ceil()).ceil() as usize;
        let cks = RadixClientKey::from((cks, nb_ct));

        executor.setup(&cks, sks);

        let clear = 123u64;
        let scalar = 17823812983255694336u64;
        assert_eq!(scalar % 256, 0);

        let ct = cks.encrypt(clear);
        let ct_res = executor.execute((&ct, scalar));
        let dec_res: u64 = cks.decrypt(&ct_res);
        assert_eq!(clear.wrapping_mul(scalar) % 256, dec_res);
    }
}

pub(crate) fn unchecked_scalar_left_shift_test<P, T>(param: P, mut executor: T)
where
    P: Into<TestParameters>,
    T: for<'a> FunctionExecutor<(&'a RadixCiphertext, u64), RadixCiphertext>,
{
    let param = param.into();
    let nb_tests = nb_tests_for_params(param);
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let sks = Arc::new(sks);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    let mut rng = rand::rng();

    // message_modulus^vec_length
    let modulus = cks.parameters().message_modulus().0.pow(NB_CTXT as u32);
    let nb_bits = modulus.ilog2();

    executor.setup(&cks, sks);

    for _ in 0..nb_tests {
        let clear = rng.gen::<u64>() % modulus;
        let scalar = rng.gen::<u32>();

        let ct = cks.encrypt(clear);

        // case when 0<= scalar < nb_bits
        {
            let scalar = scalar % nb_bits;
            let encrypted_result = executor.execute((&ct, scalar as u64));
            let decrypted_result: u64 = cks.decrypt(&encrypted_result);
            let expected = (clear << u64::from(scalar)) % modulus;
            assert_eq!(
                expected, decrypted_result,
                "Invalid left shift result for {clear} << {scalar}: \
                expected {expected}, got {decrypted_result}"
            );
        }

        // case when scalar >= nb_bits
        {
            let scalar = scalar.saturating_add(nb_bits);
            let encrypted_result = executor.execute((&ct, scalar as u64));
            let decrypted_result: u64 = cks.decrypt(&encrypted_result);
            let expected = (clear << u64::from(scalar % nb_bits)) % modulus;
            assert_eq!(
                expected, decrypted_result,
                "Invalid left shift result for {clear} << {scalar}: \
                expected {expected}, got {decrypted_result}"
            );
        }
    }

    let clear = rng.gen::<u64>() % modulus;
    let ct = cks.encrypt(clear);

    let nb_bits_in_block = cks.parameters().message_modulus().0.ilog2();
    for scalar in 0..nb_bits_in_block {
        let encrypted_result = executor.execute((&ct, scalar as u64));
        let decrypted_result: u64 = cks.decrypt(&encrypted_result);
        let expected = (clear << u64::from(scalar)) % modulus;
        assert_eq!(
            expected, decrypted_result,
            "Invalid left shift result for {clear} << {scalar}: \
            expected {expected}, got {decrypted_result}"
        );
    }
}

pub(crate) fn unchecked_scalar_right_shift_test<P, T>(param: P, mut executor: T)
where
    P: Into<TestParameters>,
    T: for<'a> FunctionExecutor<(&'a RadixCiphertext, u64), RadixCiphertext>,
{
    let param = param.into();
    let nb_tests = nb_tests_for_params(param);
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let sks = Arc::new(sks);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    let mut rng = rand::rng();

    // message_modulus^vec_length
    let modulus = cks.parameters().message_modulus().0.pow(NB_CTXT as u32);
    let nb_bits = modulus.ilog2();

    executor.setup(&cks, sks);

    for _ in 0..nb_tests {
        let clear = rng.gen::<u64>() % modulus;
        let scalar = rng.gen::<u32>();

        let ct = cks.encrypt(clear);

        // case when 0<= scalar < nb_bits
        {
            let scalar = scalar % nb_bits;
            let encrypted_result = executor.execute((&ct, scalar as u64));
            assert!(encrypted_result.block_carries_are_empty());
            let decrypted_result: u64 = cks.decrypt(&encrypted_result);
            let expected = clear >> u64::from(scalar);
            assert_eq!(
                expected, decrypted_result,
                "Invalid right shift result for {clear} >> {scalar}: \
                expected {expected}, got {decrypted_result}"
            );
        }

        // case when scalar >= nb_bits
        {
            let scalar = scalar.saturating_add(nb_bits);
            let encrypted_result = executor.execute((&ct, scalar as u64));
            assert!(encrypted_result.block_carries_are_empty());
            let decrypted_result: u64 = cks.decrypt(&encrypted_result);
            let expected = clear >> u64::from(scalar % nb_bits);
            assert_eq!(
                expected, decrypted_result,
                "Invalid right shift result for {clear} >> {scalar}: \
                expected {expected}, got {decrypted_result}"
            );
        }
    }

    let clear = rng.gen::<u64>() % modulus;

    let ct = cks.encrypt(clear);
    let nb_bits_in_block = cks.parameters().message_modulus().0.ilog2();
    for scalar in 0..nb_bits_in_block {
        let encrypted_result = executor.execute((&ct, scalar as u64));
        assert!(encrypted_result.block_carries_are_empty());
        let decrypted_result: u64 = cks.decrypt(&encrypted_result);
        let expected = clear >> u64::from(scalar);
        assert_eq!(
            expected, decrypted_result,
            "Invalid right shift result for {clear} >> {scalar}: \
            expected {expected}, got {decrypted_result}"
        );
    }
}

//=============================================================================
// Smart Tests
//=============================================================================

pub(crate) fn smart_mul_test<P, T>(param: P, mut executor: T)
where
    P: Into<TestParameters>,
    T: for<'a> FunctionExecutor<
        (&'a mut RadixCiphertext, &'a mut RadixCiphertext),
        RadixCiphertext,
    >,
{
    let param = param.into();
    let nb_tests_smaller = nb_tests_smaller_for_params(param);
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let sks = Arc::new(sks);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    let mut rng = rand::rng();

    // message_modulus^vec_length
    let modulus = cks.parameters().message_modulus().0.pow(NB_CTXT as u32);

    executor.setup(&cks, sks);

    for _ in 0..nb_tests_smaller {
        let clear1 = rng.gen::<u64>() % modulus;
        let clear2 = rng.gen::<u64>() % modulus;

        let ctxt_1 = cks.encrypt(clear1);
        let mut ctxt_2 = cks.encrypt(clear2);

        let mut res = ctxt_1.clone();
        let mut clear = clear1;

        res = executor.execute((&mut res, &mut ctxt_2));
        for _ in 0..nb_tests_smaller {
            res = executor.execute((&mut res, &mut ctxt_2));
            clear = (clear * clear2) % modulus;
        }
        let dec: u64 = cks.decrypt(&res);

        clear = (clear * clear2) % modulus;

        // Check the correctness
        assert_eq!(clear, dec);
    }
}

pub(crate) fn smart_block_mul_test<P, T>(param: P, mut executor: T)
where
    P: Into<TestParameters>,
    T: for<'a> FunctionExecutor<
        (
            &'a mut RadixCiphertext,
            &'a mut crate::shortint::Ciphertext,
            usize,
        ),
        RadixCiphertext,
    >,
{
    let param = param.into();
    let nb_tests_smaller = nb_tests_smaller_for_params(param);
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let sks = Arc::new(sks);
    let cks = RadixClientKey::from((cks, NB_CTXT));
    let mut rng = rand::rng();

    // message_modulus^vec_length
    let modulus = cks.parameters().message_modulus().0.pow(NB_CTXT as u32);

    let block_modulus = cks.parameters().message_modulus().0;

    executor.setup(&cks, sks);

    for _ in 0..nb_tests_smaller {
        // Define the cleartexts
        let clear1 = rng.gen::<u64>() % modulus;
        let clear2 = rng.gen::<u64>() % block_modulus;

        // Encrypt the integers
        let ctxt_1 = cks.encrypt(clear1);
        let mut ctxt_2 = cks.encrypt_one_block(clear2);

        let mut res = ctxt_1.clone();
        let mut clear = clear1;

        let index = rng.gen_range(0..=(NB_CTXT - 1) as u32);
        let multiplier = cks.parameters().message_modulus().0.pow(index) as u64;
        let index = index as usize;

        res = executor.execute((&mut res, &mut ctxt_2, index));
        clear = (clear.wrapping_mul(clear2.wrapping_mul(multiplier))) % modulus;

        for _ in 0..nb_tests_smaller {
            res = executor.execute((&mut res, &mut ctxt_2, index));
            clear = (clear.wrapping_mul(clear2.wrapping_mul(multiplier))) % modulus;
        }

        let dec: u64 = cks.decrypt(&res);
        assert_eq!(clear, dec);
    }
}

pub(crate) fn smart_bitand_test<P, T>(param: P, mut executor: T)
where
    P: Into<TestParameters>,
    T: for<'a> FunctionExecutor<
        (&'a mut RadixCiphertext, &'a mut RadixCiphertext),
        RadixCiphertext,
    >,
{
    let param = param.into();
    let nb_tests_smaller = nb_tests_smaller_for_params(param);
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let sks = Arc::new(sks);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    let mut rng = rand::rng();

    // message_modulus^vec_length
    let modulus = cks.parameters().message_modulus().0.pow(NB_CTXT as u32);

    executor.setup(&cks, sks);

    let mut clear;

    for _ in 0..nb_tests_smaller {
        let clear_0 = rng.gen::<u64>() % modulus;
        let clear_1 = rng.gen::<u64>() % modulus;

        let mut ctxt_0 = cks.encrypt(clear_0);
        let mut ctxt_1 = cks.encrypt(clear_1);

        let mut ct_res = executor.execute((&mut ctxt_0, &mut ctxt_1));

        clear = clear_0 & clear_1;

        for _ in 0..nb_tests_smaller {
            let clear_2 = rng.gen::<u64>() % modulus;

            let mut ctxt_2 = cks.encrypt(clear_2);

            ct_res = executor.execute((&mut ct_res, &mut ctxt_2));
            clear &= clear_2;

            let dec_res: u64 = cks.decrypt(&ct_res);
            assert_eq!(clear, dec_res);
        }
    }
}

pub(crate) fn smart_bitor_test<P, T>(param: P, mut executor: T)
where
    P: Into<TestParameters>,
    T: for<'a> FunctionExecutor<
        (&'a mut RadixCiphertext, &'a mut RadixCiphertext),
        RadixCiphertext,
    >,
{
    let param = param.into();
    let nb_tests_smaller = nb_tests_smaller_for_params(param);
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let sks = Arc::new(sks);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    let mut rng = rand::rng();

    // message_modulus^vec_length
    let modulus = cks.parameters().message_modulus().0.pow(NB_CTXT as u32);

    executor.setup(&cks, sks);

    let mut clear;

    for _ in 0..nb_tests_smaller {
        let clear_0 = rng.gen::<u64>() % modulus;
        let clear_1 = rng.gen::<u64>() % modulus;

        let mut ctxt_0 = cks.encrypt(clear_0);
        let mut ctxt_1 = cks.encrypt(clear_1);

        let mut ct_res = executor.execute((&mut ctxt_0, &mut ctxt_1));

        clear = (clear_0 | clear_1) % modulus;

        for _ in 0..nb_tests_smaller {
            let clear_2 = rng.gen::<u64>() % modulus;

            let mut ctxt_2 = cks.encrypt(clear_2);

            ct_res = executor.execute((&mut ct_res, &mut ctxt_2));
            clear = (clear | clear_2) % modulus;

            let dec_res: u64 = cks.decrypt(&ct_res);

            assert_eq!(clear, dec_res);
        }
    }
}

pub(crate) fn smart_bitxor_test<P, T>(param: P, mut executor: T)
where
    P: Into<TestParameters>,
    T: for<'a> FunctionExecutor<
        (&'a mut RadixCiphertext, &'a mut RadixCiphertext),
        RadixCiphertext,
    >,
{
    let param = param.into();
    let nb_tests_smaller = nb_tests_smaller_for_params(param);
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let sks = Arc::new(sks);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    let mut rng = rand::rng();

    // message_modulus^vec_length
    let modulus = cks.parameters().message_modulus().0.pow(NB_CTXT as u32);

    executor.setup(&cks, sks);

    let mut clear;

    for _ in 0..nb_tests_smaller {
        let clear_0 = rng.gen::<u64>() % modulus;
        let clear_1 = rng.gen::<u64>() % modulus;

        let mut ctxt_0 = cks.encrypt(clear_0);
        let mut ctxt_1 = cks.encrypt(clear_1);

        let mut ct_res = executor.execute((&mut ctxt_0, &mut ctxt_1));

        clear = (clear_0 ^ clear_1) % modulus;

        for _ in 0..nb_tests_smaller {
            let clear_2 = rng.gen::<u64>() % modulus;

            let mut ctxt_2 = cks.encrypt(clear_2);

            ct_res = executor.execute((&mut ct_res, &mut ctxt_2));
            clear = (clear ^ clear_2) % modulus;

            let dec_res: u64 = cks.decrypt(&ct_res);

            assert_eq!(clear, dec_res);
        }
    }
}

//=============================================================================
// Smart Scalar Tests
//=============================================================================

pub(crate) fn smart_scalar_add_test<P, T>(param: P, mut executor: T)
where
    P: Into<TestParameters>,
    T: for<'a> FunctionExecutor<(&'a mut RadixCiphertext, u64), RadixCiphertext>,
{
    let param = param.into();
    let nb_tests_smaller = nb_tests_smaller_for_params(param);
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let sks = Arc::new(sks);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    // message_modulus^vec_length
    let modulus = cks.parameters().message_modulus().0.pow(NB_CTXT as u32);

    let mut clear;

    let mut rng = rand::rng();

    executor.setup(&cks, sks);

    for _ in 0..nb_tests_smaller {
        let clear_0 = rng.gen::<u64>() % modulus;
        let clear_1 = rng.gen::<u64>() % modulus;

        let mut ctxt_0 = cks.encrypt(clear_0);

        let mut ct_res = executor.execute((&mut ctxt_0, clear_1));
        clear = (clear_0 + clear_1) % modulus;

        // Add multiple times to raise the degree
        for _ in 0..nb_tests_smaller {
            ct_res = executor.execute((&mut ct_res, clear_1));
            clear = (clear + clear_1) % modulus;

            let dec_res: u64 = cks.decrypt(&ct_res);

            assert_eq!(clear, dec_res);
        }
    }
}

pub(crate) fn smart_scalar_sub_test<P, T>(param: P, mut executor: T)
where
    P: Into<TestParameters>,
    T: for<'a> FunctionExecutor<(&'a mut RadixCiphertext, u64), RadixCiphertext>,
{
    let param = param.into();
    let nb_tests_smaller = nb_tests_smaller_for_params(param);
    // generate the server-client key set
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let sks = Arc::new(sks);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    // message_modulus^vec_length
    let modulus = cks.parameters().message_modulus().0.pow(NB_CTXT as u32);

    let mut clear;

    let mut rng = rand::rng();

    executor.setup(&cks, sks);

    for _ in 0..nb_tests_smaller {
        let clear_0 = rng.gen::<u64>() % modulus;
        let clear_1 = rng.gen::<u64>() % modulus;

        let mut ctxt_0 = cks.encrypt(clear_0);

        let mut ct_res = executor.execute((&mut ctxt_0, clear_1));
        clear = clear_0.wrapping_sub(clear_1) % modulus;

        // Sub multiple times to raise the degree
        for _ in 0..nb_tests_smaller {
            ct_res = executor.execute((&mut ct_res, clear_1));
            clear = clear.wrapping_sub(clear_1) % modulus;

            let dec_res: u64 = cks.decrypt(&ct_res);

            assert_eq!(clear, dec_res);
        }
    }
}

pub(crate) fn smart_scalar_mul_test<P, T>(param: P, mut executor: T)
where
    P: Into<TestParameters>,
    T: for<'a> FunctionExecutor<(&'a mut RadixCiphertext, u64), RadixCiphertext>,
{
    let param = param.into();
    let nb_tests = nb_tests_for_params(param);
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let sks = Arc::new(sks);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    let mut rng = rand::rng();

    // message_modulus^vec_length
    let modulus = cks.parameters().message_modulus().0.pow(NB_CTXT as u32);

    executor.setup(&cks, sks);

    for _ in 0..nb_tests {
        let clear = rng.gen::<u64>() % modulus;
        let scalar = rng.gen::<u64>() % modulus;

        let mut ct = cks.encrypt(clear);

        let ct_res = executor.execute((&mut ct, scalar));

        let dec_res: u64 = cks.decrypt(&ct_res);
        assert_eq!((clear * scalar) % modulus, dec_res);
    }
}

pub(crate) fn smart_scalar_mul_u128_fix_non_reg_test<P, T>(param: P, mut executor: T)
where
    P: Into<TestParameters>,
    T: for<'a> FunctionExecutor<(&'a mut RadixCiphertext, u64), RadixCiphertext>,
{
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let sks = Arc::new(sks);
    let nb_ct =
        (128f64 / (cks.parameters().message_modulus().0 as f64).log2().ceil()).ceil() as usize;
    let cks = RadixClientKey::from((cks, nb_ct));

    let mut rng = rand::rng();

    executor.setup(&cks, sks);

    let clear = rng.gen::<u128>();
    let scalar = rng.gen::<u64>();

    let mut ct = cks.encrypt(clear);

    let ct_res = executor.execute((&mut ct, scalar));

    let dec_res: u128 = cks.decrypt(&ct_res);
    assert_eq!(clear.wrapping_mul(scalar as u128), dec_res);
}

//=============================================================================
// Default Tests
//=============================================================================

pub(crate) fn default_mul_test<P, T>(param: P, mut executor: T)
where
    P: Into<TestParameters>,
    T: for<'a> FunctionExecutor<(&'a RadixCiphertext, &'a RadixCiphertext), RadixCiphertext>,
{
    let param = param.into();
    let nb_tests_smaller = nb_tests_smaller_for_params(param);
    let (cks, mut sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    sks.set_deterministic_pbs_execution(true);
    let sks = Arc::new(sks);

    let mut rng = rand::rng();

    // message_modulus^vec_length
    let modulus = cks.parameters().message_modulus().0.pow(NB_CTXT as u32);

    executor.setup(&cks, sks.clone());

    for _ in 0..nb_tests_smaller {
        let clear1 = rng.gen::<u64>() % modulus;
        let clear2 = rng.gen::<u64>() % modulus;

        let ctxt_1 = cks.encrypt(clear1);
        let ctxt_2 = cks.encrypt(clear2);

        let mut res = ctxt_1.clone();
        let mut clear = clear1;

        res = executor.execute((&res, &ctxt_2));
        assert!(res.block_carries_are_empty());
        for _ in 0..nb_tests_smaller {
            let tmp = executor.execute((&res, &ctxt_2));
            res = executor.execute((&res, &ctxt_2));
            assert!(res.block_carries_are_empty());
            assert_eq!(res, tmp);
            assert_eq!(res, tmp, "Failed determinism check, \n\n\n msg0: {clear1}, msg1: {clear2}, \n\n\nctxt0: {ctxt_1:?}, \n\n\nctxt1: {ctxt_2:?}\n\n\n");
            clear = (clear * clear2) % modulus;
        }
        let dec: u64 = cks.decrypt(&res);

        clear = (clear * clear2) % modulus;

        assert_eq!(clear, dec);
    }

    {
        // test x * y and y * x
        // where y encrypts a boolean value
        let clear1 = rng.gen::<u64>() % modulus;
        let clear2 = rng.gen_range(0u64..=1);

        let ctxt_1 = cks.encrypt(clear1);
        let ctxt_2: RadixCiphertext = sks.create_trivial_radix(clear2, ctxt_1.blocks.len());
        assert!(ctxt_2.holds_boolean_value());

        let res = executor.execute((&ctxt_1, &ctxt_2));
        let dec: u64 = cks.decrypt(&res);
        assert_eq!(dec, clear1 * clear2);

        let res = executor.execute((&ctxt_2, &ctxt_1));
        let dec: u64 = cks.decrypt(&res);
        assert_eq!(dec, clear1 * clear2);
    }
}

pub(crate) fn default_overflowing_mul_test<P, T>(param: P, mut executor: T)
where
    P: Into<TestParameters>,
    T: for<'a> FunctionExecutor<
        (&'a RadixCiphertext, &'a RadixCiphertext),
        (RadixCiphertext, BooleanBlock),
    >,
{
    let param = param.into();
    let nb_tests_smaller = nb_tests_smaller_for_params(param);
    let (cks, mut sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    sks.set_deterministic_pbs_execution(true);
    let sks = Arc::new(sks);

    let mut rng = rand::rng();

    // message_modulus^vec_length
    let modulus = cks.parameters().message_modulus().0.pow(NB_CTXT as u32);

    executor.setup(&cks, sks.clone());

    for _ in 0..nb_tests_smaller {
        let clear_0 = rng.gen::<u64>() % modulus;
        let clear_1 = rng.gen::<u64>() % modulus;

        let ctxt_0 = cks.encrypt(clear_0);
        let ctxt_1 = cks.encrypt(clear_1);

        let (ct_res, result_overflowed) = executor.execute((&ctxt_0, &ctxt_1));
        let (tmp_ct, tmp_o) = executor.execute((&ctxt_0, &ctxt_1));
        assert!(ct_res.block_carries_are_empty());
        assert_eq!(ct_res, tmp_ct, "Failed determinism check, \n\n\n msg0: {clear_0}, msg1: {clear_1}, \n\n\nctxt0: {ctxt_0:?}, \n\n\nctxt1: {ctxt_1:?}\n\n\n");
        assert_eq!(tmp_o, result_overflowed, "Failed determinism check, \n\n\n msg0: {clear_0}, msg1: {clear_1}, \n\n\nctxt0: {ctxt_0:?}, \n\n\nctxt1: {ctxt_1:?}\n\n\n");

        let (expected_result, expected_overflowed) =
            overflowing_mul_under_modulus(clear_0, clear_1, modulus);

        let decrypted_result: u64 = cks.decrypt(&ct_res);
        let decrypted_overflowed = cks.decrypt_bool(&result_overflowed);
        assert_eq!(
            decrypted_result, expected_result,
            "Invalid result for mul, for ({clear_0} * {clear_1}) % {modulus} \
                expected {expected_result}, got {decrypted_result}"
        );
        assert_eq!(
            decrypted_overflowed,
            expected_overflowed,
            "Invalid overflow flag result for overflowing_mul for ({clear_0} * {clear_1}) % {modulus}
            expected overflow flag {expected_overflowed}, got {decrypted_overflowed}"
        );
        assert_eq!(result_overflowed.0.degree.get(), 1);
        assert_eq!(result_overflowed.0.noise_level(), NoiseLevel::NOMINAL);

        for _ in 0..nb_tests_smaller {
            // Add non-zero scalar to have non-clean ciphertexts
            let clear_2 = random_non_zero_value(&mut rng, modulus);
            let clear_3 = random_non_zero_value(&mut rng, modulus);

            let ctxt_0 = sks.unchecked_scalar_add(&ctxt_0, clear_2);
            let ctxt_1 = sks.unchecked_scalar_add(&ctxt_1, clear_3);

            let clear_lhs = clear_0.wrapping_add(clear_2) % modulus;
            let clear_rhs = clear_1.wrapping_add(clear_3) % modulus;

            let d0: u64 = cks.decrypt(&ctxt_0);
            assert_eq!(d0, clear_lhs, "Failed sanity decryption check");
            let d1: u64 = cks.decrypt(&ctxt_1);
            assert_eq!(d1, clear_rhs, "Failed sanity decryption check");

            let (ct_res, result_overflowed) = executor.execute((&ctxt_0, &ctxt_1));
            assert!(ct_res.block_carries_are_empty());

            let (expected_result, expected_overflowed) =
                overflowing_mul_under_modulus(clear_lhs, clear_rhs, modulus);

            let decrypted_result: u64 = cks.decrypt(&ct_res);
            let decrypted_overflowed = cks.decrypt_bool(&result_overflowed);
            assert_eq!(
                decrypted_result, expected_result,
                "Invalid result for mul, for ({clear_lhs} * {clear_rhs}) % {modulus} \
                   expected {expected_result}, got {decrypted_result}"
            );
            assert_eq!(
                decrypted_overflowed,
                expected_overflowed,
                "Invalid overflow flag result for overflowing_mul, for ({clear_lhs} -{clear_rhs}) % {modulus}
                    expected overflow flag {expected_overflowed}, got {decrypted_overflowed}"
            );
            assert_eq!(result_overflowed.0.degree.get(), 1);
            assert_eq!(result_overflowed.0.noise_level(), NoiseLevel::NOMINAL);
        }
    }

    let values = [
        (rng.gen::<u64>() % modulus, rng.gen::<u64>() % modulus),
        (rng.gen::<u64>() % modulus, rng.gen::<u64>() % modulus),
        (rng.gen::<u64>() % modulus, rng.gen::<u64>() % modulus),
        (rng.gen::<u64>() % modulus, rng.gen::<u64>() % modulus),
        (rng.gen::<u64>() % modulus, 0),
        (0, rng.gen::<u64>() % modulus),
    ];
    for (clear_0, clear_1) in values {
        let a: RadixCiphertext = sks.create_trivial_radix(clear_0, NB_CTXT);
        let b: RadixCiphertext = sks.create_trivial_radix(clear_1, NB_CTXT);

        let (encrypted_result, encrypted_overflow) = executor.execute((&a, &b));

        let (expected_result, expected_overflowed) =
            overflowing_mul_under_modulus(clear_0, clear_1, modulus);

        let decrypted_result: u64 = cks.decrypt(&encrypted_result);
        let decrypted_overflowed = cks.decrypt_bool(&encrypted_overflow);
        assert_eq!(
            decrypted_result, expected_result,
            "Invalid result for mul, for ({clear_0} * {clear_1}) % {modulus} \
                expected {expected_result}, got {decrypted_result}"
        );
        assert_eq!(
            decrypted_overflowed,
            expected_overflowed,
            "Invalid overflow flag result for overflowing_mul, for ({clear_0}  {clear_1}) % {modulus} \
                expected overflow flag {expected_overflowed}, got {decrypted_overflowed}"
        );
        assert_eq!(encrypted_overflow.0.degree.get(), 1);
        assert_eq!(encrypted_overflow.0.noise_level(), NoiseLevel::ZERO);
    }
}

pub(crate) fn unchecked_bitnot_test<P, T>(param: P, mut executor: T)
where
    P: Into<TestParameters>,
    T: for<'a> FunctionExecutor<&'a RadixCiphertext, RadixCiphertext>,
{
    let param = param.into();
    let nb_tests = nb_tests_for_params(param);
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let cks = RadixClientKey::from((cks, NB_CTXT));
    let sks = Arc::new(sks);

    let mut rng = rand::rng();

    // message_modulus^vec_length
    let modulus = cks.parameters().message_modulus().0.pow(NB_CTXT as u32);

    executor.setup(&cks, sks);

    for _ in 0..nb_tests {
        let clear = rng.gen::<u64>() % modulus;

        let ctxt = cks.encrypt(clear);

        let ct_res = executor.execute(&ctxt);

        let dec: u64 = cks.decrypt(&ct_res);

        let clear_result = !clear % modulus;
        assert_eq!(clear_result, dec);
    }
}

pub(crate) fn unchecked_bitand_test<P, T>(param: P, mut executor: T)
where
    P: Into<TestParameters>,
    T: for<'a> FunctionExecutor<(&'a RadixCiphertext, &'a RadixCiphertext), RadixCiphertext>,
{
    let param = param.into();
    let nb_tests_smaller = nb_tests_smaller_for_params(param);
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let cks = RadixClientKey::from((cks, NB_CTXT));
    let sks = Arc::new(sks);

    let mut rng = rand::rng();

    // message_modulus^vec_length
    let modulus = cks.parameters().message_modulus().0.pow(NB_CTXT as u32);

    executor.setup(&cks, sks);

    let mut clear;
    for _ in 0..nb_tests_smaller {
        let clear_0 = rng.gen::<u64>() % modulus;
        let clear_1 = rng.gen::<u64>() % modulus;

        let ctxt_0 = cks.encrypt(clear_0);
        let ctxt_1 = cks.encrypt(clear_1);

        let mut ct_res = executor.execute((&ctxt_0, &ctxt_1));

        clear = clear_0 & clear_1;

        for _ in 0..nb_tests_smaller {
            let clear_2 = rng.gen::<u64>() % modulus;

            let ctxt_2 = cks.encrypt(clear_2);

            ct_res = executor.execute((&ct_res, &ctxt_2));
            clear &= clear_2;

            let dec_res: u64 = cks.decrypt(&ct_res);
            assert_eq!(clear, dec_res);
        }
    }
}

pub(crate) fn unchecked_bitor_test<P, T>(param: P, mut executor: T)
where
    P: Into<TestParameters>,
    T: for<'a> FunctionExecutor<(&'a RadixCiphertext, &'a RadixCiphertext), RadixCiphertext>,
{
    let param = param.into();
    let nb_tests_smaller = nb_tests_smaller_for_params(param);
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let cks = RadixClientKey::from((cks, NB_CTXT));
    let sks = Arc::new(sks);

    let mut rng = rand::rng();

    // message_modulus^vec_length
    let modulus = cks.parameters().message_modulus().0.pow(NB_CTXT as u32);

    executor.setup(&cks, sks);

    let mut clear;

    for _ in 0..nb_tests_smaller {
        let clear_0 = rng.gen::<u64>() % modulus;
        let clear_1 = rng.gen::<u64>() % modulus;

        let ctxt_0 = cks.encrypt(clear_0);
        let ctxt_1 = cks.encrypt(clear_1);

        let mut ct_res = executor.execute((&ctxt_0, &ctxt_1));

        clear = (clear_0 | clear_1) % modulus;

        for _ in 0..nb_tests_smaller {
            let clear_2 = rng.gen::<u64>() % modulus;
            let ctxt_2 = cks.encrypt(clear_2);
            ct_res = executor.execute((&ct_res, &ctxt_2));
            clear |= clear_2;

            let dec_res: u64 = cks.decrypt(&ct_res);
            assert_eq!(clear, dec_res);
        }
    }
}

pub(crate) fn unchecked_bitxor_test<P, T>(param: P, mut executor: T)
where
    P: Into<TestParameters>,
    T: for<'a> FunctionExecutor<(&'a RadixCiphertext, &'a RadixCiphertext), RadixCiphertext>,
{
    let param = param.into();
    let nb_tests_smaller = nb_tests_smaller_for_params(param);
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let cks = RadixClientKey::from((cks, NB_CTXT));
    let sks = Arc::new(sks);

    let mut rng = rand::rng();

    // message_modulus^vec_length
    let modulus = cks.parameters().message_modulus().0.pow(NB_CTXT as u32);

    executor.setup(&cks, sks);

    let mut clear;
    for _ in 0..nb_tests_smaller {
        let clear_0 = rng.gen::<u64>() % modulus;
        let clear_1 = rng.gen::<u64>() % modulus;

        let ctxt_0 = cks.encrypt(clear_0);
        let ctxt_1 = cks.encrypt(clear_1);
        let mut ct_res = executor.execute((&ctxt_0, &ctxt_1));

        clear = clear_0 ^ clear_1;

        for _ in 0..nb_tests_smaller {
            let clear_2 = rng.gen::<u64>() % modulus;

            let ctxt_2 = cks.encrypt(clear_2);

            ct_res = executor.execute((&ct_res, &ctxt_2));
            clear = (clear ^ clear_2) % modulus;

            let dec_res: u64 = cks.decrypt(&ct_res);
            assert_eq!(clear, dec_res);
        }
    }
}

pub(crate) fn default_bitand_test<P, T>(param: P, mut executor: T)
where
    P: Into<TestParameters>,
    T: for<'a> FunctionExecutor<(&'a RadixCiphertext, &'a RadixCiphertext), RadixCiphertext>,
{
    let param = param.into();
    let nb_tests_smaller = nb_tests_smaller_for_params(param);
    let (cks, mut sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    sks.set_deterministic_pbs_execution(true);
    let sks = Arc::new(sks);

    let mut rng = rand::rng();

    // message_modulus^vec_length
    let modulus = cks.parameters().message_modulus().0.pow(NB_CTXT as u32);

    executor.setup(&cks, sks);

    let mut clear;

    for _ in 0..nb_tests_smaller {
        let clear_0 = rng.gen::<u64>() % modulus;
        let clear_1 = rng.gen::<u64>() % modulus;

        let ctxt_0 = cks.encrypt(clear_0);
        let ctxt_1 = cks.encrypt(clear_1);

        let mut ct_res = executor.execute((&ctxt_0, &ctxt_1));
        assert!(ct_res.block_carries_are_empty());

        clear = clear_0 & clear_1;

        for _ in 0..nb_tests_smaller {
            let clear_2 = rng.gen::<u64>() % modulus;

            let ctxt_2 = cks.encrypt(clear_2);

            let tmp = executor.execute((&ct_res, &ctxt_2));
            ct_res = executor.execute((&ct_res, &ctxt_2));
            assert!(ct_res.block_carries_are_empty());
            assert_eq!(ct_res, tmp);
            clear &= clear_2;

            let dec_res: u64 = cks.decrypt(&ct_res);
            assert_eq!(clear, dec_res);
        }
    }
}

pub(crate) fn default_bitor_test<P, T>(param: P, mut executor: T)
where
    P: Into<TestParameters>,
    T: for<'a> FunctionExecutor<(&'a RadixCiphertext, &'a RadixCiphertext), RadixCiphertext>,
{
    let param = param.into();
    let nb_tests_smaller = nb_tests_smaller_for_params(param);
    let (cks, mut sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    sks.set_deterministic_pbs_execution(true);
    let sks = Arc::new(sks);

    let mut rng = rand::rng();

    // message_modulus^vec_length
    let modulus = cks.parameters().message_modulus().0.pow(NB_CTXT as u32);

    executor.setup(&cks, sks);

    let mut clear;

    for _ in 0..nb_tests_smaller {
        let clear_0 = rng.gen::<u64>() % modulus;
        let clear_1 = rng.gen::<u64>() % modulus;

        let ctxt_0 = cks.encrypt(clear_0);
        let ctxt_1 = cks.encrypt(clear_1);

        let mut ct_res = executor.execute((&ctxt_0, &ctxt_1));
        assert!(ct_res.block_carries_are_empty());

        clear = (clear_0 | clear_1) % modulus;

        for _ in 0..nb_tests_smaller {
            let clear_2 = rng.gen::<u64>() % modulus;

            let ctxt_2 = cks.encrypt(clear_2);

            let tmp = executor.execute((&ct_res, &ctxt_2));
            ct_res = executor.execute((&ct_res, &ctxt_2));
            assert!(ct_res.block_carries_are_empty());
            assert_eq!(ct_res, tmp);
            clear |= clear_2;

            let dec_res: u64 = cks.decrypt(&ct_res);
            assert_eq!(clear, dec_res);
        }
    }
}

pub(crate) fn default_bitxor_test<P, T>(param: P, mut executor: T)
where
    P: Into<TestParameters>,
    T: for<'a> FunctionExecutor<(&'a RadixCiphertext, &'a RadixCiphertext), RadixCiphertext>,
{
    let param = param.into();
    let nb_tests_smaller = nb_tests_smaller_for_params(param);
    let (cks, mut sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    sks.set_deterministic_pbs_execution(true);
    let sks = Arc::new(sks);

    let mut rng = rand::rng();

    // message_modulus^vec_length
    let modulus = cks.parameters().message_modulus().0.pow(NB_CTXT as u32);

    executor.setup(&cks, sks);

    let mut clear;

    for _ in 0..nb_tests_smaller {
        let clear_0 = rng.gen::<u64>() % modulus;
        let clear_1 = rng.gen::<u64>() % modulus;

        let ctxt_0 = cks.encrypt(clear_0);
        let ctxt_1 = cks.encrypt(clear_1);

        let mut ct_res = executor.execute((&ctxt_0, &ctxt_1));
        assert!(ct_res.block_carries_are_empty());

        clear = clear_0 ^ clear_1;

        for _ in 0..nb_tests_smaller {
            let clear_2 = rng.gen::<u64>() % modulus;

            let ctxt_2 = cks.encrypt(clear_2);

            let tmp = executor.execute((&ct_res, &ctxt_2));
            ct_res = executor.execute((&ct_res, &ctxt_2));
            assert!(ct_res.block_carries_are_empty());
            assert_eq!(ct_res, tmp);
            clear = (clear ^ clear_2) % modulus;

            let dec_res: u64 = cks.decrypt(&ct_res);
            assert_eq!(clear, dec_res);
        }
    }
}

pub(crate) fn default_bitnot_test<P, T>(param: P, mut executor: T)
where
    P: Into<TestParameters>,
    T: for<'a> FunctionExecutor<&'a RadixCiphertext, RadixCiphertext>,
{
    let param = param.into();
    let nb_tests = nb_tests_for_params(param);
    let (cks, mut sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    sks.set_deterministic_pbs_execution(true);
    let sks = Arc::new(sks);

    let mut rng = rand::rng();

    executor.setup(&cks, sks);

    // message_modulus^vec_length
    let modulus = cks.parameters().message_modulus().0.pow(NB_CTXT as u32);

    for _ in 0..nb_tests {
        let clear = rng.gen::<u64>() % modulus;

        let ctxt = cks.encrypt(clear);

        let tmp = executor.execute(&ctxt);
        let ct_res = executor.execute(&ctxt);
        assert!(ct_res.block_carries_are_empty());
        assert_eq!(ct_res, tmp);

        let dec: u64 = cks.decrypt(&ct_res);

        let clear_result = !clear % modulus;
        assert_eq!(clear_result, dec);
    }
}

//=============================================================================
// Default Scalar Tests
//=============================================================================

pub(crate) fn default_scalar_add_test<P, T>(param: P, mut executor: T)
where
    P: Into<TestParameters>,
    T: for<'a> FunctionExecutor<(&'a RadixCiphertext, u64), RadixCiphertext>,
{
    let param = param.into();
    let nb_tests_smaller = nb_tests_smaller_for_params(param);
    let (cks, mut sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    sks.set_deterministic_pbs_execution(true);
    let sks = Arc::new(sks);

    let mut rng = rand::rng();

    executor.setup(&cks, sks);

    let cks: crate::integer::ClientKey = cks.into();

    let mut clear;

    for num_blocks in 1..MAX_NB_CTXT {
        // message_modulus^vec_length
        let modulus = cks.parameters().message_modulus().0.pow(num_blocks as u32);

        for _ in 0..nb_tests_smaller {
            let clear_0 = rng.gen::<u64>() % modulus;
            let clear_1 = rng.gen::<u64>() % modulus;

            let ctxt_0 = cks.encrypt_radix(clear_0, num_blocks);

            let mut ct_res = executor.execute((&ctxt_0, clear_1));
            assert!(ct_res.block_carries_are_empty());

            clear = (clear_0 + clear_1) % modulus;

            let dec_res: u64 = cks.decrypt_radix(&ct_res);
            assert_eq!(
                clear, dec_res,
                "invalid result for ({clear_0} + {clear_1}) % {modulus} (num_blocks: {num_blocks})"
            );

            // Add multiple times to raise the degree
            for _ in 0..nb_tests_smaller {
                let tmp = executor.execute((&ct_res, clear_1));
                ct_res = executor.execute((&ct_res, clear_1));
                assert!(ct_res.block_carries_are_empty());
                assert_eq!(ct_res, tmp);
                clear = clear.wrapping_add(clear_1) % modulus;

                let dec_res: u64 = cks.decrypt_radix(&ct_res);
                assert_eq!(clear, dec_res);
            }
        }
    }
}

pub(crate) fn default_overflowing_scalar_add_test<P, T>(param: P, mut executor: T)
where
    P: Into<TestParameters>,
    T: for<'a> FunctionExecutor<(&'a RadixCiphertext, u64), (RadixCiphertext, BooleanBlock)>,
{
    let param = param.into();
    let nb_tests_smaller = nb_tests_smaller_for_params(param);
    let (cks, mut sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    sks.set_deterministic_pbs_execution(true);
    let sks = Arc::new(sks);

    let mut rng = rand::rng();

    executor.setup(&cks, sks.clone());

    let cks: crate::integer::ClientKey = cks.into();

    for num_blocks in 1..MAX_NB_CTXT {
        // message_modulus^vec_length
        let modulus = cks.parameters().message_modulus().0.pow(num_blocks as u32);

        for _ in 0..nb_tests_smaller {
            let clear_0 = rng.gen::<u64>() % modulus;
            let clear_1 = rng.gen::<u64>() % modulus;

            let ctxt_0 = cks.encrypt_radix(clear_0, num_blocks);

            let (ct_res, result_overflowed) = executor.execute((&ctxt_0, clear_1));
            let (tmp_ct, tmp_o) = executor.execute((&ctxt_0, clear_1));
            assert!(ct_res.block_carries_are_empty());
            assert_eq!(ct_res, tmp_ct, "Failed determinism check, \n\n\n msg0: {clear_0}, msg1: {clear_1}, \n\n\nctxt0: {ctxt_0:?}, \n\n\nclear1: {clear_1:?}\n\n\n");
            assert_eq!(tmp_o, result_overflowed, "Failed determinism check, \n\n\n msg0: {clear_0}, msg1: {clear_1}, \n\n\nctxt0: {ctxt_0:?}, \n\n\nclear1: {clear_1:?}\n\n\n");

            let (expected_result, expected_overflowed) =
                overflowing_add_under_modulus(clear_0, clear_1, modulus);

            let decrypted_result: u64 = cks.decrypt_radix(&ct_res);
            let decrypted_overflowed = cks.decrypt_bool(&result_overflowed);
            assert_eq!(
                decrypted_result, expected_result,
                "Invalid result for add, for ({clear_0} + {clear_1}) % {modulus} ({num_blocks} blocks) \
                expected {expected_result}, got {decrypted_result}"
            );
            assert_eq!(
                decrypted_overflowed,
                expected_overflowed,
                "Invalid overflow flag result for overflowing_add for ({clear_0} + {clear_1}) % {modulus} ({num_blocks} blocks) \
                expected overflow flag {expected_overflowed}, got {decrypted_overflowed}"
            );
            assert_eq!(result_overflowed.0.degree.get(), 1);
            assert_eq!(result_overflowed.0.noise_level(), NoiseLevel::NOMINAL);

            for _ in 0..nb_tests_smaller {
                // Add non zero scalar to have non clean ciphertexts
                let clear_2 = random_non_zero_value(&mut rng, modulus);
                let clear_rhs = random_non_zero_value(&mut rng, modulus);

                let ctxt_0 = sks.unchecked_scalar_add(&ctxt_0, clear_2);
                let (clear_lhs, _) = overflowing_add_under_modulus(clear_0, clear_2, modulus);
                let d0: u64 = cks.decrypt_radix(&ctxt_0);
                assert_eq!(d0, clear_lhs, "Failed sanity decryption check");

                let (ct_res, result_overflowed) = executor.execute((&ctxt_0, clear_rhs));
                assert!(ct_res.block_carries_are_empty());
                let (expected_result, expected_overflowed) =
                    overflowing_add_under_modulus(clear_lhs, clear_rhs, modulus);

                let decrypted_result: u64 = cks.decrypt_radix(&ct_res);
                let decrypted_overflowed = cks.decrypt_bool(&result_overflowed);
                assert_eq!(
                    decrypted_result, expected_result,
                    "Invalid result for add, for ({clear_lhs} + {clear_rhs}) % {modulus} ({num_blocks} blocks) \
                    expected {expected_result}, got {decrypted_result}"
                );
                assert_eq!(
                    decrypted_overflowed, expected_overflowed,
                    "Invalid overflow flag result for overflowing_add, \
                    for ({clear_lhs} + {clear_rhs}) % {modulus} ({num_blocks} blocks) \n\
                    expected overflow flag {expected_overflowed}, got {decrypted_overflowed}"
                );
                assert_eq!(result_overflowed.0.degree.get(), 1);
                assert_eq!(result_overflowed.0.noise_level(), NoiseLevel::NOMINAL);
            }
        }

        // Test with trivial inputs
        for _ in 0..4 {
            let clear_0 = rng.gen::<u64>() % modulus;
            let clear_1 = rng.gen::<u64>() % modulus;

            let a: RadixCiphertext = sks.create_trivial_radix(clear_0, num_blocks);

            let (encrypted_result, encrypted_overflow) = executor.execute((&a, clear_1));

            let (expected_result, expected_overflowed) =
                overflowing_add_under_modulus(clear_0, clear_1, modulus);

            let decrypted_result: u64 = cks.decrypt_radix(&encrypted_result);
            let decrypted_overflowed = cks.decrypt_bool(&encrypted_overflow);
            assert_eq!(
                decrypted_result, expected_result,
                "Invalid result for add, for ({clear_0} + {clear_1}) % {modulus} ({num_blocks} blocks) \
                expected {expected_result}, got {decrypted_result}"
            );
            assert_eq!(
                decrypted_overflowed, expected_overflowed,
                "Invalid overflow flag result for overflowing_add, \
                for ({clear_0} + {clear_1}) % {modulus} ({num_blocks} blocks) \n\
                expected overflow flag {expected_overflowed}, got {decrypted_overflowed}"
            );
            assert_eq!(encrypted_overflow.0.degree.get(), 1);
            #[cfg(not(feature = "gpu"))]
            assert_eq!(encrypted_overflow.0.noise_level(), NoiseLevel::ZERO);
        }

        // Test with scalar that is bigger than ciphertext modulus
        for _ in 0..2 {
            let clear_0 = rng.gen::<u64>() % modulus;
            let clear_1 = rng.gen_range(modulus..=u64::MAX);

            let a: RadixCiphertext = cks.encrypt_radix(clear_0, num_blocks);

            let (encrypted_result, encrypted_overflow) = executor.execute((&a, clear_1));

            let (expected_result, expected_overflowed) =
                overflowing_add_under_modulus(clear_0, clear_1, modulus);

            let decrypted_result: u64 = cks.decrypt_radix(&encrypted_result);
            let decrypted_overflowed = cks.decrypt_bool(&encrypted_overflow);
            assert_eq!(
                decrypted_result, expected_result,
                "Invalid result for add, for ({clear_0} + {clear_1}) % {modulus} ({num_blocks} blocks) \
                expected {expected_result}, got {decrypted_result}"
            );
            assert_eq!(
                decrypted_overflowed, expected_overflowed,
                "Invalid overflow flag result for overflowing_add, \
                for ({clear_0} + {clear_1}) % {modulus} ({num_blocks} blocks) \n\
                expected overflow flag {expected_overflowed}, got {decrypted_overflowed}"
            );
            assert!(decrypted_overflowed); // Actually we know its an overflow case
            assert_eq!(encrypted_overflow.0.degree.get(), 1);
            assert_eq!(encrypted_overflow.0.noise_level(), NoiseLevel::ZERO);
        }
    }
}

pub(crate) fn default_scalar_sub_test<P, T>(param: P, mut executor: T)
where
    P: Into<TestParameters>,
    T: for<'a> FunctionExecutor<(&'a RadixCiphertext, u64), RadixCiphertext>,
{
    let param = param.into();
    let nb_tests_smaller = nb_tests_smaller_for_params(param);
    let (cks, mut sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    sks.set_deterministic_pbs_execution(true);
    let sks = Arc::new(sks);

    let mut rng = rand::rng();

    executor.setup(&cks, sks);

    let cks: crate::integer::ClientKey = cks.into();

    let mut clear;

    for num_blocks in 1..MAX_NB_CTXT {
        // message_modulus^vec_length
        let modulus = cks.parameters().message_modulus().0.pow(num_blocks as u32);

        for _ in 0..nb_tests_smaller {
            let clear_0 = rng.gen::<u64>() % modulus;
            let clear_1 = rng.gen::<u64>() % modulus;

            let ctxt_0 = cks.encrypt_radix(clear_0, num_blocks);

            let mut ct_res = executor.execute((&ctxt_0, clear_1));
            assert!(ct_res.block_carries_are_empty());

            clear = (clear_0.wrapping_sub(clear_1)) % modulus;

            // Sub multiple times to raise the degree
            for _ in 0..nb_tests_smaller {
                let tmp = executor.execute((&ct_res, clear_1));
                ct_res = executor.execute((&ct_res, clear_1));
                assert!(ct_res.block_carries_are_empty());
                assert_eq!(ct_res, tmp);
                clear = (clear.wrapping_sub(clear_1)) % modulus;

                let dec_res: u64 = cks.decrypt_radix(&ct_res);
                assert_eq!(clear, dec_res);
            }
        }
    }
}

pub(crate) fn default_overflowing_scalar_sub_test<P, T>(param: P, mut executor: T)
where
    P: Into<TestParameters>,
    T: for<'a> FunctionExecutor<(&'a RadixCiphertext, u64), (RadixCiphertext, BooleanBlock)>,
{
    let param = param.into();
    let nb_tests_smaller = nb_tests_smaller_for_params(param);
    let (cks, mut sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    sks.set_deterministic_pbs_execution(true);
    let sks = Arc::new(sks);

    let mut rng = rand::rng();

    executor.setup(&cks, sks.clone());

    let cks: crate::integer::ClientKey = cks.into();

    for num_blocks in 1..MAX_NB_CTXT {
        // message_modulus^vec_length
        let modulus = cks.parameters().message_modulus().0.pow(num_blocks as u32);

        for _ in 0..nb_tests_smaller {
            let clear_0 = rng.gen::<u64>() % modulus;
            let clear_1 = rng.gen::<u64>() % modulus;

            let ctxt_0 = cks.encrypt_radix(clear_0, num_blocks);

            let (ct_res, result_overflowed) = executor.execute((&ctxt_0, clear_1));
            let (tmp_ct, tmp_o) = executor.execute((&ctxt_0, clear_1));
            assert!(ct_res.block_carries_are_empty());
            assert_eq!(ct_res, tmp_ct, "Failed determinism check, \n\n\n msg0: {clear_0}, msg1: {clear_1}, \n\n\nctxt0: {ctxt_0:?}, \n\n\nclear1: {clear_1:?}\n\n\n");
            assert_eq!(tmp_o, result_overflowed, "Failed determinism check, \n\n\n msg0: {clear_0}, msg1: {clear_1}, \n\n\nctxt0: {ctxt_0:?}, \n\n\nclear1: {clear_1:?}\n\n\n");

            let (expected_result, expected_overflowed) =
                overflowing_sub_under_modulus(clear_0, clear_1, modulus);

            let decrypted_result: u64 = cks.decrypt_radix(&ct_res);
            let decrypted_overflowed = cks.decrypt_bool(&result_overflowed);
            assert_eq!(
                decrypted_result, expected_result,
                "Invalid result for sub, for ({clear_0} - {clear_1}) % {modulus} \
             expected {expected_result}, got {decrypted_result}"
            );
            assert_eq!(
                decrypted_overflowed,
                expected_overflowed,
                "Invalid overflow flag result for overflowing_sub for ({clear_0} - {clear_1}) % {modulus} \
             expected overflow flag {expected_overflowed}, got {decrypted_overflowed}"
            );
            assert_eq!(result_overflowed.0.degree.get(), 1);
            assert_eq!(result_overflowed.0.noise_level(), NoiseLevel::NOMINAL);

            for _ in 0..nb_tests_smaller {
                // Add non zero scalar to have non clean ciphertexts
                let clear_2 = random_non_zero_value(&mut rng, modulus);
                let clear_rhs = random_non_zero_value(&mut rng, modulus);

                let ctxt_0 = sks.unchecked_scalar_add(&ctxt_0, clear_2);
                let (clear_lhs, _) = overflowing_add_under_modulus(clear_0, clear_2, modulus);
                let d0: u64 = cks.decrypt_radix(&ctxt_0);
                assert_eq!(d0, clear_lhs, "Failed sanity decryption check");

                let (ct_res, result_overflowed) = executor.execute((&ctxt_0, clear_rhs));
                assert!(ct_res.block_carries_are_empty());
                let (expected_result, expected_overflowed) =
                    overflowing_sub_under_modulus(clear_lhs, clear_rhs, modulus);

                let decrypted_result: u64 = cks.decrypt_radix(&ct_res);
                let decrypted_overflowed = cks.decrypt_bool(&result_overflowed);
                assert_eq!(
                    decrypted_result, expected_result,
                    "Invalid result for sub, for ({clear_lhs} + {clear_rhs}) % {modulus} \
                expected {expected_result}, got {decrypted_result}"
                );
                assert_eq!(
                    decrypted_overflowed,
                    expected_overflowed,
                    "Invalid overflow flag result for overflowing_sub, for ({clear_lhs} - {clear_rhs}) % {modulus} \
                expected overflow flag {expected_overflowed}, got {decrypted_overflowed}"
                );
                assert_eq!(result_overflowed.0.degree.get(), 1);
                assert_eq!(result_overflowed.0.noise_level(), NoiseLevel::NOMINAL);
            }
        }

        // Test with trivial inputs
        for _ in 0..4 {
            let clear_0 = rng.gen::<u64>() % modulus;
            let clear_1 = rng.gen::<u64>() % modulus;

            let a: RadixCiphertext = sks.create_trivial_radix(clear_0, num_blocks);

            let (encrypted_result, encrypted_overflow) = executor.execute((&a, clear_1));

            let (expected_result, expected_overflowed) =
                overflowing_sub_under_modulus(clear_0, clear_1, modulus);

            let decrypted_result: u64 = cks.decrypt_radix(&encrypted_result);
            let decrypted_overflowed = cks.decrypt_bool(&encrypted_overflow);
            assert_eq!(
                decrypted_result, expected_result,
                "Invalid result for add, for ({clear_0} - {clear_1}) % {modulus} \
                expected {expected_result}, got {decrypted_result}"
            );
            assert_eq!(
                decrypted_overflowed,
                expected_overflowed,
                "Invalid overflow flag result for overflowing_sub, for ({clear_0} - {clear_1}) % {modulus} \
                expected overflow flag {expected_overflowed}, got {decrypted_overflowed}"
            );
            assert_eq!(encrypted_overflow.0.degree.get(), 1);
            assert_eq!(encrypted_overflow.0.noise_level(), NoiseLevel::ZERO);
        }

        // Test with scalar that is bigger than ciphertext modulus
        for _ in 0..2 {
            let clear_0 = rng.gen::<u64>() % modulus;
            let clear_1 = rng.gen_range(modulus..=u64::MAX);

            let a: RadixCiphertext = cks.encrypt_radix(clear_0, num_blocks);

            let (encrypted_result, encrypted_overflow) = executor.execute((&a, clear_1));

            let (expected_result, expected_overflowed) =
                overflowing_sub_under_modulus(clear_0, clear_1, modulus);

            let decrypted_result: u64 = cks.decrypt_radix(&encrypted_result);
            let decrypted_overflowed = cks.decrypt_bool(&encrypted_overflow);
            assert_eq!(
                decrypted_result, expected_result,
                "Invalid result for sub, for ({clear_0} - {clear_1}) % {modulus} \
                expected {expected_result}, got {decrypted_result}"
            );
            assert_eq!(
                decrypted_overflowed,
                expected_overflowed,
                "Invalid overflow flag result for overflowing_sub, for ({clear_0} - {clear_1}) % {modulus} \
                expected overflow flag {expected_overflowed}, got {decrypted_overflowed}"
            );
            assert!(decrypted_overflowed); // Actually we know its an overflow case
            assert_eq!(encrypted_overflow.0.degree.get(), 1);
            assert_eq!(encrypted_overflow.0.noise_level(), NoiseLevel::ZERO);
        }
    }
}

pub(crate) fn default_scalar_mul_test<P, T>(param: P, mut executor: T)
where
    P: Into<TestParameters>,
    T: for<'a> FunctionExecutor<(&'a RadixCiphertext, u64), RadixCiphertext>,
{
    let param = param.into();
    let nb_tests_smaller = nb_tests_smaller_for_params(param);
    let (cks, mut sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    sks.set_deterministic_pbs_execution(true);
    let sks = Arc::new(sks);
    let mut rng = rand::rng();

    // message_modulus^vec_length
    let modulus = cks.parameters().message_modulus().0.pow(NB_CTXT as u32);

    executor.setup(&cks, sks);

    for _ in 0..nb_tests_smaller {
        let clear = rng.gen::<u64>() % modulus;
        let scalar = rng.gen::<u64>() % modulus;

        let ct = cks.encrypt(clear);

        // scalar mul
        let ct_res = executor.execute((&ct, scalar));
        let tmp = executor.execute((&ct, scalar));
        assert!(ct_res.block_carries_are_empty());
        assert_eq!(ct_res, tmp);

        let dec_res: u64 = cks.decrypt(&ct_res);
        assert_eq!((clear * scalar) % modulus, dec_res);
    }
}

pub(crate) fn default_default_block_mul_test<P, T>(param: P, mut executor: T)
where
    P: Into<TestParameters>,
    T: for<'a> FunctionExecutor<
        (&'a RadixCiphertext, &'a crate::shortint::Ciphertext, usize),
        RadixCiphertext,
    >,
{
    let param = param.into();
    let nb_tests_smaller = nb_tests_smaller_for_params(param);
    let (cks, mut sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    sks.set_deterministic_pbs_execution(true);
    let sks = Arc::new(sks);

    let mut rng = rand::rng();

    // message_modulus^vec_length
    let modulus = cks.parameters().message_modulus().0.pow(NB_CTXT as u32);

    let block_modulus = cks.parameters().message_modulus().0;

    executor.setup(&cks, sks);

    for _ in 0..nb_tests_smaller {
        // Define the cleartexts
        let clear1 = rng.gen::<u64>() % modulus;
        let clear2 = rng.gen::<u64>() % block_modulus;

        // Encrypt the integers
        let ctxt_1 = cks.encrypt(clear1);
        let ctxt_2 = cks.encrypt_one_block(clear2);

        let index = rng.gen_range(0..=(NB_CTXT - 1) as u32);
        let multiplier = cks.parameters().message_modulus().0.pow(index) as u64;
        let index = index as usize;

        let mut res = ctxt_1.clone();
        let mut clear = clear1;

        for _ in 0..nb_tests_smaller {
            let tmp = executor.execute((&res, &ctxt_2, index));
            res = executor.execute((&res, &ctxt_2, index));
            assert!(res.block_carries_are_empty());
            assert!(res
                .blocks
                .iter()
                .all(|b| b.noise_level() <= NoiseLevel::NOMINAL));
            assert_eq!(res, tmp);

            clear = clear.wrapping_mul(clear2.wrapping_mul(multiplier)) % modulus;
            let dec: u64 = cks.decrypt(&res);
            assert_eq!(clear, dec);
        }
    }
}

pub(crate) fn default_scalar_mul_u128_fix_non_reg_test<P, T>(param: P, mut executor: T)
where
    P: Into<TestParameters>,
    T: for<'a> FunctionExecutor<(&'a RadixCiphertext, u64), RadixCiphertext>,
{
    let (cks, mut sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let nb_ct =
        (128f64 / (cks.parameters().message_modulus().0 as f64).log2().ceil()).ceil() as usize;
    let cks = RadixClientKey::from((cks, nb_ct));
    sks.set_deterministic_pbs_execution(true);
    let sks = Arc::new(sks);

    executor.setup(&cks, sks);

    let mut rng = rand::rng();

    let clear = rng.gen::<u128>();
    let scalar = rng.gen::<u64>();

    let ct = cks.encrypt(clear);

    // scalar mul
    let ct_res = executor.execute((&ct, scalar));

    let dec_res: u128 = cks.decrypt(&ct_res);
    assert_eq!(
        clear.wrapping_mul(scalar as u128),
        dec_res,
        "Invalid result {clear} * {scalar}"
    );
}

pub(crate) fn default_scalar_bitand_test<P, T>(param: P, mut executor: T)
where
    P: Into<TestParameters>,
    T: for<'a> FunctionExecutor<(&'a RadixCiphertext, u64), RadixCiphertext>,
{
    let param = param.into();
    let nb_tests_smaller = nb_tests_smaller_for_params(param);
    let (cks, mut sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    sks.set_deterministic_pbs_execution(true);
    let sks = Arc::new(sks);

    let mut rng = rand::rng();

    // message_modulus^vec_length
    let modulus = cks.parameters().message_modulus().0.pow(NB_CTXT as u32);

    let mut clear;

    executor.setup(&cks, sks);

    for _ in 0..nb_tests_smaller {
        let clear_0 = rng.gen::<u64>() % modulus;
        let clear_1 = rng.gen::<u64>() % modulus;

        let ctxt_0 = cks.encrypt(clear_0);

        // Do with a small clear to check the way we avoid
        // unecesseray work is correct
        let ct_res = executor.execute((&ctxt_0, 1));
        let dec_res: u64 = cks.decrypt(&ct_res);
        assert_eq!(clear_0 & 1, dec_res);

        let mut ct_res = executor.execute((&ctxt_0, clear_1));
        assert!(ct_res.block_carries_are_empty());

        clear = clear_0 & clear_1;

        for _ in 0..nb_tests_smaller {
            let clear_2 = rng.gen::<u64>() % modulus;

            let tmp = executor.execute((&ct_res, clear_2));
            ct_res = executor.execute((&ct_res, clear_2));
            assert!(ct_res.block_carries_are_empty());
            assert_eq!(ct_res, tmp);
            clear &= clear_2;

            let dec_res: u64 = cks.decrypt(&ct_res);
            assert_eq!(clear, dec_res);
        }
    }
}

pub(crate) fn default_scalar_bitor_test<P, T>(param: P, mut executor: T)
where
    P: Into<TestParameters>,
    T: for<'a> FunctionExecutor<(&'a RadixCiphertext, u64), RadixCiphertext>,
{
    let param = param.into();
    let nb_tests_smaller = nb_tests_smaller_for_params(param);
    let (cks, mut sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    sks.set_deterministic_pbs_execution(true);
    let sks = Arc::new(sks);

    let mut rng = rand::rng();

    // message_modulus^vec_length
    let modulus = cks.parameters().message_modulus().0.pow(NB_CTXT as u32);

    let mut clear;

    executor.setup(&cks, sks);

    for _ in 0..nb_tests_smaller {
        let clear_0 = rng.gen::<u64>() % modulus;
        let clear_1 = rng.gen::<u64>() % modulus;

        let ctxt_0 = cks.encrypt(clear_0);

        // Do with a small clear to check the way we avoid
        // unecesseray work is correct
        let ct_res = executor.execute((&ctxt_0, 1));
        let dec_res: u64 = cks.decrypt(&ct_res);
        assert_eq!(clear_0 | 1, dec_res);

        let mut ct_res = executor.execute((&ctxt_0, clear_1));
        assert!(ct_res.block_carries_are_empty());
        clear = (clear_0 | clear_1) % modulus;

        for _ in 0..nb_tests_smaller {
            let clear_2 = rng.gen::<u64>() % modulus;

            let tmp = executor.execute((&ct_res, clear_2));
            ct_res = executor.execute((&ct_res, clear_2));
            assert!(ct_res.block_carries_are_empty());
            assert_eq!(ct_res, tmp);
            clear = (clear | clear_2) % modulus;

            let dec_res: u64 = cks.decrypt(&ct_res);
            assert_eq!(clear, dec_res);
        }
    }
}

pub(crate) fn default_scalar_bitxor_test<P, T>(param: P, mut executor: T)
where
    P: Into<TestParameters>,
    T: for<'a> FunctionExecutor<(&'a RadixCiphertext, u64), RadixCiphertext>,
{
    let param = param.into();
    let nb_tests_smaller = nb_tests_smaller_for_params(param);
    let (cks, mut sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    sks.set_deterministic_pbs_execution(true);
    let sks = Arc::new(sks);

    let mut rng = rand::rng();

    // message_modulus^vec_length
    let modulus = cks.parameters().message_modulus().0.pow(NB_CTXT as u32);

    let mut clear;

    executor.setup(&cks, sks);

    for _ in 0..nb_tests_smaller {
        let clear_0 = rng.gen::<u64>() % modulus;
        let clear_1 = rng.gen::<u64>() % modulus;

        let ctxt_0 = cks.encrypt(clear_0);

        // Do with a small clear to check the way we avoid
        // unnecessary work is correct
        let ct_res = executor.execute((&ctxt_0, 1));
        let dec_res: u64 = cks.decrypt(&ct_res);
        assert_eq!(clear_0 ^ 1, dec_res);

        let mut ct_res = executor.execute((&ctxt_0, clear_1));
        assert!(ct_res.block_carries_are_empty());
        clear = (clear_0 ^ clear_1) % modulus;

        for _ in 0..nb_tests_smaller {
            let clear_2 = rng.gen::<u64>() % modulus;

            let tmp = executor.execute((&ct_res, clear_2));
            ct_res = executor.execute((&ct_res, clear_2));
            assert!(ct_res.block_carries_are_empty());
            assert_eq!(ct_res, tmp);
            clear = (clear ^ clear_2) % modulus;

            let dec_res: u64 = cks.decrypt(&ct_res);
            assert_eq!(clear, dec_res);
        }
    }
}

pub(crate) fn default_scalar_left_shift_test<P, T>(param: P, mut executor: T)
where
    P: Into<TestParameters>,
    T: for<'a> FunctionExecutor<(&'a RadixCiphertext, u64), RadixCiphertext>,
{
    let param = param.into();
    let nb_tests = nb_tests_for_params(param);
    let (cks, mut sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    sks.set_deterministic_pbs_execution(true);
    let sks = Arc::new(sks);

    let mut rng = rand::rng();

    let modulus = cks.parameters().message_modulus().0.pow(NB_CTXT as u32);
    let nb_bits = modulus.ilog2();

    executor.setup(&cks, sks);

    for _ in 0..nb_tests {
        let clear = rng.gen::<u64>() % modulus;
        let scalar = rng.gen::<u32>();

        let ct = cks.encrypt(clear);

        // case when 0<= scalar < nb_bits
        {
            let scalar = scalar % nb_bits;
            let ct_res = executor.execute((&ct, scalar as u64));
            let tmp = executor.execute((&ct, scalar as u64));
            assert!(ct_res.block_carries_are_empty());
            assert_eq!(ct_res, tmp);
            let dec_res: u64 = cks.decrypt(&ct_res);
            assert_eq!(clear.checked_shl(scalar).unwrap_or(0) % modulus, dec_res);
        }

        // case when scalar >= nb_bits
        {
            let scalar = scalar.saturating_add(nb_bits);
            let ct_res = executor.execute((&ct, scalar as u64));
            let tmp = executor.execute((&ct, scalar as u64));
            assert!(ct_res.block_carries_are_empty());
            assert_eq!(ct_res, tmp);
            let dec_res: u64 = cks.decrypt(&ct_res);
            assert_eq!(clear.wrapping_shl(scalar % nb_bits) % modulus, dec_res);
        }
    }

    let clear = rng.gen::<u64>() % modulus;
    let ct = cks.encrypt(clear);

    let nb_bits_in_block = cks.parameters().message_modulus().0.ilog2();
    for scalar in 0..nb_bits_in_block {
        let ct_res = executor.execute((&ct, scalar as u64));
        let dec_res: u64 = cks.decrypt(&ct_res);
        assert_eq!(clear.wrapping_shl(scalar % nb_bits) % modulus, dec_res);
    }
}

pub(crate) fn default_scalar_right_shift_test<P, T>(param: P, mut executor: T)
where
    P: Into<TestParameters>,
    T: for<'a> FunctionExecutor<(&'a RadixCiphertext, u64), RadixCiphertext>,
{
    let param = param.into();
    let nb_tests_smaller = nb_tests_smaller_for_params(param);
    let (cks, mut sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    sks.set_deterministic_pbs_execution(true);
    let sks = Arc::new(sks);

    let mut rng = rand::rng();

    executor.setup(&cks, sks);

    // message_modulus^vec_length
    let modulus = cks.parameters().message_modulus().0.pow(NB_CTXT as u32);
    let nb_bits = modulus.ilog2();

    for _ in 0..nb_tests_smaller {
        let clear = rng.gen::<u64>() % modulus;
        let scalar = rng.gen::<u32>();

        let ct = cks.encrypt(clear);

        // case when 0<= scalar < nb_bits
        {
            let scalar = scalar % nb_bits;
            let ct_res = executor.execute((&ct, scalar as u64));
            let tmp = executor.execute((&ct, scalar as u64));
            assert!(ct_res.block_carries_are_empty());
            assert_eq!(ct_res, tmp);
            let dec_res: u64 = cks.decrypt(&ct_res);
            assert_eq!(clear.wrapping_shr(scalar) % modulus, dec_res);
        }

        // case when scalar >= nb_bits
        {
            let scalar = scalar.saturating_add(nb_bits);
            let ct_res = executor.execute((&ct, scalar as u64));
            let tmp = executor.execute((&ct, scalar as u64));
            assert!(ct_res.block_carries_are_empty());
            assert_eq!(ct_res, tmp);
            let dec_res: u64 = cks.decrypt(&ct_res);
            assert_eq!(clear.wrapping_shr(scalar % nb_bits) % modulus, dec_res);
        }
    }

    let clear = rng.gen::<u64>() % modulus;

    let ct = cks.encrypt(clear);
    let nb_bits_in_block = cks.parameters().message_modulus().0.ilog2();
    for scalar in 0..nb_bits_in_block {
        let ct_res = executor.execute((&ct, scalar as u64));
        let tmp = executor.execute((&ct, scalar as u64));
        assert!(ct_res.block_carries_are_empty());
        assert_eq!(ct_res, tmp);
        let dec_res: u64 = cks.decrypt(&ct_res);
        assert_eq!(clear.wrapping_shr(scalar) % modulus, dec_res);
    }
}

pub(crate) fn full_propagate_test<P, T>(param: P, mut executor: T)
where
    P: Into<TestParameters>,
    T: for<'a> FunctionExecutor<&'a mut RadixCiphertext, ()>,
{
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let sks = Arc::new(sks);

    // We need at least 4 blocks to perform this test.
    let nb_ctxt = 4.max(NB_CTXT);

    let cks = RadixClientKey::from((cks, nb_ctxt));

    // message_modulus^vec_length
    let modulus = cks.parameters().message_modulus().0.pow(nb_ctxt as u32);

    executor.setup(&cks, sks.clone());

    let block_msg_mod = cks.parameters().message_modulus().0;
    let block_carry_mod = cks.parameters().carry_modulus().0;
    let block_total_mod = block_carry_mod * block_msg_mod;

    let clear_max_value = modulus - 1;
    for msg in 1..block_msg_mod {
        // Here we just create a block, encrypting the max message,
        // which means its carries are empty, and test that adding
        // something to the first block, correctly propagates

        // The first block has value block_msg_mod - 1
        // and we will add to it a message in range [1..msg_mod-1]
        // We still have to make sure, it won't exceed the block space
        // (which for param_message_X_carry_X is wont)
        if (block_msg_mod - 1) + msg >= block_total_mod {
            continue;
        }

        let max_value = cks.encrypt(clear_max_value);
        let rhs = cks.encrypt(msg);

        let mut ct = sks.unchecked_add(&max_value, &rhs);

        // Manually check that each shortint block of the input
        // corresponds to what we want.
        let shortint_cks = &cks.as_ref().key;
        let first_block = shortint_cks.decrypt_message_and_carry(&ct.blocks[0]);
        let first_block_msg = first_block % block_msg_mod;
        let first_block_carry = first_block / block_msg_mod;
        assert_eq!(first_block_msg, (block_msg_mod - 1 + msg) % block_msg_mod);
        assert_eq!(first_block_carry, msg.div_ceil(block_msg_mod));
        for b in &ct.blocks[1..] {
            let block = shortint_cks.decrypt_message_and_carry(b);
            let msg = block % block_msg_mod;
            let carry = block / block_msg_mod;
            assert_eq!(msg, block_msg_mod - 1);
            assert_eq!(carry, 0);
        }

        executor.execute(&mut ct);
        let decrypted_result: u64 = cks.decrypt(&ct);
        let expected_result = clear_max_value.wrapping_add(msg) % modulus;
        assert_eq!(
            decrypted_result, expected_result,
            "Invalid full propagation result, gave ct = {clear_max_value} + {msg}, \
            after propagation expected {expected_result}, got {decrypted_result}"
        );
        assert!(
            ct.blocks
                .iter()
                .all(|b| b.degree.get() == block_msg_mod - 1),
            "Invalid degree after propagation"
        );
        assert!(
            ct.blocks
                .iter()
                .all(|b| b.noise_level() <= NoiseLevel::NOMINAL),
            "Invalid noise_level after propagation"
        );

        // Manually check each shortint block of the output
        let shortint_cks = &cks.as_ref().key;
        assert_eq!(
            shortint_cks.decrypt_message_and_carry(&ct.blocks[0]),
            (block_msg_mod - 1 + msg) % block_msg_mod
        );
        for b in &ct.blocks[1..] {
            assert_eq!(shortint_cks.decrypt_message_and_carry(b), 0);
        }
    }

    if block_carry_mod >= block_msg_mod {
        // This test is easier to write with this assumption
        // which, conveniently is true for our radix type
        //
        // In this test, we are creating a ciphertext which is at full capacity
        // with just enough room that allows sequential (non-parallel)
        // propagation to work

        let mut expected_result = clear_max_value;

        let msg = cks.encrypt(clear_max_value);
        let mut ct = cks.encrypt(clear_max_value);
        while sks.is_add_possible(&ct, &msg).is_ok() {
            sks.unchecked_add_assign(&mut ct, &msg);
            expected_result = expected_result.wrapping_add(clear_max_value) % modulus;
        }
        let max_degree_that_can_absorb_carry = (block_total_mod - 1) - (block_carry_mod - 1);
        assert!(ct
            .blocks
            .iter()
            .all(|b| { b.degree.get() <= max_degree_that_can_absorb_carry }),);

        // All but the first blocks are full,
        // So we do one more unchecked add on the first block to make it full
        sks.is_scalar_add_possible(&ct, block_msg_mod - 1).unwrap();
        sks.unchecked_scalar_add_assign(&mut ct, block_msg_mod - 1);
        assert_eq!(
            { ct.blocks[0].degree.get() },
            max_degree_that_can_absorb_carry + (block_msg_mod - 1)
        );
        expected_result = expected_result.wrapping_add(block_msg_mod - 1) % modulus;

        // Do the propagation
        executor.execute(&mut ct);

        // Quick check on the result
        let decrypted_result: u64 = cks.decrypt(&ct);
        assert_eq!(
            decrypted_result, expected_result,
            "Invalid full propagation result, expected {expected_result}, got {decrypted_result}"
        );
        assert!(
            ct.blocks
                .iter()
                .all(|b| b.degree.get() == block_msg_mod - 1),
            "Invalid degree after propagation"
        );
        assert!(
            ct.blocks
                .iter()
                .all(|b| b.noise_level() <= NoiseLevel::NOMINAL),
            "Invalid noise_level after propagation"
        );

        // Manually check each shortint block of the output
        let expected_block_iter = BlockDecomposer::new(expected_result, block_msg_mod.ilog2())
            .iter_as::<u64>()
            .take(cks.num_blocks());
        let shortint_cks = &cks.as_ref().key;
        for (block, expected_msg) in ct.blocks.iter().zip(expected_block_iter) {
            let block = shortint_cks.decrypt_message_and_carry(block);
            let msg = block % block_msg_mod;
            let carry = block / block_msg_mod;

            assert_eq!(msg, expected_msg);
            assert_eq!(carry, 0);
        }
    }

    {
        // This test is written with these assumptions in mind
        // they should hold true
        assert!(cks.num_blocks() >= 4);
        assert!(block_msg_mod.is_power_of_two());

        // The absorber block will be set to 0
        // All other blocks are max block msg
        // The absorber block will 'absorb' carry propagation
        let absorber_block_index = 2;

        let mut ct = cks.encrypt(clear_max_value);
        ct.blocks[absorber_block_index] = cks.encrypt_one_block(0); // use cks to have noise

        let block_mask = block_msg_mod - 1;
        let num_bits_in_msg = block_msg_mod.ilog2();
        // Its 00..11..00 (only bits of the absorber block set to 1
        let absorber_block_mask = block_mask << (absorber_block_index as u32 * num_bits_in_msg);
        let mask = u64::MAX ^ absorber_block_mask;
        // Initial value has all its bits set to one (bits that are in modulus)
        // except for the bits in the absorber block which are 0s
        let initial_value = clear_max_value & mask;

        let to_add = cks.encrypt(block_msg_mod - 1);
        sks.unchecked_add_assign(&mut ct, &to_add);
        let expected_result = initial_value.wrapping_add(block_msg_mod - 1) % modulus;

        // Manual check on the input blocks
        let shortint_cks = &cks.as_ref().key;
        let mut expected_blocks = vec![block_msg_mod - 1; cks.num_blocks()];
        expected_blocks[0] += block_msg_mod - 1;
        expected_blocks[absorber_block_index] = 0;

        for (block, expected_block) in ct.blocks.iter().zip(expected_blocks) {
            let block = shortint_cks.decrypt_message_and_carry(block);
            let msg = block % block_msg_mod;
            let carry = block / block_msg_mod;

            let expected_msg = expected_block % block_msg_mod;
            let expected_carry = expected_block / block_msg_mod;

            assert_eq!(msg, expected_msg);
            assert_eq!(carry, expected_carry);
        }

        // Do the propagation
        executor.execute(&mut ct);

        // Quick checks on the result
        let decrypted_result: u64 = cks.decrypt(&ct);
        assert_eq!(
            decrypted_result, expected_result,
            "Invalid full propagation result, expected {expected_result}, got {decrypted_result}"
        );
        assert!(
            ct.blocks
                .iter()
                .all(|b| b.degree.get() == block_msg_mod - 1),
            "Invalid degree after propagation"
        );
        assert!(
            ct.blocks
                .iter()
                .all(|b| b.noise_level() <= NoiseLevel::NOMINAL),
            "Invalid noise_level after propagation"
        );

        // Take the initial value, but remove any bits below absober block
        // as the bits below will have changed, but bits above will not.
        let mut expected_built_by_hand =
            initial_value & (u64::MAX << ((absorber_block_index + 1) as u32 * num_bits_in_msg));
        // The first block generated a carry,
        // but also results in a non zero block.
        //
        // The carry gets propagated by other blocks
        // until it hits the absorber block, which takes the value of the carry
        // (1) as its new value. Blocks that propagated the carry will have as new value
        // 0 as for these block we did: ((block_msg_mod - 1  + 1) % block_msg_modulus) == 0
        // and carry = ((block_msg_mod - 1  + 1) / block_msg_modulus) == 1
        //
        // Set the value of first block
        expected_built_by_hand |= (2 * (block_msg_mod - 1)) % block_msg_mod;
        // Set the value of the absorbed block
        expected_built_by_hand |= 1 << (absorber_block_index as u32 * num_bits_in_msg);
        assert_eq!(expected_result, expected_built_by_hand);

        // Manually check each shortint block of the output
        let expected_block_iter =
            BlockDecomposer::new(expected_built_by_hand, block_msg_mod.ilog2())
                .iter_as::<u64>()
                .take(cks.num_blocks());
        let shortint_cks = &cks.as_ref().key;
        for (block, expected_msg) in ct.blocks.iter().zip(expected_block_iter) {
            let block = shortint_cks.decrypt_message_and_carry(block);
            let msg = block % block_msg_mod;
            let carry = block / block_msg_mod;

            assert_eq!(msg, expected_msg);
            assert_eq!(carry, 0);
        }
    }
    {
        // Here, we want to ensure at the end of full propagate
        // all the blocks are clean, that is, noise_level == NOMINAL && degree = msg_mod -1

        let block_max_value = block_msg_mod - 1;
        let blocks = vec![
            cks.encrypt_one_block(block_max_value),
            cks.encrypt_one_block(block_max_value),
            cks.encrypt_one_block(block_max_value),
            cks.encrypt_one_block(block_max_value),
        ];

        let mut ct = RadixCiphertext::from(blocks);
        // Check we crafted what we want
        for block in &ct.blocks {
            assert_eq!(
                block.noise_degree(),
                CiphertextNoiseDegree::new(NoiseLevel::NOMINAL, Degree::new(block_max_value))
            );
        }

        // For the noise level to be not zero, but non of the blocks have carries
        for block in &mut ct.blocks {
            block.set_noise_level(NoiseLevel::NOMINAL * 2, sks.key.max_noise_level);
        }

        executor.execute(&mut ct);
        // For the ct we crafted, the full_propagate implementation may not do the carry propagation
        // But we still expect it to clean the noise
        let clean_noise_degree =
            CiphertextNoiseDegree::new(NoiseLevel::NOMINAL, Degree::new(block_max_value));
        assert_eq!(ct.blocks[0].noise_degree(), clean_noise_degree);
        assert_eq!(ct.blocks[1].noise_degree(), clean_noise_degree);
        assert_eq!(ct.blocks[2].noise_degree(), clean_noise_degree);
        assert_eq!(ct.blocks[3].noise_degree(), clean_noise_degree);
    }
    {
        // Also here, we want to ensure at the end of full propagate
        // all the blocks are clean, that is, noise_level == NOMINAL && degree = msg_mod -1
        // as the full_propagate may skip blocks until there is one that actually has a carry

        let block_max_value = block_msg_mod - 1;
        let blocks = vec![
            cks.encrypt_bool(true).0,
            cks.encrypt_bool(true).0,
            cks.encrypt_one_block(block_max_value),
            cks.encrypt_one_block(block_max_value),
        ];

        let mut ct = RadixCiphertext::from(blocks);
        // Check we crafted what we want
        assert_eq!(
            ct.blocks[0].noise_degree(),
            CiphertextNoiseDegree::new(NoiseLevel::NOMINAL, Degree::new(1))
        );
        assert_eq!(
            ct.blocks[1].noise_degree(),
            CiphertextNoiseDegree::new(NoiseLevel::NOMINAL, Degree::new(1))
        );
        assert_eq!(
            ct.blocks[2].noise_degree(),
            CiphertextNoiseDegree::new(NoiseLevel::NOMINAL, Degree::new(block_max_value))
        );
        assert_eq!(
            ct.blocks[3].noise_degree(),
            CiphertextNoiseDegree::new(NoiseLevel::NOMINAL, Degree::new(block_max_value))
        );
        let ct_cloned = ct.clone();
        // We want to add such that the first two blocks have a degree that indicates no carry,
        // but we also want to make sure doing that won't cause overflow in other blocks and/or
        // go beyond max noise level
        let num_ct_to_sum = block_max_value
            .min((block_total_mod - 1) / block_max_value)
            .min(sks.key.max_noise_level.get());
        let num_add = num_ct_to_sum - 1;
        for _ in 0..num_add {
            sks.unchecked_add_assign(&mut ct, &ct_cloned);
        }
        // Check we crafted what we want
        assert_eq!(
            ct.blocks[0].noise_degree(),
            CiphertextNoiseDegree::new(
                NoiseLevel::NOMINAL * num_ct_to_sum,
                Degree::new(num_ct_to_sum)
            )
        );
        assert_eq!(
            ct.blocks[1].noise_degree(),
            CiphertextNoiseDegree::new(
                NoiseLevel::NOMINAL * num_ct_to_sum,
                Degree::new(num_ct_to_sum)
            )
        );
        assert_eq!(
            ct.blocks[2].noise_degree(),
            CiphertextNoiseDegree::new(
                NoiseLevel::NOMINAL * num_ct_to_sum,
                Degree::new(block_max_value * num_ct_to_sum)
            )
        );
        assert_eq!(
            ct.blocks[3].noise_degree(),
            CiphertextNoiseDegree::new(
                NoiseLevel::NOMINAL * num_ct_to_sum,
                Degree::new(block_max_value * num_ct_to_sum)
            )
        );

        executor.execute(&mut ct);
        // For the ct we crafted, the full_propagate implementation may not start propagating
        // from blocks index 0, since it does not have carries.
        // If the implementation does skip blocks, then we still expect it to clean the noise of
        // preceding blocks Check we crafted what we want
        let clean_noise_degree =
            CiphertextNoiseDegree::new(NoiseLevel::NOMINAL, Degree::new(block_max_value));
        assert_eq!(ct.blocks[0].noise_degree(), clean_noise_degree);
        assert_eq!(ct.blocks[1].noise_degree(), clean_noise_degree);
        assert_eq!(ct.blocks[2].noise_degree(), clean_noise_degree);
        assert_eq!(ct.blocks[3].noise_degree(), clean_noise_degree);
    }

    {
        // Test with an input with only one bit of carry, but noise level is maxed

        let mut ct = RadixCiphertext::from(vec![
            cks.encrypt_one_block(block_msg_mod - 1),
            cks.encrypt_one_block(block_msg_mod - 1),
            cks.encrypt_one_block(block_msg_mod - 1),
            cks.encrypt_one_block(block_msg_mod - 1),
        ]);

        let ct_cloned = ct.clone();
        sks.unchecked_add_assign(&mut ct, &ct_cloned);

        for block in &mut ct.blocks[1..] {
            block.set_noise_level(
                NoiseLevel::NOMINAL * sks.key.max_noise_level.get(),
                sks.key.max_noise_level,
            );
        }

        executor.execute(&mut ct);

        let clean_degree = Degree::new(block_msg_mod - 1);
        for block in &mut ct.blocks {
            assert_eq!(block.noise_level(), NoiseLevel::NOMINAL);
            assert_eq!(block.degree, clean_degree);
        }

        let decrypted: u64 = cks.decrypt(&ct);
        let modulus = cks
            .parameters()
            .message_modulus()
            .0
            .pow(ct.blocks.len() as u32);
        let expected = ((modulus - 1) * 2) % modulus;
        assert_eq!(decrypted, expected);
    }

    {
        // Test corner case where all blocks (except first) have degree 0, but non-nominal noise
        // to make sure they are still cleaned up
        let mut ct = RadixCiphertext::from(vec![
            cks.encrypt_one_block(block_msg_mod - 1),
            cks.encrypt_one_block(0),
            cks.encrypt_one_block(0),
            cks.encrypt_one_block(0),
        ]);

        // Add to have non-nominal noise level
        let ct_cloned = ct.clone();
        sks.unchecked_add_assign(&mut ct, &ct_cloned);

        // Set degree to 0 for all blocks (except first)
        for block in &mut ct.blocks[1..] {
            block.degree = Degree::new(0);
        }

        // Check we crafted what we want
        assert_eq!(
            ct.blocks[0].noise_degree(),
            CiphertextNoiseDegree::new(
                NoiseLevel::NOMINAL * 2,
                Degree::new((block_msg_mod - 1) * 2)
            )
        );
        for block in &mut ct.blocks[1..] {
            assert_eq!(
                block.noise_degree(),
                CiphertextNoiseDegree::new(NoiseLevel::NOMINAL * 2, Degree::new(0))
            );
        }

        executor.execute(&mut ct);

        let clean_degree = Degree::new(block_msg_mod - 1);
        for block in &mut ct.blocks {
            assert_eq!(block.noise_level(), NoiseLevel::NOMINAL);
            assert!(block.degree <= clean_degree);
        }

        let decrypted: u64 = cks.decrypt(&ct);
        assert_eq!(decrypted, (block_msg_mod - 1) * 2);
    }

    // Here we want to test that propagating a radix which has trivial zeros in its MSB
    // yields correct results. We do this test as our implementation skips the propagation
    // on the MSB when they are trivial zeros
    {
        let nb_blocks = 4;
        let num_bits_in_msg = sks.message_modulus().0.ilog2();

        // The maximum encryptable value, i.e. all bits set to 1
        let clear_a = (1u32 << num_bits_in_msg) - 1;
        // The most significant block is full of 1, the least significant bit is 1
        // all other bits are 0
        let clear_b = ((1 << num_bits_in_msg) - 1) << (num_bits_in_msg * (nb_blocks - 1)) | 1u32;

        let a = cks.as_ref().encrypt_radix(clear_a, nb_blocks as usize);
        let b = cks.as_ref().encrypt_radix(clear_b, nb_blocks as usize);

        // Cast to double precision, making the top nb_blocks be trivial zeros
        let mut a = sks.cast_to_unsigned(a, 2 * nb_blocks as usize);
        let b = sks.cast_to_unsigned(b, 2 * nb_blocks as usize);

        sks.unchecked_add_assign(&mut a, &b);
        executor.execute(&mut a);

        assert!(a.block_carries_are_empty());
        assert!(a
            .blocks
            .iter()
            .all(|b| b.noise_level() <= NoiseLevel::NOMINAL));

        let result: u32 = cks.as_ref().decrypt_radix(&a);
        let expected = clear_a + clear_b;
        assert_eq!(
            result,
            clear_a + clear_b,
            "Invalid full propagation result for {clear_a} + {clear_b}, expected {expected}, got {result}"
        );
    }
}
