use crate::integer::keycache::KEY_CACHE;
use crate::integer::server_key::radix_parallel::tests_cases_unsigned::{FunctionExecutor, NB_CTXT};
use crate::integer::server_key::radix_parallel::tests_unsigned::{
    nb_tests_for_params, nb_tests_smaller_for_params, rotate_left_helper, rotate_right_helper,
    CpuFunctionExecutor, MAX_NB_CTXT,
};
use crate::integer::tests::create_parameterized_test;
use crate::integer::{ClientKey, IntegerKeyKind, RadixCiphertext, RadixClientKey, ServerKey};
#[cfg(tarpaulin)]
use crate::shortint::parameters::coverage_parameters::*;
use crate::shortint::parameters::test_params::*;
use crate::shortint::parameters::*;
use rand::Rng;
use std::sync::Arc;

create_parameterized_test!(integer_unchecked_rotate_right);

create_parameterized_test!(integer_unchecked_rotate_left);

create_parameterized_test!(integer_rotate_right);

create_parameterized_test!(integer_rotate_left);

fn integer_unchecked_rotate_right<P>(param: P)
where
    P: Into<TestParameters> + Copy,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::unchecked_rotate_right_parallelized);
    unchecked_rotate_right_test(param, executor);
}

fn integer_rotate_right<P>(param: P)
where
    P: Into<TestParameters> + Copy,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::rotate_right_parallelized);
    default_rotate_right_test(param, executor);
}

fn integer_unchecked_rotate_left<P>(param: P)
where
    P: Into<TestParameters> + Copy,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::unchecked_rotate_left_parallelized);
    unchecked_rotate_left_test(param, executor);
}

fn integer_rotate_left<P>(param: P)
where
    P: Into<TestParameters> + Copy,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::rotate_left_parallelized);
    default_rotate_left_test(param, executor);
}

pub(crate) fn unchecked_rotate_left_test<P, T>(param: P, mut executor: T)
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
    assert!(modulus.is_power_of_two());
    let nb_bits = modulus.ilog2();

    executor.setup(&cks, sks);

    for _ in 0..nb_tests {
        let clear = rng.gen::<u64>() % modulus;
        let clear_shift = rng.gen::<u32>();

        let ct = cks.encrypt(clear);

        // case when 0 <= rotate < nb_bits
        {
            let clear_rotate = clear_shift % nb_bits;
            let shift = cks.encrypt(clear_rotate as u64);
            let encrypted_result = executor.execute((&ct, &shift));
            let decrypted_result: u64 = cks.decrypt(&encrypted_result);
            let expected = rotate_left_helper(clear, clear_rotate, nb_bits);
            assert_eq!(expected, decrypted_result);
        }

        // case when shift >= nb_bits
        {
            let clear_rotate = clear_shift.saturating_add(nb_bits);
            let shift = cks.encrypt(clear_rotate as u64);
            let encrypted_result = executor.execute((&ct, &shift));
            let decrypted_result: u64 = cks.decrypt(&encrypted_result);
            // When nb_bits is not a power of two
            // then the behaviour is not the same
            let true_nb_bits = nb_bits;
            let mut nb_bits = nb_bits;
            if !nb_bits.is_power_of_two() {
                nb_bits = nb_bits.next_power_of_two();
            }
            let expected = rotate_left_helper(clear, clear_rotate % nb_bits, true_nb_bits);
            assert_eq!(expected, decrypted_result);
        }
    }
}

pub(crate) fn unchecked_rotate_right_test<P, T>(param: P, mut executor: T)
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
    assert!(modulus.is_power_of_two());
    let nb_bits = modulus.ilog2();

    executor.setup(&cks, sks);

    for _ in 0..nb_tests {
        let clear = rng.gen::<u64>() % modulus;
        let clear_shift = rng.gen::<u32>();

        let ct = cks.encrypt(clear);

        // case when 0 <= rotate < nb_bits
        {
            let clear_rotate = clear_shift % nb_bits;
            let shift = cks.encrypt(clear_rotate as u64);
            let encrypted_result = executor.execute((&ct, &shift));
            let decrypted_result: u64 = cks.decrypt(&encrypted_result);
            let expected = rotate_right_helper(clear, clear_rotate, nb_bits);
            assert_eq!(expected, decrypted_result);
        }

        // case when shift >= nb_bits
        {
            let clear_rotate = clear_shift.saturating_add(nb_bits);
            let shift = cks.encrypt(clear_rotate as u64);
            let encrypted_result = executor.execute((&ct, &shift));
            let decrypted_result: u64 = cks.decrypt(&encrypted_result);
            // When nb_bits is not a power of two
            // then the behaviour is not the same
            let true_nb_bits = nb_bits;
            let mut nb_bits = nb_bits;
            if !nb_bits.is_power_of_two() {
                nb_bits = nb_bits.next_power_of_two();
            }
            let expected = rotate_right_helper(clear, clear_rotate % nb_bits, true_nb_bits);
            assert_eq!(expected, decrypted_result);
        }
    }
}

pub(crate) fn default_rotate_left_test<P, T>(param: P, mut executor: T)
where
    P: Into<TestParameters>,
    T: for<'a> FunctionExecutor<(&'a RadixCiphertext, &'a RadixCiphertext), RadixCiphertext>,
{
    let param = param.into();
    let nb_tests = nb_tests_smaller_for_params(param);
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let sks = Arc::new(sks);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    let mut rng = rand::rng();

    executor.setup(&cks, sks);

    let cks: ClientKey = cks.into();

    for num_blocks in 1..MAX_NB_CTXT {
        // message_modulus^vec_length
        let modulus = cks.parameters().message_modulus().0.pow(num_blocks as u32);
        assert!(modulus.is_power_of_two());
        let nb_bits = modulus.ilog2();
        for _ in 0..nb_tests {
            let clear = rng.gen::<u64>() % modulus;
            let clear_shift = rng.gen::<u32>();

            let ct = cks.encrypt_radix(clear, num_blocks);

            // case when 0 <= rotate < nb_bits
            {
                let clear_shift = clear_shift % nb_bits;
                let shift = cks.encrypt_radix(clear_shift as u64, num_blocks);
                let encrypted_result = executor.execute((&ct, &shift));
                let decrypted_result: u64 = cks.decrypt_radix(&encrypted_result);
                assert!(
                    encrypted_result
                        .blocks
                        .iter()
                        .all(|b| b.noise_level() <= NoiseLevel::NOMINAL),
                    "Expected all blocks to have at most NOMINAL noise level"
                );
                let expected = rotate_left_helper(clear, clear_shift, nb_bits);
                assert_eq!(expected, decrypted_result);
            }

            // case when shift >= nb_bits
            {
                let clear_shift = rng.gen_range(nb_bits..modulus as u32);
                let shift = cks.encrypt_radix(clear_shift as u64, num_blocks);
                let encrypted_result = executor.execute((&ct, &shift));
                assert!(
                    encrypted_result
                        .blocks
                        .iter()
                        .all(|b| b.noise_level() <= NoiseLevel::NOMINAL),
                    "Expected all blocks to have at most NOMINAL noise level"
                );
                let decrypted_result: u64 = cks.decrypt_radix(&encrypted_result);
                // When nb_bits is not a power of two
                // then the behaviour is not the same
                let true_nb_bits = nb_bits;
                let mut nb_bits = nb_bits;
                if !nb_bits.is_power_of_two() {
                    nb_bits = nb_bits.next_power_of_two();
                }
                let expected = rotate_left_helper(clear, clear_shift % nb_bits, true_nb_bits);
                assert_eq!(expected, decrypted_result);
            }
        }
    }
}

pub(crate) fn default_rotate_right_test<P, T>(param: P, mut executor: T)
where
    P: Into<TestParameters>,
    T: for<'a> FunctionExecutor<(&'a RadixCiphertext, &'a RadixCiphertext), RadixCiphertext>,
{
    let param = param.into();
    let nb_tests = nb_tests_smaller_for_params(param);
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let sks = Arc::new(sks);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    let mut rng = rand::rng();

    executor.setup(&cks, sks);

    let cks: ClientKey = cks.into();

    for num_blocks in 1..MAX_NB_CTXT {
        // message_modulus^vec_length
        let modulus = cks.parameters().message_modulus().0.pow(num_blocks as u32);
        assert!(modulus.is_power_of_two());
        let nb_bits = modulus.ilog2();
        for _ in 0..nb_tests {
            let clear = rng.gen::<u64>() % modulus;
            let clear_shift = rng.gen::<u32>();

            let ct = cks.encrypt_radix(clear, num_blocks);

            // case when 0 <= rotate < nb_bits
            {
                let clear_shift = clear_shift % nb_bits;
                let shift = cks.encrypt_radix(clear_shift as u64, num_blocks);
                let encrypted_result = executor.execute((&ct, &shift));
                assert!(
                    encrypted_result
                        .blocks
                        .iter()
                        .all(|b| b.noise_level() <= NoiseLevel::NOMINAL),
                    "Expected all blocks to have at most NOMINAL noise level"
                );
                let decrypted_result: u64 = cks.decrypt_radix(&encrypted_result);
                let expected = rotate_right_helper(clear, clear_shift, nb_bits);
                assert_eq!(expected, decrypted_result);
            }

            // case when shift >= nb_bits
            {
                let clear_shift = rng.gen_range(nb_bits..modulus as u32);
                let shift = cks.encrypt_radix(clear_shift as u64, num_blocks);
                let encrypted_result = executor.execute((&ct, &shift));
                assert!(
                    encrypted_result
                        .blocks
                        .iter()
                        .all(|b| b.noise_level() <= NoiseLevel::NOMINAL),
                    "Expected all blocks to have at most NOMINAL noise level"
                );
                let decrypted_result: u64 = cks.decrypt_radix(&encrypted_result);
                // When nb_bits is not a power of two
                // then the behaviour is not the same
                let true_nb_bits = nb_bits;
                let mut nb_bits = nb_bits;
                if !nb_bits.is_power_of_two() {
                    nb_bits = nb_bits.next_power_of_two();
                }
                let expected = rotate_right_helper(clear, clear_shift % nb_bits, true_nb_bits);
                assert_eq!(expected, decrypted_result);
            }
        }
    }
}
