use crate::integer::keycache::KEY_CACHE;
use crate::integer::server_key::radix_parallel::tests_cases_unsigned::{FunctionExecutor, NB_CTXT};
use crate::integer::server_key::radix_parallel::tests_unsigned::{
    nb_tests_for_params, nb_tests_smaller_for_params, CpuFunctionExecutor, MAX_NB_CTXT,
};
use crate::integer::tests::create_parameterized_test;
use crate::integer::{ClientKey, IntegerKeyKind, RadixCiphertext, RadixClientKey, ServerKey};
#[cfg(tarpaulin)]
use crate::shortint::parameters::coverage_parameters::*;
use crate::shortint::parameters::test_params::*;
use crate::shortint::parameters::*;
use rand::Rng;
use std::sync::Arc;

create_parameterized_test!(integer_unchecked_left_shift);
create_parameterized_test!(integer_unchecked_right_shift);
create_parameterized_test!(integer_left_shift);
create_parameterized_test!(integer_right_shift);

fn integer_unchecked_left_shift<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::unchecked_left_shift_parallelized);
    unchecked_left_shift_test(param, executor);
}

fn integer_unchecked_right_shift<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::unchecked_right_shift_parallelized);
    unchecked_right_shift_test(param, executor);
}

fn integer_right_shift<P>(param: P)
where
    P: Into<TestParameters> + Copy,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::right_shift_parallelized);
    default_right_shift_test(param, executor);
}

fn integer_left_shift<P>(param: P)
where
    P: Into<TestParameters> + Copy,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::left_shift_parallelized);
    default_left_shift_test(param, executor);
}

pub(crate) fn unchecked_left_shift_test<P, T>(param: P, mut executor: T)
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

        // case when 0 <= shift < nb_bits
        {
            let clear_shift = clear_shift % nb_bits;
            let shift = cks.encrypt(clear_shift as u64);

            let encrypted_result = executor.execute((&ct, &shift));
            let decrypted_result: u64 = cks.decrypt(&encrypted_result);
            assert_eq!((clear << clear_shift) % modulus, decrypted_result);
        }

        // case when shift >= nb_bits
        {
            let clear_shift = clear_shift.saturating_add(nb_bits);
            let shift = cks.encrypt(clear_shift as u64);

            let encrypted_result = executor.execute((&ct, &shift));
            let decrypted_result: u64 = cks.decrypt(&encrypted_result);
            // When nb_bits is not a power of two
            // then the behaviour is not the same
            let mut nb_bits = modulus.ilog2();
            if !nb_bits.is_power_of_two() {
                nb_bits = nb_bits.next_power_of_two();
            }
            // We mimic wrapping_shl manually as we use a bigger type
            // than the nb_bits we actually simulate in this test
            assert_eq!(
                (clear << (clear_shift % nb_bits)) % modulus,
                decrypted_result
            );
        }
    }
}

pub(crate) fn unchecked_right_shift_test<P, T>(param: P, mut executor: T)
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

        // case when 0 <= shift < nb_bits
        {
            let clear_shift = clear_shift % nb_bits;
            let shift = cks.encrypt(clear_shift as u64);
            let encrypted_result = executor.execute((&ct, &shift));
            let decrypted_result: u64 = cks.decrypt(&encrypted_result);
            assert_eq!((clear >> clear_shift) % modulus, decrypted_result);
        }

        // case when shift >= nb_bits
        {
            let clear_shift = clear_shift.saturating_add(nb_bits);
            let shift = cks.encrypt(clear_shift as u64);
            let encrypted_result = executor.execute((&ct, &shift));
            let decrypted_result: u64 = cks.decrypt(&encrypted_result);

            // When nb_bits is not a power of two
            // then the behaviour is not the same
            let mut nb_bits = modulus.ilog2();
            if !nb_bits.is_power_of_two() {
                nb_bits = nb_bits.next_power_of_two();
            }
            // We mimic wrapping_shr manually as we use a bigger type
            // than the nb_bits we actually simulate in this test
            assert_eq!(
                (clear >> (clear_shift % nb_bits)) % modulus,
                decrypted_result
            );
        }
    }
}

pub(crate) fn default_left_shift_test<P, T>(param: P, mut executor: T)
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

            // case when 0 <= shift < nb_bits
            {
                let clear_shift = clear_shift % nb_bits;
                let shift = cks.encrypt_radix(clear_shift as u64, num_blocks);

                let encrypted_result = executor.execute((&ct, &shift));
                for (i, b) in encrypted_result.blocks.iter().enumerate() {
                    if b.noise_level() > NoiseLevel::NOMINAL {
                        println!("{i}: {:?}", b.noise_level());
                    }
                }
                assert!(
                    encrypted_result
                        .blocks
                        .iter()
                        .all(|b| b.noise_level() <= NoiseLevel::NOMINAL),
                    "Expected all blocks to have at most NOMINAL noise level"
                );
                let decrypted_result: u64 = cks.decrypt_radix(&encrypted_result);
                assert_eq!((clear << clear_shift) % modulus, decrypted_result);
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
                let mut nb_bits = modulus.ilog2();
                if !nb_bits.is_power_of_two() {
                    nb_bits = nb_bits.next_power_of_two();
                }
                // We mimic wrapping_shl manually as we use a bigger type
                // than the nb_bits we actually simulate in this test
                assert_eq!(
                    (clear << (clear_shift % nb_bits)) % modulus,
                    decrypted_result
                );
            }
        }
    }
}

pub(crate) fn default_right_shift_test<P, T>(param: P, mut executor: T)
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

            // case when 0 <= shift < nb_bits
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
                assert_eq!((clear >> clear_shift) % modulus, decrypted_result);
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
                let mut nb_bits = modulus.ilog2();
                if !nb_bits.is_power_of_two() {
                    nb_bits = nb_bits.next_power_of_two();
                }
                // We mimic wrapping_shr manually as we use a bigger type
                // than the nb_bits we actually simulate in this test
                assert_eq!(
                    (clear >> (clear_shift % nb_bits)) % modulus,
                    decrypted_result
                );
            }
        }
    }
}
