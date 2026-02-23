use crate::integer::keycache::KEY_CACHE;
use crate::integer::server_key::radix_parallel::tests_cases_unsigned::{FunctionExecutor, NB_CTXT};
use crate::integer::server_key::radix_parallel::tests_unsigned::{
    block_shift_left_helper, block_shift_right_helper, nb_tests_smaller_for_params,
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

create_parameterized_test!(integer_block_shift_right);

create_parameterized_test!(integer_block_shift_left);

fn integer_block_shift_right<P>(param: P)
where
    P: Into<TestParameters> + Copy,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::block_shift_right);
    default_block_shift_right_test(param, executor);
}

fn integer_block_shift_left<P>(param: P)
where
    P: Into<TestParameters> + Copy,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::block_shift_left);
    default_block_shift_left_test(param, executor);
}

pub(crate) fn default_block_shift_left_test<P, T>(param: P, mut executor: T)
where
    P: Into<TestParameters>,
    T: for<'a> FunctionExecutor<(&'a RadixCiphertext, &'a RadixCiphertext), RadixCiphertext>,
{
    let param = param.into();
    let nb_tests = nb_tests_smaller_for_params(param);
    let (cks, mut sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    sks.set_deterministic_pbs_execution(true);

    let sks = Arc::new(sks);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    let mut rng = rand::rng();

    executor.setup(&cks, sks.clone());

    let cks: ClientKey = cks.into();
    let bits_per_blocks = cks.parameters().message_modulus().0.ilog2();

    for num_blocks in 1..MAX_NB_CTXT {
        // message_modulus^vec_length
        let modulus = cks.parameters().message_modulus().0.pow(num_blocks as u32);
        assert!(modulus.is_power_of_two());
        for _ in 0..nb_tests {
            let clear = rng.gen::<u64>() % modulus;
            let ct = cks.encrypt_radix(clear, num_blocks);

            // case when 0 <= shift < nb_bits
            {
                let clear_shift = rng.gen_range(0..num_blocks as u32);
                let shift = cks.encrypt_radix(clear_shift as u64, num_blocks);
                let encrypted_result = executor.execute((&ct, &shift));
                assert_eq!(encrypted_result.blocks.len(), num_blocks);
                assert!(
                    encrypted_result
                        .blocks
                        .iter()
                        .all(|b| b.noise_level() <= NoiseLevel::NOMINAL),
                    "Expected all blocks to have at most NOMINAL noise level"
                );
                assert!(
                    encrypted_result.block_carries_are_empty(),
                    "Expected all blocks to have no carries"
                );
                let expected =
                    block_shift_left_helper(clear, clear_shift, num_blocks as u32, bits_per_blocks);
                let decrypted_result: u64 = cks.decrypt_radix(&encrypted_result);
                assert_eq!(expected, decrypted_result);

                let encrypted_result2 = executor.execute((&ct, &shift));
                assert_eq!(
                    encrypted_result, encrypted_result2,
                    "Failed determinism check"
                )
            }

            // case when shift >= nb_bits
            {
                let clear_shift = rng.gen_range(num_blocks as u32..modulus as u32);
                let shift = sks.create_trivial_radix(clear_shift as u64, num_blocks);
                let encrypted_result = executor.execute((&ct, &shift));
                assert!(
                    encrypted_result
                        .blocks
                        .iter()
                        .all(|b| b.noise_level() <= NoiseLevel::NOMINAL),
                    "Expected all blocks to have at most NOMINAL noise level"
                );
                assert!(
                    encrypted_result.block_carries_are_empty(),
                    "Expected all blocks to have no carries"
                );
                let decrypted_result: u64 = cks.decrypt_radix(&encrypted_result);
                let expected =
                    block_shift_left_helper(clear, clear_shift, num_blocks as u32, bits_per_blocks);
                assert_eq!(expected, decrypted_result);

                let encrypted_result2 = executor.execute((&ct, &shift));
                assert_eq!(
                    encrypted_result, encrypted_result2,
                    "Failed determinism check"
                )
            }
        }
    }
}

pub(crate) fn default_block_shift_right_test<P, T>(param: P, mut executor: T)
where
    P: Into<TestParameters>,
    T: for<'a> FunctionExecutor<(&'a RadixCiphertext, &'a RadixCiphertext), RadixCiphertext>,
{
    let param = param.into();
    let nb_tests = nb_tests_smaller_for_params(param);
    let (cks, mut sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    sks.set_deterministic_pbs_execution(true);

    let sks = Arc::new(sks);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    let mut rng = rand::rng();

    executor.setup(&cks, sks.clone());

    let cks: ClientKey = cks.into();
    let bits_per_blocks = cks.parameters().message_modulus().0.ilog2();

    for num_blocks in 1..MAX_NB_CTXT {
        // message_modulus^vec_length
        let modulus = cks.parameters().message_modulus().0.pow(num_blocks as u32);
        assert!(modulus.is_power_of_two());
        for _ in 0..nb_tests {
            let clear = rng.gen::<u64>() % modulus;
            let ct = cks.encrypt_radix(clear, num_blocks);

            // case when 0 <= shift < nb_bits
            {
                let clear_shift = rng.gen_range(0..num_blocks as u32);
                let shift = cks.encrypt_radix(clear_shift as u64, num_blocks);
                let encrypted_result = executor.execute((&ct, &shift));
                assert_eq!(encrypted_result.blocks.len(), num_blocks);
                assert!(
                    encrypted_result
                        .blocks
                        .iter()
                        .all(|b| b.noise_level() <= NoiseLevel::NOMINAL),
                    "Expected all blocks to have at most NOMINAL noise level"
                );
                assert!(
                    encrypted_result.block_carries_are_empty(),
                    "Expected all blocks to have no carries"
                );
                let expected = block_shift_right_helper(
                    clear,
                    clear_shift,
                    num_blocks as u32,
                    bits_per_blocks,
                );
                let decrypted_result: u64 = cks.decrypt_radix(&encrypted_result);
                assert_eq!(expected, decrypted_result);

                let encrypted_result2 = executor.execute((&ct, &shift));
                assert_eq!(
                    encrypted_result, encrypted_result2,
                    "Failed determinism check"
                )
            }

            // case when shift >= nb_bits
            {
                let clear_shift = rng.gen_range(num_blocks as u32..modulus as u32);
                let shift = sks.create_trivial_radix(clear_shift as u64, num_blocks);
                let encrypted_result = executor.execute((&ct, &shift));
                assert!(
                    encrypted_result
                        .blocks
                        .iter()
                        .all(|b| b.noise_level() <= NoiseLevel::NOMINAL),
                    "Expected all blocks to have at most NOMINAL noise level"
                );
                assert!(
                    encrypted_result.block_carries_are_empty(),
                    "Expected all blocks to have no carries"
                );
                let decrypted_result: u64 = cks.decrypt_radix(&encrypted_result);
                let expected = block_shift_right_helper(
                    clear,
                    clear_shift,
                    num_blocks as u32,
                    bits_per_blocks,
                );
                assert_eq!(expected, decrypted_result);

                let encrypted_result2 = executor.execute((&ct, &shift));
                assert_eq!(
                    encrypted_result, encrypted_result2,
                    "Failed determinism check"
                )
            }
        }
    }
}
