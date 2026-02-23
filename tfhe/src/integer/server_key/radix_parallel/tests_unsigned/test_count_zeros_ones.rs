use crate::integer::keycache::KEY_CACHE;
use crate::integer::server_key::radix_parallel::tests_cases_unsigned::FunctionExecutor;
use crate::integer::server_key::radix_parallel::tests_unsigned::{
    nb_tests_smaller_for_params, CpuFunctionExecutor, MAX_NB_CTXT, NB_CTXT,
};
use crate::integer::tests::create_parameterized_test;
use crate::integer::{IntegerKeyKind, RadixCiphertext, RadixClientKey, ServerKey};
use crate::shortint::parameters::test_params::*;
use crate::shortint::parameters::*;
use rand::Rng;
use std::sync::Arc;

create_parameterized_test!(integer_extensive_trivial_default_count_zeros_ones);
create_parameterized_test!(integer_default_count_zeros_ones);

fn integer_extensive_trivial_default_count_zeros_ones<P>(param: P)
where
    P: Into<TestParameters>,
{
    let count_zeros_executor = CpuFunctionExecutor::new(&ServerKey::count_zeros_parallelized);
    let count_ones_executor = CpuFunctionExecutor::new(&ServerKey::count_ones_parallelized);
    extensive_trivial_default_count_zeros_ones_test(
        param,
        count_zeros_executor,
        count_ones_executor,
    );
}

fn integer_default_count_zeros_ones<P>(param: P)
where
    P: Into<TestParameters>,
{
    let count_zeros_executor = CpuFunctionExecutor::new(&ServerKey::count_zeros_parallelized);
    let count_ones_executor = CpuFunctionExecutor::new(&ServerKey::count_ones_parallelized);
    default_count_zeros_ones_test(param, count_zeros_executor, count_ones_executor);
}

pub(crate) fn default_count_zeros_ones_test<P, E1, E2>(
    param: P,
    mut count_zeros_executor: E1,
    mut count_ones_executor: E2,
) where
    P: Into<TestParameters>,
    E1: for<'a> FunctionExecutor<&'a RadixCiphertext, RadixCiphertext>,
    E2: for<'a> FunctionExecutor<&'a RadixCiphertext, RadixCiphertext>,
{
    let param = param.into();
    let nb_tests = nb_tests_smaller_for_params(param);
    let (cks, mut sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    sks.set_deterministic_pbs_execution(true);
    let sks = Arc::new(sks);

    let mut rng = rand::rng();

    count_zeros_executor.setup(&cks, sks.clone());
    count_ones_executor.setup(&cks, sks);

    let cks: crate::integer::ClientKey = cks.into();

    for num_blocks in 1..=MAX_NB_CTXT {
        let Some(modulus) =
            (cks.parameters().message_modulus().0 as u128).checked_pow(num_blocks as u32)
        else {
            break;
        };
        for _ in 0..nb_tests {
            let clear_a = rng.gen::<u128>() % modulus;

            let a: RadixCiphertext = cks.encrypt_radix(clear_a, num_blocks);

            let encrypted = count_ones_executor.execute(&a);
            let decrypted: u32 = cks.decrypt_radix(&encrypted);
            assert_eq!(
                decrypted,
                clear_a.count_ones(),
                "Invalid count_ones for input {clear_a}"
            );

            // Set all bits above the modulus to 1, so the count_zeros does no count them
            // mask looks like `111111111111110000000`
            //                                ^ modulus.ilog2()
            let mask = u128::MAX.wrapping_mul(modulus);
            let clear_a = mask | clear_a;
            let encrypted = count_zeros_executor.execute(&a);
            let decrypted: u32 = cks.decrypt_radix(&encrypted);
            assert_eq!(
                decrypted,
                clear_a.count_zeros(),
                "Invalid count_zeros for input {clear_a}"
            );
        }
    }
}

pub(crate) fn extensive_trivial_default_count_zeros_ones_test<P, E1, E2>(
    param: P,
    mut count_zeros_executor: E1,
    mut count_ones_executor: E2,
) where
    P: Into<TestParameters>,
    E1: for<'a> FunctionExecutor<&'a RadixCiphertext, RadixCiphertext>,
    E2: for<'a> FunctionExecutor<&'a RadixCiphertext, RadixCiphertext>,
{
    let param = param.into();
    let (cks, mut sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    sks.set_deterministic_pbs_execution(true);
    let sks = Arc::new(sks);

    let mut rng = rand::rng();

    count_zeros_executor.setup(&cks, sks.clone());
    count_ones_executor.setup(&cks, sks.clone());

    let cks: crate::integer::ClientKey = cks.into();

    for num_blocks in 1..=64 {
        let Some(modulus) = (cks.parameters().message_modulus().0 as u128).checked_pow(num_blocks)
        else {
            break;
        };
        for _ in 0..50 {
            let clear_a = rng.gen::<u128>() % modulus;

            let a: RadixCiphertext = sks.create_trivial_radix(clear_a, num_blocks as usize);

            let encrypted = count_ones_executor.execute(&a);
            let decrypted: u32 = cks.decrypt_radix(&encrypted);
            assert_eq!(
                decrypted,
                clear_a.count_ones(),
                "Invalid count_ones for input {clear_a}"
            );

            // Set all bits above the modulus to 1, so the count_zeros does no count them
            // mask looks like `111111111111110000000`
            //                                ^ modulus.ilog2()
            let mask = u128::MAX.wrapping_mul(modulus);
            let clear_a = mask | clear_a;
            let encrypted = count_zeros_executor.execute(&a);
            let decrypted: u32 = cks.decrypt_radix(&encrypted);
            assert_eq!(
                decrypted,
                clear_a.count_zeros(),
                "Invalid count_zeros for input {clear_a}"
            );
        }
    }
}
