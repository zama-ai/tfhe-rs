use crate::integer::keycache::KEY_CACHE;
use crate::integer::server_key::radix_parallel::tests_cases_unsigned::FunctionExecutor;
use crate::integer::server_key::radix_parallel::tests_unsigned::{
    nb_tests_smaller_for_params, CpuFunctionExecutor, MAX_NB_CTXT, NB_CTXT,
};
use crate::integer::tests::create_parameterized_test;
use crate::integer::{
    IntegerKeyKind, RadixCiphertext, RadixClientKey, ServerKey, SignedRadixCiphertext,
};
use crate::shortint::parameters::test_params::*;
use crate::shortint::parameters::*;
use rand::Rng;
use std::sync::Arc;

create_parameterized_test!(integer_extensive_trivial_signed_default_count_zeros_ones);
create_parameterized_test!(integer_signed_default_count_zeros_ones);

fn integer_extensive_trivial_signed_default_count_zeros_ones<P>(param: P)
where
    P: Into<TestParameters>,
{
    let count_zeros_executor = CpuFunctionExecutor::new(&ServerKey::count_zeros_parallelized);
    let count_ones_executor = CpuFunctionExecutor::new(&ServerKey::count_ones_parallelized);
    extensive_trivial_signed_default_count_zeros_ones_test(
        param,
        count_zeros_executor,
        count_ones_executor,
    );
}

fn integer_signed_default_count_zeros_ones<P>(param: P)
where
    P: Into<TestParameters>,
{
    let count_zeros_executor = CpuFunctionExecutor::new(&ServerKey::count_zeros_parallelized);
    let count_ones_executor = CpuFunctionExecutor::new(&ServerKey::count_ones_parallelized);
    signed_default_count_zeros_ones_test(param, count_zeros_executor, count_ones_executor);
}

pub(crate) fn signed_default_count_zeros_ones_test<P, E1, E2>(
    param: P,
    mut count_zeros_executor: E1,
    mut count_ones_executor: E2,
) where
    P: Into<TestParameters>,
    E1: for<'a> FunctionExecutor<&'a SignedRadixCiphertext, RadixCiphertext>,
    E2: for<'a> FunctionExecutor<&'a SignedRadixCiphertext, RadixCiphertext>,
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
        if modulus > i128::MAX as u128 {
            break;
        }
        if modulus <= 2 {
            continue;
        }
        let half_modulus = modulus / 2;

        for _ in 0..nb_tests {
            let clear_a = rng.gen_range(-(half_modulus as i128)..half_modulus as i128);

            // Set all bits above the modulus to 0, so the count_ones does not count them
            // mask looks like `000000000000001111111`
            //                                ^ modulus.ilog2()
            // This has to be done for signed numbers because if clear_a < 0
            // then bits above 2**modulus are all `1`, thus the clear_a.count_one() is not correct
            let mask = (half_modulus as i128 * 2) - 1;
            let clear_a = mask & clear_a;

            let a: SignedRadixCiphertext = cks.encrypt_signed_radix(clear_a, num_blocks);

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
            let mask = -1i128.wrapping_mul(modulus as i128);
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

pub(crate) fn extensive_trivial_signed_default_count_zeros_ones_test<P, E1, E2>(
    param: P,
    mut count_zeros_executor: E1,
    mut count_ones_executor: E2,
) where
    P: Into<TestParameters>,
    E1: for<'a> FunctionExecutor<&'a SignedRadixCiphertext, RadixCiphertext>,
    E2: for<'a> FunctionExecutor<&'a SignedRadixCiphertext, RadixCiphertext>,
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
        if modulus > i128::MAX as u128 || modulus <= 2 {
            break;
        }
        let half_modulus = modulus / 2;
        for _ in 0..50 {
            let clear_a = rng.gen_range(-(half_modulus as i128)..half_modulus as i128);

            // Set all bits above the modulus to 0, so the count_ones does not count them
            // mask looks like `000000000000001111111`
            //                                ^ modulus.ilog2()
            // This has to be done for signed numbers because if clear_a < 0
            // then bits above 2**modulus are all `1`, thus the clear_a.count_one() is not correct
            let mask = (half_modulus as i128 * 2) - 1;
            let clear_a = mask & clear_a;

            let a: SignedRadixCiphertext = sks.create_trivial_radix(clear_a, num_blocks as usize);

            let encrypted = count_ones_executor.execute(&a);
            let decrypted: u32 = cks.decrypt_radix(&encrypted);
            assert_eq!(
                decrypted,
                clear_a.count_ones(),
                "Invalid count_ones for input {clear_a}"
            );

            // Set all bits above the modulus to 1, so the count_zeros does not count them
            // mask looks like `111111111111110000000`
            //                                ^ modulus.ilog2()
            let mask = -1i128.wrapping_mul(modulus as i128);
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
