use crate::integer::keycache::KEY_CACHE;
use crate::integer::prelude::*;
use crate::integer::server_key::radix_parallel::tests_cases_unsigned::{FunctionExecutor, NB_CTXT};
use crate::integer::server_key::radix_parallel::tests_signed::signed_add_under_modulus;
use crate::integer::server_key::radix_parallel::tests_unsigned::{
    nb_tests_for_params, CpuFunctionExecutor,
};
use crate::integer::tests::create_parameterized_test;
use crate::integer::{
    BooleanBlock, IntegerKeyKind, RadixClientKey, ServerKey, SignedRadixCiphertext,
};
#[cfg(tarpaulin)]
use crate::shortint::parameters::coverage_parameters::*;
use crate::shortint::parameters::test_params::*;
use crate::shortint::parameters::*;
use rand::Rng;
use std::sync::Arc;

create_parameterized_test!(integer_signed_unchecked_if_then_else);
create_parameterized_test!(integer_signed_default_if_then_else);
create_parameterized_test!(integer_signed_default_scalar_if_then_else);

fn integer_signed_unchecked_if_then_else<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::unchecked_if_then_else_parallelized);
    signed_unchecked_if_then_else_test(param, executor);
}

fn integer_signed_default_if_then_else<P>(param: P)
where
    P: Into<TestParameters>,
{
    let func =
        |sks: &ServerKey,
         cond: &BooleanBlock,
         lhs: &SignedRadixCiphertext,
         rhs: &SignedRadixCiphertext| { sks.if_then_else_parallelized(cond, lhs, rhs) };
    let executor = CpuFunctionExecutor::new(&func);
    signed_default_if_then_else_test(param, executor);
}

fn integer_signed_default_scalar_if_then_else<P>(param: P)
where
    P: Into<TestParameters>,
{
    let func = |sks: &ServerKey, cond: &BooleanBlock, lhs: i64, rhs: i64, n_blocks: usize| {
        sks.scalar_if_then_else_parallelized(cond, lhs, rhs, n_blocks)
    };
    let executor = CpuFunctionExecutor::new(&func);
    signed_default_scalar_if_then_else_test(param, executor);
}

pub(crate) fn signed_default_if_then_else_test<P, T>(param: P, mut executor: T)
where
    P: Into<TestParameters>,
    T: for<'a> FunctionExecutor<
        (
            &'a BooleanBlock,
            &'a SignedRadixCiphertext,
            &'a SignedRadixCiphertext,
        ),
        SignedRadixCiphertext,
    >,
{
    let param = param.into();
    let nb_tests = nb_tests_for_params(param);
    let (cks, mut sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    sks.set_deterministic_pbs_execution(true);
    let sks = Arc::new(sks);

    let mut rng = rand::rng();

    // message_modulus^vec_length
    let modulus = cks.parameters().message_modulus().0.pow(NB_CTXT as u32) as i64 / 2;

    executor.setup(&cks, sks.clone());

    for _ in 0..nb_tests {
        let clear_0 = rng.random::<i64>() % modulus;
        let clear_1 = rng.random::<i64>() % modulus;
        let clear_condition = rng.random_bool(0.5);

        let mut ctxt_0 = cks.encrypt_signed(clear_0);
        let mut ctxt_1 = cks.encrypt_signed(clear_1);
        let ctxt_condition = cks.encrypt_bool(clear_condition);

        let ct_res = executor.execute((&ctxt_condition, &ctxt_0, &ctxt_1));
        assert!(ct_res.block_carries_are_empty());

        let dec_res: i64 = cks.decrypt_signed(&ct_res);
        assert_eq!(dec_res, if clear_condition { clear_0 } else { clear_1 });

        let ct_res2 = executor.execute((&ctxt_condition, &ctxt_0, &ctxt_1));
        assert_eq!(ct_res, ct_res2, "Operation is not deterministic");

        let clear_2 = rng.random::<i64>() % modulus;
        let clear_3 = rng.random::<i64>() % modulus;

        let ctxt_2 = cks.encrypt_signed(clear_2);
        let ctxt_3 = cks.encrypt_signed(clear_3);

        // Add to have non empty carries
        sks.unchecked_add_assign(&mut ctxt_0, &ctxt_2);
        sks.unchecked_add_assign(&mut ctxt_1, &ctxt_3);
        assert!(!ctxt_0.block_carries_are_empty());
        assert!(!ctxt_1.block_carries_are_empty());

        let ct_res = executor.execute((&ctxt_condition, &ctxt_0, &ctxt_1));
        assert!(ct_res.block_carries_are_empty());

        let dec_res: i64 = cks.decrypt_signed(&ct_res);
        assert_eq!(
            dec_res,
            if clear_condition {
                signed_add_under_modulus(clear_0, clear_2, modulus)
            } else {
                signed_add_under_modulus(clear_1, clear_3, modulus)
            }
        );
    }

    // Some test with trivial ciphertext as input
    let one = sks.create_trivial_radix(1, NB_CTXT);
    let two = sks.create_trivial_radix(2, NB_CTXT);
    {
        // Condition is false
        let condition = sks.create_trivial_boolean_block(false);

        let result = executor.execute((&condition, &one, &two));
        assert!(result.block_carries_are_empty());
        assert_eq!(cks.decrypt_signed::<i64>(&result), 2);

        let result = executor.execute((&condition, &one, &one));
        assert!(result.block_carries_are_empty());
        assert_eq!(cks.decrypt_signed::<i64>(&result), 1);

        let result = executor.execute((&condition, &two, &one));
        assert!(result.block_carries_are_empty());
        assert_eq!(cks.decrypt_signed::<i64>(&result), 1);

        let result = executor.execute((&condition, &two, &two));
        assert!(result.block_carries_are_empty());
        assert_eq!(cks.decrypt_signed::<i64>(&result), 2);
    }
    {
        // Condition is true
        let condition = sks.create_trivial_boolean_block(true);

        let result = executor.execute((&condition, &one, &two));
        assert!(result.block_carries_are_empty());
        assert_eq!(cks.decrypt_signed::<i64>(&result), 1);

        let result = executor.execute((&condition, &one, &one));
        assert!(result.block_carries_are_empty());
        assert_eq!(cks.decrypt_signed::<i64>(&result), 1);

        let result = executor.execute((&condition, &two, &one));
        assert!(result.block_carries_are_empty());
        assert_eq!(cks.decrypt_signed::<i64>(&result), 2);

        let result = executor.execute((&condition, &two, &two));
        assert!(result.block_carries_are_empty());
        assert_eq!(cks.decrypt_signed::<i64>(&result), 2);
    }
}

pub(crate) fn signed_default_scalar_if_then_else_test<P, T>(param: P, mut executor: T)
where
    P: Into<TestParameters>,
    T: for<'a> FunctionExecutor<(&'a BooleanBlock, i64, i64, usize), SignedRadixCiphertext>,
{
    let param = param.into();
    let nb_tests = nb_tests_for_params(param);
    let (cks, mut sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    sks.set_deterministic_pbs_execution(true);
    let sks = Arc::new(sks);

    let mut rng = rand::rng();

    // message_modulus^vec_length
    let modulus = cks.parameters().message_modulus().0.pow(NB_CTXT as u32) as i64 / 2;

    executor.setup(&cks, sks);

    for _ in 0..nb_tests {
        let clear_0 = rng.random::<i64>() % modulus;
        let clear_1 = rng.random::<i64>() % modulus;
        let clear_condition = rng.random_bool(0.5);

        let ctxt_condition = cks.encrypt_bool(clear_condition);

        let ct_res = executor.execute((&ctxt_condition, clear_0, clear_1, NB_CTXT));
        assert!(ct_res.block_carries_are_empty());

        let dec_res: i64 = cks.decrypt_signed(&ct_res);
        assert_eq!(dec_res, if clear_condition { clear_0 } else { clear_1 });

        let ct_res2 = executor.execute((&ctxt_condition, clear_0, clear_1, NB_CTXT));
        assert_eq!(ct_res, ct_res2, "Operation is not deterministic");
    }
}

pub(crate) fn signed_unchecked_if_then_else_test<P, T>(param: P, mut executor: T)
where
    P: Into<TestParameters>,
    T: for<'a> FunctionExecutor<
        (
            &'a BooleanBlock,
            &'a SignedRadixCiphertext,
            &'a SignedRadixCiphertext,
        ),
        SignedRadixCiphertext,
    >,
{
    let param = param.into();
    let nb_tests = nb_tests_for_params(param);
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let sks = Arc::new(sks);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    let mut rng = rand::rng();

    // message_modulus^vec_length
    let modulus = cks.parameters().message_modulus().0.pow(NB_CTXT as u32) as i64 / 2;

    executor.setup(&cks, sks);

    for _ in 0..nb_tests {
        let clear_0 = rng.random::<i64>() % modulus;
        let clear_1 = rng.random::<i64>() % modulus;
        let clear_condition = rng.random_bool(0.5);

        let ctxt_0 = cks.encrypt_signed(clear_0);
        let ctxt_1 = cks.encrypt_signed(clear_1);
        let ctxt_condition = cks.encrypt_bool(clear_condition);

        let ct_res = executor.execute((&ctxt_condition, &ctxt_0, &ctxt_1));

        let dec_res: i64 = cks.decrypt_signed(&ct_res);
        assert_eq!(dec_res, if clear_condition { clear_0 } else { clear_1 });
    }
}
