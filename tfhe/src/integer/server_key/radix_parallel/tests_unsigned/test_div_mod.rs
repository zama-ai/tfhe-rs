use crate::integer::keycache::KEY_CACHE;
use crate::integer::server_key::radix_parallel::tests_cases_unsigned::FunctionExecutor;
use crate::integer::server_key::radix_parallel::tests_unsigned::{
    nb_tests_smaller_for_params, CpuFunctionExecutor, NB_CTXT,
};
use crate::integer::tests::create_parametrized_test;
use crate::integer::{IntegerKeyKind, RadixCiphertext, RadixClientKey, ServerKey};
#[cfg(tarpaulin)]
use crate::shortint::parameters::coverage_parameters::*;
use crate::shortint::parameters::*;
use rand::Rng;
use std::sync::Arc;

create_parametrized_test!(
    integer_smart_div_rem {
        coverage => {
            COVERAGE_PARAM_MESSAGE_2_CARRY_2_KS_PBS,
            COVERAGE_PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_2_KS_PBS,
        },
        no_coverage => {
            // Due to the use of comparison,
            // this algorithm requires 3 bits
            PARAM_MESSAGE_2_CARRY_2_KS_PBS,
            PARAM_MESSAGE_3_CARRY_3_KS_PBS,
            PARAM_MESSAGE_4_CARRY_4_KS_PBS,
            PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_2_KS_PBS,
            PARAM_MULTI_BIT_MESSAGE_3_CARRY_3_GROUP_2_KS_PBS,
            PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_3_KS_PBS,
            PARAM_MULTI_BIT_MESSAGE_3_CARRY_3_GROUP_3_KS_PBS,
        }
    }
);
create_parametrized_test!(
    integer_smart_div {
        coverage => {
            COVERAGE_PARAM_MESSAGE_2_CARRY_2_KS_PBS,
            COVERAGE_PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_2_KS_PBS,
        },
        no_coverage => {
            // Due to the use of comparison,
            // this algorithm requires 3 bits
            PARAM_MESSAGE_2_CARRY_2_KS_PBS,
            PARAM_MESSAGE_3_CARRY_3_KS_PBS,
            PARAM_MESSAGE_4_CARRY_4_KS_PBS,
            PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_2_KS_PBS,
            PARAM_MULTI_BIT_MESSAGE_3_CARRY_3_GROUP_2_KS_PBS,
            PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_3_KS_PBS,
            PARAM_MULTI_BIT_MESSAGE_3_CARRY_3_GROUP_3_KS_PBS,
        }
    }
);
create_parametrized_test!(
    integer_smart_rem {
        coverage => {
            COVERAGE_PARAM_MESSAGE_2_CARRY_2_KS_PBS,
            COVERAGE_PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_2_KS_PBS,
        },
        no_coverage => {
            // Due to the use of comparison,
            // this algorithm requires 3 bits
            PARAM_MESSAGE_2_CARRY_2_KS_PBS,
            PARAM_MESSAGE_3_CARRY_3_KS_PBS,
            PARAM_MESSAGE_4_CARRY_4_KS_PBS,
            PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_2_KS_PBS,
            PARAM_MULTI_BIT_MESSAGE_3_CARRY_3_GROUP_2_KS_PBS,
            PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_3_KS_PBS,
            PARAM_MULTI_BIT_MESSAGE_3_CARRY_3_GROUP_3_KS_PBS,
        }
    }
);
create_parametrized_test!(
    integer_default_div_rem {
        coverage => {
            COVERAGE_PARAM_MESSAGE_2_CARRY_2_KS_PBS,
            COVERAGE_PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_2_KS_PBS,
        },
        no_coverage => {
            // Due to the use of comparison,
            // this algorithm requires 3 bits
            PARAM_MESSAGE_2_CARRY_2_KS_PBS,
            PARAM_MESSAGE_3_CARRY_3_KS_PBS,
            PARAM_MESSAGE_4_CARRY_4_KS_PBS,
            PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_2_KS_PBS,
            PARAM_MULTI_BIT_MESSAGE_3_CARRY_3_GROUP_2_KS_PBS,
            PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_3_KS_PBS,
            PARAM_MULTI_BIT_MESSAGE_3_CARRY_3_GROUP_3_KS_PBS,
        }
    }
);
create_parametrized_test!(
    integer_default_rem {
        coverage => {
            COVERAGE_PARAM_MESSAGE_2_CARRY_2_KS_PBS,
            COVERAGE_PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_2_KS_PBS,
        },
        no_coverage => {
            // Due to the use of comparison,
            // this algorithm requires 3 bits
            PARAM_MESSAGE_2_CARRY_2_KS_PBS,
            PARAM_MESSAGE_3_CARRY_3_KS_PBS,
            PARAM_MESSAGE_4_CARRY_4_KS_PBS,
            PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_2_KS_PBS,
            PARAM_MULTI_BIT_MESSAGE_3_CARRY_3_GROUP_2_KS_PBS,
            PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_3_KS_PBS,
            PARAM_MULTI_BIT_MESSAGE_3_CARRY_3_GROUP_3_KS_PBS,
        }
    }
);
create_parametrized_test!(
    integer_default_div {
        coverage => {
            COVERAGE_PARAM_MESSAGE_2_CARRY_2_KS_PBS,
            COVERAGE_PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_2_KS_PBS,
        },
        no_coverage => {
            // Due to the use of comparison,
            // this algorithm requires 3 bits
            PARAM_MESSAGE_2_CARRY_2_KS_PBS,
            PARAM_MESSAGE_3_CARRY_3_KS_PBS,
            PARAM_MESSAGE_4_CARRY_4_KS_PBS,
            PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_2_KS_PBS,
            PARAM_MULTI_BIT_MESSAGE_3_CARRY_3_GROUP_2_KS_PBS,
            PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_3_KS_PBS,
            PARAM_MULTI_BIT_MESSAGE_3_CARRY_3_GROUP_3_KS_PBS,
        }
    }
);

fn integer_smart_div_rem<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::smart_div_rem_parallelized);
    smart_div_rem_test(param, executor);
}

fn integer_smart_div<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::smart_div_parallelized);
    smart_div_test(param, executor);
}

fn integer_smart_rem<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::smart_rem_parallelized);
    smart_rem_test(param, executor);
}

fn integer_default_div_rem<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::div_rem_parallelized);
    default_div_rem_test(param, executor);
}

fn integer_default_div<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::div_parallelized);
    default_div_test(param, executor);
}

fn integer_default_rem<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::rem_parallelized);
    default_rem_test(param, executor);
}

pub(crate) fn default_div_rem_test<P, T>(param: P, mut executor: T)
where
    P: Into<PBSParameters>,
    T: for<'a> FunctionExecutor<
        (&'a RadixCiphertext, &'a RadixCiphertext),
        (RadixCiphertext, RadixCiphertext),
    >,
{
    let param = param.into();
    let (cks, mut sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let cks = RadixClientKey::from((cks, NB_CTXT));
    let nb_tests_smaller = nb_tests_smaller_for_params(param);

    sks.set_deterministic_pbs_execution(true);
    let sks = Arc::new(sks);

    let mut rng = rand::thread_rng();

    // message_modulus^vec_length
    let modulus = cks
        .parameters()
        .message_modulus()
        .0
        .pow(crate::integer::server_key::radix_parallel::tests_cases_unsigned::NB_CTXT as u32)
        as u64;

    executor.setup(&cks, sks.clone());

    // Test case of division by 0
    // This is mainly to show we know the behaviour of division by 0
    // using the current algorithm
    for clear_0 in [0, rng.gen::<u64>() % modulus] {
        let ctxt_0 = cks.encrypt(clear_0);
        let ctxt_1 = cks.encrypt(0u64);

        let (q_res, r_res) = executor.execute((&ctxt_0, &ctxt_1));
        let q: u64 = cks.decrypt(&q_res);
        let r: u64 = cks.decrypt(&r_res);

        assert_eq!(r, clear_0);
        assert_eq!(q, modulus - 1);
    }

    for _ in 0..nb_tests_smaller {
        let mut clear_0 = rng.gen::<u64>() % modulus;
        let clear_1 = rng.gen_range(1..modulus); // avoid division by zero
        let clear_2 = rng.gen::<u64>() % modulus;

        let mut ctxt_0 = cks.encrypt(clear_0);
        let ctxt_1 = cks.encrypt(clear_1);

        // add to change degree
        sks.unchecked_scalar_add_assign(&mut ctxt_0, clear_2);
        clear_0 += clear_2;
        clear_0 %= modulus;

        let (q_res, r_res) = executor.execute((&ctxt_0, &ctxt_1));
        let q: u64 = cks.decrypt(&q_res);
        let r: u64 = cks.decrypt(&r_res);

        assert!(q_res.block_carries_are_empty());
        assert!(r_res.block_carries_are_empty());
        assert_eq!(clear_0 / clear_1, q);
        assert_eq!(clear_0 % clear_1, r);

        let (q2, r2) = executor.execute((&ctxt_0, &ctxt_1));
        assert_eq!(q2, q_res, "Operation was not deterministic");
        assert_eq!(r2, r_res, "Operation was not deterministic");
    }
}

pub(crate) fn default_div_test<P, T>(param: P, mut executor: T)
where
    P: Into<PBSParameters>,
    T: for<'a> FunctionExecutor<(&'a RadixCiphertext, &'a RadixCiphertext), RadixCiphertext>,
{
    let param = param.into();
    let (cks, mut sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let cks = RadixClientKey::from((cks, NB_CTXT));
    let nb_tests_smaller = nb_tests_smaller_for_params(param);

    sks.set_deterministic_pbs_execution(true);
    let sks = Arc::new(sks);

    let mut rng = rand::thread_rng();

    // message_modulus^vec_length
    let modulus = cks.parameters().message_modulus().0.pow(NB_CTXT as u32) as u64;

    executor.setup(&cks, sks.clone());

    for _ in 0..nb_tests_smaller {
        let mut clear_0 = rng.gen::<u64>() % modulus;
        let clear_1 = rng.gen_range(1..modulus); // avoid division by zero
        let clear_2 = rng.gen::<u64>() % modulus;

        let mut ctxt_0 = cks.encrypt(clear_0);
        let ctxt_1 = cks.encrypt(clear_1);

        // add to change degree
        sks.unchecked_scalar_add_assign(&mut ctxt_0, clear_2);
        clear_0 += clear_2;
        clear_0 %= modulus;

        let q_res = executor.execute((&ctxt_0, &ctxt_1));
        let q: u64 = cks.decrypt(&q_res);

        assert!(q_res.block_carries_are_empty());
        assert_eq!(clear_0 / clear_1, q);

        // Determinism checks
        let q2 = executor.execute((&ctxt_0, &ctxt_1));
        assert_eq!(q2, q_res, "Operation was not deterministic");
    }
}

pub(crate) fn default_rem_test<P, T>(param: P, mut executor: T)
where
    P: Into<PBSParameters>,
    T: for<'a> FunctionExecutor<(&'a RadixCiphertext, &'a RadixCiphertext), RadixCiphertext>,
{
    let param = param.into();
    let (cks, mut sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let cks = RadixClientKey::from((cks, NB_CTXT));
    let nb_tests_smaller = nb_tests_smaller_for_params(param);

    sks.set_deterministic_pbs_execution(true);
    let sks = Arc::new(sks);

    let mut rng = rand::thread_rng();

    // message_modulus^vec_length
    let modulus = cks.parameters().message_modulus().0.pow(NB_CTXT as u32) as u64;

    executor.setup(&cks, sks.clone());

    for _ in 0..nb_tests_smaller {
        let mut clear_0 = rng.gen::<u64>() % modulus;
        let clear_1 = rng.gen_range(1..modulus); // avoid division by zero
        let clear_2 = rng.gen::<u64>() % modulus;

        let mut ctxt_0 = cks.encrypt(clear_0);
        let ctxt_1 = cks.encrypt(clear_1);

        // add to change degree
        sks.unchecked_scalar_add_assign(&mut ctxt_0, clear_2);
        clear_0 += clear_2;
        clear_0 %= modulus;

        let r_res = executor.execute((&ctxt_0, &ctxt_1));
        let r: u64 = cks.decrypt(&r_res);

        assert!(r_res.block_carries_are_empty());
        assert_eq!(clear_0 % clear_1, r);

        // Determinism checks
        let r2 = executor.execute((&ctxt_0, &ctxt_1));
        assert_eq!(r2, r_res, "Operation was not deterministic");
    }
}

pub(crate) fn smart_div_rem_test<P, T>(param: P, mut executor: T)
where
    P: Into<PBSParameters>,
    T: for<'a> FunctionExecutor<
        (&'a mut RadixCiphertext, &'a mut RadixCiphertext),
        (RadixCiphertext, RadixCiphertext),
    >,
{
    let param = param.into();
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let sks = Arc::new(sks);
    let cks = RadixClientKey::from((cks, NB_CTXT));
    let nb_tests_smaller = nb_tests_smaller_for_params(param);

    let mut rng = rand::thread_rng();

    // message_modulus^vec_length
    let modulus = cks.parameters().message_modulus().0.pow(NB_CTXT as u32) as u64;

    executor.setup(&cks, sks.clone());

    for _ in 0..nb_tests_smaller {
        let mut clear_0 = rng.gen::<u64>() % modulus;
        let clear_1 = rng.gen_range(1..modulus); // avoid division by zero
        let clear_2 = rng.gen::<u64>() % modulus;

        let mut ctxt_0 = cks.encrypt(clear_0);
        let mut ctxt_1 = cks.encrypt(clear_1);

        // add to change degree
        sks.unchecked_scalar_add_assign(&mut ctxt_0, clear_2);
        clear_0 += clear_2;
        clear_0 %= modulus;

        let (q_res, r_res) = executor.execute((&mut ctxt_0, &mut ctxt_1));
        let q: u64 = cks.decrypt(&q_res);
        let r: u64 = cks.decrypt(&r_res);

        assert_eq!(clear_0 / clear_1, q);
        assert_eq!(clear_0 % clear_1, r);
    }
}

pub(crate) fn smart_div_test<P, T>(param: P, mut executor: T)
where
    P: Into<PBSParameters>,
    T: for<'a> FunctionExecutor<
        (&'a mut RadixCiphertext, &'a mut RadixCiphertext),
        RadixCiphertext,
    >,
{
    let param = param.into();
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let sks = Arc::new(sks);
    let cks = RadixClientKey::from((cks, NB_CTXT));
    let nb_tests_smaller = nb_tests_smaller_for_params(param);

    let mut rng = rand::thread_rng();

    // message_modulus^vec_length
    let modulus = cks.parameters().message_modulus().0.pow(NB_CTXT as u32) as u64;

    executor.setup(&cks, sks.clone());

    for _ in 0..nb_tests_smaller {
        let mut clear_0 = rng.gen::<u64>() % modulus;
        let clear_1 = rng.gen_range(1..modulus); // avoid division by zero
        let clear_2 = rng.gen::<u64>() % modulus;

        let mut ctxt_0 = cks.encrypt(clear_0);
        let mut ctxt_1 = cks.encrypt(clear_1);

        // add to change degree
        sks.unchecked_scalar_add_assign(&mut ctxt_0, clear_2);
        clear_0 += clear_2;
        clear_0 %= modulus;

        let q_res = executor.execute((&mut ctxt_0, &mut ctxt_1));
        let q: u64 = cks.decrypt(&q_res);
        assert_eq!(clear_0 / clear_1, q);
    }
}

pub(crate) fn smart_rem_test<P, T>(param: P, mut executor: T)
where
    P: Into<PBSParameters>,
    T: for<'a> FunctionExecutor<
        (&'a mut RadixCiphertext, &'a mut RadixCiphertext),
        RadixCiphertext,
    >,
{
    let param = param.into();
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let sks = Arc::new(sks);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    let mut rng = rand::thread_rng();

    // message_modulus^vec_length
    let modulus = cks.parameters().message_modulus().0.pow(NB_CTXT as u32) as u64;
    let nb_tests_smaller = nb_tests_smaller_for_params(param);

    executor.setup(&cks, sks.clone());

    for _ in 0..nb_tests_smaller {
        let mut clear_0 = rng.gen::<u64>() % modulus;
        let clear_1 = rng.gen_range(1..modulus); // avoid division by zero
        let clear_2 = rng.gen::<u64>() % modulus;

        let mut ctxt_0 = cks.encrypt(clear_0);
        let mut ctxt_1 = cks.encrypt(clear_1);

        // add to change degree
        sks.unchecked_scalar_add_assign(&mut ctxt_0, clear_2);
        clear_0 += clear_2;
        clear_0 %= modulus;

        let q_res = executor.execute((&mut ctxt_0, &mut ctxt_1));
        let q: u64 = cks.decrypt(&q_res);
        assert_eq!(clear_0 % clear_1, q);
    }
}
