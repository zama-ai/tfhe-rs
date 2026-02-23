use crate::integer::keycache::KEY_CACHE;
use crate::integer::server_key::radix_parallel::tests_cases_unsigned::FunctionExecutor;
use crate::integer::server_key::radix_parallel::tests_signed::{
    signed_div_rem_floor_under_modulus, signed_div_under_modulus, signed_rem_under_modulus, NB_CTXT,
};
use crate::integer::server_key::radix_parallel::tests_unsigned::{
    nb_tests_smaller_for_params, CpuFunctionExecutor,
};
use crate::integer::tests::create_parameterized_test;
use crate::integer::{IntegerKeyKind, RadixClientKey, ServerKey, SignedRadixCiphertext};
#[cfg(tarpaulin)]
use crate::shortint::parameters::coverage_parameters::*;
use crate::shortint::parameters::test_params::*;
use crate::shortint::parameters::*;
use rand::Rng;
use std::sync::Arc;

create_parameterized_test!(
    integer_signed_unchecked_div_rem {
        coverage => {
            COVERAGE_PARAM_MESSAGE_2_CARRY_2_KS_PBS,
            COVERAGE_PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_2_KS_PBS,
        },
        no_coverage => {
            // Does not support 1_1
            PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
            TEST_PARAM_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M128,
            // 2M128 is too slow for 4_4, it is estimated to be 2x slower
            TEST_PARAM_MESSAGE_4_CARRY_4_KS_PBS_GAUSSIAN_2M64,
            TEST_PARAM_MULTI_BIT_GROUP_2_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64,
            TEST_PARAM_MULTI_BIT_GROUP_2_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M64,
            TEST_PARAM_MULTI_BIT_GROUP_3_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64,
            TEST_PARAM_MULTI_BIT_GROUP_3_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M64,
        }
    }
);
create_parameterized_test!(
    integer_signed_unchecked_div_rem_floor {
        coverage => {
            COVERAGE_PARAM_MESSAGE_2_CARRY_2_KS_PBS,
            COVERAGE_PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_2_KS_PBS,
        },
        no_coverage => {
            // Does not support 1_1
            PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
            TEST_PARAM_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M128,
            // 2M128 is too slow for 4_4, it is estimated to be 2x slower
            TEST_PARAM_MESSAGE_4_CARRY_4_KS_PBS_GAUSSIAN_2M64,
            TEST_PARAM_MULTI_BIT_GROUP_2_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64,
            TEST_PARAM_MULTI_BIT_GROUP_2_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M64,
            TEST_PARAM_MULTI_BIT_GROUP_3_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64,
            TEST_PARAM_MULTI_BIT_GROUP_3_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M64,
        }
    }
);
fn integer_signed_unchecked_div_rem<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::unchecked_div_rem_parallelized);
    signed_unchecked_div_rem_test(param, executor);
}

fn integer_signed_unchecked_div_rem_floor<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::unchecked_div_rem_floor_parallelized);
    signed_unchecked_div_rem_floor_test(param, executor);
}

pub(crate) fn signed_unchecked_div_rem_test<P, T>(param: P, mut executor: T)
where
    P: Into<TestParameters>,
    T: for<'a> FunctionExecutor<
        (&'a SignedRadixCiphertext, &'a SignedRadixCiphertext),
        (SignedRadixCiphertext, SignedRadixCiphertext),
    >,
{
    let param = param.into();
    let nb_tests_smaller = nb_tests_smaller_for_params(param);
    let (cks, mut sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    sks.set_deterministic_pbs_execution(true);
    let sks = Arc::new(sks);

    executor.setup(&cks, sks);

    let mut rng = rand::rng();

    let modulus = (cks.parameters().message_modulus().0.pow(NB_CTXT as u32) / 2) as i64;

    // Test case of division by 0
    // This is mainly to show we know the behaviour of division by 0
    // using the current algorithm
    for clear_0 in [0i64, rng.gen::<i64>() % modulus] {
        let ctxt_0 = cks.encrypt_signed(clear_0);
        let ctxt_1 = cks.encrypt_signed(0);

        let (q_res, r_res) = executor.execute((&ctxt_0, &ctxt_1));
        let q: i64 = cks.decrypt_signed(&q_res);
        let r: i64 = cks.decrypt_signed(&r_res);

        assert_eq!(r, clear_0);
        assert_eq!(q, if clear_0 >= 0 { -1 } else { 1 });
    }

    // Div is the slowest operation
    for _ in 0..nb_tests_smaller {
        let clear_0 = rng.gen::<i64>() % modulus;
        let clear_1 = loop {
            let value = rng.gen::<i64>() % modulus;
            if value != 0 {
                break value;
            }
        };

        let ctxt_0 = cks.encrypt_signed(clear_0);
        let ctxt_1 = cks.encrypt_signed(clear_1);

        let (q_res, r_res) = executor.execute((&ctxt_0, &ctxt_1));
        let q: i64 = cks.decrypt_signed(&q_res);
        let r: i64 = cks.decrypt_signed(&r_res);
        let expected_q = signed_div_under_modulus(clear_0, clear_1, modulus);
        assert_eq!(
            q, expected_q,
            "Invalid division result, for {clear_0} / {clear_1} \
            expected quotient: {expected_q} got: {q}"
        );
        let expected_r = signed_rem_under_modulus(clear_0, clear_1, modulus);
        assert_eq!(
            r, expected_r,
            "Invalid remainder result, for {clear_0} % {clear_1} \
            expected quotient: {expected_r} got: {r}"
        );
    }
}

pub(crate) fn signed_unchecked_div_rem_floor_test<P, T>(param: P, mut executor: T)
where
    P: Into<TestParameters>,
    T: for<'a> FunctionExecutor<
        (&'a SignedRadixCiphertext, &'a SignedRadixCiphertext),
        (SignedRadixCiphertext, SignedRadixCiphertext),
    >,
{
    let param = param.into();
    let (cks, mut sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    sks.set_deterministic_pbs_execution(true);
    let sks = Arc::new(sks);

    executor.setup(&cks, sks);

    let mut rng = rand::rng();

    let modulus = (cks.parameters().message_modulus().0.pow(NB_CTXT as u32) / 2) as i64;

    if modulus > 8 {
        // Some hard coded test for flooring div
        // For example, truncating_div(-7, 3) would give q = -2 and r = -1
        // truncating div is the default in rust (and many other languages)
        // Python does use a flooring div, so you can try these values in you local
        // interpreter.
        let values = [
            (-8, 3, -3, 1),
            (8, -3, -3, -1),
            (7, 3, 2, 1),
            (-7, 3, -3, 2),
            (7, -3, -3, -2),
            (-7, -3, 2, -1),
        ];
        for (clear_0, clear_1, expected_q, expected_r) in values {
            let ctxt_0 = cks.encrypt_signed(clear_0);
            let ctxt_1 = cks.encrypt_signed(clear_1);

            let (q_res, r_res) = executor.execute((&ctxt_0, &ctxt_1));
            let q: i64 = cks.decrypt_signed(&q_res);
            let r: i64 = cks.decrypt_signed(&r_res);

            // Uses the hardcoded values to also test our clear function
            let (q2, r2) = signed_div_rem_floor_under_modulus(clear_0, clear_1, modulus);

            assert_eq!(q2, expected_q);
            assert_eq!(r2, expected_r);
            assert_eq!(q, expected_q);
            assert_eq!(r, expected_r);
        }
    }

    // A test where the division is whole, aka remainder is zero
    {
        let ctxt_0 = cks.encrypt_signed(4);
        let ctxt_1 = cks.encrypt_signed(-2);

        let (q_res, r_res) = executor.execute((&ctxt_0, &ctxt_1));
        let q: i64 = cks.decrypt_signed(&q_res);
        let r: i64 = cks.decrypt_signed(&r_res);

        // Uses the hardcoded values to also test our clear function
        let (q2, r2) = signed_div_rem_floor_under_modulus(4, -2, modulus);

        assert_eq!(q2, -2);
        assert_eq!(r2, 0);
        assert_eq!(q, -2);
        assert_eq!(r, 0);
    }

    // Div is the slowest operation
    for _ in 0..5 {
        let clear_0 = rng.gen::<i64>() % modulus;
        let clear_1 = loop {
            let value = rng.gen::<i64>() % modulus;
            if value != 0 {
                break value;
            }
        };

        let ctxt_0 = cks.encrypt_signed(clear_0);
        let ctxt_1 = cks.encrypt_signed(clear_1);

        let (q_res, r_res) = executor.execute((&ctxt_0, &ctxt_1));
        let q: i64 = cks.decrypt_signed(&q_res);
        let r: i64 = cks.decrypt_signed(&r_res);
        let (expected_q, expected_r) =
            signed_div_rem_floor_under_modulus(clear_0, clear_1, modulus);

        println!("{clear_0} / {clear_1} -> ({q}, {r})");
        assert_eq!(q, expected_q);
        assert_eq!(r, expected_r);
    }
}
