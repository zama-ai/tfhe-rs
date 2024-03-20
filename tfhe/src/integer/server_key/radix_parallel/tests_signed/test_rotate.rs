use crate::integer::keycache::KEY_CACHE;
use crate::integer::server_key::radix_parallel::tests_cases_unsigned::FunctionExecutor;
use crate::integer::server_key::radix_parallel::tests_signed::{
    random_non_zero_value, rotate_left_helper, rotate_right_helper, signed_add_under_modulus,
    NB_CTXT, NB_TESTS, NB_TESTS_SMALLER,
};
use crate::integer::server_key::radix_parallel::tests_unsigned::CpuFunctionExecutor;
use crate::integer::tests::create_parametrized_test;
use crate::integer::{
    IntegerKeyKind, RadixCiphertext, RadixClientKey, ServerKey, SignedRadixCiphertext,
};
#[cfg(tarpaulin)]
use crate::shortint::parameters::coverage_parameters::*;
use crate::shortint::parameters::*;
use rand::Rng;
use std::sync::Arc;

create_parametrized_test!(
    integer_signed_unchecked_rotate_right {
        coverage => {
            COVERAGE_PARAM_MESSAGE_2_CARRY_2_KS_PBS,
            COVERAGE_PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_2_KS_PBS,
        },
        no_coverage => {
            // Requires 4 bits, so 1_1 parameters are not supported
            // until they get their own version of the algorithm
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
    integer_signed_unchecked_rotate_left {
        coverage => {
            COVERAGE_PARAM_MESSAGE_2_CARRY_2_KS_PBS,
            COVERAGE_PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_2_KS_PBS,
        },
        no_coverage => {
            // Requires 4 bits, so 1_1 parameters are not supported
            // until they get their own version of the algorithm
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
    integer_signed_rotate_right {
        coverage => {
            COVERAGE_PARAM_MESSAGE_2_CARRY_2_KS_PBS,
            COVERAGE_PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_2_KS_PBS,
        },
        no_coverage => {
            // Requires 4 bits, so 1_1 parameters are not supported
            // until they get their own version of the algorithm
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
    integer_signed_rotate_left {
        coverage => {
            COVERAGE_PARAM_MESSAGE_2_CARRY_2_KS_PBS,
            COVERAGE_PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_2_KS_PBS,
        },
        no_coverage => {
            // Requires 4 bits, so 1_1 parameters are not supported
            // until they get their own version of the algorithm
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

pub(crate) fn signed_default_rotate_left_test<P, T>(param: P, mut executor: T)
where
    P: Into<PBSParameters>,
    T: for<'a> FunctionExecutor<
        (&'a SignedRadixCiphertext, &'a RadixCiphertext),
        SignedRadixCiphertext,
    >,
{
    let (cks, mut sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let cks = RadixClientKey::from((cks, NB_CTXT));
    sks.set_deterministic_pbs_execution(true);
    let sks = Arc::new(sks);

    let mut rng = rand::thread_rng();

    executor.setup(&cks, sks.clone());

    let modulus = (cks.parameters().message_modulus().0.pow(NB_CTXT as u32) / 2) as i64;

    assert!(modulus > 0);
    assert!((modulus as u64).is_power_of_two());
    let nb_bits = modulus.ilog2() + 1; // We are using signed numbers

    for _ in 0..NB_TESTS_SMALLER {
        let mut clear = rng.gen::<i64>() % modulus;

        let offset = random_non_zero_value(&mut rng, modulus);

        let mut ct = cks.encrypt_signed(clear);
        sks.unchecked_scalar_add_assign(&mut ct, offset);
        clear = signed_add_under_modulus(clear, offset, modulus);

        // case when 0 <= shift < nb_bits
        {
            // Here we create a encrypted shift value in range O..nb_bits
            // in a way that the shift ciphertext is seen as having non empty carries
            let clear_shift = rng.gen::<u32>() % nb_bits;
            let tmp = cks.encrypt(clear_shift);
            let mut shift = cks.encrypt(0u32);
            sks.unchecked_add_assign(&mut shift, &tmp);
            assert!(!shift.block_carries_are_empty());

            let ct_res = executor.execute((&ct, &shift));
            let dec_res: i64 = cks.decrypt_signed(&ct_res);
            let clear_res = rotate_left_helper(clear, clear_shift, nb_bits);
            assert_eq!(
                clear_res, dec_res,
                "Invalid left shift result, for '{clear}.rotate_left({clear_shift})', \
                expected:  {clear_res}, got: {dec_res}"
            );

            let ct_res2 = executor.execute((&ct, &shift));
            assert_eq!(ct_res, ct_res2, "Failed determinism check");
        }

        // case when shift >= nb_bits
        {
            // Here we create a encrypted shift value >= nb_bits
            // in a way that the shift ciphertext is seen as having non empty carries
            let mut clear_shift = rng.gen::<u32>() % nb_bits;
            let tmp = cks.encrypt(clear_shift);
            let mut shift = cks.encrypt(nb_bits);
            sks.unchecked_add_assign(&mut shift, &tmp);
            clear_shift += nb_bits;
            assert!(!shift.block_carries_are_empty());

            let ct_res = executor.execute((&ct, &shift));
            let dec_res: i64 = cks.decrypt_signed(&ct_res);
            // When nb_bits is not a power of two
            // then the behaviour is not the same
            let true_nb_bits = nb_bits;
            let mut nb_bits = modulus.ilog2();
            if !nb_bits.is_power_of_two() {
                nb_bits = nb_bits.next_power_of_two();
            }
            // We mimic wrapping_shl manually as we use a bigger type
            // than the nb_bits we actually simulate in this test
            let clear_res = rotate_left_helper(clear, clear_shift % nb_bits, true_nb_bits);
            assert_eq!(
                clear_res,
                dec_res,
                "Invalid rotate left result, for '{clear}.rotate_left({})', \
                expected:  {clear_res}, got: {dec_res}",
                clear_shift % nb_bits
            );

            let ct_res2 = executor.execute((&ct, &shift));
            assert_eq!(ct_res, ct_res2, "Failed determinism check");
        }
    }
}

pub(crate) fn signed_default_rotate_right_test<P, T>(param: P, mut executor: T)
where
    P: Into<PBSParameters>,
    T: for<'a> FunctionExecutor<
        (&'a SignedRadixCiphertext, &'a RadixCiphertext),
        SignedRadixCiphertext,
    >,
{
    let (cks, mut sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let cks = RadixClientKey::from((cks, NB_CTXT));
    sks.set_deterministic_pbs_execution(true);
    let sks = Arc::new(sks);

    let mut rng = rand::thread_rng();

    executor.setup(&cks, sks.clone());

    let modulus = (cks.parameters().message_modulus().0.pow(NB_CTXT as u32) / 2) as i64;

    assert!(modulus > 0);
    assert!((modulus as u64).is_power_of_two());
    let nb_bits = modulus.ilog2() + 1; // We are using signed numbers

    for _ in 0..NB_TESTS_SMALLER {
        let mut clear = rng.gen::<i64>() % modulus;

        let offset = random_non_zero_value(&mut rng, modulus);

        let mut ct = cks.encrypt_signed(clear);
        sks.unchecked_scalar_add_assign(&mut ct, offset);
        clear = signed_add_under_modulus(clear, offset, modulus);

        // case when 0 <= shift < nb_bits
        {
            // Here we create a encrypted shift value in range O..nb_bits
            // in a way that the shift ciphertext is seen as having non empty carries
            let clear_shift = rng.gen::<u32>() % nb_bits;
            let tmp = cks.encrypt(clear_shift);
            let mut shift = cks.encrypt(0u32);
            sks.unchecked_add_assign(&mut shift, &tmp);
            assert!(!shift.block_carries_are_empty());

            let ct_res = executor.execute((&ct, &shift));
            let dec_res: i64 = cks.decrypt_signed(&ct_res);
            let clear_res = rotate_right_helper(clear, clear_shift, nb_bits);
            assert_eq!(
                clear_res, dec_res,
                "Invalid right shift result, for '{clear}.rotate_right({clear_shift})', \
                expected:  {clear_res}, got: {dec_res}"
            );

            let ct_res2 = executor.execute((&ct, &shift));
            assert_eq!(ct_res, ct_res2, "Failed determinism check");
        }

        // case when shift >= nb_bits
        {
            // Here we create a encrypted shift value >= nb_bits
            // in a way that the shift ciphertext is seen as having non empty carries
            let mut clear_shift = rng.gen::<u32>() % nb_bits;
            let tmp = cks.encrypt(clear_shift);
            let mut shift = cks.encrypt(nb_bits);
            sks.unchecked_add_assign(&mut shift, &tmp);
            clear_shift += nb_bits;
            assert!(!shift.block_carries_are_empty());

            let ct_res = executor.execute((&ct, &shift));
            let dec_res: i64 = cks.decrypt_signed(&ct_res);
            // When nb_bits is not a power of two
            // then the behaviour is not the same
            let true_nb_bits = nb_bits;
            let mut nb_bits = modulus.ilog2();
            if !nb_bits.is_power_of_two() {
                nb_bits = nb_bits.next_power_of_two();
            }
            // We mimic wrapping_shl manually as we use a bigger type
            // than the nb_bits we actually simulate in this test
            let clear_res = rotate_right_helper(clear, clear_shift % nb_bits, true_nb_bits);
            assert_eq!(
                clear_res, dec_res,
                "Invalid rotate right result, for '{clear}.rotate_right({clear_shift})', \
                expected:  {clear_res}, got: {dec_res}"
            );

            let ct_res2 = executor.execute((&ct, &shift));
            assert_eq!(ct_res, ct_res2, "Failed determinism check");
        }
    }
}

pub(crate) fn signed_unchecked_rotate_left_test<P, T>(param: P, mut executor: T)
where
    P: Into<PBSParameters>,
    T: for<'a> FunctionExecutor<
        (&'a SignedRadixCiphertext, &'a RadixCiphertext),
        SignedRadixCiphertext,
    >,
{
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let cks = RadixClientKey::from((cks, NB_CTXT));
    let sks = Arc::new(sks);

    let mut rng = rand::thread_rng();

    executor.setup(&cks, sks);

    let modulus = (cks.parameters().message_modulus().0.pow(NB_CTXT as u32) / 2) as i64;

    assert!(modulus > 0);
    assert!((modulus as u64).is_power_of_two());
    let nb_bits = modulus.ilog2() + 1; // We are using signed numbers

    for _ in 0..NB_TESTS {
        let clear = rng.gen::<i64>() % modulus;
        let clear_shift = rng.gen::<u32>();

        let ct = cks.encrypt_signed(clear);

        // case when 0 <= rotate < nb_bits
        {
            let clear_shift = clear_shift % nb_bits;
            let shift = cks.encrypt(clear_shift as u64);
            let ct_res = executor.execute((&ct, &shift));
            let dec_res: i64 = cks.decrypt_signed(&ct_res);
            let expected = rotate_left_helper(clear, clear_shift, nb_bits);
            assert_eq!(expected, dec_res);
        }

        // case when shift >= nb_bits
        {
            let clear_shift = clear_shift.saturating_add(nb_bits);
            let shift = cks.encrypt(clear_shift as u64);
            let ct_res = executor.execute((&ct, &shift));
            let dec_res: i64 = cks.decrypt_signed(&ct_res);
            // When nb_bits is not a power of two
            // then the behaviour is not the same
            let true_nb_bits = nb_bits;
            let mut nb_bits = nb_bits;
            if !nb_bits.is_power_of_two() {
                nb_bits = nb_bits.next_power_of_two();
            }
            let expected = rotate_left_helper(clear, clear_shift % nb_bits, true_nb_bits);
            assert_eq!(expected, dec_res);
        }
    }
}

pub(crate) fn signed_unchecked_rotate_right_test<P, T>(param: P, mut executor: T)
where
    P: Into<PBSParameters>,
    T: for<'a> FunctionExecutor<
        (&'a SignedRadixCiphertext, &'a RadixCiphertext),
        SignedRadixCiphertext,
    >,
{
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let cks = RadixClientKey::from((cks, NB_CTXT));
    let sks = Arc::new(sks);

    let mut rng = rand::thread_rng();

    executor.setup(&cks, sks);

    let modulus = (cks.parameters().message_modulus().0.pow(NB_CTXT as u32) / 2) as i64;

    assert!(modulus > 0);
    assert!((modulus as u64).is_power_of_two());
    let nb_bits = modulus.ilog2() + 1; // We are using signed numbers

    for _ in 0..NB_TESTS {
        let clear = rng.gen::<i64>() % modulus;
        let clear_shift = rng.gen::<u32>();

        let ct = cks.encrypt_signed(clear);

        // case when 0 <= rotate < nb_bits
        {
            let clear_shift = clear_shift % nb_bits;
            let shift = cks.encrypt(clear_shift as u64);
            let ct_res = executor.execute((&ct, &shift));
            let dec_res: i64 = cks.decrypt_signed(&ct_res);
            let expected = rotate_right_helper(clear, clear_shift, nb_bits);
            assert_eq!(expected, dec_res);
        }

        // case when shift >= nb_bits
        {
            let clear_shift = clear_shift.saturating_add(nb_bits);
            let shift = cks.encrypt(clear_shift as u64);
            let ct_res = executor.execute((&ct, &shift));
            let dec_res: i64 = cks.decrypt_signed(&ct_res);
            // When nb_bits is not a power of two
            // then the behaviour is not the same
            let true_nb_bits = nb_bits;
            let mut nb_bits = nb_bits;
            if !nb_bits.is_power_of_two() {
                nb_bits = nb_bits.next_power_of_two();
            }
            let expected = rotate_right_helper(clear, clear_shift % nb_bits, true_nb_bits);
            assert_eq!(expected, dec_res);
        }
    }
}

fn integer_signed_unchecked_rotate_right<P>(param: P)
where
    P: Into<PBSParameters> + Copy,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::unchecked_rotate_right_parallelized);
    signed_unchecked_rotate_right_test(param, executor);
}

fn integer_signed_rotate_right<P>(param: P)
where
    P: Into<PBSParameters> + Copy,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::rotate_right_parallelized);
    signed_default_rotate_right_test(param, executor);
}

fn integer_signed_unchecked_rotate_left<P>(param: P)
where
    P: Into<PBSParameters> + Copy,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::unchecked_rotate_left_parallelized);
    signed_unchecked_rotate_left_test(param, executor);
}

fn integer_signed_rotate_left<P>(param: P)
where
    P: Into<PBSParameters> + Copy,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::rotate_left_parallelized);
    signed_default_rotate_left_test(param, executor);
}
