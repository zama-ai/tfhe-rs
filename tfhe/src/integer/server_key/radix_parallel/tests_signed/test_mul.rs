use crate::integer::keycache::KEY_CACHE;
use crate::integer::server_key::radix_parallel::tests_cases_unsigned::FunctionExecutor;
use crate::integer::server_key::radix_parallel::tests_signed::{
    create_iterator_of_signed_random_pairs, overflowing_mul_under_modulus, random_non_zero_value,
    signed_add_under_modulus, signed_mul_under_modulus, NB_CTXT, NB_TESTS_SMALLER,
    NB_TESTS_UNCHECKED,
};
use crate::integer::server_key::radix_parallel::tests_unsigned::CpuFunctionExecutor;
use crate::integer::tests::create_parametrized_test;
use crate::integer::{IntegerKeyKind, RadixClientKey, ServerKey, SignedRadixCiphertext};
#[cfg(tarpaulin)]
use crate::shortint::parameters::coverage_parameters::*;
use crate::shortint::parameters::*;
use rand::Rng;
use std::sync::Arc;

create_parametrized_test!(integer_signed_unchecked_mul);
create_parametrized_test!(integer_signed_default_mul);
create_parametrized_test!(
    integer_signed_default_overflowing_mul {
        coverage => {
            COVERAGE_PARAM_MESSAGE_2_CARRY_2_KS_PBS,
            COVERAGE_PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_2_KS_PBS,
        },
        no_coverage => {
            // Uses comparisons internally, so no 1_1
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

fn integer_signed_unchecked_mul<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::unchecked_mul_parallelized);
    signed_unchecked_mul_test(param, executor);
}

fn integer_signed_default_mul<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::mul_parallelized);
    signed_default_mul_test(param, executor);
}

fn integer_signed_default_overflowing_mul(param: impl Into<PBSParameters>) {
    let (cks, mut sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    sks.set_deterministic_pbs_execution(true);

    let mut rng = rand::thread_rng();

    // message_modulus^vec_length
    let modulus = (cks.parameters().message_modulus().0.pow(NB_CTXT as u32) / 2) as i64;

    const NB_HARDCODED_VALUES: usize = 3;
    let mut test_inputs = [(0i64, 0i64); NB_TESTS_SMALLER + NB_HARDCODED_VALUES];
    test_inputs[0] = (0i64, -modulus);
    test_inputs[1] = (-modulus, 3);
    test_inputs[2] = (-1, 26);
    for inputs in &mut test_inputs[NB_HARDCODED_VALUES..] {
        let clear_0 = rng.gen::<i64>() % modulus;
        let clear_1 = rng.gen::<i64>() % modulus;
        *inputs = (clear_0, clear_1);
    }

    for (clear_0, clear_1) in test_inputs {
        let ctxt_0 = cks.encrypt_signed(clear_0);
        let ctxt_1 = cks.encrypt_signed(clear_1);

        let (ct_res, result_overflowed) = sks.signed_overflowing_mul_parallelized(&ctxt_0, &ctxt_1);
        let (tmp_ct, tmp_o) = sks.signed_overflowing_mul_parallelized(&ctxt_0, &ctxt_1);
        assert!(ct_res.block_carries_are_empty());
        assert_eq!(ct_res, tmp_ct, "Failed determinism check");
        assert_eq!(tmp_o, result_overflowed, "Failed determinism check");

        let (expected_result, expected_overflowed) =
            overflowing_mul_under_modulus(clear_0, clear_1, modulus);

        let decrypted_result: i64 = cks.decrypt_signed(&ct_res);
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

        for _ in 0..NB_TESTS_SMALLER {
            // Add non zero scalar to have non clean ciphertexts
            let clear_2 = random_non_zero_value(&mut rng, modulus);
            let clear_3 = random_non_zero_value(&mut rng, modulus);

            let ctxt_lhs = sks.unchecked_scalar_add(&ctxt_0, clear_2);
            let ctxt_rhs = sks.unchecked_scalar_add(&ctxt_1, clear_3);

            let clear_lhs = signed_add_under_modulus(clear_0, clear_2, modulus);
            let clear_rhs = signed_add_under_modulus(clear_1, clear_3, modulus);

            let d0: i64 = cks.decrypt_signed(&ctxt_lhs);
            assert_eq!(d0, clear_lhs, "Failed sanity decryption check");
            let d1: i64 = cks.decrypt_signed(&ctxt_rhs);
            assert_eq!(d1, clear_rhs, "Failed sanity decryption check");

            let (ct_res, result_overflowed) =
                sks.signed_overflowing_mul_parallelized(&ctxt_lhs, &ctxt_rhs);
            assert!(ct_res.block_carries_are_empty());

            let (expected_result, expected_overflowed) =
                overflowing_mul_under_modulus(clear_lhs, clear_rhs, modulus);

            let decrypted_result: i64 = cks.decrypt_signed(&ct_res);
            let decrypted_overflowed = cks.decrypt_bool(&result_overflowed);
            assert_eq!(
                decrypted_result, expected_result,
                "Invalid result for mul, for ({clear_lhs} * {clear_rhs}) % {modulus} \
               expected {expected_result}, got {decrypted_result}"
            );
            assert_eq!(
                decrypted_overflowed,
                expected_overflowed,
                "Invalid overflow flag result for overflowing_mul, for ({clear_lhs} * {clear_rhs}) % {modulus}
                 expected overflow flag {expected_overflowed}, got {decrypted_overflowed}"
            );
            assert_eq!(result_overflowed.0.degree.get(), 1);
            assert_eq!(result_overflowed.0.noise_level(), NoiseLevel::NOMINAL);
        }
    }

    let values = [
        (rng.gen::<i64>() % modulus, rng.gen::<i64>() % modulus),
        (rng.gen::<i64>() % modulus, rng.gen::<i64>() % modulus),
        (rng.gen::<i64>() % modulus, rng.gen::<i64>() % modulus),
        (rng.gen::<i64>() % modulus, rng.gen::<i64>() % modulus),
        (rng.gen::<i64>() % modulus, 0),
        (0, rng.gen::<i64>() % modulus),
        (0i64, -modulus),
        (-modulus, 3),
    ];
    for (clear_0, clear_1) in values {
        let a: SignedRadixCiphertext = sks.create_trivial_radix(clear_0, NB_CTXT);
        let b: SignedRadixCiphertext = sks.create_trivial_radix(clear_1, NB_CTXT);

        let (encrypted_result, encrypted_overflow) =
            sks.signed_overflowing_mul_parallelized(&a, &b);

        let (expected_result, expected_overflowed) =
            overflowing_mul_under_modulus(clear_0, clear_1, modulus);

        let decrypted_result: i64 = cks.decrypt_signed(&encrypted_result);
        let decrypted_overflowed = cks.decrypt_bool(&encrypted_overflow);
        assert_eq!(
            decrypted_result, expected_result,
            "Invalid result for mul, for ({clear_0} * {clear_1}) % {modulus} \
            expected {expected_result}, got {decrypted_result}"
        );
        assert_eq!(
            decrypted_overflowed,
            expected_overflowed,
            "Invalid overflow flag result for overflowing_mul, for ({clear_0}  {clear_1}) %  {modulus}
             expected overflow flag {expected_overflowed}, got {decrypted_overflowed}"
        );
        assert_eq!(encrypted_overflow.0.degree.get(), 1);
        assert_eq!(encrypted_overflow.0.noise_level(), NoiseLevel::ZERO);
    }
}

pub(crate) fn signed_unchecked_mul_test<P, T>(param: P, mut executor: T)
where
    P: Into<PBSParameters>,
    T: for<'a> FunctionExecutor<
        (&'a SignedRadixCiphertext, &'a SignedRadixCiphertext),
        SignedRadixCiphertext,
    >,
{
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let cks = RadixClientKey::from((cks, NB_CTXT));
    let sks = Arc::new(sks);

    let mut rng = rand::thread_rng();

    let modulus = (cks.parameters().message_modulus().0.pow(NB_CTXT as u32) / 2) as i64;

    executor.setup(&cks, sks);

    for (clear_0, clear_1) in
        create_iterator_of_signed_random_pairs::<{ NB_TESTS_UNCHECKED }>(&mut rng, modulus)
    {
        let ctxt_0 = cks.encrypt_signed(clear_0);
        let ctxt_1 = cks.encrypt_signed(clear_1);

        let ct_res = executor.execute((&ctxt_0, &ctxt_1));
        let dec_res: i64 = cks.decrypt_signed(&ct_res);
        let clear_res = signed_mul_under_modulus(clear_0, clear_1, modulus);
        assert_eq!(clear_res, dec_res);
    }
}

pub(crate) fn signed_default_mul_test<P, T>(param: P, mut executor: T)
where
    P: Into<PBSParameters>,
    T: for<'a> FunctionExecutor<
        (&'a SignedRadixCiphertext, &'a SignedRadixCiphertext),
        SignedRadixCiphertext,
    >,
{
    let (cks, mut sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    sks.set_deterministic_pbs_execution(true);
    let sks = Arc::new(sks);

    let mut rng = rand::thread_rng();

    // message_modulus^vec_length
    let modulus = (cks.parameters().message_modulus().0.pow(NB_CTXT as u32) / 2) as i64;

    executor.setup(&cks, sks);

    let mut clear;

    for _ in 0..NB_TESTS_SMALLER {
        let clear_0 = rng.gen::<i64>() % modulus;
        let clear_1 = rng.gen::<i64>() % modulus;

        let ctxt_0 = cks.encrypt_signed(clear_0);
        let ctxt_1 = cks.encrypt_signed(clear_1);

        let mut ct_res = executor.execute((&ctxt_0, &ctxt_1));
        let tmp_ct = executor.execute((&ctxt_0, &ctxt_1));
        assert!(ct_res.block_carries_are_empty());
        assert_eq!(ct_res, tmp_ct);

        clear = signed_mul_under_modulus(clear_0, clear_1, modulus);

        // mul multiple times to raise the degree
        for _ in 0..NB_TESTS_SMALLER {
            ct_res = executor.execute((&ct_res, &ctxt_0));
            assert!(ct_res.block_carries_are_empty());
            clear = signed_mul_under_modulus(clear, clear_0, modulus);

            let dec_res: i64 = cks.decrypt_signed(&ct_res);

            // println!("clear = {}, dec_res = {}", clear, dec_res);
            assert_eq!(clear, dec_res);
        }
    }
}
