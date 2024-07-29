use crate::integer::keycache::KEY_CACHE;
use crate::integer::server_key::radix_parallel::ilog2::{BitValue, Direction};
use crate::integer::server_key::radix_parallel::tests_cases_unsigned::FunctionExecutor;
use crate::integer::server_key::radix_parallel::tests_signed::{
    create_iterator_of_signed_random_pairs, random_non_zero_value, signed_add_under_modulus,
    signed_overflowing_add_under_modulus, NB_CTXT,
};
use crate::integer::server_key::radix_parallel::tests_unsigned::{
    nb_tests_for_params, nb_tests_smaller_for_params, nb_unchecked_tests_for_params,
    CpuFunctionExecutor,
};
use crate::integer::tests::create_parametrized_test;
use crate::integer::{
    BooleanBlock, IntegerKeyKind, RadixCiphertext, RadixClientKey, ServerKey, SignedRadixCiphertext,
};
#[cfg(tarpaulin)]
use crate::shortint::parameters::coverage_parameters::*;
use crate::shortint::parameters::*;
use crate::shortint::PBSParameters;
use rand::Rng;
use std::sync::Arc;

create_parametrized_test!(integer_signed_default_trailing_zeros);
create_parametrized_test!(integer_signed_default_trailing_ones);
create_parametrized_test!(integer_signed_default_leading_zeros);
create_parametrized_test!(integer_signed_default_leading_ones);
create_parametrized_test!(integer_signed_default_ilog2);
create_parametrized_test!(integer_signed_default_checked_ilog2 {
    // uses comparison so 1_1 parameters are not supported
    PARAM_MESSAGE_2_CARRY_2_KS_PBS,
    PARAM_MESSAGE_3_CARRY_3_KS_PBS,
    PARAM_MESSAGE_4_CARRY_4_KS_PBS,
    PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_2_KS_PBS,
    PARAM_MULTI_BIT_MESSAGE_3_CARRY_3_GROUP_2_KS_PBS,
    PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_3_KS_PBS,
    PARAM_MULTI_BIT_MESSAGE_3_CARRY_3_GROUP_3_KS_PBS
});

fn integer_signed_default_trailing_zeros<P>(param: P)
where
    P: Into<PBSParameters>,
{
    default_trailing_zeros_test(param);
}

fn integer_signed_default_trailing_ones<P>(param: P)
where
    P: Into<PBSParameters>,
{
    default_trailing_ones_test(param);
}

fn integer_signed_default_leading_zeros<P>(param: P)
where
    P: Into<PBSParameters>,
{
    default_leading_zeros_test(param);
}

fn integer_signed_default_leading_ones<P>(param: P)
where
    P: Into<PBSParameters>,
{
    default_leading_ones_test(param);
}

fn integer_signed_default_ilog2<P>(param: P)
where
    P: Into<PBSParameters>,
{
    default_ilog2_test(param);
}

fn integer_signed_default_checked_ilog2<P>(param: P)
where
    P: Into<PBSParameters>,
{
    default_checked_ilog2_test(param);
}

pub(crate) fn default_test_count_consecutive_bits<P, F>(
    direction: Direction,
    bit_value: BitValue,
    param: P,
    sks_method: F,
) where
    P: Into<PBSParameters>,
    F: for<'a> Fn(&'a ServerKey, &'a SignedRadixCiphertext) -> RadixCiphertext,
{
    let param = param.into();
    let nb_tests_smaller = nb_tests_smaller_for_params(param);
    let (cks, mut sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    sks.set_deterministic_pbs_execution(true);

    let mut rng = rand::thread_rng();

    // message_modulus^vec_length
    let modulus = (cks.parameters().message_modulus().0.pow(NB_CTXT as u32) / 2) as i64;

    let num_bits = NB_CTXT as u32 * cks.parameters().message_modulus().0.ilog2();

    let compute_expected_clear = |x: i64| match (direction, bit_value) {
        (Direction::Trailing, BitValue::Zero) => {
            if x == 0 {
                num_bits
            } else {
                x.trailing_zeros()
            }
        }
        (Direction::Trailing, BitValue::One) => x.trailing_ones().min(num_bits),
        (Direction::Leading, BitValue::Zero) => {
            if x == 0 {
                num_bits
            } else {
                (x << (u64::BITS - num_bits)).leading_zeros()
            }
        }
        (Direction::Leading, BitValue::One) => (x << (u64::BITS - num_bits)).leading_ones(),
    };

    let method_name = match (direction, bit_value) {
        (Direction::Trailing, BitValue::Zero) => "trailing_zeros",
        (Direction::Trailing, BitValue::One) => "trailing_ones",
        (Direction::Leading, BitValue::Zero) => "leading_zeros",
        (Direction::Leading, BitValue::One) => "leading_ones",
    };

    let input_values = [-modulus, 0i64, modulus - 1]
        .into_iter()
        .chain((0..nb_tests_smaller).map(|_| rng.gen::<i64>() % modulus))
        .collect::<Vec<_>>();

    for clear in input_values {
        let ctxt = cks.encrypt_signed(clear);

        let ct_res = sks_method(&sks, &ctxt);
        let tmp = sks_method(&sks, &ctxt);
        assert!(ct_res.block_carries_are_empty());
        assert_eq!(ct_res, tmp);

        let decrypted_result: u32 = cks.decrypt(&ct_res);
        let expected_result = compute_expected_clear(clear);
        assert_eq!(
            decrypted_result, expected_result,
            "Invalid result for {method_name}, for {clear}.{method_name}() \
                expected {expected_result}, got {decrypted_result}"
        );

        for _ in 0..nb_tests_smaller {
            // Add non-zero scalar to have non-clean ciphertexts
            let clear_2 = random_non_zero_value(&mut rng, modulus);

            let ctxt = sks.unchecked_scalar_add(&ctxt, clear_2);

            let clear = signed_add_under_modulus(clear, clear_2, modulus);

            let d0: i64 = cks.decrypt_signed(&ctxt);
            assert_eq!(d0, clear, "Failed sanity decryption check");

            let ct_res = sks_method(&sks, &ctxt);
            assert!(ct_res.block_carries_are_empty());

            let expected_result = compute_expected_clear(clear);

            let decrypted_result: u32 = cks.decrypt(&ct_res);
            assert_eq!(
                decrypted_result, expected_result,
                "Invalid result for {method_name}, for {clear}.{method_name}() \
                    expected {expected_result}, got {decrypted_result}"
            );
        }
    }

    let input_values = [-modulus, 0i64, modulus - 1]
        .into_iter()
        .chain((0..nb_tests_smaller).map(|_| rng.gen::<i64>() % modulus));

    for clear in input_values {
        let ctxt = sks.create_trivial_radix(clear, NB_CTXT);

        let ct_res = sks_method(&sks, &ctxt);
        assert!(ct_res.block_carries_are_empty());

        let decrypted_result: u32 = cks.decrypt(&ct_res);
        let expected_result = compute_expected_clear(clear);
        assert_eq!(
            decrypted_result, expected_result,
            "Invalid result for {method_name}, for {clear}.{method_name}() \
                expected {expected_result}, got {decrypted_result}"
        );
    }
}

pub(crate) fn default_trailing_zeros_test<P>(param: P)
where
    P: Into<PBSParameters>,
{
    default_test_count_consecutive_bits(
        Direction::Trailing,
        BitValue::Zero,
        param,
        ServerKey::trailing_zeros_parallelized,
    );
}

pub(crate) fn default_trailing_ones_test<P>(param: P)
where
    P: Into<PBSParameters>,
{
    default_test_count_consecutive_bits(
        Direction::Trailing,
        BitValue::One,
        param,
        ServerKey::trailing_ones_parallelized,
    );
}

pub(crate) fn default_leading_zeros_test<P>(param: P)
where
    P: Into<PBSParameters>,
{
    default_test_count_consecutive_bits(
        Direction::Leading,
        BitValue::Zero,
        param,
        ServerKey::leading_zeros_parallelized,
    );
}

pub(crate) fn default_leading_ones_test<P>(param: P)
where
    P: Into<PBSParameters>,
{
    default_test_count_consecutive_bits(
        Direction::Leading,
        BitValue::One,
        param,
        ServerKey::leading_ones_parallelized,
    );
}

pub(crate) fn default_ilog2_test<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let param = param.into();
    let nb_tests_smaller = nb_tests_smaller_for_params(param);
    let (cks, mut sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    sks.set_deterministic_pbs_execution(true);

    let mut rng = rand::thread_rng();

    // message_modulus^vec_length
    let modulus = (cks.parameters().message_modulus().0.pow(NB_CTXT as u32) / 2) as i64;

    let num_bits = NB_CTXT as u32 * cks.parameters().message_modulus().0.ilog2();

    // Test with invalid input
    {
        for clear in [0i64, rng.gen_range(-modulus..=-1i64)] {
            let ctxt = cks.encrypt_signed(clear);

            let ct_res = sks.ilog2_parallelized(&ctxt);
            assert!(ct_res.block_carries_are_empty());

            let decrypted_result: u32 = cks.decrypt(&ct_res);
            let expected_result = if clear < 0 {
                num_bits - 1
            } else {
                let counter_num_blocks = ((num_bits - 1).ilog2() + 1 + 1)
                    .div_ceil(cks.parameters().message_modulus().0.ilog2())
                    as usize;
                (1u32 << (counter_num_blocks as u32 * cks.parameters().message_modulus().0.ilog2()))
                    - 1
            };
            assert_eq!(
                decrypted_result, expected_result,
                "Invalid result for ilog2 for {clear}.ilog2() \
                    expected {expected_result}, got {decrypted_result}"
            );
        }
    }

    let input_values = (0..num_bits - 1)
        .map(|i| 1 << i)
        .chain(
            (0..nb_tests_smaller.saturating_sub(num_bits as usize))
                .map(|_| rng.gen_range(1..modulus)),
        )
        .collect::<Vec<_>>();

    for clear in input_values {
        let ctxt = cks.encrypt_signed(clear);

        let ct_res = sks.ilog2_parallelized(&ctxt);
        let tmp = sks.ilog2_parallelized(&ctxt);
        assert!(ct_res.block_carries_are_empty());
        assert_eq!(ct_res, tmp);

        let decrypted_result: u32 = cks.decrypt(&ct_res);
        let expected_result = clear.ilog2();
        assert_eq!(
            decrypted_result, expected_result,
            "Invalid result for ilog2 for {clear}.ilog2() \
                expected {expected_result}, got {decrypted_result}"
        );

        for _ in 0..nb_tests_smaller {
            // Add non-zero scalar to have non-clean ciphertexts
            // But here, we have to make sure clear is still > 0
            // as we are only testing valid ilog2 inputs
            let (clear, clear_2) = loop {
                let clear_2 = random_non_zero_value(&mut rng, modulus);
                let clear = signed_add_under_modulus(clear, clear_2, modulus);
                if clear > 0 {
                    break (clear, clear_2);
                }
            };

            let ctxt = sks.unchecked_scalar_add(&ctxt, clear_2);

            let d0: i64 = cks.decrypt_signed(&ctxt);
            assert_eq!(d0, clear, "Failed sanity decryption check");

            let ct_res = sks.ilog2_parallelized(&ctxt);
            assert!(ct_res.block_carries_are_empty());

            let expected_result = clear.ilog2();

            let decrypted_result: u32 = cks.decrypt(&ct_res);
            assert_eq!(
                decrypted_result, expected_result,
                "Invalid result for ilog2, for {clear}.ilog2() \
                    expected {expected_result}, got {decrypted_result}"
            );
        }
    }

    let input_values = (0..num_bits - 1)
        .map(|i| 1 << i)
        .chain(
            (0..nb_tests_smaller.saturating_sub(num_bits as usize))
                .map(|_| rng.gen_range(1..modulus)),
        )
        .collect::<Vec<_>>();

    for clear in input_values {
        let ctxt: SignedRadixCiphertext = sks.create_trivial_radix(clear, NB_CTXT);

        let ct_res = sks.ilog2_parallelized(&ctxt);
        let tmp = sks.ilog2_parallelized(&ctxt);
        assert!(ct_res.block_carries_are_empty());
        assert_eq!(ct_res, tmp);

        let decrypted_result: u32 = cks.decrypt(&ct_res);
        let expected_result = clear.ilog2();

        assert_eq!(
            decrypted_result, expected_result,
            "Invalid result for ilog2, for {clear}.ilog2() \
                expected {expected_result}, got {decrypted_result}"
        );
    }
}

pub(crate) fn default_checked_ilog2_test<P, T>(param: P, mut executor: T)
where
    P: Into<PBSParameters>,
    T: for<'a> FunctionExecutor<(&'a SignedRadixCiphertext), SignedRadixCiphertext>,
{
    let param = param.into();
    let nb_tests_smaller = nb_tests_smaller_for_params(param);
    let (cks, mut sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    sks.set_deterministic_pbs_execution(true);

    let mut rng = rand::thread_rng();
    let sks = Arc::new(sks);
    executor.setup(&cks, sks);

    // message_modulus^vec_length
    let modulus = (cks.parameters().message_modulus().0.pow(NB_CTXT as u32) / 2) as i64;

    let num_bits = NB_CTXT as u32 * cks.parameters().message_modulus().0.ilog2();

    // Test with invalid input
    {
        for clear in [0i64, rng.gen_range(-modulus..=-1i64)] {
            let ctxt = cks.encrypt_signed(clear);

            let (ct_res, is_ok) = executor.execute((&ctxt));
            assert!(ct_res.block_carries_are_empty());

            let decrypted_result: u32 = cks.decrypt(&ct_res);
            let expected_result = if clear < 0 {
                num_bits - 1
            } else {
                let counter_num_blocks = ((num_bits - 1).ilog2() + 1 + 1)
                    .div_ceil(cks.parameters().message_modulus().0.ilog2())
                    as usize;
                (1u32 << (counter_num_blocks as u32 * cks.parameters().message_modulus().0.ilog2()))
                    - 1
            };
            assert_eq!(
                decrypted_result, expected_result,
                "Invalid result for ilog2 for {clear}.ilog2() \
                    expected {expected_result}, got {decrypted_result}"
            );
            let is_ok = cks.decrypt_bool(&is_ok);
            assert!(!is_ok);
        }
    }

    let input_values = (0..num_bits - 1)
        .map(|i| 1 << i)
        .chain(
            (0..nb_tests_smaller.saturating_sub(num_bits as usize))
                .map(|_| rng.gen_range(1..modulus)),
        )
        .collect::<Vec<_>>();

    for clear in input_values {
        let ctxt = cks.encrypt_signed(clear);

        let (ct_res, is_ok) = sks.checked_ilog2_parallelized(&ctxt);
        let (tmp, tmp_is_ok) = sks.checked_ilog2_parallelized(&ctxt);
        assert!(ct_res.block_carries_are_empty());
        assert_eq!(ct_res, tmp);
        assert_eq!(is_ok, tmp_is_ok);

        let decrypted_result: u32 = cks.decrypt(&ct_res);
        let expected_result = clear.ilog2();
        assert_eq!(
            decrypted_result, expected_result,
            "Invalid result for ilog2 for {clear}.ilog2() \
                expected {expected_result}, got {decrypted_result}"
        );
        let is_ok = cks.decrypt_bool(&is_ok);
        assert!(is_ok);

        for _ in 0..nb_tests_smaller {
            // Add non-zero scalar to have non-clean ciphertexts
            // But here, we have to make sure clear is still > 0
            // as we are only testing valid ilog2 inputs
            let (clear, clear_2) = loop {
                let clear_2 = random_non_zero_value(&mut rng, modulus);
                let clear = signed_add_under_modulus(clear, clear_2, modulus);
                if clear > 0 {
                    break (clear, clear_2);
                }
            };

            let ctxt = sks.unchecked_scalar_add(&ctxt, clear_2);

            let d0: i64 = cks.decrypt_signed(&ctxt);
            assert_eq!(d0, clear, "Failed sanity decryption check");

            let (ct_res, is_ok) = sks.checked_ilog2_parallelized(&ctxt);
            assert!(ct_res.block_carries_are_empty());
            assert_eq!(is_ok.as_ref().degree.get(), 1);

            let expected_result = clear.ilog2();

            let decrypted_result: u32 = cks.decrypt(&ct_res);
            assert_eq!(
                decrypted_result, expected_result,
                "Invalid result for ilog2, for {clear}.ilog2() \
                    expected {expected_result}, got {decrypted_result}"
            );
            let is_ok = cks.decrypt_bool(&is_ok);
            assert!(is_ok);
        }
    }

    let input_values = (0..num_bits - 1)
        .map(|i| 1 << i)
        .chain(
            (0..nb_tests_smaller.saturating_sub(num_bits as usize))
                .map(|_| rng.gen_range(1..modulus)),
        )
        .collect::<Vec<_>>();

    for clear in input_values {
        let ctxt: SignedRadixCiphertext = sks.create_trivial_radix(clear, NB_CTXT);

        let (ct_res, is_ok) = sks.checked_ilog2_parallelized(&ctxt);
        assert!(ct_res.block_carries_are_empty());

        let decrypted_result: u32 = cks.decrypt(&ct_res);
        let expected_result = clear.ilog2();

        assert_eq!(
            decrypted_result, expected_result,
            "Invalid result for ilog2, for {clear}.ilog2() \
                expected {expected_result}, got {decrypted_result}"
        );
        let is_ok = cks.decrypt_bool(&is_ok);
        assert!(is_ok);
    }
}
