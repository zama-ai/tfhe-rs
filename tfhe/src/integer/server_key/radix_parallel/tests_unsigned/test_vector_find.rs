use crate::integer::keycache::KEY_CACHE;
use crate::integer::server_key::radix_parallel::tests_cases_unsigned::FunctionExecutor;
use crate::integer::server_key::radix_parallel::tests_unsigned::panic_if_any_block_is_not_clean_or_trivial;
use crate::integer::{BooleanBlock, IntegerKeyKind, RadixCiphertext, RadixClientKey, ServerKey};
use std::collections::HashSet;
use std::sync::Arc;

use super::{
    nb_tests_for_params, random_non_zero_value, unsigned_modulus, CpuFunctionExecutor,
    ExpectedDegrees, ExpectedNoiseLevels, MAX_VEC_LEN, NB_CTXT,
};
use crate::integer::server_key::MatchValues;
use crate::integer::tests::create_parameterized_test;
use rand::prelude::*;

#[cfg(tarpaulin)]
use crate::shortint::parameters::coverage_parameters::*;
use crate::shortint::parameters::test_params::*;
use crate::shortint::parameters::*;

create_parameterized_test!(integer_unchecked_match_value);
create_parameterized_test!(integer_unchecked_match_value_or);
create_parameterized_test!(integer_unchecked_contains);
create_parameterized_test!(integer_unchecked_contains_clear);
create_parameterized_test!(integer_unchecked_is_in_clears);
create_parameterized_test!(integer_unchecked_index_in_clears);
create_parameterized_test!(integer_unchecked_first_index_in_clears);
create_parameterized_test!(integer_unchecked_index_of);
create_parameterized_test!(integer_unchecked_index_of_clear);
create_parameterized_test!(integer_unchecked_first_index_of);
create_parameterized_test!(integer_unchecked_first_index_of_clear);

create_parameterized_test!(integer_default_match_value);
create_parameterized_test!(integer_default_match_value_or);
create_parameterized_test!(integer_default_contains);
create_parameterized_test!(integer_default_contains_clear);
create_parameterized_test!(integer_default_is_in_clears);
create_parameterized_test!(integer_default_index_in_clears);
create_parameterized_test!(integer_default_first_index_in_clears);
create_parameterized_test!(integer_default_index_of);
create_parameterized_test!(integer_default_index_of_clear);
create_parameterized_test!(integer_default_first_index_of);
create_parameterized_test!(integer_default_first_index_of_clear);

fn integer_unchecked_match_value<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::unchecked_match_value_parallelized);
    unchecked_match_value_test_case(param, executor);
}

fn integer_unchecked_match_value_or<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::unchecked_match_value_or_parallelized);
    unchecked_match_value_or_test_case(param, executor);
}

fn integer_unchecked_contains<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::unchecked_contains_parallelized);
    unchecked_contains_test_case(param, executor);
}

fn integer_unchecked_contains_clear<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::unchecked_contains_clear_parallelized);
    unchecked_contains_clear_test_case(param, executor);
}

fn integer_unchecked_is_in_clears<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::unchecked_is_in_clears_parallelized);
    unchecked_is_in_clears_test_case(param, executor);
}

fn integer_unchecked_index_in_clears<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::unchecked_index_in_clears_parallelized);
    unchecked_index_in_clears_test_case(param, executor);
}

fn integer_unchecked_first_index_in_clears<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor =
        CpuFunctionExecutor::new(&ServerKey::unchecked_first_index_in_clears_parallelized);
    unchecked_first_index_in_clears_test_case(param, executor);
}

fn integer_unchecked_index_of<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::unchecked_index_of_parallelized);
    unchecked_index_of_test_case(param, executor);
}

fn integer_unchecked_index_of_clear<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::unchecked_index_of_clear_parallelized);
    unchecked_index_of_clear_test_case(param, executor);
}

fn integer_unchecked_first_index_of<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::unchecked_first_index_of_parallelized);
    unchecked_first_index_of_test_case(param, executor);
}

fn integer_unchecked_first_index_of_clear<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor =
        CpuFunctionExecutor::new(&ServerKey::unchecked_first_index_of_clear_parallelized);
    unchecked_first_index_of_clear_test_case(param, executor);
}

// Default tests

fn integer_default_match_value<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::match_value_parallelized);
    default_match_value_test_case(param, executor);
}

fn integer_default_match_value_or<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::match_value_or_parallelized);
    default_match_value_or_test_case(param, executor);
}

fn integer_default_contains<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::contains_parallelized);
    default_contains_test_case(param, executor);
}

fn integer_default_contains_clear<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::contains_clear_parallelized);
    default_contains_clear_test_case(param, executor);
}

fn integer_default_is_in_clears<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::is_in_clears_parallelized);
    default_is_in_clears_test_case(param, executor);
}

fn integer_default_index_in_clears<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::index_in_clears_parallelized);
    default_index_in_clears_test_case(param, executor);
}

fn integer_default_first_index_in_clears<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::first_index_in_clears_parallelized);
    default_first_index_in_clears_test_case(param, executor);
}

fn integer_default_index_of<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::index_of_parallelized);
    default_index_of_test_case(param, executor);
}

fn integer_default_index_of_clear<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::index_of_clear_parallelized);
    default_index_of_clear_test_case(param, executor);
}

fn integer_default_first_index_of<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::first_index_of_parallelized);
    default_first_index_of_test_case(param, executor);
}

fn integer_default_first_index_of_clear<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::first_index_of_clear_parallelized);
    default_first_index_of_clear_test_case(param, executor);
}

/// This function takes a list of ciphertexts and their corresponding clear values
/// and picks one ciphertext at random to make it so it has carries (via unchecked_add)
///
/// The new expected value (once propagated) is updated in the list of clears.
///
///`value_to_avoid`: If the randomly selected ciphertext has its value equal to `value_to_avoid`
/// it won't be modified, AND the modified ciphertext will never have its new value set to value to
/// avoid.
fn make_one_ciphertext_have_carries(
    clears: &mut [u64],
    cts: &mut [RadixCiphertext],
    rng: &mut ThreadRng,
    sks: &ServerKey,
    value_to_avoid: u64,
    modulus: u64,
) {
    assert_eq!(clears.len(), cts.len());

    if clears.iter().copied().all(|v| v == value_to_avoid) {
        // Otherwise we would endlessly loop
        return;
    }

    loop {
        let i = rng.gen_range(0..cts.len());
        // Don't change the cell that has the value to be found
        if clears[i] != value_to_avoid {
            let clear_0 = random_non_zero_value(rng, modulus);
            let tmp_new = clears[i].wrapping_add(clear_0) % modulus;
            // But also don't introduce a new cell that contains the value to find
            // we took care of that earlier
            if tmp_new != value_to_avoid {
                sks.unchecked_scalar_add_assign(&mut cts[i], clear_0);

                clears[i] = tmp_new;
                break;
            }
        }
    }
}

fn draw_unique_randoms_into_with_an_exclusion(
    unique_numbers: &mut HashSet<u64>,
    rng: &mut ThreadRng,
    num_values: usize,
    excluded_value: u64,
    modulus: u64,
) {
    while unique_numbers.len() < num_values {
        let random_number = rng.gen_range(0..modulus);
        if random_number == excluded_value {
            continue;
        }

        unique_numbers.insert(random_number);
    }
}

fn draw_unique_randoms_into_with_an_inclusion(
    unique_numbers: &mut HashSet<u64>,
    rng: &mut ThreadRng,
    num_values: usize,
    included_value: u64,
    modulus: u64,
) {
    while unique_numbers.len() < num_values.saturating_sub(1) {
        let random_number = rng.gen_range(0..modulus);

        unique_numbers.insert(random_number);
    }

    if unique_numbers.contains(&included_value) {
        loop {
            let new_value = rng.gen_range(0..modulus);
            if new_value != included_value && unique_numbers.insert(new_value) {
                break;
            }
        }
    } else {
        unique_numbers.insert(included_value);
    }
    assert_eq!(num_values, unique_numbers.len());
}

/// Draws at most `num_values` random_values that are in range `0..modulus`
///
/// With `special_value` being included as many times as `occurrence count`
/// tells. (0 effectively means special value won't be included)
fn draw_unique_randoms(
    rng: &mut ThreadRng,
    num_values: usize,
    special_value: u64,
    occurrence_count: usize,
    modulus: u64,
) -> Vec<u64> {
    assert!(num_values >= occurrence_count);

    // if modulus < num_values we won't be able to drawn num_values unique randoms
    let mut num_values = num_values.min(modulus as usize);

    if num_values as u64 == modulus && occurrence_count == 0 {
        num_values -= 1;
    }

    let mut unique_numbers = HashSet::new();
    if occurrence_count == 0 {
        draw_unique_randoms_into_with_an_exclusion(
            &mut unique_numbers,
            rng,
            num_values,
            special_value,
            modulus,
        );
    } else {
        draw_unique_randoms_into_with_an_inclusion(
            &mut unique_numbers,
            rng,
            num_values - (occurrence_count - 1),
            special_value,
            modulus,
        );
    }

    let mut numbers = unique_numbers.into_iter().collect::<Vec<u64>>();
    for _ in 0..occurrence_count.saturating_sub(1) {
        numbers.insert(rng.gen_range(0..numbers.len()), special_value);
    }

    assert_eq!(numbers.len(), num_values);
    numbers
}

pub(crate) fn unchecked_match_value_test_case<P, T>(param: P, mut executor: T)
where
    P: Into<TestParameters>,
    T: for<'a> FunctionExecutor<
        (&'a RadixCiphertext, &'a MatchValues<u64>),
        (RadixCiphertext, BooleanBlock),
    >,
{
    let param = param.into();
    let nb_tests = nb_tests_for_params(param);
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let sks = Arc::new(sks);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    let mut rng = thread_rng();

    // message_modulus^vec_length
    let modulus = unsigned_modulus(cks.parameters().message_modulus(), NB_CTXT as u32);

    executor.setup(&cks, sks.clone());

    // empty LUT test
    {
        let expected_degrees = ExpectedDegrees::new(Degree::new(0), 1);
        let expected_noise_level = ExpectedNoiseLevels::new(NoiseLevel::ZERO, 1);

        let empty_lut = MatchValues::new(vec![]).unwrap();
        let inputs = [
            cks.encrypt(rng.gen_range(0..modulus)),
            sks.create_trivial_radix(rng.gen_range(0..modulus), NB_CTXT),
        ];
        for ct in inputs {
            let (result, is_ok) = executor.execute((&ct, &empty_lut));

            // If the LUT is empty, the output has 1 block
            assert_eq!(result.blocks.len(), 1);

            assert!(result.is_trivial());
            assert!(is_ok.is_trivial());

            expected_degrees.panic_if_any_is_not_equal(&result);
            expected_noise_level.panic_if_any_is_not_equal(&result);
            assert_eq!(is_ok.0.degree.get(), 0);
            assert_eq!(is_ok.0.noise_level().get(), 0);

            assert_eq!(cks.decrypt::<u64>(&result), 0);
            assert!(!cks.decrypt_bool(&is_ok));
        }
    }

    // LUT with only 1 possible output value, that requires more block than the input
    {
        let block_msg_modulus = cks.parameters().message_modulus().0;

        let vec = (0..block_msg_modulus)
            .map(|input| (input, u64::MAX))
            .collect::<Vec<_>>();
        let lut = MatchValues::new(vec).unwrap();

        let inputs = [cks.encrypt(rng.gen_range(0..block_msg_modulus))];
        for ct in inputs {
            let (result, is_ok) = executor.execute((&ct, &lut));

            panic_if_any_block_is_not_clean_or_trivial(&result, &cks);

            assert!(result.blocks.len() > ct.blocks.len());

            assert_eq!(cks.decrypt::<u64>(&result), u64::MAX);
            assert!(cks.decrypt_bool(&is_ok));
        }
    }

    // We want to split test in half,
    // one half where the lut contains the clear, the other half where it does not
    let halved_nb_test: usize = if nb_tests > 1 { nb_tests / 2 } else { 0 };

    let mut lut = Vec::with_capacity(modulus as usize);
    for i in 0..nb_tests {
        lut.clear();

        let clear = rng.gen_range(0..modulus);
        let num_values = rng.gen_range(1..MAX_VEC_LEN) as usize;
        let occurrence_count = if i < halved_nb_test { 0 } else { 1 };
        let mut unique_numbers =
            draw_unique_randoms(&mut rng, num_values, clear, occurrence_count, modulus);
        for input in unique_numbers.drain(..) {
            let output = rng.gen_range(0..modulus);
            lut.push((input, output));
        }

        let ct = cks.encrypt(clear);

        let (expected_result, expected_is_ok) = lut
            .iter()
            .find(|(input, _)| *input == clear)
            .map_or((0, false), |(_, output)| (*output, true));

        let lut = MatchValues::new(lut.clone()).unwrap();
        let (result, is_ok) = executor.execute((&ct, &lut));

        panic_if_any_block_is_not_clean_or_trivial(&result, &cks);
        assert_eq!(is_ok.0.degree, Degree::new(1));
        assert_eq!(is_ok.0.noise_level(), NoiseLevel::NOMINAL);

        let result = cks.decrypt::<u64>(&result);
        let is_ok = cks.decrypt_bool(&is_ok);
        assert_eq!(
            result, expected_result,
            "Invalid match output: for input {clear} and match values: {lut:?}"
        );
        assert_eq!(is_ok, expected_is_ok);
    }

    // Test that the data is properly unpacked
    {
        let msg_mod = cks.parameters().message_modulus().0;
        let clear = rng.gen_range(0..modulus);
        // The output value is such that it is on the message part of the second packed block
        // [msg4|msg3] [msg1|msg0], so in msg3, if the result is not properly unpacked then its
        // going to be wrong
        let lut = vec![(clear, msg_mod * msg_mod)];

        let ct = cks.encrypt(clear);

        let (expected_result, expected_is_ok) = lut
            .iter()
            .find(|(input, _)| *input == clear)
            .map_or((0, false), |(_, output)| (*output, true));

        let lut = MatchValues::new(lut).unwrap();
        let (result, is_ok) = executor.execute((&ct, &lut));

        panic_if_any_block_is_not_clean_or_trivial(&result, &cks);
        assert_eq!(is_ok.0.degree, Degree::new(1));
        assert_eq!(is_ok.0.noise_level(), NoiseLevel::NOMINAL);

        let result = cks.decrypt::<u64>(&result);
        let is_ok = cks.decrypt_bool(&is_ok);
        assert_eq!(
            result, expected_result,
            "Invalid match output: for input {clear} and match values: {lut:?}"
        );
        assert_eq!(is_ok, expected_is_ok);
    }
}

pub(crate) fn default_match_value_test_case<P, T>(param: P, mut executor: T)
where
    P: Into<TestParameters>,
    T: for<'a> FunctionExecutor<
        (&'a RadixCiphertext, &'a MatchValues<u64>),
        (RadixCiphertext, BooleanBlock),
    >,
{
    let param = param.into();
    let nb_tests = nb_tests_for_params(param);
    let (cks, mut sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    sks.set_deterministic_pbs_execution(true);

    let sks = Arc::new(sks);

    let cks = RadixClientKey::from((cks, NB_CTXT));
    let mut rng = thread_rng();

    // message_modulus^vec_length
    let modulus = unsigned_modulus(cks.parameters().message_modulus(), NB_CTXT as u32);

    executor.setup(&cks, sks.clone());

    // We want to split test in half,
    // one half where the lut contains the clear, the other half where it does not
    let halved_nb_test: usize = if nb_tests > 1 { nb_tests / 2 } else { 0 };

    let mut lut = Vec::with_capacity(modulus as usize);
    for i in 0..nb_tests {
        lut.clear();

        let clear = rng.gen_range(0..modulus);
        let clear_0 = random_non_zero_value(&mut rng, modulus);

        let mut ct = cks.encrypt(clear);
        sks.unchecked_scalar_add_assign(&mut ct, clear_0);

        let clear = clear.wrapping_add(clear_0) % modulus;

        let num_values = rng.gen_range(1..MAX_VEC_LEN);
        let occurrence_count = if i < halved_nb_test { 0 } else { 1 };
        let mut unique_numbers =
            draw_unique_randoms(&mut rng, num_values, clear, occurrence_count, modulus);
        for input in unique_numbers.drain(..) {
            let output = rng.gen_range(0..modulus);
            lut.push((input, output));
        }

        let (expected_result, expected_is_ok) = lut
            .iter()
            .find(|(input, _)| *input == clear)
            .map_or((0, false), |(_, output)| (*output, true));

        let lut = MatchValues::new(lut.clone()).unwrap();
        let (result, is_ok) = executor.execute((&ct, &lut));

        let (result_2, is_ok_2) = executor.execute((&ct, &lut));
        assert_eq!(result, result_2, "Failed determinism test");
        assert_eq!(is_ok, is_ok_2, "Failed determinism test");

        panic_if_any_block_is_not_clean_or_trivial(&result, &cks);
        assert_eq!(is_ok.0.degree, Degree::new(1));
        assert_eq!(is_ok.0.noise_level(), NoiseLevel::NOMINAL);

        let result = cks.decrypt::<u64>(&result);
        let is_ok = cks.decrypt_bool(&is_ok);

        assert_eq!(
            result, expected_result,
            "Invalid match output: for input {clear} and match values: {lut:?}"
        );
        assert_eq!(is_ok, expected_is_ok);
    }
}

pub(crate) fn unchecked_match_value_or_test_case<P, T>(param: P, mut executor: T)
where
    P: Into<TestParameters>,
    T: for<'a> FunctionExecutor<(&'a RadixCiphertext, &'a MatchValues<u64>, u64), RadixCiphertext>,
{
    let param = param.into();
    let nb_tests = nb_tests_for_params(param);
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let sks = Arc::new(sks);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    let mut rng = thread_rng();

    // message_modulus^vec_length
    let modulus = unsigned_modulus(cks.parameters().message_modulus(), NB_CTXT as u32);

    executor.setup(&cks, sks.clone());

    // empty LUT test
    {
        let empty_lut = MatchValues::new(vec![]).unwrap();
        let inputs = [
            cks.encrypt(rng.gen_range(0..modulus)),
            sks.create_trivial_radix(rng.gen_range(0..modulus), NB_CTXT),
        ];
        let default_value = rng.gen_range(0..modulus);
        let expected_len = sks.num_blocks_to_represent_unsigned_value(default_value);

        for ct in inputs {
            let result = executor.execute((&ct, &empty_lut, default_value));

            assert_eq!(result.blocks.len(), expected_len);

            let expected_degrees = ExpectedDegrees::new(
                Degree::new(cks.parameters().message_modulus().0 - 1),
                expected_len,
            );
            let expected_noise_level = ExpectedNoiseLevels::new(NoiseLevel::ZERO, expected_len);
            expected_degrees.panic_if_any_is_greater(&result);
            expected_noise_level.panic_if_any_is_not_equal(&result);

            assert_eq!(cks.decrypt::<u64>(&result), default_value);
        }
    }

    // LUT with only 1 possible output value, that requires more block than the input
    {
        let block_msg_modulus = cks.parameters().message_modulus().0;

        let vec = (0..block_msg_modulus)
            .map(|input| (input, u64::MAX))
            .collect::<Vec<_>>();
        let lut = MatchValues::new(vec).unwrap();

        let inputs = [cks.encrypt(rng.gen_range(0..block_msg_modulus))];
        for ct in inputs {
            let result = executor.execute((&ct, &lut, u64::MAX));

            panic_if_any_block_is_not_clean_or_trivial(&result, &cks);

            assert_eq!(
                result.blocks.len(),
                sks.num_blocks_to_represent_unsigned_value(u64::MAX)
            );

            assert_eq!(cks.decrypt::<u64>(&result), u64::MAX);
        }
    }

    // We want to split test in half,
    // one half where the lut contains the clear, the other half where it does not
    let halved_nb_test: usize = nb_tests / 2;

    let mut lut = Vec::with_capacity(modulus as usize);
    for i in 0..nb_tests {
        lut.clear();

        let clear = rng.gen_range(0..modulus);
        let clear_default = rng.gen_range(0..modulus);
        let num_values = rng.gen_range(1..MAX_VEC_LEN) as usize;
        let occurrence_count = if i < halved_nb_test { 0 } else { 1 };
        let mut unique_numbers =
            draw_unique_randoms(&mut rng, num_values, clear, occurrence_count, modulus);
        for input in unique_numbers.drain(..) {
            let output = rng.gen_range(0..modulus);
            lut.push((input, output));
        }

        let ct = cks.encrypt(clear);

        let expected_result = lut
            .iter()
            .find(|(input, _)| *input == clear)
            .map_or(clear_default, |(_, output)| *output);

        let lut = MatchValues::new(lut.clone()).unwrap();
        let result = executor.execute((&ct, &lut, clear_default));

        panic_if_any_block_is_not_clean_or_trivial(&result, &cks);
        let result = cks.decrypt::<u64>(&result);

        assert_eq!(result, expected_result);
    }
}

pub(crate) fn default_match_value_or_test_case<P, T>(param: P, mut executor: T)
where
    P: Into<TestParameters>,
    T: for<'a> FunctionExecutor<(&'a RadixCiphertext, &'a MatchValues<u64>, u64), RadixCiphertext>,
{
    let param = param.into();
    let nb_tests = nb_tests_for_params(param);
    let (cks, mut sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);

    sks.set_deterministic_pbs_execution(true);

    let sks = Arc::new(sks);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    let mut rng = thread_rng();

    // message_modulus^vec_length
    let modulus = unsigned_modulus(cks.parameters().message_modulus(), NB_CTXT as u32);

    executor.setup(&cks, sks.clone());

    // We want to split test in half,
    // one half where the lut contains the clear, the other half where it does not
    let halved_nb_test: usize = nb_tests / 2;

    let mut lut = Vec::with_capacity(modulus as usize);
    for i in 0..nb_tests {
        lut.clear();

        let clear = rng.gen_range(0..modulus);
        let clear_0 = random_non_zero_value(&mut rng, modulus);

        let mut ct = cks.encrypt(clear);
        sks.unchecked_scalar_add_assign(&mut ct, clear_0);

        let clear = clear.wrapping_add(clear_0) % modulus;

        let clear_default = rng.gen_range(0..modulus);
        let occurrence_count = if i < halved_nb_test { 0 } else { 1 };
        let num_values = rng.gen_range(occurrence_count.max(1)..MAX_VEC_LEN) as usize;
        let mut unique_numbers =
            draw_unique_randoms(&mut rng, num_values, clear, occurrence_count, modulus);
        for input in unique_numbers.drain(..) {
            let output = rng.gen_range(0..modulus);
            lut.push((input, output));
        }

        let expected_result = lut
            .iter()
            .find(|(input, _)| *input == clear)
            .map_or(clear_default, |(_, output)| *output);

        let lut = MatchValues::new(lut.clone()).unwrap();
        let result = executor.execute((&ct, &lut, clear_default));

        let result_2 = executor.execute((&ct, &lut, clear_default));
        assert_eq!(result, result_2, "Failed determinism test");

        panic_if_any_block_is_not_clean_or_trivial(&result, &cks);
        let result = cks.decrypt::<u64>(&result);

        assert_eq!(result, expected_result);
    }
}

pub(crate) fn unchecked_contains_test_case<P, T>(param: P, mut executor: T)
where
    P: Into<TestParameters>,
    T: for<'a> FunctionExecutor<(&'a [RadixCiphertext], &'a RadixCiphertext), BooleanBlock>,
{
    let param = param.into();
    let nb_tests = nb_tests_for_params(param);
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let sks = Arc::new(sks);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    let mut rng = thread_rng();

    // message_modulus^vec_length
    let modulus = unsigned_modulus(cks.parameters().message_modulus(), NB_CTXT as u32);

    executor.setup(&cks, sks.clone());

    // empty collection
    {
        let inputs = [
            cks.encrypt(rng.gen_range(0..modulus)),
            sks.create_trivial_radix(rng.gen_range(0..modulus), NB_CTXT),
        ];
        for ct in inputs {
            let result = executor.execute((&[], &ct));

            assert!(result.is_trivial());
            assert_eq!(result.0.degree, Degree::new(0));
            assert_eq!(result.0.noise_level(), NoiseLevel::ZERO);
            assert!(!cks.decrypt_bool(&result));
        }
    }

    // We want to split test in half,
    // one half where the collection contains the element, the other half where it does not
    let halved_nb_test: usize = nb_tests / 2;

    for i in 0..nb_tests {
        let clear = rng.gen_range(0..modulus);
        let num_values = rng.gen_range(1..MAX_VEC_LEN) as usize;
        let clears = draw_unique_randoms(
            &mut rng,
            num_values,
            clear,
            if i < halved_nb_test { 0 } else { 1 },
            modulus,
        );

        let ct = cks.encrypt(clear);
        let cts = clears
            .iter()
            .copied()
            .map(|value| cks.encrypt(value))
            .collect::<Vec<_>>();

        let expected_result = i >= halved_nb_test;
        let result = executor.execute((&cts, &ct));

        // If the mapping only contains numbers (output) that needs less than NB_CTXT
        // blocks, some trivial zeros will be appended
        assert_eq!(result.0.degree, Degree::new(1));
        assert_eq!(result.0.noise_level(), NoiseLevel::NOMINAL);

        let result = cks.decrypt_bool(&result);

        assert_eq!(result, expected_result);
    }
}

pub(crate) fn default_contains_test_case<P, T>(param: P, mut executor: T)
where
    P: Into<TestParameters>,
    T: for<'a> FunctionExecutor<(&'a [RadixCiphertext], &'a RadixCiphertext), BooleanBlock>,
{
    let param = param.into();
    let nb_tests = nb_tests_for_params(param);
    let (cks, mut sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    sks.set_deterministic_pbs_execution(true);

    let sks = Arc::new(sks);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    let mut rng = thread_rng();

    // message_modulus^vec_length
    let modulus = unsigned_modulus(cks.parameters().message_modulus(), NB_CTXT as u32);

    executor.setup(&cks, sks.clone());

    // We want to split test in half,
    // one half where the collection contains the element, the other half where it does not
    let halved_nb_test: usize = nb_tests / 2;

    for i in 0..nb_tests {
        let clear = rng.gen_range(0..modulus);
        let clear_0 = random_non_zero_value(&mut rng, modulus);

        let mut ct = cks.encrypt(clear);
        sks.unchecked_scalar_add_assign(&mut ct, clear_0);

        let clear = clear.wrapping_add(clear_0) % modulus;

        let num_values = rng.gen_range(1..MAX_VEC_LEN) as usize;
        let mut clears = draw_unique_randoms(
            &mut rng,
            num_values,
            clear,
            if i < halved_nb_test { 0 } else { 1 },
            modulus,
        );

        let mut cts = clears
            .iter()
            .copied()
            .map(|value| cks.encrypt(value))
            .collect::<Vec<_>>();

        // change one ct of the cts
        make_one_ciphertext_have_carries(&mut clears, &mut cts, &mut rng, &sks, clear, modulus);

        let expected_result = i >= halved_nb_test;
        let result = executor.execute((&cts, &ct));

        let result_2 = executor.execute((&cts, &ct));
        assert_eq!(result, result_2, "Failed determinism test");

        // If the mapping only contains numbers (output) that needs less than NB_CTXT
        // blocks, some trivial zeros will be appended
        assert_eq!(result.0.degree, Degree::new(1));
        assert_eq!(result.0.noise_level(), NoiseLevel::NOMINAL);

        let result = cks.decrypt_bool(&result);

        assert_eq!(result, expected_result);
    }
}

pub(crate) fn unchecked_contains_clear_test_case<P, T>(param: P, mut executor: T)
where
    P: Into<TestParameters>,
    T: for<'a> FunctionExecutor<(&'a [RadixCiphertext], u64), BooleanBlock>,
{
    let param = param.into();
    let nb_tests = nb_tests_for_params(param);
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let sks = Arc::new(sks);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    let mut rng = thread_rng();

    // message_modulus^vec_length
    let modulus = unsigned_modulus(cks.parameters().message_modulus(), NB_CTXT as u32);

    executor.setup(&cks, sks);

    // empty collection
    {
        let input = rng.gen_range(0..modulus);
        let result = executor.execute((&[], input));

        assert!(result.is_trivial());
        assert_eq!(result.0.degree, Degree::new(0));
        assert_eq!(result.0.noise_level(), NoiseLevel::ZERO);
        assert!(!cks.decrypt_bool(&result));
    }

    // We want to split test in half,
    // one half where the collection contains the element, the other half where it does not
    let halved_nb_test: usize = nb_tests / 2;

    for i in 0..nb_tests {
        let clear = rng.gen_range(0..modulus);
        let num_values = rng.gen_range(1..MAX_VEC_LEN) as usize;
        let clears = draw_unique_randoms(
            &mut rng,
            num_values,
            clear,
            if i < halved_nb_test { 0 } else { 1 },
            modulus,
        );

        let cts = clears
            .iter()
            .copied()
            .map(|value| cks.encrypt(value))
            .collect::<Vec<_>>();

        let expected_result = i >= halved_nb_test;
        let result = executor.execute((&cts, clear));

        // If the mapping only contains numbers (output) that needs less than NB_CTXT
        // blocks, some trivial zeros will be appended
        assert_eq!(result.0.degree, Degree::new(1));
        assert_eq!(result.0.noise_level(), NoiseLevel::NOMINAL);

        let result = cks.decrypt_bool(&result);
        assert_eq!(result, expected_result);
    }
}

pub(crate) fn default_contains_clear_test_case<P, T>(param: P, mut executor: T)
where
    P: Into<TestParameters>,
    T: for<'a> FunctionExecutor<(&'a [RadixCiphertext], u64), BooleanBlock>,
{
    let param = param.into();
    let nb_tests = nb_tests_for_params(param);
    let (cks, mut sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    sks.set_deterministic_pbs_execution(true);

    let sks = Arc::new(sks);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    let mut rng = thread_rng();

    // message_modulus^vec_length
    let modulus = unsigned_modulus(cks.parameters().message_modulus(), NB_CTXT as u32);

    executor.setup(&cks, sks.clone());

    // We want to split test in half,
    // one half where the collection contains the element, the other half where it does not
    let halved_nb_test: usize = nb_tests / 2;

    for i in 0..nb_tests {
        let clear = rng.gen_range(0..modulus);
        let clear_0 = random_non_zero_value(&mut rng, modulus);

        let mut ct = cks.encrypt(clear);
        sks.unchecked_scalar_add_assign(&mut ct, clear_0);

        let clear = clear.wrapping_add(clear_0) % modulus;

        let num_values = rng.gen_range(1..MAX_VEC_LEN) as usize;
        let clears = draw_unique_randoms(
            &mut rng,
            num_values,
            clear,
            if i < halved_nb_test { 0 } else { 1 },
            modulus,
        );

        let cts = clears
            .iter()
            .copied()
            .map(|value| cks.encrypt(value))
            .collect::<Vec<_>>();

        let expected_result = i >= halved_nb_test;
        let result = executor.execute((&cts, clear));

        let result_2 = executor.execute((&cts, clear));
        assert_eq!(result, result_2, "Failed determinism test");

        // If the mapping only contains numbers (output) that needs less than NB_CTXT
        // blocks, some trivial zeros will be appended
        assert_eq!(result.0.degree, Degree::new(1));
        assert_eq!(result.0.noise_level(), NoiseLevel::NOMINAL);

        let result = cks.decrypt_bool(&result);
        assert_eq!(result, expected_result);
    }
}

pub(crate) fn unchecked_is_in_clears_test_case<P, T>(param: P, mut executor: T)
where
    P: Into<TestParameters>,
    T: for<'a> FunctionExecutor<(&'a RadixCiphertext, &'a [u64]), BooleanBlock>,
{
    let param = param.into();
    let nb_tests = nb_tests_for_params(param);
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let sks = Arc::new(sks);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    let mut rng = thread_rng();

    // message_modulus^vec_length
    let modulus = unsigned_modulus(cks.parameters().message_modulus(), NB_CTXT as u32);

    executor.setup(&cks, sks);

    // empty collection
    {
        let input = cks.encrypt(rng.gen_range(0..modulus));
        let result = executor.execute((&input, &[]));

        assert!(result.is_trivial());
        assert_eq!(result.0.degree, Degree::new(0));
        assert_eq!(result.0.noise_level(), NoiseLevel::ZERO);
        assert!(!cks.decrypt_bool(&result));
    }

    // We want to split test in half,
    // one half where the collection contains the element, the other half where it does not
    let halved_nb_test: usize = nb_tests / 2;

    for i in 0..nb_tests {
        let clear = rng.gen_range(0..modulus);
        let num_values = rng.gen_range(1..MAX_VEC_LEN) as usize;
        let clears = draw_unique_randoms(
            &mut rng,
            num_values,
            clear,
            if i < halved_nb_test { 0 } else { 1 },
            modulus,
        );
        let ct = cks.encrypt(clear);
        let expected_result = i >= halved_nb_test;
        let result = executor.execute((&ct, &clears));

        // If the mapping only contains numbers (output) that needs less than NB_CTXT
        // blocks, some trivial zeros will be appended
        assert_eq!(result.0.degree, Degree::new(1));
        assert_eq!(result.0.noise_level(), NoiseLevel::NOMINAL);

        let result = cks.decrypt_bool(&result);
        assert_eq!(result, expected_result);
    }
}

pub(crate) fn default_is_in_clears_test_case<P, T>(param: P, mut executor: T)
where
    P: Into<TestParameters>,
    T: for<'a> FunctionExecutor<(&'a RadixCiphertext, &'a [u64]), BooleanBlock>,
{
    let param = param.into();
    let nb_tests = nb_tests_for_params(param);
    let (cks, mut sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    sks.set_deterministic_pbs_execution(true);

    let sks = Arc::new(sks);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    let mut rng = thread_rng();

    // message_modulus^vec_length
    let modulus = unsigned_modulus(cks.parameters().message_modulus(), NB_CTXT as u32);

    executor.setup(&cks, sks.clone());

    // We want to split test in half,
    // one half where the collection contains the element, the other half where it does not
    let halved_nb_test: usize = nb_tests / 2;

    for i in 0..nb_tests {
        let clear = rng.gen_range(0..modulus);
        let clear_0 = random_non_zero_value(&mut rng, modulus);

        let mut ct = cks.encrypt(clear);
        sks.unchecked_scalar_add_assign(&mut ct, clear_0);

        let clear = clear.wrapping_add(clear_0) % modulus;

        let num_values = rng.gen_range(1..MAX_VEC_LEN) as usize;
        let clears = draw_unique_randoms(
            &mut rng,
            num_values,
            clear,
            if i < halved_nb_test { 0 } else { 1 },
            modulus,
        );
        let ct = cks.encrypt(clear);
        let expected_result = i >= halved_nb_test;
        let result = executor.execute((&ct, &clears));

        let result_2 = executor.execute((&ct, &clears));
        assert_eq!(result, result_2, "Failed determinism test");

        // If the mapping only contains numbers (output) that needs less than NB_CTXT
        // blocks, some trivial zeros will be appended
        assert_eq!(result.0.degree, Degree::new(1));
        assert_eq!(result.0.noise_level(), NoiseLevel::NOMINAL);

        let result = cks.decrypt_bool(&result);
        assert_eq!(result, expected_result);
    }
}

pub(crate) fn unchecked_index_in_clears_test_case<P, T>(param: P, mut executor: T)
where
    P: Into<TestParameters>,
    T: for<'a> FunctionExecutor<(&'a RadixCiphertext, &'a [u64]), (RadixCiphertext, BooleanBlock)>,
{
    let param = param.into();
    let nb_tests = nb_tests_for_params(param);
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let sks = Arc::new(sks);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    let mut rng = thread_rng();

    // message_modulus^vec_length
    let modulus = unsigned_modulus(cks.parameters().message_modulus(), NB_CTXT as u32);

    executor.setup(&cks, sks);

    // empty collection
    {
        let input = cks.encrypt(rng.gen_range(0..modulus));
        let (index, is_in) = executor.execute((&input, &[]));

        assert!(index.is_trivial());
        assert_eq!(cks.decrypt::<u16>(&index), 0);

        assert!(is_in.is_trivial());
        assert_eq!(is_in.0.degree, Degree::new(0));
        assert_eq!(is_in.0.noise_level(), NoiseLevel::ZERO);
        assert!(!cks.decrypt_bool(&is_in));
    }

    // We want to split test in half,
    // one half where the collection contains the element, the other half where it does not
    let halved_nb_test: usize = nb_tests / 2;

    for i in 0..nb_tests {
        let clear = rng.gen_range(0..modulus);
        let num_values = rng.gen_range(1..MAX_VEC_LEN) as usize;
        let clears = draw_unique_randoms(
            &mut rng,
            num_values,
            clear,
            if i < halved_nb_test { 0 } else { 1 },
            modulus,
        );
        let ct = cks.encrypt(clear);
        let expected_index = clears
            .iter()
            .position(|element| *element == clear)
            .unwrap_or(0);
        let expected_is_in = i >= halved_nb_test;
        let (index, is_in) = executor.execute((&ct, &clears));

        let index: u16 = cks.decrypt(&index);
        assert_eq!(index, expected_index as u16);

        assert_eq!(is_in.0.degree, Degree::new(1));
        assert_eq!(is_in.0.noise_level(), NoiseLevel::NOMINAL);

        let is_in = cks.decrypt_bool(&is_in);
        assert_eq!(is_in, expected_is_in);
    }
}

pub(crate) fn default_index_in_clears_test_case<P, T>(param: P, mut executor: T)
where
    P: Into<TestParameters>,
    T: for<'a> FunctionExecutor<(&'a RadixCiphertext, &'a [u64]), (RadixCiphertext, BooleanBlock)>,
{
    let param = param.into();
    let nb_tests = nb_tests_for_params(param);
    let (cks, mut sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    sks.set_deterministic_pbs_execution(true);

    let sks = Arc::new(sks);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    let mut rng = thread_rng();

    // message_modulus^vec_length
    let modulus = unsigned_modulus(cks.parameters().message_modulus(), NB_CTXT as u32);

    executor.setup(&cks, sks.clone());

    // We want to split test in half,
    // one half where the collection contains the element, the other half where it does not
    let halved_nb_test: usize = nb_tests / 2;

    for i in 0..nb_tests {
        let clear = rng.gen_range(0..modulus);
        let clear_0 = random_non_zero_value(&mut rng, modulus);

        let mut ct = cks.encrypt(clear);
        sks.unchecked_scalar_add_assign(&mut ct, clear_0);

        let clear = clear.wrapping_add(clear_0) % modulus;

        let num_values = rng.gen_range(1..MAX_VEC_LEN) as usize;

        let clears = draw_unique_randoms(
            &mut rng,
            num_values,
            clear,
            if i < halved_nb_test { 0 } else { 1 },
            modulus,
        );

        let expected_index = clears
            .iter()
            .position(|element| *element == clear)
            .unwrap_or(0);
        let expected_is_in = i >= halved_nb_test;
        let (index, is_in) = executor.execute((&ct, &clears));

        let (index_2, is_in_2) = executor.execute((&ct, &clears));
        assert_eq!(index, index_2, "Failed determinism test");
        assert_eq!(is_in, is_in_2, "Failed determinism test");

        let index: u16 = cks.decrypt(&index);
        assert_eq!(index, expected_index as u16);

        assert_eq!(is_in.0.degree, Degree::new(1));
        assert_eq!(is_in.0.noise_level(), NoiseLevel::NOMINAL);

        let is_in = cks.decrypt_bool(&is_in);
        assert_eq!(is_in, expected_is_in);
    }
}

pub(crate) fn unchecked_first_index_in_clears_test_case<P, T>(param: P, mut executor: T)
where
    P: Into<TestParameters>,
    T: for<'a> FunctionExecutor<(&'a RadixCiphertext, &'a [u64]), (RadixCiphertext, BooleanBlock)>,
{
    let param = param.into();
    let nb_tests = nb_tests_for_params(param);
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let sks = Arc::new(sks);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    let mut rng = thread_rng();

    // message_modulus^vec_length
    let modulus = unsigned_modulus(cks.parameters().message_modulus(), NB_CTXT as u32);

    executor.setup(&cks, sks);

    // empty collection
    {
        let input = cks.encrypt(rng.gen_range(0..modulus));
        let (index, is_in) = executor.execute((&input, &[]));

        assert!(index.is_trivial());
        assert_eq!(cks.decrypt::<u16>(&index), 0);

        assert!(is_in.is_trivial());
        assert_eq!(is_in.0.degree, Degree::new(0));
        assert_eq!(is_in.0.noise_level(), NoiseLevel::ZERO);
        assert!(!cks.decrypt_bool(&is_in));
    }

    // We want to split test in half,
    // one half where the collection contains the element, the other half where it does not
    let halved_nb_test: usize = nb_tests / 2;

    for i in 0..nb_tests {
        let clear = rng.gen_range(0..modulus);

        let occurrence_count = if i < halved_nb_test {
            0
        } else {
            rng.gen_range(1..4)
        };
        let num_values = rng.gen_range(occurrence_count.max(1)..MAX_VEC_LEN) as usize;
        let clears = draw_unique_randoms(&mut rng, num_values, clear, occurrence_count, modulus);
        let ct = cks.encrypt(clear);
        let expected_index = clears
            .iter()
            .position(|element| *element == clear)
            .unwrap_or(0);
        let expected_is_in = i >= halved_nb_test;
        let (index, is_in) = executor.execute((&ct, &clears));

        let index: u16 = cks.decrypt(&index);
        assert_eq!(index, expected_index as u16);

        assert_eq!(is_in.0.degree, Degree::new(1));
        assert_eq!(is_in.0.noise_level(), NoiseLevel::NOMINAL);

        let is_in = cks.decrypt_bool(&is_in);
        assert_eq!(is_in, expected_is_in);
    }
}

pub(crate) fn default_first_index_in_clears_test_case<P, T>(param: P, mut executor: T)
where
    P: Into<TestParameters>,
    T: for<'a> FunctionExecutor<(&'a RadixCiphertext, &'a [u64]), (RadixCiphertext, BooleanBlock)>,
{
    let param = param.into();
    let nb_tests = nb_tests_for_params(param);
    let (cks, mut sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    sks.set_deterministic_pbs_execution(true);

    let sks = Arc::new(sks);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    let mut rng = thread_rng();

    // message_modulus^vec_length
    let modulus = unsigned_modulus(cks.parameters().message_modulus(), NB_CTXT as u32);

    executor.setup(&cks, sks.clone());

    // We want to split test in half,
    // one half where the collection contains the element, the other half where it does not
    let halved_nb_test: usize = nb_tests / 2;

    for i in 0..nb_tests {
        let clear = rng.gen_range(0..modulus);
        let clear_0 = random_non_zero_value(&mut rng, modulus);

        let mut ct = cks.encrypt(clear);
        sks.unchecked_scalar_add_assign(&mut ct, clear_0);

        let clear = clear.wrapping_add(clear_0) % modulus;

        let occurrence_count = if i < halved_nb_test {
            0usize
        } else {
            rng.gen_range(1..4)
        };
        let num_values =
            rng.gen_range((occurrence_count as u64).max(1)..MAX_VEC_LEN as u64) as usize;
        let clears = draw_unique_randoms(&mut rng, num_values, clear, occurrence_count, modulus);
        let ct = cks.encrypt(clear);
        let expected_index = clears
            .iter()
            .position(|element| *element == clear)
            .unwrap_or(0);
        let expected_is_in = i >= halved_nb_test;
        let (index, is_in) = executor.execute((&ct, &clears));

        let (index_2, is_in_2) = executor.execute((&ct, &clears));
        assert_eq!(index, index_2, "Failed determinism test");
        assert_eq!(is_in, is_in_2, "Failed determinism test");

        let index: u16 = cks.decrypt(&index);
        assert_eq!(index, expected_index as u16);

        assert_eq!(is_in.0.degree, Degree::new(1));
        assert_eq!(is_in.0.noise_level(), NoiseLevel::NOMINAL);

        let is_in = cks.decrypt_bool(&is_in);
        assert_eq!(is_in, expected_is_in);
    }
}

pub(crate) fn unchecked_index_of_test_case<P, T>(param: P, mut executor: T)
where
    P: Into<TestParameters>,
    T: for<'a> FunctionExecutor<
        (&'a [RadixCiphertext], &'a RadixCiphertext),
        (RadixCiphertext, BooleanBlock),
    >,
{
    let param = param.into();
    let nb_tests = nb_tests_for_params(param);
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let sks = Arc::new(sks);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    let mut rng = thread_rng();

    // message_modulus^vec_length
    let modulus = unsigned_modulus(cks.parameters().message_modulus(), NB_CTXT as u32);

    executor.setup(&cks, sks);

    // empty collection
    {
        let input = cks.encrypt(rng.gen_range(0..modulus));
        let (index, is_in) = executor.execute((&[], &input));

        assert!(index.is_trivial());
        assert_eq!(cks.decrypt::<u16>(&index), 0);

        assert!(is_in.is_trivial());
        assert_eq!(is_in.0.degree, Degree::new(0));
        assert_eq!(is_in.0.noise_level(), NoiseLevel::ZERO);
        assert!(!cks.decrypt_bool(&is_in));
    }

    // We want to split test in half,
    // one half where the collection contains the element, the other half where it does not
    let halved_nb_test: usize = nb_tests / 2;

    for i in 0..nb_tests {
        let clear = rng.gen_range(0..modulus);
        let num_values = rng.gen_range(1..MAX_VEC_LEN) as usize;
        let clears = draw_unique_randoms(
            &mut rng,
            num_values,
            clear,
            if i < halved_nb_test { 0 } else { 1 },
            modulus,
        );

        let cts = clears
            .iter()
            .copied()
            .map(|v| cks.encrypt(v))
            .collect::<Vec<_>>();
        let ct_to_find = cks.encrypt(clear);
        let expected_index = clears
            .iter()
            .position(|element| *element == clear)
            .unwrap_or(0);
        let expected_is_in = i >= halved_nb_test;
        let (index, is_in) = executor.execute((&cts, &ct_to_find));

        let index: u16 = cks.decrypt(&index);
        assert_eq!(index, expected_index as u16);

        assert_eq!(is_in.0.degree, Degree::new(1));
        assert_eq!(is_in.0.noise_level(), NoiseLevel::NOMINAL);

        let is_in = cks.decrypt_bool(&is_in);
        assert_eq!(is_in, expected_is_in);
    }
}

pub(crate) fn default_index_of_test_case<P, T>(param: P, mut executor: T)
where
    P: Into<TestParameters>,
    T: for<'a> FunctionExecutor<
        (&'a [RadixCiphertext], &'a RadixCiphertext),
        (RadixCiphertext, BooleanBlock),
    >,
{
    let param = param.into();
    let nb_tests = nb_tests_for_params(param);
    let (cks, mut sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    sks.set_deterministic_pbs_execution(true);

    let sks = Arc::new(sks);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    let mut rng = thread_rng();

    // message_modulus^vec_length
    let modulus = unsigned_modulus(cks.parameters().message_modulus(), NB_CTXT as u32);

    executor.setup(&cks, sks.clone());

    // We want to split test in half,
    // one half where the collection contains the element, the other half where it does not
    let halved_nb_test: usize = nb_tests / 2;

    for i in 0..nb_tests {
        let clear = rng.gen_range(0..modulus);
        let clear_0 = random_non_zero_value(&mut rng, modulus);

        let mut ct_to_find = cks.encrypt(clear);
        sks.unchecked_scalar_add_assign(&mut ct_to_find, clear_0);

        let clear = clear.wrapping_add(clear_0) % modulus;

        let num_values = rng.gen_range(1..MAX_VEC_LEN) as usize;
        let mut clears = draw_unique_randoms(
            &mut rng,
            num_values,
            clear,
            if i < halved_nb_test { 0 } else { 1 },
            modulus,
        );

        let mut cts = clears
            .iter()
            .copied()
            .map(|v| cks.encrypt(v))
            .collect::<Vec<_>>();

        make_one_ciphertext_have_carries(&mut clears, &mut cts, &mut rng, &sks, clear, modulus);

        let expected_index = clears
            .iter()
            .position(|element| *element == clear)
            .unwrap_or(0);
        let expected_is_in = i >= halved_nb_test;
        let (index, is_in) = executor.execute((&cts, &ct_to_find));

        let (index_2, is_in_2) = executor.execute((&cts, &ct_to_find));
        assert_eq!(index, index_2, "Failed determinism test");
        assert_eq!(is_in, is_in_2, "Failed determinism test");

        let index: u16 = cks.decrypt(&index);
        assert_eq!(index, expected_index as u16);

        assert_eq!(is_in.0.degree, Degree::new(1));
        assert_eq!(is_in.0.noise_level(), NoiseLevel::NOMINAL);

        let is_in = cks.decrypt_bool(&is_in);
        assert_eq!(is_in, expected_is_in);
    }
}

pub(crate) fn unchecked_index_of_clear_test_case<P, T>(param: P, mut executor: T)
where
    P: Into<TestParameters>,
    T: for<'a> FunctionExecutor<(&'a [RadixCiphertext], u64), (RadixCiphertext, BooleanBlock)>,
{
    let param = param.into();
    let nb_tests = nb_tests_for_params(param);
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let sks = Arc::new(sks);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    let mut rng = thread_rng();

    // message_modulus^vec_length
    let modulus = unsigned_modulus(cks.parameters().message_modulus(), NB_CTXT as u32);

    executor.setup(&cks, sks);

    // empty collection
    {
        let (index, is_in) = executor.execute((&[], rng.gen_range(0..modulus)));

        assert!(index.is_trivial());
        assert_eq!(cks.decrypt::<u16>(&index), 0);

        assert!(is_in.is_trivial());
        assert_eq!(is_in.0.degree, Degree::new(0));
        assert_eq!(is_in.0.noise_level(), NoiseLevel::ZERO);
        assert!(!cks.decrypt_bool(&is_in));
    }

    // We want to split test in half,
    // one half where the collection contains the element, the other half where it does not
    let halved_nb_test: usize = nb_tests / 2;

    for i in 0..nb_tests {
        let clear = rng.gen_range(0..modulus);
        let num_values = rng.gen_range(1..MAX_VEC_LEN) as usize;
        let clears = draw_unique_randoms(
            &mut rng,
            num_values,
            clear,
            if i < halved_nb_test { 0 } else { 1 },
            modulus,
        );

        let cts = clears
            .iter()
            .copied()
            .map(|v| cks.encrypt(v))
            .collect::<Vec<_>>();
        let expected_index = clears
            .iter()
            .position(|element| *element == clear)
            .unwrap_or(0);
        let expected_is_in = i >= halved_nb_test;
        let (index, is_in) = executor.execute((&cts, clear));

        let index: u16 = cks.decrypt(&index);
        assert_eq!(index, expected_index as u16);

        assert_eq!(is_in.0.degree, Degree::new(1));
        assert_eq!(is_in.0.noise_level(), NoiseLevel::NOMINAL);

        let is_in = cks.decrypt_bool(&is_in);
        assert_eq!(is_in, expected_is_in);
    }
}

pub(crate) fn default_index_of_clear_test_case<P, T>(param: P, mut executor: T)
where
    P: Into<TestParameters>,
    T: for<'a> FunctionExecutor<(&'a [RadixCiphertext], u64), (RadixCiphertext, BooleanBlock)>,
{
    let param = param.into();
    let nb_tests = nb_tests_for_params(param);
    let (cks, mut sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    sks.set_deterministic_pbs_execution(true);

    let sks = Arc::new(sks);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    let mut rng = thread_rng();

    // message_modulus^vec_length
    let modulus = unsigned_modulus(cks.parameters().message_modulus(), NB_CTXT as u32);

    executor.setup(&cks, sks.clone());

    // We want to split test in half,
    // one half where the collection contains the element, the other half where it does not
    let halved_nb_test: usize = nb_tests / 2;

    for i in 0..nb_tests {
        let clear = rng.gen_range(0..modulus);

        let num_values = rng.gen_range(1..MAX_VEC_LEN) as usize;
        let mut clears = draw_unique_randoms(
            &mut rng,
            num_values,
            clear,
            if i < halved_nb_test { 0 } else { 1 },
            modulus,
        );

        let mut cts = clears
            .iter()
            .copied()
            .map(|v| cks.encrypt(v))
            .collect::<Vec<_>>();

        make_one_ciphertext_have_carries(&mut clears, &mut cts, &mut rng, &sks, clear, modulus);

        let expected_index = clears
            .iter()
            .position(|element| *element == clear)
            .unwrap_or(0);
        let expected_is_in = i >= halved_nb_test;
        let (index, is_in) = executor.execute((&cts, clear));

        let (index_2, is_in_2) = executor.execute((&cts, clear));
        assert_eq!(index, index_2, "Failed determinism test");
        assert_eq!(is_in, is_in_2, "Failed determinism test");

        let index: u16 = cks.decrypt(&index);
        assert_eq!(index, expected_index as u16);

        assert_eq!(is_in.0.degree, Degree::new(1));
        assert_eq!(is_in.0.noise_level(), NoiseLevel::NOMINAL);

        let is_in = cks.decrypt_bool(&is_in);
        assert_eq!(is_in, expected_is_in);
    }
}

pub(crate) fn unchecked_first_index_of_test_case<P, T>(param: P, mut executor: T)
where
    P: Into<TestParameters>,
    T: for<'a> FunctionExecutor<
        (&'a [RadixCiphertext], &'a RadixCiphertext),
        (RadixCiphertext, BooleanBlock),
    >,
{
    let param = param.into();
    let nb_tests = nb_tests_for_params(param);
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let sks = Arc::new(sks);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    let mut rng = thread_rng();

    // message_modulus^vec_length
    let modulus = unsigned_modulus(cks.parameters().message_modulus(), NB_CTXT as u32);

    executor.setup(&cks, sks);

    // empty collection
    {
        let input = cks.encrypt(rng.gen_range(0..modulus));
        let (index, is_in) = executor.execute((&[], &input));

        assert!(index.is_trivial());
        assert_eq!(cks.decrypt::<u16>(&index), 0);

        assert!(is_in.is_trivial());
        assert_eq!(is_in.0.degree, Degree::new(0));
        assert_eq!(is_in.0.noise_level(), NoiseLevel::ZERO);
        assert!(!cks.decrypt_bool(&is_in));
    }

    // We want to split test in half,
    // one half where the collection contains the element, the other half where it does not
    let halved_nb_test: usize = nb_tests / 2;

    for i in 0..nb_tests {
        let clear = rng.gen_range(0..modulus);
        let occurrence_count = if i < halved_nb_test {
            0
        } else {
            rng.gen_range(1..4)
        };
        let num_values = rng.gen_range(occurrence_count.max(1)..MAX_VEC_LEN) as usize;
        let clears = draw_unique_randoms(
            &mut rng,
            num_values,
            clear,
            occurrence_count as usize,
            modulus,
        );

        let ct_to_find = cks.encrypt(clear);
        let expected_index = clears
            .iter()
            .position(|element| *element == clear)
            .unwrap_or(0);
        let encrypted_values = clears
            .iter()
            .copied()
            .map(|x| cks.encrypt(x))
            .collect::<Vec<_>>();
        let expected_is_in = i >= halved_nb_test;
        let (index, is_in) = executor.execute((&encrypted_values, &ct_to_find));

        let index: u16 = cks.decrypt(&index);
        assert_eq!(index, expected_index as u16);

        assert_eq!(is_in.0.degree, Degree::new(1));
        assert_eq!(is_in.0.noise_level(), NoiseLevel::NOMINAL);

        let is_in = cks.decrypt_bool(&is_in);
        assert_eq!(is_in, expected_is_in);
    }
}

pub(crate) fn default_first_index_of_test_case<P, T>(param: P, mut executor: T)
where
    P: Into<TestParameters>,
    T: for<'a> FunctionExecutor<
        (&'a [RadixCiphertext], &'a RadixCiphertext),
        (RadixCiphertext, BooleanBlock),
    >,
{
    let param = param.into();
    let nb_tests = nb_tests_for_params(param);
    let (cks, mut sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    sks.set_deterministic_pbs_execution(true);

    let sks = Arc::new(sks);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    let mut rng = thread_rng();

    // message_modulus^vec_length
    let modulus = unsigned_modulus(cks.parameters().message_modulus(), NB_CTXT as u32);

    executor.setup(&cks, sks.clone());

    // We want to split test in half,
    // one half where the collection contains the element, the other half where it does not
    let halved_nb_test: usize = nb_tests / 2;

    for i in 0..nb_tests {
        let clear = rng.gen_range(0..modulus);
        let clear_0 = random_non_zero_value(&mut rng, modulus);

        let mut ct_to_find = cks.encrypt(clear);
        sks.unchecked_scalar_add_assign(&mut ct_to_find, clear_0);

        let clear = clear.wrapping_add(clear_0) % modulus;

        let occurrence_count = if i < halved_nb_test {
            0usize
        } else {
            rng.gen_range(1..4)
        };
        let num_values =
            rng.gen_range((occurrence_count as u64).max(1)..MAX_VEC_LEN as u64) as usize;
        let mut clears =
            draw_unique_randoms(&mut rng, num_values, clear, occurrence_count, modulus);

        let mut encrypted_values = clears
            .iter()
            .copied()
            .map(|x| cks.encrypt(x))
            .collect::<Vec<_>>();

        make_one_ciphertext_have_carries(
            &mut clears,
            &mut encrypted_values,
            &mut rng,
            &sks,
            clear,
            modulus,
        );

        let expected_index = clears
            .iter()
            .position(|element| *element == clear)
            .unwrap_or(0);

        let expected_is_in = i >= halved_nb_test;
        let (index, is_in) = executor.execute((&encrypted_values, &ct_to_find));

        let (index_2, is_in_2) = executor.execute((&encrypted_values, &ct_to_find));
        assert_eq!(index, index_2, "Failed determinism test");
        assert_eq!(is_in, is_in_2, "Failed determinism test");

        let index: u16 = cks.decrypt(&index);
        assert_eq!(index, expected_index as u16);

        assert_eq!(is_in.0.degree, Degree::new(1));
        assert_eq!(is_in.0.noise_level(), NoiseLevel::NOMINAL);

        let is_in = cks.decrypt_bool(&is_in);
        assert_eq!(is_in, expected_is_in);
    }
}

pub(crate) fn unchecked_first_index_of_clear_test_case<P, T>(param: P, mut executor: T)
where
    P: Into<TestParameters>,
    T: for<'a> FunctionExecutor<(&'a [RadixCiphertext], u64), (RadixCiphertext, BooleanBlock)>,
{
    let param = param.into();
    let nb_tests = nb_tests_for_params(param);
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let sks = Arc::new(sks);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    let mut rng = thread_rng();

    // message_modulus^vec_length
    let modulus = unsigned_modulus(cks.parameters().message_modulus(), NB_CTXT as u32);

    executor.setup(&cks, sks);

    // empty collection
    {
        let (index, is_in) = executor.execute((&[], rng.gen_range(0..modulus)));

        assert!(index.is_trivial());
        assert_eq!(cks.decrypt::<u16>(&index), 0);

        assert!(is_in.is_trivial());
        assert_eq!(is_in.0.degree, Degree::new(0));
        assert_eq!(is_in.0.noise_level(), NoiseLevel::ZERO);
        assert!(!cks.decrypt_bool(&is_in));
    }

    // We want to split test in half,
    // one half where the collection contains the element, the other half where it does not
    let halved_nb_test: usize = nb_tests / 2;

    for i in 0..nb_tests {
        let clear = rng.gen_range(0..modulus);
        let occurrence_count = if i < halved_nb_test {
            0
        } else {
            rng.gen_range(1..2)
        };
        let num_values = rng.gen_range(occurrence_count.max(1)..MAX_VEC_LEN) as usize;
        let clears = draw_unique_randoms(
            &mut rng,
            num_values,
            clear,
            occurrence_count as usize,
            modulus,
        );

        let expected_index = clears
            .iter()
            .position(|element| *element == clear)
            .unwrap_or(0);
        let encrypted_values = clears
            .iter()
            .copied()
            .map(|x| cks.encrypt(x))
            .collect::<Vec<_>>();
        let expected_is_in = i >= halved_nb_test;
        let (index, is_in) = executor.execute((&encrypted_values, clear));

        let index: u16 = cks.decrypt(&index);
        assert_eq!(index, expected_index as u16);

        assert_eq!(is_in.0.degree, Degree::new(1));
        assert_eq!(is_in.0.noise_level(), NoiseLevel::NOMINAL);

        let is_in = cks.decrypt_bool(&is_in);
        assert_eq!(is_in, expected_is_in);
    }
}

pub(crate) fn default_first_index_of_clear_test_case<P, T>(param: P, mut executor: T)
where
    P: Into<TestParameters>,
    T: for<'a> FunctionExecutor<(&'a [RadixCiphertext], u64), (RadixCiphertext, BooleanBlock)>,
{
    let param = param.into();
    let nb_tests = nb_tests_for_params(param);
    let (cks, mut sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    sks.set_deterministic_pbs_execution(true);

    let sks = Arc::new(sks);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    let mut rng = thread_rng();

    // message_modulus^vec_length
    let modulus = unsigned_modulus(cks.parameters().message_modulus(), NB_CTXT as u32);

    executor.setup(&cks, sks);

    // We want to split test in half,
    // one half where the collection contains the element, the other half where it does not
    let halved_nb_test: usize = nb_tests / 2;

    for i in 0..nb_tests {
        let clear = rng.gen_range(0..modulus);
        let occurrence_count = if i < halved_nb_test {
            0
        } else {
            rng.gen_range(1..4)
        };
        let num_values = rng.gen_range(occurrence_count.max(1)..MAX_VEC_LEN) as usize;
        let clears = draw_unique_randoms(
            &mut rng,
            num_values,
            clear,
            occurrence_count as usize,
            modulus,
        );

        let expected_index = clears
            .iter()
            .position(|element| *element == clear)
            .unwrap_or(0);
        let encrypted_values = clears
            .iter()
            .copied()
            .map(|x| cks.encrypt(x))
            .collect::<Vec<_>>();
        let expected_is_in = i >= halved_nb_test;
        let (index, is_in) = executor.execute((&encrypted_values, clear));

        let index: u16 = cks.decrypt(&index);
        assert_eq!(index, expected_index as u16);

        assert_eq!(is_in.0.degree, Degree::new(1));
        assert_eq!(is_in.0.noise_level(), NoiseLevel::NOMINAL);

        let is_in = cks.decrypt_bool(&is_in);
        assert_eq!(is_in, expected_is_in);
    }
}
