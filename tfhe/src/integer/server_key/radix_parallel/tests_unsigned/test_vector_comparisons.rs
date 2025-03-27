use crate::integer::keycache::KEY_CACHE;
use crate::integer::server_key::radix_parallel::tests_cases_unsigned::FunctionExecutor;
use crate::integer::server_key::radix_parallel::tests_unsigned::{
    nb_tests_for_params, unsigned_modulus, CpuFunctionExecutor, MAX_VEC_LEN, NB_CTXT,
};
use crate::integer::{
    BooleanBlock, IntegerKeyKind, IntegerRadixCiphertext, RadixCiphertext, RadixClientKey,
    ServerKey,
};
use crate::shortint::parameters::test_params::*;
use crate::shortint::parameters::*;
use rand::distributions::uniform::{SampleRange, SampleUniform};
use std::ops::Range;
use std::sync::Arc;

use crate::core_crypto::prelude::Numeric;
use crate::integer::block_decomposition::DecomposableInto;
use crate::integer::tests::create_parameterized_test;
use rand::prelude::*;

create_parameterized_test!(integer_unchecked_all_eq_slices_test_case);
create_parameterized_test!(integer_default_all_eq_slices_test_case);

create_parameterized_test!(integer_unchecked_contains_slice_test_case);

fn integer_unchecked_all_eq_slices_test_case<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::unchecked_all_eq_slices_parallelized);
    unchecked_all_eq_slices_test_case(param, executor);
}

fn integer_default_all_eq_slices_test_case<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::all_eq_slices_parallelized);
    default_all_eq_slices_test_case(param, executor);
}

fn integer_unchecked_contains_slice_test_case<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::unchecked_contains_sub_slice_parallelized);
    unchecked_slice_contains_test_case(param, executor);
}

/// Unchecked test for the function that compares slices of radix ciphertexts
/// returning true if all pairs are equal, false otherwise
///
/// Supports both Signed and Unsigned
pub(crate) fn unchecked_all_eq_slices_test_case_impl<E, Clear, Ciphertext, F>(
    mut executor: E,
    cks: &RadixClientKey,
    range: Range<Clear>,
    encryption_fn: F,
) where
    E: for<'a> FunctionExecutor<(&'a [Ciphertext], &'a [Ciphertext]), BooleanBlock>,
    F: Fn(&RadixClientKey, Clear) -> Ciphertext,
    Clear: SampleUniform + Numeric,
    Ciphertext: IntegerRadixCiphertext,
    Range<Clear>: SampleRange<Clear> + Clone,
{
    let nb_tests = nb_tests_for_params(cks.parameters());
    let mut rng = thread_rng();

    // empty slice test
    {
        let result = executor.execute((&[], &[]));

        assert_eq!(result.decrypt_trivial(), Ok(true));
    }

    let halved_nb_tests = nb_tests / 2;

    // Test where inputs are not equal
    for _ in 0..halved_nb_tests {
        let num_values = rng.gen_range(1..MAX_VEC_LEN);
        let values = (0..num_values)
            .map(|_| encryption_fn(cks, rng.gen_range(range.clone())))
            .collect::<Vec<_>>();
        let mut values2 = values.clone();

        // Modify such that one block is different
        let value_index = rng.gen_range(0..num_values);
        let block_index = rng.gen_range(0..NB_CTXT);
        let value_to_avoid = cks.decrypt_one_block(&values[value_index].blocks()[block_index]);
        loop {
            let new_value = rng.gen_range(0..cks.parameters().message_modulus().0);
            if new_value != value_to_avoid {
                let new_block = cks.encrypt_one_block(new_value);
                values2[value_index].blocks_mut()[block_index] = new_block;
                break;
            }
        }

        let result = executor.execute((&values, &values2));
        let result = cks.decrypt_bool(&result);
        assert!(!result);
    }

    // Test where inputs are equal
    for _ in halved_nb_tests..nb_tests {
        let num_values = rng.gen_range(1..MAX_VEC_LEN);
        let values = (0..num_values)
            .map(|_| encryption_fn(cks, rng.gen_range(range.clone())))
            .collect::<Vec<_>>();

        let result = executor.execute((&values, &values));
        let result = cks.decrypt_bool(&result);
        assert!(result);
    }
}

pub(crate) fn unchecked_all_eq_slices_test_case<P, E>(params: P, mut executor: E)
where
    P: Into<TestParameters>,
    E: for<'a> FunctionExecutor<(&'a [RadixCiphertext], &'a [RadixCiphertext]), BooleanBlock>,
{
    let (cks, sks) = KEY_CACHE.get_from_params(params, IntegerKeyKind::Radix);
    let sks = Arc::new(sks);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    // message_modulus^vec_length
    let modulus = unsigned_modulus(cks.parameters().message_modulus(), NB_CTXT as u32);

    executor.setup(&cks, sks);

    unchecked_all_eq_slices_test_case_impl(executor, &cks, 0..modulus, RadixClientKey::encrypt);
}

/// Default test for the function that compares slices of radix ciphertexts
/// returning true if all pairs are equal, false otherwise
///
/// Supports both Signed and Unsigned
pub(crate) fn default_all_eq_slices_test_case_impl<E, Clear, Ciphertext, F>(
    mut executor: E,
    sks: &ServerKey,
    cks: &RadixClientKey,
    range: Range<Clear>,
    encryption_fn: F,
) where
    E: for<'a> FunctionExecutor<(&'a [Ciphertext], &'a [Ciphertext]), BooleanBlock>,
    F: Fn(&RadixClientKey, Clear) -> Ciphertext,
    Clear: SampleUniform + Numeric + DecomposableInto<u8>,
    Ciphertext: IntegerRadixCiphertext,
    Range<Clear>: SampleRange<Clear> + Clone,
{
    let nb_tests = nb_tests_for_params(cks.parameters());
    let mut rng = thread_rng();

    // empty slice test
    {
        let result = executor.execute((&[], &[]));

        assert_eq!(result.decrypt_trivial(), Ok(true));
    }

    let halved_nb_tests = nb_tests / 2;

    // Test where inputs are not equal
    for _ in 0..halved_nb_tests {
        let num_values = rng.gen_range(1..MAX_VEC_LEN);
        let mut values = (0..num_values)
            .map(|_| encryption_fn(cks, rng.gen_range(range.clone())))
            .collect::<Vec<_>>();
        let mut values2 = values.clone();

        // Modify such that one block is different
        let value_index = rng.gen_range(0..num_values);
        let block_index = rng.gen_range(0..NB_CTXT);
        let value_to_avoid = cks.decrypt_one_block(&values[value_index].blocks()[block_index]);
        loop {
            let new_value = rng.gen_range(0..cks.parameters().message_modulus().0);
            if new_value != value_to_avoid {
                let new_block = cks.encrypt_one_block(new_value);
                values2[value_index].blocks_mut()[block_index] = new_block;
                break;
            }
        }

        // Add carry to trigger propagation
        let non_zero_clear = loop {
            let r = rng.gen_range(range.clone());
            if r != Clear::ZERO {
                break r;
            }
        };
        sks.unchecked_scalar_add_assign(
            &mut values2[(value_index + 1) % num_values],
            non_zero_clear,
        );
        sks.unchecked_scalar_add_assign(
            &mut values[(value_index + 1) % num_values],
            non_zero_clear,
        );

        let encrypted_result = executor.execute((&values, &values2));
        let result = cks.decrypt_bool(&encrypted_result);
        assert!(!result);

        let encrypted_result2 = executor.execute((&values, &values2));
        assert_eq!(
            encrypted_result2, encrypted_result,
            "Failed determinism check"
        );
    }

    // Test where inputs are equal
    for _ in halved_nb_tests..nb_tests {
        let num_values = rng.gen_range(1..MAX_VEC_LEN);
        let values = (0..num_values)
            .map(|_| encryption_fn(cks, rng.gen_range(range.clone())))
            .collect::<Vec<_>>();

        let result = executor.execute((&values, &values));
        let result = cks.decrypt_bool(&result);
        assert!(result);
    }
}

pub(crate) fn default_all_eq_slices_test_case<P, E>(params: P, mut executor: E)
where
    P: Into<TestParameters>,
    E: for<'a> FunctionExecutor<(&'a [RadixCiphertext], &'a [RadixCiphertext]), BooleanBlock>,
{
    let (cks, mut sks) = KEY_CACHE.get_from_params(params, IntegerKeyKind::Radix);
    sks.set_deterministic_pbs_execution(true);

    let sks = Arc::new(sks);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    // message_modulus^vec_length
    let modulus = unsigned_modulus(cks.parameters().message_modulus(), NB_CTXT as u32);

    executor.setup(&cks, sks.clone());

    default_all_eq_slices_test_case_impl(executor, &sks, &cks, 0..modulus, RadixClientKey::encrypt);
}

pub(crate) fn unchecked_slice_contains_test_case<P, E>(params: P, mut executor: E)
where
    P: Into<TestParameters>,
    E: for<'a> FunctionExecutor<(&'a [RadixCiphertext], &'a [RadixCiphertext]), BooleanBlock>,
{
    let (cks, mut sks) = KEY_CACHE.get_from_params(params, IntegerKeyKind::Radix);
    sks.set_deterministic_pbs_execution(true);

    let sks = Arc::new(sks);

    let nb_ctxt = 8usize.div_ceil(cks.parameters().message_modulus().0.ilog2() as usize);
    let cks = RadixClientKey::from((cks, nb_ctxt));

    executor.setup(&cks, sks);

    const ALPHABET: [char; 36] = [
        'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's',
        't', 'u', 'v', 'x', 'y', 'z', '0', '🐧', '🦆', '🦦', '🦨', '🐈', '🐱', '🎮', '⊹', 'Ã',
        '🤗', '✅',
    ];

    let nb_tests = nb_tests_for_params(cks.parameters());
    let mut rng = thread_rng();

    let halved_tests = (nb_tests / 2).max(1);

    const MIN_STR_LEN: usize = 25;
    const MAX_STR_LEN: usize = 50;

    // First half of test: tests when the sub slice is actually contained
    for _ in 0..halved_tests {
        let str_size = rng.gen_range(MIN_STR_LEN..MAX_STR_LEN);
        let mut str = String::with_capacity(str_size);
        for _ in 0..str_size {
            let i = rng.gen_range(0..ALPHABET.len());
            str.push(ALPHABET[i]);
        }

        let slice_start = rng.gen_range(0..str_size - 1);
        let slice_end = rng.gen_range(slice_start + 1..str_size);
        let slice = str
            .chars()
            .skip(slice_start)
            .take(slice_end - slice_start)
            .collect::<String>();
        assert!(str.contains(&slice));

        let encrypted_str = str
            .as_bytes()
            .iter()
            .map(|byte| cks.encrypt(*byte))
            .collect::<Vec<_>>();
        let encrypted_slice = slice
            .as_bytes()
            .iter()
            .map(|byte| cks.encrypt(*byte))
            .collect::<Vec<_>>();

        let is_contained = executor.execute((&encrypted_str, &encrypted_slice));

        let is_contained = cks.decrypt_bool(&is_contained);
        assert!(is_contained);
    }

    // Second half of test: tests when the sub slice is NOT actually contained
    for _ in 0..halved_tests {
        let str_size = rng.gen_range(MIN_STR_LEN..MAX_STR_LEN);
        let mut str = String::with_capacity(str_size);
        for _ in 0..str_size {
            let i = rng.gen_range(0..ALPHABET.len());
            str.push(ALPHABET[i]);
        }

        let slice_size = rng.gen_range(MIN_STR_LEN..MAX_STR_LEN);
        let mut slice = String::with_capacity(str_size);
        loop {
            for _ in 0..slice_size {
                let i = rng.gen_range(0..ALPHABET.len());
                slice.push(ALPHABET[i]);
            }

            if !str.contains(&slice) {
                break;
            }
            slice.clear();
        }

        let encrypted_str = str
            .as_bytes()
            .iter()
            .map(|byte| cks.encrypt(*byte))
            .collect::<Vec<_>>();
        let encrypted_slice = slice
            .as_bytes()
            .iter()
            .map(|byte| cks.encrypt(*byte))
            .collect::<Vec<_>>();

        let is_contained = executor.execute((&encrypted_str, &encrypted_slice));

        let is_contained = cks.decrypt_bool(&is_contained);
        assert!(!is_contained);
    }
}
