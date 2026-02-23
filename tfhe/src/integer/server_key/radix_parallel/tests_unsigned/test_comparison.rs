use crate::core_crypto::prelude::UnsignedNumeric;
use crate::integer::block_decomposition::{DecomposableInto, RecomposableFrom};
use crate::integer::ciphertext::RadixCiphertext;
use crate::integer::keycache::KEY_CACHE;
use crate::integer::server_key::radix_parallel::tests_cases_unsigned::FunctionExecutor;
use crate::integer::server_key::radix_parallel::tests_unsigned::{CpuFunctionExecutor, NB_CTXT};
use crate::integer::tests::create_parameterized_test;
use crate::integer::{BooleanBlock, IntegerKeyKind, RadixClientKey, ServerKey, U256};
#[cfg(tarpaulin)]
use crate::shortint::parameters::coverage_parameters::*;
use crate::shortint::parameters::test_params::*;
use crate::shortint::parameters::*;
use rand::distributions::Standard;
use rand::prelude::*;
use std::ops::AddAssign;
use std::sync::Arc;

/// Function to test an "unchecked" server key function.
///
/// This calls the `unchecked_server_key_method` with fresh ciphertexts
/// and compares that it gives the same results as the `clear_fn`.
pub(crate) fn test_unchecked_function<P, T, ClearF, Scalar>(
    param: P,
    num_test: usize,
    mut executor: T,
    clear_fn: ClearF,
) where
    P: Into<TestParameters>,
    Scalar: UnsignedNumeric
        + AddAssign<Scalar>
        + DecomposableInto<u64>
        + RecomposableFrom<u64>
        + std::ops::Shr<usize, Output = Scalar>
        + From<bool>,
    T: for<'a> FunctionExecutor<(&'a RadixCiphertext, &'a RadixCiphertext), BooleanBlock>,
    ClearF: Fn(Scalar, Scalar) -> Scalar,
    Standard: Distribution<Scalar>,
{
    let mut rng = rand::rng();

    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let num_bits_per_block = cks.parameters().message_modulus().0.ilog2() as usize;
    let num_block = 256usize.div_ceil(num_bits_per_block);

    let sks = Arc::new(sks);
    let cks = RadixClientKey::from((cks, num_block));

    executor.setup(&cks, sks);

    // Test with low number of blocks, as they take a different branches
    // (regression tests)
    for num_block in [num_block, 1, 2] {
        let max = Scalar::MAX >> (Scalar::BITS - (num_block * num_bits_per_block));
        for _ in 0..num_test {
            let clear_a = rng.gen::<Scalar>() & max;
            let clear_b = rng.gen::<Scalar>() & max;
            let a = cks.encrypt(clear_a);
            let b = cks.encrypt(clear_b);

            {
                let result = executor.execute((&a, &b));
                let decrypted: Scalar = cks.decrypt_bool(&result).into();
                let expected_result = clear_fn(clear_a, clear_b);
                assert_eq!(decrypted, expected_result);
            }

            {
                // Force case where lhs == rhs
                let result = executor.execute((&a, &a));
                let decrypted: Scalar = cks.decrypt_bool(&result).into();
                let expected_result = clear_fn(clear_a, clear_a);
                assert_eq!(decrypted, expected_result);
            }
        }
    }
}

/// Function to test a "smart" server_key function.
///
/// This calls the `smart_server_key_method` with non-fresh ciphertexts,
/// that is ciphertexts that have non-zero carries, and compares that the result is
/// the same as the one of`clear_fn`.
pub(crate) fn test_smart_function<P, T, ClearF, Scalar>(
    param: P,
    num_test: usize,
    mut executor: T,
    clear_fn: ClearF,
) where
    P: Into<TestParameters>,
    Scalar: UnsignedNumeric
        + AddAssign<Scalar>
        + DecomposableInto<u64>
        + RecomposableFrom<u64>
        + From<bool>,
    T: for<'a> FunctionExecutor<(&'a mut RadixCiphertext, &'a mut RadixCiphertext), BooleanBlock>,
    ClearF: Fn(Scalar, Scalar) -> Scalar,
    Standard: Distribution<Scalar>,
{
    let mut rng = rand::rng();

    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let sks = Arc::new(sks);
    let num_block = Scalar::BITS.div_ceil(cks.parameters().message_modulus().0.ilog2() as usize);
    let cks = RadixClientKey::from((cks, num_block));

    executor.setup(&cks, sks.clone());
    assert_eq!(
        Scalar::BITS as u32 % cks.parameters().message_modulus().0.ilog2(),
        0,
        "bit width must be a multiple of number of bit in a block"
    );

    for _ in 0..num_test {
        let mut clear_0 = rng.gen::<Scalar>();
        let mut clear_1 = rng.gen::<Scalar>();
        let mut ct_0 = cks.encrypt(clear_0);
        let mut ct_1 = cks.encrypt(clear_1);

        // Raise the degree to ensure worst case path in operations
        while ct_0.block_carries_are_empty() {
            let clear_2 = rng.gen::<Scalar>();
            let ct_2 = cks.encrypt(clear_2);
            sks.unchecked_add_assign(&mut ct_0, &ct_2);
            clear_0 += clear_2;
        }

        while ct_1.block_carries_are_empty() {
            let clear_2 = rng.gen::<Scalar>();
            let ct_2 = cks.encrypt(clear_2);
            sks.unchecked_add_assign(&mut ct_1, &ct_2);
            clear_1 += clear_2;
        }

        // Sanity decryption checks
        {
            let a: Scalar = cks.decrypt(&ct_0);
            assert_eq!(a, clear_0);

            let b: Scalar = cks.decrypt(&ct_1);
            assert_eq!(b, clear_1);
        }

        assert!(!ct_0.block_carries_are_empty());
        assert!(!ct_1.block_carries_are_empty());
        let encrypted_result = executor.execute((&mut ct_0, &mut ct_1));
        assert!(ct_0.block_carries_are_empty());
        assert!(ct_1.block_carries_are_empty());

        // Sanity decryption checks
        {
            let a: Scalar = cks.decrypt(&ct_0);
            assert_eq!(a, clear_0);

            let b: Scalar = cks.decrypt(&ct_1);
            assert_eq!(b, clear_1);
        }

        let decrypted_result: Scalar = cks.decrypt_bool(&encrypted_result).into();

        let expected_result = clear_fn(clear_0, clear_1);
        assert_eq!(decrypted_result, expected_result);
    }
}

/// Function to test a "default" server_key function.
///
/// This calls the `server_key_method` with non-fresh ciphertexts,
/// that is ciphertexts that have non-zero carries, and compares that the result is
/// the same as the one of`clear_fn`.
pub(crate) fn test_default_function<P, T, ClearF, Scalar>(
    param: P,
    num_test: usize,
    mut executor: T,
    clear_fn: ClearF,
) where
    P: Into<TestParameters>,
    Scalar: UnsignedNumeric
        + AddAssign<Scalar>
        + DecomposableInto<u64>
        + RecomposableFrom<u64>
        + From<bool>,
    T: for<'a> FunctionExecutor<(&'a RadixCiphertext, &'a RadixCiphertext), BooleanBlock>,
    ClearF: Fn(Scalar, Scalar) -> Scalar,
    Standard: Distribution<Scalar>,
{
    let mut rng = rand::rng();

    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let sks = Arc::new(sks);
    let num_block = Scalar::BITS.div_ceil(cks.parameters().message_modulus().0.ilog2() as usize);
    let cks = RadixClientKey::from((cks, num_block));

    executor.setup(&cks, sks.clone());

    assert_eq!(
        Scalar::BITS as u32 % cks.parameters().message_modulus().0.ilog2(),
        0,
        "bit width must be a multiple of number of bit in a block"
    );

    for _ in 0..num_test {
        let mut clear_0 = rng.gen::<Scalar>();
        let mut clear_1 = rng.gen::<Scalar>();
        let mut ct_0 = cks.encrypt(clear_0);
        let mut ct_1 = cks.encrypt(clear_1);

        // Raise the degree, so as to ensure worst case path in operations
        while ct_0.block_carries_are_empty() {
            let clear_2 = rng.gen::<Scalar>();
            let ct_2 = cks.encrypt(clear_2);
            sks.unchecked_add_assign(&mut ct_0, &ct_2);
            clear_0 += clear_2;
        }

        while ct_1.block_carries_are_empty() {
            let clear_2 = rng.gen::<Scalar>();
            let ct_2 = cks.encrypt(clear_2);
            sks.unchecked_add_assign(&mut ct_1, &ct_2);
            clear_1 += clear_2;
        }

        // Sanity decryption checks
        {
            let a: Scalar = cks.decrypt(&ct_0);
            assert_eq!(a, clear_0);

            let b: Scalar = cks.decrypt(&ct_1);
            assert_eq!(b, clear_1);
        }

        assert!(!ct_0.block_carries_are_empty());
        assert!(!ct_1.block_carries_are_empty());
        let encrypted_result = executor.execute((&ct_0, &ct_1));

        // Sanity decryption checks
        {
            let a: Scalar = cks.decrypt(&ct_0);
            assert_eq!(a, clear_0);

            let b: Scalar = cks.decrypt(&ct_1);
            assert_eq!(b, clear_1);
        }

        let decrypted_result: Scalar = cks.decrypt_bool(&encrypted_result).into();

        let expected_result = clear_fn(clear_0, clear_1);
        assert_eq!(decrypted_result, expected_result);
    }
}

/// This macro generates the tests for a given comparison fn
///
/// All our comparison function have 5 variants:
/// - unchecked_$comparison_name
/// - unchecked_$comparison_name_parallelized
/// - smart_$comparison_name
/// - smart_$comparison_name_parallelized
/// - $comparison_name_parallelized
///
/// So, for example, for the `gt` comparison fn, this macro will generate the tests for
/// the 5 variants described above
macro_rules! define_comparison_test_functions {
    ($comparison_name:ident, $clear_type:ty) => {
        ::paste::paste!{
            fn [<integer_unchecked_ $comparison_name _ $clear_type:lower>]<P>(param: P) where P: Into<TestParameters>{
                let num_tests = 1;
                let executor = CpuFunctionExecutor::new(&ServerKey::[<unchecked_ $comparison_name>]);
                test_unchecked_function(
                    param,
                    num_tests,
                    executor,
                    |lhs, rhs| $clear_type::from(<$clear_type>::$comparison_name(&lhs, &rhs)),
                )
            }

            fn [<integer_unchecked_ $comparison_name _parallelized_ $clear_type:lower>]<P>(param: P) where P: Into<TestParameters> {
                let num_tests = 1;
                let executor = CpuFunctionExecutor::new(&ServerKey::[<unchecked_ $comparison_name _parallelized>]);
                test_unchecked_function(
                    param,
                    num_tests,
                    executor,
                    |lhs, rhs| $clear_type::from(<$clear_type>::$comparison_name(&lhs, &rhs)),
                )
            }

            fn [<integer_smart_ $comparison_name _ $clear_type:lower>]<P>(param: P) where P: Into<TestParameters> {
                let num_tests = 1;
                let executor = CpuFunctionExecutor::new(&ServerKey::[<smart_ $comparison_name>]);
                test_smart_function(
                    param,
                    num_tests,
                    executor,
                    |lhs, rhs| $clear_type::from(<$clear_type>::$comparison_name(&lhs, &rhs)),
                )
            }

            fn [<integer_smart_ $comparison_name _parallelized_ $clear_type:lower>]<P>(param: P) where P: Into<TestParameters> {
                let num_tests = 1;
                let executor = CpuFunctionExecutor::new(&ServerKey::[<smart_ $comparison_name _parallelized>]);
                test_smart_function(
                    param,
                    num_tests,
                    executor,
                    |lhs, rhs| $clear_type::from(<$clear_type>::$comparison_name(&lhs, &rhs)),
                )
            }

            fn [<integer_default_ $comparison_name _parallelized_ $clear_type:lower>]<P>(param: P) where P: Into<TestParameters> {
                let num_tests = 1;
                let executor = CpuFunctionExecutor::new(&ServerKey::[<$comparison_name _parallelized>]);
                test_default_function(
                    param,
                    num_tests,
                    executor,
                    |lhs, rhs| $clear_type::from(<$clear_type>::$comparison_name(&lhs, &rhs)),
                )
            }

            create_parameterized_test!([<integer_unchecked_ $comparison_name _ $clear_type:lower>]
            {
                // Non parallelized does not support 1_1

                PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,

                TEST_PARAM_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M128,

                // 2M128 is too slow for 4_4, it is estimated to be 2x slower
                TEST_PARAM_MESSAGE_4_CARRY_4_KS_PBS_GAUSSIAN_2M64,
                #[cfg(tarpaulin)]
                COVERAGE_PARAM_MESSAGE_2_CARRY_2_KS_PBS
            });
            create_parameterized_test!([<integer_unchecked_ $comparison_name _parallelized_ $clear_type:lower>]
            {
                TEST_PARAM_MESSAGE_1_CARRY_1_KS_PBS_GAUSSIAN_2M128,

                PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,

                TEST_PARAM_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M128,

                // 2M128 is too slow for 4_4, it is estimated to be 2x slower
                TEST_PARAM_MESSAGE_4_CARRY_4_KS_PBS_GAUSSIAN_2M64,
                #[cfg(tarpaulin)]
                COVERAGE_PARAM_MESSAGE_2_CARRY_2_KS_PBS
            });

            create_parameterized_test!([<integer_smart_ $comparison_name _ $clear_type:lower>]
            {
                // Non parallelized does not support 1_1

                PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
                // We don't use PARAM_MESSAGE_3_CARRY_3_KS_PBS,
                // as smart test might overflow values
                // and when using 3_3 to represent 256 we actually have more than 256 bits
                // of message so the overflow behaviour is not the same, leading to false negatives

                // 2M128 is too slow for 4_4, it is estimated to be 2x slower
                TEST_PARAM_MESSAGE_4_CARRY_4_KS_PBS_GAUSSIAN_2M64,
                #[cfg(tarpaulin)]
                COVERAGE_PARAM_MESSAGE_2_CARRY_2_KS_PBS
            });

            create_parameterized_test!([<integer_smart_ $comparison_name _parallelized_ $clear_type:lower>]
            {
                TEST_PARAM_MESSAGE_1_CARRY_1_KS_PBS_GAUSSIAN_2M128,

                PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
                // We don't use PARAM_MESSAGE_3_CARRY_3_KS_PBS,
                // as smart test might overflow values
                // and when using 3_3 to represent 256 we actually have more than 256 bits
                // of message so the overflow behaviour is not the same, leading to false negatives

                // 2M128 is too slow for 4_4, it is estimated to be 2x slower
                TEST_PARAM_MESSAGE_4_CARRY_4_KS_PBS_GAUSSIAN_2M64,
                #[cfg(tarpaulin)]
                COVERAGE_PARAM_MESSAGE_2_CARRY_2_KS_PBS
            });

            create_parameterized_test!([<integer_default_ $comparison_name _parallelized_ $clear_type:lower>]
            {
                TEST_PARAM_MESSAGE_1_CARRY_1_KS_PBS_GAUSSIAN_2M128,

                PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
                // We don't use PARAM_MESSAGE_3_CARRY_3_KS_PBS,
                // as default test might overflow values
                // and when using 3_3 to represent 256 we actually have more than 256 bits
                // of message so the overflow behaviour is not the same, leading to false negatives

                // 2M128 is too slow for 4_4, it is estimated to be 2x slower
                TEST_PARAM_MESSAGE_4_CARRY_4_KS_PBS_GAUSSIAN_2M64,
                #[cfg(tarpaulin)]
                COVERAGE_PARAM_MESSAGE_2_CARRY_2_KS_PBS
            });
        }
    };
}

/// Function to test an "unchecked" server key function.
///
/// This calls the `unchecked_server_key_method` with fresh ciphertexts
/// and compares that it gives the same results as the `clear_fn`.
pub(crate) fn test_unchecked_minmax<P, T, ClearF, Scalar>(
    param: P,
    num_test: usize,
    mut executor: T,
    clear_fn: ClearF,
) where
    P: Into<TestParameters>,
    Scalar: UnsignedNumeric
        + AddAssign<Scalar>
        + DecomposableInto<u64>
        + RecomposableFrom<u64>
        + std::ops::Shr<usize, Output = Scalar>
        + From<bool>,
    T: for<'a> FunctionExecutor<(&'a RadixCiphertext, &'a RadixCiphertext), RadixCiphertext>,
    ClearF: Fn(Scalar, Scalar) -> Scalar,
    Standard: Distribution<Scalar>,
{
    let mut rng = rand::rng();

    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let num_bits_per_block = cks.parameters().message_modulus().0.ilog2() as usize;
    let num_block = 256usize.div_ceil(num_bits_per_block);

    let sks = Arc::new(sks);
    let cks = RadixClientKey::from((cks, num_block));

    executor.setup(&cks, sks);

    // Test with low number of blocks, as they take a different branches
    // (regression tests)
    for num_block in [num_block, 1, 2] {
        let max = Scalar::MAX >> (Scalar::BITS - (num_block * num_bits_per_block));
        for _ in 0..num_test {
            let clear_a = rng.gen::<Scalar>() & max;
            let clear_b = rng.gen::<Scalar>() & max;
            let a = cks.encrypt(clear_a);
            let b = cks.encrypt(clear_b);

            {
                let result = executor.execute((&a, &b));
                let decrypted: Scalar = cks.decrypt(&result);
                let expected_result = clear_fn(clear_a, clear_b);
                assert_eq!(decrypted, expected_result);
            }

            {
                // Force case where lhs == rhs
                let result = executor.execute((&a, &a));
                let decrypted: Scalar = cks.decrypt(&result);
                let expected_result = clear_fn(clear_a, clear_a);
                assert_eq!(decrypted, expected_result);
            }
        }
    }
}

/// Function to test a "smart" server_key function.
///
/// This calls the `smart_server_key_method` with non-fresh ciphertexts,
/// that is ciphertexts that have non-zero carries, and compares that the result is
/// the same as the one of`clear_fn`.
pub(crate) fn test_smart_minmax<P, T, ClearF, Scalar>(
    param: P,
    num_test: usize,
    mut executor: T,
    clear_fn: ClearF,
) where
    P: Into<TestParameters>,
    Scalar: UnsignedNumeric
        + AddAssign<Scalar>
        + DecomposableInto<u64>
        + RecomposableFrom<u64>
        + From<bool>,
    T: for<'a> FunctionExecutor<
        (&'a mut RadixCiphertext, &'a mut RadixCiphertext),
        RadixCiphertext,
    >,
    ClearF: Fn(Scalar, Scalar) -> Scalar,
    Standard: Distribution<Scalar>,
{
    let mut rng = rand::rng();

    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let sks = Arc::new(sks);
    let num_block = Scalar::BITS.div_ceil(cks.parameters().message_modulus().0.ilog2() as usize);
    let cks = RadixClientKey::from((cks, num_block));

    executor.setup(&cks, sks.clone());
    assert_eq!(
        Scalar::BITS as u32 % cks.parameters().message_modulus().0.ilog2(),
        0,
        "bit width must be a multiple of number of bit in a block"
    );

    for _ in 0..num_test {
        let mut clear_0 = rng.gen::<Scalar>();
        let mut clear_1 = rng.gen::<Scalar>();
        let mut ct_0 = cks.encrypt(clear_0);
        let mut ct_1 = cks.encrypt(clear_1);

        // Raise the degree to ensure worst case path in operations
        while ct_0.block_carries_are_empty() {
            let clear_2 = rng.gen::<Scalar>();
            let ct_2 = cks.encrypt(clear_2);
            sks.unchecked_add_assign(&mut ct_0, &ct_2);
            clear_0 += clear_2;
        }

        while ct_1.block_carries_are_empty() {
            let clear_2 = rng.gen::<Scalar>();
            let ct_2 = cks.encrypt(clear_2);
            sks.unchecked_add_assign(&mut ct_1, &ct_2);
            clear_1 += clear_2;
        }

        // Sanity decryption checks
        {
            let a: Scalar = cks.decrypt(&ct_0);
            assert_eq!(a, clear_0);

            let b: Scalar = cks.decrypt(&ct_1);
            assert_eq!(b, clear_1);
        }

        assert!(!ct_0.block_carries_are_empty());
        assert!(!ct_1.block_carries_are_empty());
        let encrypted_result = executor.execute((&mut ct_0, &mut ct_1));
        assert!(ct_0.block_carries_are_empty());
        assert!(ct_1.block_carries_are_empty());

        // Sanity decryption checks
        {
            let a: Scalar = cks.decrypt(&ct_0);
            assert_eq!(a, clear_0);

            let b: Scalar = cks.decrypt(&ct_1);
            assert_eq!(b, clear_1);
        }

        let decrypted_result: Scalar = cks.decrypt(&encrypted_result);

        let expected_result = clear_fn(clear_0, clear_1);
        assert_eq!(decrypted_result, expected_result);
    }
}

/// Function to test a "default" server_key function.
///
/// This calls the `server_key_method` with non-fresh ciphertexts,
/// that is ciphertexts that have non-zero carries, and compares that the result is
/// the same as the one of`clear_fn`.
pub(crate) fn test_default_minmax<P, T, ClearF, Scalar>(
    param: P,
    num_test: usize,
    mut executor: T,
    clear_fn: ClearF,
) where
    P: Into<TestParameters>,
    Scalar: UnsignedNumeric
        + AddAssign<Scalar>
        + DecomposableInto<u64>
        + RecomposableFrom<u64>
        + From<bool>,
    T: for<'a> FunctionExecutor<(&'a RadixCiphertext, &'a RadixCiphertext), RadixCiphertext>,
    ClearF: Fn(Scalar, Scalar) -> Scalar,
    Standard: Distribution<Scalar>,
{
    let mut rng = rand::rng();

    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let sks = Arc::new(sks);
    let num_block = Scalar::BITS.div_ceil(cks.parameters().message_modulus().0.ilog2() as usize);
    let cks = RadixClientKey::from((cks, num_block));

    executor.setup(&cks, sks.clone());

    assert_eq!(
        Scalar::BITS as u32 % cks.parameters().message_modulus().0.ilog2(),
        0,
        "bit width must be a multiple of number of bit in a block"
    );

    for _ in 0..num_test {
        let mut clear_0 = rng.gen::<Scalar>();
        let mut clear_1 = rng.gen::<Scalar>();
        let mut ct_0 = cks.encrypt(clear_0);
        let mut ct_1 = cks.encrypt(clear_1);

        // Raise the degree, so as to ensure worst case path in operations
        while ct_0.block_carries_are_empty() {
            let clear_2 = rng.gen::<Scalar>();
            let ct_2 = cks.encrypt(clear_2);
            sks.unchecked_add_assign(&mut ct_0, &ct_2);
            clear_0 += clear_2;
        }

        while ct_1.block_carries_are_empty() {
            let clear_2 = rng.gen::<Scalar>();
            let ct_2 = cks.encrypt(clear_2);
            sks.unchecked_add_assign(&mut ct_1, &ct_2);
            clear_1 += clear_2;
        }

        // Sanity decryption checks
        {
            let a: Scalar = cks.decrypt(&ct_0);
            assert_eq!(a, clear_0);

            let b: Scalar = cks.decrypt(&ct_1);
            assert_eq!(b, clear_1);
        }

        assert!(!ct_0.block_carries_are_empty());
        assert!(!ct_1.block_carries_are_empty());
        let encrypted_result = executor.execute((&ct_0, &ct_1));
        assert!(encrypted_result.block_carries_are_empty());

        // Sanity decryption checks
        {
            let a: Scalar = cks.decrypt(&ct_0);
            assert_eq!(a, clear_0);

            let b: Scalar = cks.decrypt(&ct_1);
            assert_eq!(b, clear_1);
        }

        let decrypted_result: Scalar = cks.decrypt(&encrypted_result);

        let expected_result = clear_fn(clear_0, clear_1);
        assert_eq!(decrypted_result, expected_result);
    }
}

#[cfg(not(tarpaulin))]
mod no_coverage {
    use super::*;

    fn integer_unchecked_min_parallelized_u256(params: impl Into<TestParameters>) {
        let executor = CpuFunctionExecutor::new(&ServerKey::unchecked_min_parallelized);
        test_unchecked_minmax(params, 2, executor, std::cmp::min::<U256>);
    }

    fn integer_unchecked_max_parallelized_u256(params: impl Into<TestParameters>) {
        let executor = CpuFunctionExecutor::new(&ServerKey::unchecked_max_parallelized);
        test_unchecked_minmax(params, 2, executor, std::cmp::max::<U256>);
    }

    fn integer_smart_min_parallelized_u256(params: impl Into<TestParameters>) {
        let executor = CpuFunctionExecutor::new(&ServerKey::smart_min_parallelized);
        test_smart_minmax(params, 2, executor, std::cmp::min::<U256>);
    }

    fn integer_smart_max_parallelized_u256(params: impl Into<TestParameters>) {
        let executor = CpuFunctionExecutor::new(&ServerKey::smart_max_parallelized);
        test_smart_minmax(params, 2, executor, std::cmp::max::<U256>);
    }

    fn integer_min_parallelized_u256(params: impl Into<TestParameters>) {
        let executor = CpuFunctionExecutor::new(&ServerKey::min_parallelized);
        test_default_minmax(params, 2, executor, std::cmp::min::<U256>);
    }

    fn integer_max_parallelized_u256(params: impl Into<TestParameters>) {
        let executor = CpuFunctionExecutor::new(&ServerKey::max_parallelized);
        test_default_minmax(params, 2, executor, std::cmp::max::<U256>);
    }

    create_parameterized_test!(integer_unchecked_min_parallelized_u256);
    create_parameterized_test!(integer_unchecked_max_parallelized_u256);
    create_parameterized_test!(integer_smart_min_parallelized_u256 {
        TEST_PARAM_MESSAGE_1_CARRY_1_KS_PBS_GAUSSIAN_2M128,
        PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        // No test for 3_3, see define_comparison_test_functions macro
        // 2M128 is too slow for 4_4, it is estimated to be 2x slower
        TEST_PARAM_MESSAGE_4_CARRY_4_KS_PBS_GAUSSIAN_2M64
    });
    create_parameterized_test!(integer_smart_max_parallelized_u256 {
        TEST_PARAM_MESSAGE_1_CARRY_1_KS_PBS_GAUSSIAN_2M128,
        PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        // No test for 3_3, see define_comparison_test_functions macro
        // 2M128 is too slow for 4_4, it is estimated to be 2x slower
        TEST_PARAM_MESSAGE_4_CARRY_4_KS_PBS_GAUSSIAN_2M64
    });
    create_parameterized_test!(integer_min_parallelized_u256 {
        TEST_PARAM_MESSAGE_1_CARRY_1_KS_PBS_GAUSSIAN_2M128,
        PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        // No test for 3_3, see define_comparison_test_functions macro
        // 2M128 is too slow for 4_4, it is estimated to be 2x slower
        TEST_PARAM_MESSAGE_4_CARRY_4_KS_PBS_GAUSSIAN_2M64
    });
    create_parameterized_test!(integer_max_parallelized_u256 {
        TEST_PARAM_MESSAGE_1_CARRY_1_KS_PBS_GAUSSIAN_2M128,
        PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        // No test for 3_3, see define_comparison_test_functions macro
        // 2M128 is too slow for 4_4, it is estimated to be 2x slower
        TEST_PARAM_MESSAGE_4_CARRY_4_KS_PBS_GAUSSIAN_2M64
    });

    define_comparison_test_functions!(eq, U256);
    define_comparison_test_functions!(ne, U256);
    define_comparison_test_functions!(lt, U256);
    define_comparison_test_functions!(le, U256);
    define_comparison_test_functions!(gt, U256);
    define_comparison_test_functions!(ge, U256);
}

// Smaller integers are used in coverage to speed-up execution.
#[cfg(tarpaulin)]
mod coverage {
    use super::*;
    use crate::integer::tests::create_parameterized_test_classical_params;

    //=============================================================
    // Unsigned comparison tests
    //=============================================================

    fn integer_unchecked_min_parallelized_u8(params: crate::shortint::ClassicPBSParameters) {
        let executor = CpuFunctionExecutor::new(&ServerKey::unchecked_min_parallelized);
        test_unchecked_minmax(params, 1, executor, std::cmp::min::<u8>);
    }

    fn integer_unchecked_max_parallelized_u8(params: crate::shortint::ClassicPBSParameters) {
        let executor = CpuFunctionExecutor::new(&ServerKey::unchecked_max_parallelized);
        test_unchecked_minmax(params, 1, executor, std::cmp::max::<u8>);
    }

    fn integer_smart_min_parallelized_u8(params: crate::shortint::ClassicPBSParameters) {
        let executor = CpuFunctionExecutor::new(&ServerKey::smart_min_parallelized);
        test_smart_minmax(params, 1, executor, std::cmp::min::<u8>);
    }

    fn integer_smart_max_parallelized_u8(params: crate::shortint::ClassicPBSParameters) {
        let executor = CpuFunctionExecutor::new(&ServerKey::smart_max_parallelized);
        test_smart_minmax(params, 1, executor, std::cmp::max::<u8>);
    }

    fn integer_min_parallelized_u8(params: crate::shortint::ClassicPBSParameters) {
        let executor = CpuFunctionExecutor::new(&ServerKey::min_parallelized);
        test_default_minmax(params, 1, executor, std::cmp::min::<u8>);
    }

    fn integer_max_parallelized_u8(params: crate::shortint::ClassicPBSParameters) {
        let executor = CpuFunctionExecutor::new(&ServerKey::max_parallelized);
        test_default_minmax(params, 1, executor, std::cmp::max::<u8>);
    }

    create_parameterized_test_classical_params!(integer_unchecked_min_parallelized_u8);
    create_parameterized_test_classical_params!(integer_unchecked_max_parallelized_u8);
    create_parameterized_test_classical_params!(integer_smart_min_parallelized_u8);
    create_parameterized_test_classical_params!(integer_smart_max_parallelized_u8);
    create_parameterized_test_classical_params!(integer_min_parallelized_u8);
    create_parameterized_test_classical_params!(integer_max_parallelized_u8);

    define_comparison_test_functions!(eq, u8);
    define_comparison_test_functions!(ne, u8);
    define_comparison_test_functions!(lt, u8);
    define_comparison_test_functions!(le, u8);
    define_comparison_test_functions!(gt, u8);
    define_comparison_test_functions!(ge, u8);
}

create_parameterized_test!(integer_extensive_trivial_default_comparisons);

fn integer_extensive_trivial_default_comparisons(params: impl Into<TestParameters>) {
    let lt_executor = CpuFunctionExecutor::new(&ServerKey::lt_parallelized);
    let le_executor = CpuFunctionExecutor::new(&ServerKey::le_parallelized);
    let gt_executor = CpuFunctionExecutor::new(&ServerKey::gt_parallelized);
    let ge_executor = CpuFunctionExecutor::new(&ServerKey::ge_parallelized);
    let min_executor = CpuFunctionExecutor::new(&ServerKey::min_parallelized);
    let max_executor = CpuFunctionExecutor::new(&ServerKey::max_parallelized);

    extensive_trivial_default_comparisons_test(
        params,
        lt_executor,
        le_executor,
        gt_executor,
        ge_executor,
        min_executor,
        max_executor,
    )
}

/// Although this uses the executor pattern and could be plugged in other backends,
/// It is not recommended to do so unless the backend is extremely fast on trivial ciphertexts
/// or extremely extremely fast in general, or if its plugged just as a one time thing.
#[allow(clippy::eq_op)]
pub(crate) fn extensive_trivial_default_comparisons_test<P, E1, E2, E3, E4, E5, E6>(
    param: P,
    mut lt_executor: E1,
    mut le_executor: E2,
    mut gt_executor: E3,
    mut ge_executor: E4,
    mut min_executor: E5,
    mut max_executor: E6,
) where
    P: Into<TestParameters>,
    E1: for<'a> FunctionExecutor<(&'a RadixCiphertext, &'a RadixCiphertext), BooleanBlock>,
    E2: for<'a> FunctionExecutor<(&'a RadixCiphertext, &'a RadixCiphertext), BooleanBlock>,
    E3: for<'a> FunctionExecutor<(&'a RadixCiphertext, &'a RadixCiphertext), BooleanBlock>,
    E4: for<'a> FunctionExecutor<(&'a RadixCiphertext, &'a RadixCiphertext), BooleanBlock>,
    E5: for<'a> FunctionExecutor<(&'a RadixCiphertext, &'a RadixCiphertext), RadixCiphertext>,
    E6: for<'a> FunctionExecutor<(&'a RadixCiphertext, &'a RadixCiphertext), RadixCiphertext>,
{
    let params = param.into();
    let (cks, mut sks) = KEY_CACHE.get_from_params(params, IntegerKeyKind::Radix);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    sks.set_deterministic_pbs_execution(true);
    let sks = Arc::new(sks);

    let mut rng = thread_rng();

    lt_executor.setup(&cks, sks.clone());
    le_executor.setup(&cks, sks.clone());
    gt_executor.setup(&cks, sks.clone());
    ge_executor.setup(&cks, sks.clone());
    min_executor.setup(&cks, sks.clone());
    max_executor.setup(&cks, sks.clone());

    for num_blocks in 1..=128 {
        let Some(modulus) = (params.message_modulus().0 as u128).checked_pow(num_blocks as u32)
        else {
            break;
        };
        for _ in 0..25 {
            let clear_a = rng.gen_range(0..modulus);
            let clear_b = rng.gen_range(0..modulus);

            let a: RadixCiphertext = sks.create_trivial_radix(clear_a, num_blocks);
            let b: RadixCiphertext = sks.create_trivial_radix(clear_b, num_blocks);

            {
                let result = lt_executor.execute((&a, &b));
                let result = cks.decrypt_bool(&result);
                assert_eq!(result, clear_a < clear_b, "{clear_a} < {clear_b}");

                let result = lt_executor.execute((&a, &a));
                let result = cks.decrypt_bool(&result);
                assert_eq!(result, clear_a < clear_a, "{clear_a} < {clear_a}");
            }

            {
                let result = le_executor.execute((&a, &b));
                let result = cks.decrypt_bool(&result);
                assert_eq!(result, clear_a <= clear_b, "{clear_a} <= {clear_b}");

                let result = le_executor.execute((&a, &a));
                let result = cks.decrypt_bool(&result);
                assert_eq!(result, clear_a <= clear_a, "{clear_a} <= {clear_a}");
            }

            {
                let result = gt_executor.execute((&a, &b));
                let result = cks.decrypt_bool(&result);
                assert_eq!(result, clear_a > clear_b, "{clear_a} > {clear_b}");

                let result = gt_executor.execute((&a, &a));
                let result = cks.decrypt_bool(&result);
                assert_eq!(result, clear_a > clear_a, "{clear_a} > {clear_a}");
            }

            {
                let result = ge_executor.execute((&a, &b));
                let result = cks.decrypt_bool(&result);
                assert_eq!(result, clear_a >= clear_b, "{clear_a} >= {clear_b}");

                let result = ge_executor.execute((&a, &a));
                let result = cks.decrypt_bool(&result);
                assert_eq!(result, clear_a >= clear_a, "{clear_a} >= {clear_a}");
            }

            {
                let result = min_executor.execute((&a, &b));
                let result: u128 = cks.decrypt(&result);
                assert_eq!(result, clear_a.min(clear_b), "{clear_a}.min({clear_b})");

                let result = min_executor.execute((&a, &a));
                let result: u128 = cks.decrypt(&result);
                assert_eq!(result, clear_a.min(clear_a), "{clear_a}.min({clear_a})");
            }

            {
                let result = max_executor.execute((&a, &b));
                let result: u128 = cks.decrypt(&result);
                assert_eq!(result, clear_a.max(clear_b), "{clear_a}.max({clear_b})");

                let result = max_executor.execute((&a, &a));
                let result: u128 = cks.decrypt(&result);
                assert_eq!(result, clear_a.max(clear_a), "{clear_a}.max({clear_a})");
            }
        }
    }
}
