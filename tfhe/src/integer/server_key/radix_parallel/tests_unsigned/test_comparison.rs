use crate::core_crypto::prelude::UnsignedNumeric;
use crate::integer::block_decomposition::{DecomposableInto, RecomposableFrom};
use crate::integer::ciphertext::RadixCiphertext;
use crate::integer::keycache::KEY_CACHE;
use crate::integer::server_key::radix_parallel::tests_cases_unsigned::FunctionExecutor;
use crate::integer::server_key::radix_parallel::tests_unsigned::CpuFunctionExecutor;
use crate::integer::tests::create_parametrized_test;
use crate::integer::{BooleanBlock, IntegerKeyKind, RadixClientKey, ServerKey, U256};
#[cfg(tarpaulin)]
use crate::shortint::parameters::coverage_parameters::*;
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
    P: Into<PBSParameters>,
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
    let mut rng = rand::thread_rng();

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
    P: Into<PBSParameters>,
    Scalar: UnsignedNumeric
        + AddAssign<Scalar>
        + DecomposableInto<u64>
        + RecomposableFrom<u64>
        + From<bool>,
    T: for<'a> FunctionExecutor<(&'a mut RadixCiphertext, &'a mut RadixCiphertext), BooleanBlock>,
    ClearF: Fn(Scalar, Scalar) -> Scalar,
    Standard: Distribution<Scalar>,
{
    let mut rng = rand::thread_rng();

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
    P: Into<PBSParameters>,
    Scalar: UnsignedNumeric
        + AddAssign<Scalar>
        + DecomposableInto<u64>
        + RecomposableFrom<u64>
        + From<bool>,
    T: for<'a> FunctionExecutor<(&'a RadixCiphertext, &'a RadixCiphertext), BooleanBlock>,
    ClearF: Fn(Scalar, Scalar) -> Scalar,
    Standard: Distribution<Scalar>,
{
    let mut rng = rand::thread_rng();

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
            fn [<integer_unchecked_ $comparison_name _ $clear_type:lower>]<P>(param: P) where P: Into<PBSParameters>{
                let num_tests = 1;
                let executor = CpuFunctionExecutor::new(&ServerKey::[<unchecked_ $comparison_name>]);
                test_unchecked_function(
                    param,
                    num_tests,
                    executor,
                    |lhs, rhs| $clear_type::from(<$clear_type>::$comparison_name(&lhs, &rhs)),
                )
            }

            fn [<integer_unchecked_ $comparison_name _parallelized_ $clear_type:lower>]<P>(param: P) where P: Into<PBSParameters> {
                let num_tests = 1;
                let executor = CpuFunctionExecutor::new(&ServerKey::[<unchecked_ $comparison_name _parallelized>]);
                test_unchecked_function(
                    param,
                    num_tests,
                    executor,
                    |lhs, rhs| $clear_type::from(<$clear_type>::$comparison_name(&lhs, &rhs)),
                )
            }

            fn [<integer_smart_ $comparison_name _ $clear_type:lower>]<P>(param: P) where P: Into<PBSParameters> {
                let num_tests = 1;
                let executor = CpuFunctionExecutor::new(&ServerKey::[<smart_ $comparison_name>]);
                test_smart_function(
                    param,
                    num_tests,
                    executor,
                    |lhs, rhs| $clear_type::from(<$clear_type>::$comparison_name(&lhs, &rhs)),
                )
            }

            fn [<integer_smart_ $comparison_name _parallelized_ $clear_type:lower>]<P>(param: P) where P: Into<PBSParameters> {
                let num_tests = 1;
                let executor = CpuFunctionExecutor::new(&ServerKey::[<smart_ $comparison_name _parallelized>]);
                test_smart_function(
                    param,
                    num_tests,
                    executor,
                    |lhs, rhs| $clear_type::from(<$clear_type>::$comparison_name(&lhs, &rhs)),
                )
            }

            fn [<integer_default_ $comparison_name _parallelized_ $clear_type:lower>]<P>(param: P) where P: Into<PBSParameters> {
                let num_tests = 1;
                let executor = CpuFunctionExecutor::new(&ServerKey::[<$comparison_name _parallelized>]);
                test_default_function(
                    param,
                    num_tests,
                    executor,
                    |lhs, rhs| $clear_type::from(<$clear_type>::$comparison_name(&lhs, &rhs)),
                )
            }

            create_parametrized_test!([<integer_unchecked_ $comparison_name _ $clear_type:lower>]
            {

                PARAM_MESSAGE_2_CARRY_2_KS_PBS,

                PARAM_MESSAGE_3_CARRY_3_KS_PBS,

                PARAM_MESSAGE_4_CARRY_4_KS_PBS,
                #[cfg(tarpaulin)]
                COVERAGE_PARAM_MESSAGE_2_CARRY_2_KS_PBS
            });
            create_parametrized_test!([<integer_unchecked_ $comparison_name _parallelized_ $clear_type:lower>]
            {

                PARAM_MESSAGE_2_CARRY_2_KS_PBS,

                PARAM_MESSAGE_3_CARRY_3_KS_PBS,

                PARAM_MESSAGE_4_CARRY_4_KS_PBS,
                #[cfg(tarpaulin)]
                COVERAGE_PARAM_MESSAGE_2_CARRY_2_KS_PBS
            });

            create_parametrized_test!([<integer_smart_ $comparison_name _ $clear_type:lower>]
            {

                PARAM_MESSAGE_2_CARRY_2_KS_PBS,
                // We don't use PARAM_MESSAGE_3_CARRY_3_KS_PBS,
                // as smart test might overflow values
                // and when using 3_3 to represent 256 we actually have more than 256 bits
                // of message so the overflow behaviour is not the same, leading to false negatives

                PARAM_MESSAGE_4_CARRY_4_KS_PBS,
                #[cfg(tarpaulin)]
                COVERAGE_PARAM_MESSAGE_2_CARRY_2_KS_PBS
            });

            create_parametrized_test!([<integer_smart_ $comparison_name _parallelized_ $clear_type:lower>]
            {

                PARAM_MESSAGE_2_CARRY_2_KS_PBS,
                // We don't use PARAM_MESSAGE_3_CARRY_3_KS_PBS,
                // as smart test might overflow values
                // and when using 3_3 to represent 256 we actually have more than 256 bits
                // of message so the overflow behaviour is not the same, leading to false negatives

                PARAM_MESSAGE_4_CARRY_4_KS_PBS,
                #[cfg(tarpaulin)]
                COVERAGE_PARAM_MESSAGE_2_CARRY_2_KS_PBS
            });

            create_parametrized_test!([<integer_default_ $comparison_name _parallelized_ $clear_type:lower>]
            {

                PARAM_MESSAGE_2_CARRY_2_KS_PBS,
                // We don't use PARAM_MESSAGE_3_CARRY_3_KS_PBS,
                // as default test might overflow values
                // and when using 3_3 to represent 256 we actually have more than 256 bits
                // of message so the overflow behaviour is not the same, leading to false negatives

                PARAM_MESSAGE_4_CARRY_4_KS_PBS,
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
    P: Into<PBSParameters>,
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
    let mut rng = rand::thread_rng();

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
    P: Into<PBSParameters>,
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
    let mut rng = rand::thread_rng();

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
    P: Into<PBSParameters>,
    Scalar: UnsignedNumeric
        + AddAssign<Scalar>
        + DecomposableInto<u64>
        + RecomposableFrom<u64>
        + From<bool>,
    T: for<'a> FunctionExecutor<(&'a RadixCiphertext, &'a RadixCiphertext), RadixCiphertext>,
    ClearF: Fn(Scalar, Scalar) -> Scalar,
    Standard: Distribution<Scalar>,
{
    let mut rng = rand::thread_rng();

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

    fn integer_unchecked_min_parallelized_u256(params: crate::shortint::ClassicPBSParameters) {
        let executor = CpuFunctionExecutor::new(&ServerKey::unchecked_min_parallelized);
        test_unchecked_minmax(params, 2, executor, std::cmp::min::<U256>);
    }

    fn integer_unchecked_max_parallelized_u256(params: crate::shortint::ClassicPBSParameters) {
        let executor = CpuFunctionExecutor::new(&ServerKey::unchecked_max_parallelized);
        test_unchecked_minmax(params, 2, executor, std::cmp::max::<U256>);
    }

    fn integer_smart_min_parallelized_u256(params: crate::shortint::ClassicPBSParameters) {
        let executor = CpuFunctionExecutor::new(&ServerKey::smart_min_parallelized);
        test_smart_minmax(params, 2, executor, std::cmp::min::<U256>);
    }

    fn integer_smart_max_parallelized_u256(params: crate::shortint::ClassicPBSParameters) {
        let executor = CpuFunctionExecutor::new(&ServerKey::smart_max_parallelized);
        test_smart_minmax(params, 2, executor, std::cmp::max::<U256>);
    }

    fn integer_min_parallelized_u256(params: crate::shortint::ClassicPBSParameters) {
        let executor = CpuFunctionExecutor::new(&ServerKey::min_parallelized);
        test_default_minmax(params, 2, executor, std::cmp::min::<U256>);
    }

    fn integer_max_parallelized_u256(params: crate::shortint::ClassicPBSParameters) {
        let executor = CpuFunctionExecutor::new(&ServerKey::max_parallelized);
        test_default_minmax(params, 2, executor, std::cmp::max::<U256>);
    }

    create_parametrized_test!(integer_unchecked_min_parallelized_u256 {
        PARAM_MESSAGE_2_CARRY_2_KS_PBS,
        PARAM_MESSAGE_3_CARRY_3_KS_PBS,
        PARAM_MESSAGE_4_CARRY_4_KS_PBS
    });
    create_parametrized_test!(integer_unchecked_max_parallelized_u256 {
        PARAM_MESSAGE_2_CARRY_2_KS_PBS,
        PARAM_MESSAGE_3_CARRY_3_KS_PBS,
        PARAM_MESSAGE_4_CARRY_4_KS_PBS
    });
    create_parametrized_test!(integer_smart_min_parallelized_u256 {
        PARAM_MESSAGE_2_CARRY_2_KS_PBS,
        // No test for 3_3, see define_comparison_test_functions macro
        PARAM_MESSAGE_4_CARRY_4_KS_PBS
    });
    create_parametrized_test!(integer_smart_max_parallelized_u256 {
        PARAM_MESSAGE_2_CARRY_2_KS_PBS,
        // No test for 3_3, see define_comparison_test_functions macro
        PARAM_MESSAGE_4_CARRY_4_KS_PBS
    });
    create_parametrized_test!(integer_min_parallelized_u256 {
        PARAM_MESSAGE_2_CARRY_2_KS_PBS,
        // No test for 3_3, see define_comparison_test_functions macro
        PARAM_MESSAGE_4_CARRY_4_KS_PBS
    });
    create_parametrized_test!(integer_max_parallelized_u256 {
        PARAM_MESSAGE_2_CARRY_2_KS_PBS,
        // No test for 3_3, see define_comparison_test_functions macro
        PARAM_MESSAGE_4_CARRY_4_KS_PBS
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
    use crate::integer::tests::create_parametrized_test_classical_params;

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

    create_parametrized_test_classical_params!(integer_unchecked_min_parallelized_u8);
    create_parametrized_test_classical_params!(integer_unchecked_max_parallelized_u8);
    create_parametrized_test_classical_params!(integer_smart_min_parallelized_u8);
    create_parametrized_test_classical_params!(integer_smart_max_parallelized_u8);
    create_parametrized_test_classical_params!(integer_min_parallelized_u8);
    create_parametrized_test_classical_params!(integer_max_parallelized_u8);

    define_comparison_test_functions!(eq, u8);
    define_comparison_test_functions!(ne, u8);
    define_comparison_test_functions!(lt, u8);
    define_comparison_test_functions!(le, u8);
    define_comparison_test_functions!(gt, u8);
    define_comparison_test_functions!(ge, u8);
}
