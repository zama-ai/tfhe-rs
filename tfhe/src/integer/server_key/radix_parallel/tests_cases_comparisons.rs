use crate::core_crypto::prelude::{SignedNumeric, UnsignedNumeric};
use crate::integer::block_decomposition::{DecomposableInto, RecomposableFrom};
use crate::integer::ciphertext::{RadixCiphertext, SignedRadixCiphertext};
use crate::integer::client_key::RecomposableSignedInteger;
use crate::integer::keycache::KEY_CACHE;
use crate::integer::{IntegerKeyKind, ServerKey, I256, U256};
#[cfg(tarpaulin)]
use crate::shortint::parameters::coverage_parameters::*;
use crate::shortint::parameters::*;
use crate::shortint::ClassicPBSParameters;
use rand;
use rand::distributions::Standard;
use rand::prelude::*;
use rand_distr::num_traits::WrappingAdd;
use std::ops::{AddAssign, Neg};

//=============================================================
// Unsigned comparison tests
//=============================================================

/// Function to test an "unchecked" server key function.
///
/// This calls the `unchecked_server_key_method` with fresh ciphertexts
/// and compares that it gives the same results as the `clear_fn`.
fn test_unchecked_function<UncheckedFn, ClearF, T>(
    param: ClassicPBSParameters,
    num_test: usize,
    unchecked_comparison_method: UncheckedFn,
    clear_fn: ClearF,
) where
    T: UnsignedNumeric
        + AddAssign<T>
        + DecomposableInto<u64>
        + RecomposableFrom<u64>
        + std::ops::Shr<usize, Output = T>,
    UncheckedFn:
        for<'a> Fn(&'a ServerKey, &'a RadixCiphertext, &'a RadixCiphertext) -> RadixCiphertext,
    ClearF: Fn(T, T) -> T,
    Standard: Distribution<T>,
{
    let mut rng = rand::thread_rng();

    let num_bits_per_block = param.message_modulus.0.ilog2() as usize;
    let num_block = 256usize.div_ceil(num_bits_per_block);

    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);

    // Test with low number of blocks, as they take a different branches
    // (regression tests)
    for num_block in [num_block, 1, 2] {
        let max = T::MAX >> (T::BITS - (num_block * num_bits_per_block));
        for _ in 0..num_test {
            let clear_a = rng.gen::<T>() & max;
            let clear_b = rng.gen::<T>() & max;
            let a = cks.encrypt_radix(clear_a, num_block);
            let b = cks.encrypt_radix(clear_b, num_block);

            {
                let result = unchecked_comparison_method(&sks, &a, &b);
                let decrypted: T = cks.decrypt_radix(&result);
                let expected_result = clear_fn(clear_a, clear_b);
                assert_eq!(decrypted, expected_result);
            }

            {
                // Force case where lhs == rhs
                let result = unchecked_comparison_method(&sks, &a, &a);
                let decrypted: T = cks.decrypt_radix(&result);
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
fn test_smart_function<SmartFn, ClearF, T>(
    param: ClassicPBSParameters,
    num_test: usize,
    smart_server_key_method: SmartFn,
    clear_fn: ClearF,
) where
    T: UnsignedNumeric + AddAssign<T> + DecomposableInto<u64> + RecomposableFrom<u64>,
    SmartFn: for<'a> Fn(
        &'a ServerKey,
        &'a mut RadixCiphertext,
        &'a mut RadixCiphertext,
    ) -> RadixCiphertext,
    ClearF: Fn(T, T) -> T,
    Standard: Distribution<T>,
{
    let mut rng = rand::thread_rng();

    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let num_block = T::BITS.div_ceil(param.message_modulus.0.ilog2() as usize);
    assert_eq!(
        T::BITS as u32 % param.message_modulus.0.ilog2(),
        0,
        "bit width must be a multiple of number of bit in a block"
    );

    for _ in 0..num_test {
        let mut clear_0 = rng.gen::<T>();
        let mut clear_1 = rng.gen::<T>();
        let mut ct_0 = cks.encrypt_radix(clear_0, num_block);
        let mut ct_1 = cks.encrypt_radix(clear_1, num_block);

        // Raise the degree, so as to ensure worst case path in operations
        while ct_0.block_carries_are_empty() {
            let clear_2 = rng.gen::<T>();
            let ct_2 = cks.encrypt_radix(clear_2, num_block);
            sks.unchecked_add_assign(&mut ct_0, &ct_2);
            clear_0 += clear_2;
        }

        while ct_1.block_carries_are_empty() {
            let clear_2 = rng.gen::<T>();
            let ct_2 = cks.encrypt_radix(clear_2, num_block);
            sks.unchecked_add_assign(&mut ct_1, &ct_2);
            clear_1 += clear_2;
        }

        // Sanity decryption checks
        {
            let a: T = cks.decrypt_radix(&ct_0);
            assert_eq!(a, clear_0);

            let b: T = cks.decrypt_radix(&ct_1);
            assert_eq!(b, clear_1);
        }

        assert!(!ct_0.block_carries_are_empty());
        assert!(!ct_1.block_carries_are_empty());
        let encrypted_result = smart_server_key_method(&sks, &mut ct_0, &mut ct_1);
        assert!(ct_0.block_carries_are_empty());
        assert!(ct_1.block_carries_are_empty());

        // Sanity decryption checks
        {
            let a: T = cks.decrypt_radix(&ct_0);
            assert_eq!(a, clear_0);

            let b: T = cks.decrypt_radix(&ct_1);
            assert_eq!(b, clear_1);
        }

        let decrypted_result: T = cks.decrypt_radix(&encrypted_result);

        let expected_result = clear_fn(clear_0, clear_1);
        assert_eq!(decrypted_result, expected_result);
    }
}

/// Function to test a "default" server_key function.
///
/// This calls the `server_key_method` with non-fresh ciphertexts,
/// that is ciphertexts that have non-zero carries, and compares that the result is
/// the same as the one of`clear_fn`.
fn test_default_function<SmartFn, ClearF, T>(
    param: ClassicPBSParameters,
    num_test: usize,
    default_comparison_method: SmartFn,
    clear_fn: ClearF,
) where
    T: UnsignedNumeric + AddAssign<T> + DecomposableInto<u64> + RecomposableFrom<u64>,
    SmartFn: for<'a> Fn(&'a ServerKey, &'a RadixCiphertext, &'a RadixCiphertext) -> RadixCiphertext,
    ClearF: Fn(T, T) -> T,
    Standard: Distribution<T>,
{
    let mut rng = rand::thread_rng();

    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let num_block = T::BITS.div_ceil(param.message_modulus.0.ilog2() as usize);
    assert_eq!(
        T::BITS as u32 % param.message_modulus.0.ilog2(),
        0,
        "bit width must be a multiple of number of bit in a block"
    );

    for _ in 0..num_test {
        let mut clear_0 = rng.gen::<T>();
        let mut clear_1 = rng.gen::<T>();
        let mut ct_0 = cks.encrypt_radix(clear_0, num_block);
        let mut ct_1 = cks.encrypt_radix(clear_1, num_block);

        // Raise the degree, so as to ensure worst case path in operations
        while ct_0.block_carries_are_empty() {
            let clear_2 = rng.gen::<T>();
            let ct_2 = cks.encrypt_radix(clear_2, num_block);
            sks.unchecked_add_assign(&mut ct_0, &ct_2);
            clear_0 += clear_2;
        }

        while ct_1.block_carries_are_empty() {
            let clear_2 = rng.gen::<T>();
            let ct_2 = cks.encrypt_radix(clear_2, num_block);
            sks.unchecked_add_assign(&mut ct_1, &ct_2);
            clear_1 += clear_2;
        }

        // Sanity decryption checks
        {
            let a: T = cks.decrypt_radix(&ct_0);
            assert_eq!(a, clear_0);

            let b: T = cks.decrypt_radix(&ct_1);
            assert_eq!(b, clear_1);
        }

        assert!(!ct_0.block_carries_are_empty());
        assert!(!ct_1.block_carries_are_empty());
        let encrypted_result = default_comparison_method(&sks, &ct_0, &ct_1);
        assert!(encrypted_result.block_carries_are_empty());

        // Sanity decryption checks
        {
            let a: T = cks.decrypt_radix(&ct_0);
            assert_eq!(a, clear_0);

            let b: T = cks.decrypt_radix(&ct_1);
            assert_eq!(b, clear_1);
        }

        let decrypted_result: T = cks.decrypt_radix(&encrypted_result);

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
        paste::paste!{
            fn [<integer_unchecked_ $comparison_name _ $clear_type:lower>](params:  crate::shortint::ClassicPBSParameters) {
                let num_tests = 1;
                test_unchecked_function(
                    params,
                    num_tests,
                    |server_key, lhs, rhs| {
                        server_key.[<unchecked_ $comparison_name>](lhs, rhs)
                        .into_radix(lhs.blocks.len(), server_key)
                    },
                    |lhs, rhs| $clear_type::from(<$clear_type>::$comparison_name(&lhs, &rhs)),
                )
            }

            fn [<integer_unchecked_ $comparison_name _parallelized_ $clear_type:lower>](params:  crate::shortint::ClassicPBSParameters) {
                let num_tests = 1;
                test_unchecked_function(
                    params,
                    num_tests,
                    |server_key, lhs, rhs| {
                        server_key.[<unchecked_ $comparison_name _parallelized>](lhs, rhs)
                        .into_radix(lhs.blocks.len(), server_key)
                    },
                    |lhs, rhs| $clear_type::from(<$clear_type>::$comparison_name(&lhs, &rhs)),
                )
            }

            fn [<integer_smart_ $comparison_name _ $clear_type:lower>](params:  crate::shortint::ClassicPBSParameters) {
                let num_tests = 1;
                test_smart_function(
                    params,
                    num_tests,
                    |server_key, lhs, rhs| {
                        server_key.[<smart_ $comparison_name>](lhs, rhs)
                        .into_radix(lhs.blocks.len(), server_key)
                    },
                    |lhs, rhs| $clear_type::from(<$clear_type>::$comparison_name(&lhs, &rhs)),
                )
            }

            fn [<integer_smart_ $comparison_name _parallelized_ $clear_type:lower>](params:  crate::shortint::ClassicPBSParameters) {
                let num_tests = 1;
                test_smart_function(
                    params,
                    num_tests,
                    |server_key, lhs, rhs| {
                        server_key.[<smart_ $comparison_name _parallelized>](lhs, rhs)
                        .into_radix(lhs.blocks.len(), server_key)
                    },
                    |lhs, rhs| $clear_type::from(<$clear_type>::$comparison_name(&lhs, &rhs)),
                )
            }

            fn [<integer_default_ $comparison_name _parallelized_ $clear_type:lower>](params:  crate::shortint::ClassicPBSParameters) {
                let num_tests = 1;
                test_default_function(
                    params,
                    num_tests,
                    |server_key, lhs, rhs| {
                        server_key.[<$comparison_name _parallelized>](lhs, rhs)
                        .into_radix(lhs.blocks.len(), server_key)
                    },
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

//=============================================================
// Signed comparison tests
//=============================================================

/// Function to test an "unchecked" compartor function.
///
/// This calls the `unchecked_server_key_method` with fresh ciphertexts
/// and compares that it gives the same results as the `clear_fn`.
fn test_signed_unchecked_function<UncheckedFn, ClearF, T>(
    param: ClassicPBSParameters,
    num_test: usize,
    unchecked_comparison_method: UncheckedFn,
    clear_fn: ClearF,
) where
    T: SignedNumeric + RecomposableSignedInteger + DecomposableInto<u64> + WrappingAdd + Neg,
    UncheckedFn: for<'a> Fn(
        &'a ServerKey,
        &'a SignedRadixCiphertext,
        &'a SignedRadixCiphertext,
    ) -> SignedRadixCiphertext,
    ClearF: Fn(T, T) -> T,
    Standard: Distribution<T>,
{
    let mut rng = rand::thread_rng();

    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let num_block = T::BITS.div_ceil(param.message_modulus.0.ilog2() as usize);

    // Some hard coded tests
    let pairs = [
        (T::ONE, T::TWO),
        (T::TWO, T::ONE),
        (-T::ONE, T::ONE),
        (T::ONE, -T::ONE),
        (-T::ONE, -T::TWO),
        (-T::TWO, -T::ONE),
        (T::ZERO, -T::ONE),
        (T::MAX, T::ZERO),
    ];
    for (clear_a, clear_b) in pairs {
        let a = cks.encrypt_signed_radix(clear_a, num_block);
        let b = cks.encrypt_signed_radix(clear_b, num_block);

        let result = unchecked_comparison_method(&sks, &a, &b);
        let decrypted: T = cks.decrypt_signed_radix(&result);
        let expected_result = clear_fn(clear_a, clear_b);
        assert_eq!(decrypted, expected_result);
    }

    for _ in 0..num_test {
        let clear_a = rng.gen::<T>();
        let clear_b = rng.gen::<T>();

        let a = cks.encrypt_signed_radix(clear_a, num_block);
        let b = cks.encrypt_signed_radix(clear_b, num_block);

        {
            let result = unchecked_comparison_method(&sks, &a, &b);
            let decrypted: T = cks.decrypt_signed_radix(&result);
            let expected_result = clear_fn(clear_a, clear_b);
            assert_eq!(decrypted, expected_result);
        }

        {
            // Force case where lhs == rhs
            let result = unchecked_comparison_method(&sks, &a, &a);
            let decrypted: T = cks.decrypt_signed_radix(&result);
            let expected_result = clear_fn(clear_a, clear_a);
            assert_eq!(decrypted, expected_result);
        }
    }
}

/// Function to test a "smart" server_key function for signed inputs
///
/// This calls the `smart_server_key_method` with non-fresh ciphertexts,
/// that is ciphertexts that have non-zero carries, and compares that the result is
/// the same as the one of`clear_fn`.
fn test_signed_smart_function<SmartFn, ClearF, T>(
    param: ClassicPBSParameters,
    num_test: usize,
    smart_comparison_method: SmartFn,
    clear_fn: ClearF,
) where
    T: SignedNumeric + RecomposableSignedInteger + DecomposableInto<u64> + WrappingAdd,
    SmartFn: for<'a> Fn(
        &'a ServerKey,
        &'a mut SignedRadixCiphertext,
        &'a mut SignedRadixCiphertext,
    ) -> SignedRadixCiphertext,
    ClearF: Fn(T, T) -> T,
    Standard: Distribution<T>,
{
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let num_block = T::BITS.div_ceil(param.message_modulus.0.ilog2() as usize);
    assert_eq!(
        T::BITS as u32 % param.message_modulus.0.ilog2(),
        0,
        "bit width must be a multiple of number of bit in a block"
    );

    let mut rng = rand::thread_rng();

    for _ in 0..num_test {
        let mut clear_0 = rng.gen::<T>();
        let mut clear_1 = rng.gen::<T>();
        let mut ct_0 = cks.encrypt_signed_radix(clear_0, num_block);
        let mut ct_1 = cks.encrypt_signed_radix(clear_1, num_block);

        // Raise the degree, so as to ensure worst case path in operations
        while ct_0.block_carries_are_empty() {
            let clear_2 = rng.gen::<T>();
            let ct_2 = cks.encrypt_signed_radix(clear_2, num_block);
            sks.unchecked_add_assign(&mut ct_0, &ct_2);
            clear_0 = clear_0.wrapping_add(&clear_2);
        }

        while ct_1.block_carries_are_empty() {
            let clear_2 = rng.gen::<T>();
            let ct_2 = cks.encrypt_signed_radix(clear_2, num_block);
            sks.unchecked_add_assign(&mut ct_1, &ct_2);
            clear_1 = clear_1.wrapping_add(&clear_2);
        }

        // Sanity decryption checks
        {
            let a: T = cks.decrypt_signed_radix(&ct_0);
            assert_eq!(a, clear_0);

            let b: T = cks.decrypt_signed_radix(&ct_1);
            assert_eq!(b, clear_1);
        }

        assert!(!ct_0.block_carries_are_empty());
        assert!(!ct_1.block_carries_are_empty());
        let encrypted_result = smart_comparison_method(&sks, &mut ct_0, &mut ct_1);
        assert!(ct_0.block_carries_are_empty());
        assert!(ct_1.block_carries_are_empty());

        // Sanity decryption checks
        {
            let a: T = cks.decrypt_signed_radix(&ct_0);
            assert_eq!(a, clear_0);

            let b: T = cks.decrypt_signed_radix(&ct_1);
            assert_eq!(b, clear_1);
        }

        let decrypted_result: T = cks.decrypt_signed_radix(&encrypted_result);

        let expected_result = clear_fn(clear_0, clear_1);
        assert_eq!(decrypted_result, expected_result);
    }
}

/// Function to test a "default" server_key function for signed inputs.
///
/// This calls the `server_key_method` with non-fresh ciphertexts,
/// that is ciphertexts that have non-zero carries, and compares that the result is
/// the same as the one of`clear_fn`.
fn test_signed_default_function<SmartFn, ClearF, T>(
    param: ClassicPBSParameters,
    num_test: usize,
    default_comparison_method: SmartFn,
    clear_fn: ClearF,
) where
    T: SignedNumeric + RecomposableSignedInteger + DecomposableInto<u64> + WrappingAdd,
    SmartFn: for<'a> Fn(
        &'a ServerKey,
        &'a SignedRadixCiphertext,
        &'a SignedRadixCiphertext,
    ) -> SignedRadixCiphertext,
    ClearF: Fn(T, T) -> T,
    Standard: Distribution<T>,
{
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let num_block = T::BITS.div_ceil(param.message_modulus.0.ilog2() as usize);
    assert_eq!(
        T::BITS as u32 % param.message_modulus.0.ilog2(),
        0,
        "bit width must be a multiple of number of bit in a block"
    );

    let mut rng = rand::thread_rng();

    for _ in 0..num_test {
        let mut clear_0 = rng.gen::<T>();
        let mut clear_1 = rng.gen::<T>();
        let mut ct_0 = cks.encrypt_signed_radix(clear_0, num_block);
        let mut ct_1 = cks.encrypt_signed_radix(clear_1, num_block);

        // Raise the degree, so as to ensure worst case path in operations
        while ct_0.block_carries_are_empty() {
            let clear_2 = rng.gen::<T>();
            let ct_2 = cks.encrypt_signed_radix(clear_2, num_block);
            sks.unchecked_add_assign(&mut ct_0, &ct_2);
            clear_0 = clear_0.wrapping_add(&clear_2);
        }

        while ct_1.block_carries_are_empty() {
            let clear_2 = rng.gen::<T>();
            let ct_2 = cks.encrypt_signed_radix(clear_2, num_block);
            sks.unchecked_add_assign(&mut ct_1, &ct_2);
            clear_1 = clear_1.wrapping_add(&clear_2);
        }

        // Sanity decryption checks
        {
            let a: T = cks.decrypt_signed_radix(&ct_0);
            assert_eq!(a, clear_0);

            let b: T = cks.decrypt_signed_radix(&ct_1);
            assert_eq!(b, clear_1);
        }

        assert!(!ct_0.block_carries_are_empty());
        assert!(!ct_1.block_carries_are_empty());
        let encrypted_result = default_comparison_method(&sks, &ct_0, &ct_1);
        assert!(encrypted_result.block_carries_are_empty());

        // Sanity decryption checks
        {
            let a: T = cks.decrypt_signed_radix(&ct_0);
            assert_eq!(a, clear_0);

            let b: T = cks.decrypt_signed_radix(&ct_1);
            assert_eq!(b, clear_1);
        }

        let decrypted_result: T = cks.decrypt_signed_radix(&encrypted_result);

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
macro_rules! define_signed_comparison_test_functions {
    ($comparison_name:ident, $clear_type:ty) => {
        paste::paste!{
            // Fist we "specialialize" the test_signed fns

            fn [<integer_signed_unchecked_ $comparison_name _ $clear_type>](params:  crate::shortint::ClassicPBSParameters) {
                let num_tests = 1;
                test_signed_unchecked_function(
                    params,
                    num_tests,
                    |server_key, lhs, rhs| {
                        server_key.[<unchecked_ $comparison_name>](lhs, rhs)
                        .into_radix(lhs.blocks.len(), server_key)
                    },
                    |lhs, rhs| $clear_type::from(<$clear_type>::$comparison_name(&lhs, &rhs) as $clear_type),
                )
            }

            fn [<integer_signed_unchecked_ $comparison_name _parallelized_ $clear_type>](params:  crate::shortint::ClassicPBSParameters) {
                let num_tests = 1;
                test_signed_unchecked_function(
                    params,
                    num_tests,
                    |server_key, lhs, rhs| {
                        server_key.[<unchecked_ $comparison_name _parallelized>](lhs, rhs)
                        .into_radix(lhs.blocks.len(), server_key)
                    },
                    |lhs, rhs| $clear_type::from(<$clear_type>::$comparison_name(&lhs, &rhs) as $clear_type),
                )
            }

            fn [<integer_signed_smart_ $comparison_name _ $clear_type>](params:  crate::shortint::ClassicPBSParameters) {
                let num_tests = 1;
                test_signed_smart_function(
                    params,
                    num_tests,
                    |server_key, lhs, rhs| {
                        server_key.[<smart_ $comparison_name>](lhs, rhs)
                        .into_radix(lhs.blocks.len(), server_key)
                    },
                    |lhs, rhs| $clear_type::from(<$clear_type>::$comparison_name(&lhs, &rhs) as $clear_type),
                )
            }

            fn [<integer_signed_smart_ $comparison_name _parallelized_ $clear_type>](params:  crate::shortint::ClassicPBSParameters) {
                let num_tests = 1;
                test_signed_smart_function(
                    params,
                    num_tests,
                    |server_key, lhs, rhs| {
                        server_key.[<smart_ $comparison_name _parallelized>](lhs, rhs)
                        .into_radix(lhs.blocks.len(), server_key)
                    },
                    |lhs, rhs| $clear_type::from(<$clear_type>::$comparison_name(&lhs, &rhs) as $clear_type),
                )
            }

            fn [<integer_signed_default_ $comparison_name _parallelized_ $clear_type>](params:  crate::shortint::ClassicPBSParameters) {
                let num_tests = 1;
                test_signed_default_function(
                    params,
                    num_tests,
                    |server_key, lhs, rhs| {
                        server_key.[<$comparison_name _parallelized>](lhs, rhs)
                        .into_radix(lhs.blocks.len(), server_key)
                    },
                    |lhs, rhs| <i8>::from(<i8>::$comparison_name(&lhs, &rhs) as i8),
                )
            }


            // Then call our create_parametrized_test macro onto or specialized fns

            create_parametrized_test!([<integer_signed_unchecked_ $comparison_name _ $clear_type>]
            {

                PARAM_MESSAGE_2_CARRY_2_KS_PBS,

                PARAM_MESSAGE_3_CARRY_3_KS_PBS,

                PARAM_MESSAGE_4_CARRY_4_KS_PBS,
                #[cfg(tarpaulin)]
                COVERAGE_PARAM_MESSAGE_2_CARRY_2_KS_PBS
            });

            create_parametrized_test!([<integer_signed_unchecked_ $comparison_name _parallelized_ $clear_type>]
            {

                PARAM_MESSAGE_2_CARRY_2_KS_PBS,

                PARAM_MESSAGE_3_CARRY_3_KS_PBS,

                PARAM_MESSAGE_4_CARRY_4_KS_PBS,
                #[cfg(tarpaulin)]
                COVERAGE_PARAM_MESSAGE_2_CARRY_2_KS_PBS
            });

            create_parametrized_test!([<integer_signed_smart_ $comparison_name _ $clear_type>]
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

            create_parametrized_test!([<integer_signed_smart_ $comparison_name _parallelized_ $clear_type>]
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

            create_parametrized_test!([<integer_signed_default_ $comparison_name _parallelized_ $clear_type>]
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

//=============================================================
// Scalar comparison tests
//=============================================================

/// Function to test an "unchecked_scalar" compartor function.
///
/// This calls the `unchecked_scalar_server_key_method` with fresh ciphertexts
/// and compares that it gives the same results as the `clear_fn`.
fn test_unchecked_scalar_function<UncheckedFn, ClearF, T>(
    param: ClassicPBSParameters,
    num_test: usize,
    unchecked_comparison_method: UncheckedFn,
    clear_fn: ClearF,
) where
    T: UnsignedNumeric + DecomposableInto<u64> + RecomposableFrom<u64>,
    UncheckedFn: for<'a, 'b> Fn(&'a ServerKey, &'a RadixCiphertext, T) -> RadixCiphertext,
    ClearF: Fn(T, T) -> T,
    Standard: Distribution<T>,
{
    let mut rng = rand::thread_rng();

    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let num_block = T::BITS.div_ceil(param.message_modulus.0.ilog2() as usize);

    for _ in 0..num_test {
        let clear_a = rng.gen::<T>();
        let clear_b = rng.gen::<T>();

        let a = cks.encrypt_radix(clear_a, num_block);

        {
            let result = unchecked_comparison_method(&sks, &a, clear_b);
            let decrypted: T = cks.decrypt_radix(&result);
            let expected_result = clear_fn(clear_a, clear_b);
            assert_eq!(decrypted, expected_result);
        }

        {
            // Force case where lhs == rhs
            let result = unchecked_comparison_method(&sks, &a, clear_a);
            let decrypted: T = cks.decrypt_radix(&result);
            let expected_result = clear_fn(clear_a, clear_a);
            assert_eq!(decrypted, expected_result);
        }
    }
}

/// Function to test a "smart_scalar" server_key function.
fn test_smart_scalar_function<SmartFn, ClearF, T>(
    param: ClassicPBSParameters,
    num_test: usize,
    smart_comparison_method: SmartFn,
    clear_fn: ClearF,
) where
    T: UnsignedNumeric + AddAssign<T> + DecomposableInto<u64> + RecomposableFrom<u64>,
    SmartFn: for<'a, 'b> Fn(&'a ServerKey, &'a mut RadixCiphertext, T) -> RadixCiphertext,
    ClearF: Fn(T, T) -> T,
    Standard: Distribution<T>,
{
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let num_block = T::BITS.div_ceil(param.message_modulus.0.ilog2() as usize);
    assert_eq!(
        T::BITS as u32 % param.message_modulus.0.ilog2(),
        0,
        "bit width must be a multiple of number of bit in a block"
    );

    let mut rng = rand::thread_rng();

    for _ in 0..num_test {
        let mut clear_0 = rng.gen::<T>();
        let clear_1 = rng.gen::<T>();
        let mut ct_0 = cks.encrypt_radix(clear_0, num_block);

        // Raise the degree, so as to ensure worst case path in operations
        while ct_0.block_carries_are_empty() {
            let clear_2 = rng.gen::<T>();
            let ct_2 = cks.encrypt_radix(clear_2, num_block);
            sks.unchecked_add_assign(&mut ct_0, &ct_2);
            clear_0 += clear_2;
        }

        // Sanity decryption checks
        {
            let a: T = cks.decrypt_radix(&ct_0);
            assert_eq!(a, clear_0);
        }

        assert!(!ct_0.block_carries_are_empty());
        let encrypted_result = smart_comparison_method(&sks, &mut ct_0, clear_1);
        assert!(ct_0.block_carries_are_empty());

        // Sanity decryption checks
        {
            let a: T = cks.decrypt_radix(&ct_0);
            assert_eq!(a, clear_0);
        }

        let decrypted_result: T = cks.decrypt_radix(&encrypted_result);

        let expected_result = clear_fn(clear_0, clear_1);
        assert_eq!(decrypted_result, expected_result);
    }
}

/// Function to test a "default_scalar" server_key function.
fn test_default_scalar_function<SmartFn, ClearF, T>(
    param: ClassicPBSParameters,
    num_test: usize,
    default_comparison_method: SmartFn,
    clear_fn: ClearF,
) where
    T: UnsignedNumeric + AddAssign<T> + DecomposableInto<u64> + RecomposableFrom<u64>,
    SmartFn: for<'a, 'b> Fn(&'a ServerKey, &'a RadixCiphertext, T) -> RadixCiphertext,
    ClearF: Fn(T, T) -> T,
    Standard: Distribution<T>,
{
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let num_block = T::BITS.div_ceil(param.message_modulus.0.ilog2() as usize);
    assert_eq!(
        T::BITS as u32 % param.message_modulus.0.ilog2(),
        0,
        "bit width must be a multiple of number of bit in a block"
    );

    let mut rng = rand::thread_rng();

    for _ in 0..num_test {
        let mut clear_0 = rng.gen::<T>();
        let clear_1 = rng.gen::<T>();

        let mut ct_0 = cks.encrypt_radix(clear_0, num_block);

        // Raise the degree, so as to ensure worst case path in operations
        while ct_0.block_carries_are_empty() {
            let clear_2 = rng.gen::<T>();
            let ct_2 = cks.encrypt_radix(clear_2, num_block);
            sks.unchecked_add_assign(&mut ct_0, &ct_2);
            clear_0 += clear_2;
        }

        // Sanity decryption checks
        {
            let a: T = cks.decrypt_radix(&ct_0);
            assert_eq!(a, clear_0);
        }

        assert!(!ct_0.block_carries_are_empty());
        let encrypted_result = default_comparison_method(&sks, &ct_0, clear_1);
        assert!(encrypted_result.block_carries_are_empty());

        // Sanity decryption checks
        {
            let a: T = cks.decrypt_radix(&ct_0);
            assert_eq!(a, clear_0);
        }

        let decrypted_result: T = cks.decrypt_radix(&encrypted_result);

        let expected_result = clear_fn(clear_0, clear_1);
        assert_eq!(decrypted_result, expected_result);
    }
}

/// This macro generates the tests for a given scalar comparison fn
///
/// All our scalar comparison function have 3 variants:
/// - unchecked_scalar_$comparison_name_parallelized
/// - smart_scalar_$comparison_name_parallelized
/// - scalar_$comparison_name_parallelized
///
/// So, for example, for the `gt` comparison fn,
/// this macro will generate the tests for the 3 variants described above
macro_rules! define_scalar_comparison_test_functions {
    ($comparison_name:ident, $clear_type:ty) => {
        paste::paste!{

            fn [<integer_unchecked_scalar_ $comparison_name _parallelized _ $clear_type:lower>](params:  crate::shortint::ClassicPBSParameters) {
                let num_tests = 1;
                test_unchecked_scalar_function(
                    params,
                    num_tests,
                    |server_key, lhs, rhs| {
                        server_key.[<unchecked_scalar_ $comparison_name _parallelized>](lhs, rhs)
                        .into_radix(lhs.blocks.len(), server_key)
                    },
                    |lhs, rhs| $clear_type::from(<$clear_type>::$comparison_name(&lhs, &rhs)),
                )
            }

            fn [<integer_smart_scalar_ $comparison_name _parallelized _ $clear_type:lower>](params:  crate::shortint::ClassicPBSParameters) {
                let num_tests = 1;
                test_smart_scalar_function(
                    params,
                    num_tests,
                    |server_key, lhs, rhs| {
                        server_key.[<smart_scalar_ $comparison_name _parallelized>](lhs, rhs)
                        .into_radix(lhs.blocks.len(), server_key)
                    },
                    |lhs, rhs| $clear_type::from(<$clear_type>::$comparison_name(&lhs, &rhs)),
                )
            }

            fn [<integer_default_scalar_ $comparison_name _parallelized _ $clear_type:lower>](params:  crate::shortint::ClassicPBSParameters) {
                let num_tests = 1;
                test_default_scalar_function(
                    params,
                    num_tests,
                    |server_key, lhs, rhs| {
                        server_key.[<scalar_ $comparison_name _parallelized>](lhs, rhs)
                        .into_radix(lhs.blocks.len(), server_key)
                    },
                    |lhs, rhs| $clear_type::from(<$clear_type>::$comparison_name(&lhs, &rhs)),
                )
            }

            create_parametrized_test!([<integer_unchecked_scalar_ $comparison_name _parallelized_ $clear_type:lower>]
            {

                PARAM_MESSAGE_2_CARRY_2_KS_PBS,

                PARAM_MESSAGE_3_CARRY_3_KS_PBS,

                PARAM_MESSAGE_4_CARRY_4_KS_PBS,
                #[cfg(tarpaulin)]
                COVERAGE_PARAM_MESSAGE_2_CARRY_2_KS_PBS
            });

            create_parametrized_test!([<integer_smart_scalar_ $comparison_name _parallelized_ $clear_type:lower>]
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

            create_parametrized_test!([<integer_default_scalar_ $comparison_name _parallelized_ $clear_type:lower>]
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

/// The goal of this function is to ensure that scalar comparisons
/// work when the scalar type used is either bigger or smaller (in bit size)
/// compared to the ciphertext
fn integer_unchecked_scalar_comparisons_edge(param: ClassicPBSParameters) {
    let mut rng = rand::thread_rng();

    let num_block = (128f64 / (param.message_modulus.0 as f64).log(2.0)).ceil() as usize;

    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);

    for _ in 0..4 {
        let clear_a = rng.gen_range((u128::from(u64::MAX) + 1)..=u128::MAX);
        let smaller_clear = rng.gen::<u64>();
        let bigger_clear = rng.gen::<U256>();

        let a = cks.encrypt_radix(clear_a, num_block);

        // >=
        {
            let result = sks.unchecked_scalar_ge_parallelized(&a, smaller_clear);
            let decrypted = cks.decrypt_bool(&result);
            assert_eq!(decrypted, U256::from(clear_a) >= U256::from(smaller_clear));

            let result = sks.unchecked_scalar_ge_parallelized(&a, bigger_clear);
            let decrypted = cks.decrypt_bool(&result);
            assert_eq!(decrypted, U256::from(clear_a) >= bigger_clear);
        }

        // >
        {
            let result = sks.unchecked_scalar_gt_parallelized(&a, smaller_clear);
            let decrypted = cks.decrypt_bool(&result);
            assert_eq!(decrypted, U256::from(clear_a) > U256::from(smaller_clear));

            let result = sks.unchecked_scalar_gt_parallelized(&a, bigger_clear);
            let decrypted = cks.decrypt_bool(&result);
            assert_eq!(decrypted, U256::from(clear_a) > bigger_clear);
        }

        // <=
        {
            let result = sks.unchecked_scalar_le_parallelized(&a, smaller_clear);
            let decrypted = cks.decrypt_bool(&result);
            assert_eq!(decrypted, U256::from(clear_a) <= U256::from(smaller_clear));

            let result = sks.unchecked_scalar_le_parallelized(&a, bigger_clear);
            let decrypted = cks.decrypt_bool(&result);
            assert_eq!(decrypted, U256::from(clear_a) <= bigger_clear);
        }

        // <
        {
            let result = sks.unchecked_scalar_lt_parallelized(&a, smaller_clear);
            let decrypted = cks.decrypt_bool(&result);
            assert_eq!(decrypted, U256::from(clear_a) < U256::from(smaller_clear));

            let result = sks.unchecked_scalar_lt_parallelized(&a, bigger_clear);
            let decrypted = cks.decrypt_bool(&result);
            assert_eq!(decrypted, U256::from(clear_a) < bigger_clear);
        }

        // ==
        {
            let result = sks.unchecked_scalar_eq_parallelized(&a, smaller_clear);
            let decrypted = cks.decrypt_bool(&result);
            assert_eq!(decrypted, U256::from(clear_a) == U256::from(smaller_clear));

            let result = sks.unchecked_scalar_eq_parallelized(&a, bigger_clear);
            let decrypted = cks.decrypt_bool(&result);
            assert_eq!(decrypted, U256::from(clear_a) == bigger_clear);
        }

        // !=
        {
            let result = sks.unchecked_scalar_ne_parallelized(&a, smaller_clear);
            let decrypted = cks.decrypt_bool(&result);
            assert_eq!(decrypted, U256::from(clear_a) != U256::from(smaller_clear));

            let result = sks.unchecked_scalar_ne_parallelized(&a, bigger_clear);
            let decrypted = cks.decrypt_bool(&result);
            assert_eq!(decrypted, U256::from(clear_a) != bigger_clear);
        }

        // Here the goal is to test, the branching
        // made in the scalar sign function
        //
        // We are forcing one of the two branches to work on empty slices
        {
            let result = sks.unchecked_scalar_lt_parallelized(&a, U256::ZERO);
            let decrypted = cks.decrypt_bool(&result);
            assert_eq!(decrypted, U256::from(clear_a) < U256::ZERO);

            let result = sks.unchecked_scalar_lt_parallelized(&a, U256::MAX);
            let decrypted = cks.decrypt_bool(&result);
            assert_eq!(decrypted, U256::from(clear_a) < U256::MAX);

            // == (as it does not share same code)
            let result = sks.unchecked_scalar_eq_parallelized(&a, U256::ZERO);
            let decrypted = cks.decrypt_bool(&result);
            assert_eq!(decrypted, U256::from(clear_a) == U256::ZERO);

            // != (as it does not share same code)
            let result = sks.unchecked_scalar_ne_parallelized(&a, U256::MAX);
            let decrypted = cks.decrypt_bool(&result);
            assert_eq!(decrypted, U256::from(clear_a) != U256::MAX);
        }
    }
}

fn integer_is_scalar_out_of_bounds(param: ClassicPBSParameters) {
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let num_block = 128usize.div_ceil(param.message_modulus.0.ilog2() as usize);

    let mut rng = thread_rng();

    let clear_unsigned = rng.gen::<u128>();
    let ct = cks.encrypt_radix(clear_unsigned, num_block);

    // Positive scalars
    {
        // This one is in range
        let scalar = U256::from(u128::MAX);
        let res = sks.is_scalar_out_of_bounds(&ct, scalar);
        assert_eq!(res, None);

        let scalar = U256::from(u128::MAX) + U256::ONE;
        let res = sks.is_scalar_out_of_bounds(&ct, scalar);
        assert_eq!(res, Some(std::cmp::Ordering::Greater));

        let scalar = U256::from(u128::MAX) + U256::from(rng.gen_range(2u128..=u128::MAX));
        let res = sks.is_scalar_out_of_bounds(&ct, scalar);
        assert_eq!(res, Some(std::cmp::Ordering::Greater));

        let scalar = U256::from(u128::MAX) + U256::from(u128::MAX);
        let res = sks.is_scalar_out_of_bounds(&ct, scalar);
        assert_eq!(res, Some(std::cmp::Ordering::Greater));
    }

    // Negative scalars
    {
        let res = sks.is_scalar_out_of_bounds(&ct, -1i128);
        assert_eq!(res, Some(std::cmp::Ordering::Less));

        let scalar = I256::from(i128::MIN) - I256::ONE;
        let res = sks.is_scalar_out_of_bounds(&ct, scalar);
        assert_eq!(res, Some(std::cmp::Ordering::Less));

        let scalar = I256::from(i128::MIN) + I256::from(rng.gen_range(i128::MIN..=-2));
        let res = sks.is_scalar_out_of_bounds(&ct, scalar);
        assert_eq!(res, Some(std::cmp::Ordering::Less));

        let scalar = I256::from(i128::MIN) + I256::from(i128::MIN);
        let res = sks.is_scalar_out_of_bounds(&ct, scalar);
        assert_eq!(res, Some(std::cmp::Ordering::Less));

        let scalar = I256::from(i128::MIN) - I256::from(rng.gen_range(2..=i128::MAX));
        let res = sks.is_scalar_out_of_bounds(&ct, scalar);
        assert_eq!(res, Some(std::cmp::Ordering::Less));

        let scalar = I256::from(i128::MIN) - I256::from(i128::MAX);
        let res = sks.is_scalar_out_of_bounds(&ct, scalar);
        assert_eq!(res, Some(std::cmp::Ordering::Less));
    }

    // Negative scalar
    {
        // Case where scalar will have less blocks when decomposed than
        // the ciphertext has
        let bigger_ct = cks.encrypt_signed_radix(-1i128, num_block);
        let scalar = i64::MIN;
        let res = sks.is_scalar_out_of_bounds(&bigger_ct, scalar);
        assert_eq!(res, None);
    }
}

//=============================================================
// Scalar signed comparison tests
//=============================================================

/// Function to test an "unchecked_scalar" compartor function.
///
/// This calls the `unchecked_scalar_server_key_method` with fresh ciphertexts
/// and compares that it gives the same results as the `clear_fn`.
fn test_signed_unchecked_scalar_function<UncheckedFn, ClearF, T>(
    param: ClassicPBSParameters,
    num_test: usize,
    unchecked_comparison_method: UncheckedFn,
    clear_fn: ClearF,
) where
    T: SignedNumeric + RecomposableSignedInteger + DecomposableInto<u64>,
    UncheckedFn:
        for<'a, 'b> Fn(&'a ServerKey, &'a SignedRadixCiphertext, T) -> SignedRadixCiphertext,
    ClearF: Fn(T, T) -> T,
    Standard: Distribution<T>,
{
    let mut rng = rand::thread_rng();

    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let num_block = T::BITS.div_ceil(param.message_modulus.0.ilog2() as usize);

    // Some hard coded tests
    let pairs = [
        (T::ONE, T::TWO),
        (T::TWO, T::ONE),
        (-T::ONE, T::ONE),
        (T::ONE, -T::ONE),
        (-T::ONE, -T::TWO),
        (-T::TWO, -T::ONE),
        (T::ZERO, -T::ONE),
        (T::MAX, T::ZERO),
    ];
    for (clear_a, clear_b) in pairs {
        let a = cks.encrypt_signed_radix(clear_a, num_block);

        let result = unchecked_comparison_method(&sks, &a, clear_b);
        let decrypted: T = cks.decrypt_signed_radix(&result);
        let expected_result = clear_fn(clear_a, clear_b);
        assert_eq!(decrypted, expected_result);
    }

    for _ in 0..num_test {
        let clear_a = rng.gen::<T>();
        let clear_b = rng.gen::<T>();

        let a = cks.encrypt_signed_radix(clear_a, num_block);

        {
            let result = unchecked_comparison_method(&sks, &a, clear_b);
            let decrypted: T = cks.decrypt_signed_radix(&result);
            let expected_result = clear_fn(clear_a, clear_b);
            assert_eq!(decrypted, expected_result);
        }

        {
            // Force case where lhs == rhs
            let result = unchecked_comparison_method(&sks, &a, clear_a);
            let decrypted: T = cks.decrypt_signed_radix(&result);
            let expected_result = clear_fn(clear_a, clear_a);
            assert_eq!(decrypted, expected_result);
        }
    }
}

/// Function to test a "smart_scalar" server_key function.
fn test_signed_smart_scalar_function<SmartFn, ClearF, T>(
    param: ClassicPBSParameters,
    num_test: usize,
    smart_comparison_method: SmartFn,
    clear_fn: ClearF,
) where
    T: SignedNumeric + RecomposableSignedInteger + DecomposableInto<u64> + WrappingAdd,
    SmartFn:
        for<'a, 'b> Fn(&'a ServerKey, &'a mut SignedRadixCiphertext, T) -> SignedRadixCiphertext,
    ClearF: Fn(T, T) -> T,
    Standard: Distribution<T>,
{
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let num_block = T::BITS.div_ceil(param.message_modulus.0.ilog2() as usize);
    assert_eq!(
        T::BITS as u32 % param.message_modulus.0.ilog2(),
        0,
        "bit width must be a multiple of number of bit in a block"
    );

    let mut rng = rand::thread_rng();

    for _ in 0..num_test {
        let mut clear_0 = rng.gen::<T>();
        let clear_1 = rng.gen::<T>();
        let mut ct_0 = cks.encrypt_signed_radix(clear_0, num_block);

        // Raise the degree, so as to ensure worst case path in operations
        while ct_0.block_carries_are_empty() {
            let clear_2 = rng.gen::<T>();
            let ct_2 = cks.encrypt_signed_radix(clear_2, num_block);
            sks.unchecked_add_assign(&mut ct_0, &ct_2);
            clear_0 = clear_0.wrapping_add(&clear_2);
        }

        // Sanity decryption checks
        {
            let a: T = cks.decrypt_signed_radix(&ct_0);
            assert_eq!(a, clear_0);
        }

        assert!(!ct_0.block_carries_are_empty());
        let encrypted_result = smart_comparison_method(&sks, &mut ct_0, clear_1);
        assert!(ct_0.block_carries_are_empty());

        // Sanity decryption checks
        {
            let a: T = cks.decrypt_signed_radix(&ct_0);
            assert_eq!(a, clear_0);
        }

        let decrypted_result: T = cks.decrypt_signed_radix(&encrypted_result);

        let expected_result = clear_fn(clear_0, clear_1);
        assert_eq!(decrypted_result, expected_result);
    }
}

/// Function to test a "default_scalar" server_key function.
fn test_signed_default_scalar_function<SmartFn, ClearF, T>(
    param: ClassicPBSParameters,
    num_test: usize,
    default_comparison_method: SmartFn,
    clear_fn: ClearF,
) where
    T: SignedNumeric + RecomposableSignedInteger + DecomposableInto<u64> + WrappingAdd,
    SmartFn: for<'a, 'b> Fn(&'a ServerKey, &'a SignedRadixCiphertext, T) -> SignedRadixCiphertext,
    ClearF: Fn(T, T) -> T,
    Standard: Distribution<T>,
{
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let num_block = T::BITS.div_ceil(param.message_modulus.0.ilog2() as usize);
    assert_eq!(
        T::BITS as u32 % param.message_modulus.0.ilog2(),
        0,
        "bit width must be a multiple of number of bit in a block"
    );

    let mut rng = rand::thread_rng();

    for _ in 0..num_test {
        let mut clear_0 = rng.gen::<T>();
        let clear_1 = rng.gen::<T>();

        let mut ct_0 = cks.encrypt_signed_radix(clear_0, num_block);

        // Raise the degree, so as to ensure worst case path in operations
        while ct_0.block_carries_are_empty() {
            let clear_2 = rng.gen::<T>();
            let ct_2 = cks.encrypt_signed_radix(clear_2, num_block);
            sks.unchecked_add_assign(&mut ct_0, &ct_2);
            clear_0 = clear_0.wrapping_add(&clear_2);
        }

        // Sanity decryption checks
        {
            let a: T = cks.decrypt_signed_radix(&ct_0);
            assert_eq!(a, clear_0);
        }

        assert!(!ct_0.block_carries_are_empty());
        let encrypted_result = default_comparison_method(&sks, &ct_0, clear_1);
        assert!(encrypted_result.block_carries_are_empty());

        // Sanity decryption checks
        {
            let a: T = cks.decrypt_signed_radix(&ct_0);
            assert_eq!(a, clear_0);
        }

        let decrypted_result: T = cks.decrypt_signed_radix(&encrypted_result);

        let expected_result = clear_fn(clear_0, clear_1);
        assert_eq!(decrypted_result, expected_result);
    }
}

/// This macro generates the tests for a given scalar comparison fn
///
/// All our scalar comparison function have 3 variants:
/// - unchecked_scalar_$comparison_name_parallelized
/// - smart_scalar_$comparison_name_parallelized
/// - scalar_$comparison_name_parallelized
///
/// So, for example, for the `gt` comparison fn,
/// this macro will generate the tests for the 3 variants described above
macro_rules! define_signed_scalar_comparison_test_functions {
    ($comparison_name:ident, $clear_type:ty) => {
        paste::paste!{
            fn [<integer_signed_unchecked_scalar_ $comparison_name _parallelized_  $clear_type>](params:  crate::shortint::ClassicPBSParameters) {
                let num_tests = 2;
                test_signed_unchecked_scalar_function(
                    params,
                    num_tests,
                    |server_key, lhs, rhs| {
                        server_key.[<unchecked_scalar_ $comparison_name _parallelized>](lhs, rhs)
                        .into_radix(lhs.blocks.len(), server_key)
                    },
                    |lhs, rhs| $clear_type::from(<$clear_type>::$comparison_name(&lhs, &rhs)),
                )
            }

            fn [<integer_signed_smart_scalar_ $comparison_name _parallelized_  $clear_type>](params:  crate::shortint::ClassicPBSParameters) {
                let num_tests = 2;
                test_signed_smart_scalar_function(
                    params,
                    num_tests,
                    |server_key, lhs, rhs| {
                        server_key.[<smart_scalar_ $comparison_name _parallelized>](lhs, rhs)
                        .into_radix(lhs.blocks.len(), server_key)
                    },
                    |lhs, rhs| $clear_type::from(<$clear_type>::$comparison_name(&lhs, &rhs)),
                )
            }

            fn [<integer_signed_default_scalar_ $comparison_name _parallelized_  $clear_type>](params:  crate::shortint::ClassicPBSParameters) {
                let num_tests = 2;
                test_signed_default_scalar_function(
                    params,
                    num_tests,
                    |server_key, lhs, rhs| {
                        server_key.[<scalar_ $comparison_name _parallelized>](lhs, rhs)
                        .into_radix(lhs.blocks.len(), server_key)
                    },
                    |lhs, rhs| $clear_type::from(<$clear_type>::$comparison_name(&lhs, &rhs)),
                )
            }

            create_parametrized_test!([<integer_signed_unchecked_scalar_ $comparison_name _parallelized_  $clear_type>]
            {

                PARAM_MESSAGE_2_CARRY_2_KS_PBS,

                PARAM_MESSAGE_3_CARRY_3_KS_PBS,

                PARAM_MESSAGE_4_CARRY_4_KS_PBS,
                #[cfg(tarpaulin)]
                COVERAGE_PARAM_MESSAGE_2_CARRY_2_KS_PBS
            });

            create_parametrized_test!([<integer_signed_smart_scalar_ $comparison_name _parallelized_  $clear_type>]
            {

                PARAM_MESSAGE_2_CARRY_2_KS_PBS,
                // We don't use PARAM_MESSAGE_3_CARRY_3_KS_PBS,
                // as smart test might overflow values
                // and when using 3_3 to represent 128 we actually have more than 128 bits
                // of message so the overflow behaviour is not the same, leading to false negatives

                PARAM_MESSAGE_4_CARRY_4_KS_PBS,
                #[cfg(tarpaulin)]
                COVERAGE_PARAM_MESSAGE_2_CARRY_2_KS_PBS
            });

            create_parametrized_test!([<integer_signed_default_scalar_ $comparison_name _parallelized_  $clear_type>]
            {

                PARAM_MESSAGE_2_CARRY_2_KS_PBS,
                // We don't use PARAM_MESSAGE_3_CARRY_3_KS_PBS,
                // as default test might overflow values
                // and when using 3_3 to represent 128 we actually have more than 128 bits
                // of message so the overflow behaviour is not the same, leading to false negatives

                PARAM_MESSAGE_4_CARRY_4_KS_PBS,
                #[cfg(tarpaulin)]
                COVERAGE_PARAM_MESSAGE_2_CARRY_2_KS_PBS
            });
        }
    };
}

fn integer_signed_is_scalar_out_of_bounds(param: ClassicPBSParameters) {
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let num_block = (128f64 / (param.message_modulus.0 as f64).log(2.0)).ceil() as usize;

    let mut rng = rand::thread_rng();

    let clear_0 = rng.gen::<i128>();
    let ct = cks.encrypt_signed_radix(clear_0, num_block);

    // Positive scalars
    {
        // This one is in range
        let scalar = I256::from(i128::MAX);
        let res = sks.is_scalar_out_of_bounds(&ct, scalar);
        assert_eq!(res, None);

        let scalar = I256::from(i128::MAX) + I256::ONE;
        let res = sks.is_scalar_out_of_bounds(&ct, scalar);
        assert_eq!(res, Some(std::cmp::Ordering::Greater));

        let scalar = I256::from(i128::MAX) + I256::from(rng.gen_range(2i128..=i128::MAX));
        let res = sks.is_scalar_out_of_bounds(&ct, scalar);
        assert_eq!(res, Some(std::cmp::Ordering::Greater));

        let scalar = I256::from(i128::MAX) + I256::from(i128::MAX);
        let res = sks.is_scalar_out_of_bounds(&ct, scalar);
        assert_eq!(res, Some(std::cmp::Ordering::Greater));
    }

    // Negative scalars
    {
        // This one is in range
        let scalar = I256::from(i128::MIN);
        let res = sks.is_scalar_out_of_bounds(&ct, scalar);
        assert_eq!(res, None);

        let scalar = I256::from(i128::MIN) - I256::ONE;
        let res = sks.is_scalar_out_of_bounds(&ct, scalar);
        assert_eq!(res, Some(std::cmp::Ordering::Less));

        let scalar = I256::from(i128::MIN) + I256::from(rng.gen_range(i128::MIN..=-2));
        let res = sks.is_scalar_out_of_bounds(&ct, scalar);
        assert_eq!(res, Some(std::cmp::Ordering::Less));

        let scalar = I256::from(i128::MIN) + I256::from(i128::MIN);
        let res = sks.is_scalar_out_of_bounds(&ct, scalar);
        assert_eq!(res, Some(std::cmp::Ordering::Less));

        let scalar = I256::from(i128::MIN) - I256::from(rng.gen_range(2..=i128::MAX));
        let res = sks.is_scalar_out_of_bounds(&ct, scalar);
        assert_eq!(res, Some(std::cmp::Ordering::Less));

        let scalar = I256::from(i128::MIN) - I256::from(i128::MAX);
        let res = sks.is_scalar_out_of_bounds(&ct, scalar);
        assert_eq!(res, Some(std::cmp::Ordering::Less));
    }
}

#[cfg(not(tarpaulin))]
mod no_coverage {
    use super::*;

    //=============================================================
    // Unsigned comparison tests
    //=============================================================

    fn integer_unchecked_min_parallelized_u256(params: crate::shortint::ClassicPBSParameters) {
        test_unchecked_function(
            params,
            2,
            ServerKey::unchecked_min_parallelized,
            std::cmp::min::<U256>,
        );
    }

    fn integer_unchecked_max_parallelized_u256(params: crate::shortint::ClassicPBSParameters) {
        test_unchecked_function(
            params,
            2,
            ServerKey::unchecked_max_parallelized,
            std::cmp::max::<U256>,
        );
    }

    fn integer_smart_min_parallelized_u256(params: crate::shortint::ClassicPBSParameters) {
        test_smart_function(
            params,
            2,
            ServerKey::smart_min_parallelized,
            std::cmp::min::<U256>,
        );
    }

    fn integer_smart_max_parallelized_u256(params: crate::shortint::ClassicPBSParameters) {
        test_smart_function(
            params,
            2,
            ServerKey::smart_max_parallelized,
            std::cmp::max::<U256>,
        );
    }

    fn integer_min_parallelized_u256(params: crate::shortint::ClassicPBSParameters) {
        test_default_function(
            params,
            2,
            ServerKey::min_parallelized,
            std::cmp::min::<U256>,
        );
    }

    fn integer_max_parallelized_u256(params: crate::shortint::ClassicPBSParameters) {
        test_default_function(
            params,
            2,
            ServerKey::max_parallelized,
            std::cmp::max::<U256>,
        );
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

    //=============================================================
    // Signed comparison tests
    //=============================================================

    fn integer_signed_unchecked_min_parallelized_128_bits(params: ClassicPBSParameters) {
        test_signed_unchecked_function(
            params,
            2,
            ServerKey::unchecked_min_parallelized,
            std::cmp::min::<i128>,
        )
    }

    fn integer_signed_unchecked_max_parallelized_128_bits(
        params: crate::shortint::ClassicPBSParameters,
    ) {
        test_signed_unchecked_function(
            params,
            2,
            ServerKey::unchecked_max_parallelized,
            std::cmp::max::<i128>,
        )
    }

    fn integer_signed_smart_min_parallelized_128_bits(
        params: crate::shortint::ClassicPBSParameters,
    ) {
        test_signed_smart_function(
            params,
            2,
            ServerKey::smart_min_parallelized,
            std::cmp::min::<i128>,
        );
    }

    fn integer_signed_smart_max_parallelized_128_bits(
        params: crate::shortint::ClassicPBSParameters,
    ) {
        test_signed_smart_function(
            params,
            2,
            ServerKey::smart_max_parallelized,
            std::cmp::max::<i128>,
        );
    }

    fn integer_signed_min_parallelized_128_bits(params: crate::shortint::ClassicPBSParameters) {
        test_signed_default_function(
            params,
            2,
            ServerKey::min_parallelized,
            std::cmp::min::<i128>,
        );
    }

    fn integer_signed_max_parallelized_128_bits(params: crate::shortint::ClassicPBSParameters) {
        test_signed_default_function(
            params,
            2,
            ServerKey::max_parallelized,
            std::cmp::max::<i128>,
        );
    }

    create_parametrized_test!(integer_signed_unchecked_max_parallelized_128_bits {
        PARAM_MESSAGE_2_CARRY_2_KS_PBS,
        PARAM_MESSAGE_3_CARRY_3_KS_PBS,
        PARAM_MESSAGE_4_CARRY_4_KS_PBS
    });
    create_parametrized_test!(integer_signed_unchecked_min_parallelized_128_bits {
        PARAM_MESSAGE_2_CARRY_2_KS_PBS,
        PARAM_MESSAGE_3_CARRY_3_KS_PBS,
        PARAM_MESSAGE_4_CARRY_4_KS_PBS
    });
    create_parametrized_test!(integer_signed_smart_max_parallelized_128_bits {
        PARAM_MESSAGE_2_CARRY_2_KS_PBS,
        // We don't use PARAM_MESSAGE_3_CARRY_3_KS_PBS,
        // as default test might overflow values
        // and when using 3_3 to represent 256 we actually have more than 256 bits
        // of message so the overflow behaviour is not the same, leading to false negatives
        PARAM_MESSAGE_4_CARRY_4_KS_PBS
    });
    create_parametrized_test!(integer_signed_smart_min_parallelized_128_bits {
        PARAM_MESSAGE_2_CARRY_2_KS_PBS,
        // We don't use PARAM_MESSAGE_3_CARRY_3_KS_PBS,
        // as default test might overflow values
        // and when using 3_3 to represent 256 we actually have more than 256 bits
        // of message so the overflow behaviour is not the same, leading to false negatives
        PARAM_MESSAGE_4_CARRY_4_KS_PBS
    });
    create_parametrized_test!(integer_signed_max_parallelized_128_bits {
        PARAM_MESSAGE_2_CARRY_2_KS_PBS,
        // We don't use PARAM_MESSAGE_3_CARRY_3_KS_PBS,
        // as default test might overflow values
        // and when using 3_3 to represent 256 we actually have more than 256 bits
        // of message so the overflow behaviour is not the same, leading to false negatives
        PARAM_MESSAGE_4_CARRY_4_KS_PBS
    });
    create_parametrized_test!(integer_signed_min_parallelized_128_bits {
        PARAM_MESSAGE_2_CARRY_2_KS_PBS,
        // We don't use PARAM_MESSAGE_3_CARRY_3_KS_PBS,
        // as default test might overflow values
        // and when using 3_3 to represent 256 we actually have more than 256 bits
        // of message so the overflow behaviour is not the same, leading to false negatives
        PARAM_MESSAGE_4_CARRY_4_KS_PBS
    });

    define_signed_comparison_test_functions!(eq, i128);
    define_signed_comparison_test_functions!(ne, i128);
    define_signed_comparison_test_functions!(lt, i128);
    define_signed_comparison_test_functions!(le, i128);
    define_signed_comparison_test_functions!(gt, i128);
    define_signed_comparison_test_functions!(ge, i128);

    //=============================================================
    // Scalar unsigned comparison tests
    //=============================================================

    fn integer_unchecked_scalar_min_parallelized_u256(
        params: crate::shortint::ClassicPBSParameters,
    ) {
        test_unchecked_scalar_function(
            params,
            2,
            ServerKey::unchecked_scalar_min_parallelized,
            std::cmp::min::<U256>,
        );
    }

    fn integer_unchecked_scalar_max_parallelized_u256(
        params: crate::shortint::ClassicPBSParameters,
    ) {
        test_unchecked_scalar_function(
            params,
            2,
            ServerKey::unchecked_scalar_max_parallelized,
            std::cmp::max::<U256>,
        );
    }

    fn integer_smart_scalar_min_parallelized_u256(params: crate::shortint::ClassicPBSParameters) {
        test_smart_scalar_function(
            params,
            2,
            ServerKey::smart_scalar_min_parallelized,
            std::cmp::min::<U256>,
        );
    }

    fn integer_smart_scalar_max_parallelized_u256(params: crate::shortint::ClassicPBSParameters) {
        test_smart_scalar_function(
            params,
            2,
            ServerKey::smart_scalar_max_parallelized,
            std::cmp::max::<U256>,
        );
    }

    fn integer_scalar_min_parallelized_u256(params: crate::shortint::ClassicPBSParameters) {
        test_default_scalar_function(
            params,
            2,
            ServerKey::scalar_min_parallelized,
            std::cmp::min::<U256>,
        );
    }

    fn integer_scalar_max_parallelized_u256(params: crate::shortint::ClassicPBSParameters) {
        test_default_scalar_function(
            params,
            2,
            ServerKey::scalar_max_parallelized,
            std::cmp::max::<U256>,
        );
    }

    create_parametrized_test!(integer_unchecked_scalar_min_parallelized_u256 {
        PARAM_MESSAGE_2_CARRY_2_KS_PBS,
        PARAM_MESSAGE_3_CARRY_3_KS_PBS,
        PARAM_MESSAGE_4_CARRY_4_KS_PBS
    });
    create_parametrized_test!(integer_unchecked_scalar_max_parallelized_u256 {
        PARAM_MESSAGE_2_CARRY_2_KS_PBS,
        PARAM_MESSAGE_3_CARRY_3_KS_PBS,
        PARAM_MESSAGE_4_CARRY_4_KS_PBS
    });
    create_parametrized_test!(integer_smart_scalar_min_parallelized_u256 {
        PARAM_MESSAGE_2_CARRY_2_KS_PBS,
        // No test for 3_3, see define_scalar_comparison_test_functions macro
        PARAM_MESSAGE_4_CARRY_4_KS_PBS
    });
    create_parametrized_test!(integer_smart_scalar_max_parallelized_u256 {
        PARAM_MESSAGE_2_CARRY_2_KS_PBS,
        // No test for 3_3, see define_scalar_comparison_test_functions macro
        PARAM_MESSAGE_4_CARRY_4_KS_PBS
    });

    create_parametrized_test!(integer_scalar_min_parallelized_u256 {
        PARAM_MESSAGE_2_CARRY_2_KS_PBS,
        // No test for 3_3, see define_scalar_comparison_test_functions macro
        PARAM_MESSAGE_4_CARRY_4_KS_PBS
    });
    create_parametrized_test!(integer_scalar_max_parallelized_u256 {
        PARAM_MESSAGE_2_CARRY_2_KS_PBS,
        // No test for 3_3, see define_scalar_comparison_test_functions macro
        PARAM_MESSAGE_4_CARRY_4_KS_PBS
    });

    define_scalar_comparison_test_functions!(eq, U256);
    define_scalar_comparison_test_functions!(ne, U256);
    define_scalar_comparison_test_functions!(lt, U256);
    define_scalar_comparison_test_functions!(le, U256);
    define_scalar_comparison_test_functions!(gt, U256);
    define_scalar_comparison_test_functions!(ge, U256);

    create_parametrized_test!(integer_unchecked_scalar_comparisons_edge {
        PARAM_MESSAGE_2_CARRY_2_KS_PBS,
        PARAM_MESSAGE_3_CARRY_3_KS_PBS,
        PARAM_MESSAGE_4_CARRY_4_KS_PBS
    });

    create_parametrized_test!(integer_is_scalar_out_of_bounds {
        PARAM_MESSAGE_2_CARRY_2_KS_PBS,
        // We don't use PARAM_MESSAGE_3_CARRY_3_KS_PBS,
        // as the test relies on the ciphertext to encrypt 128bits
        // but with param 3_3 we actually encrypt more that 128bits
        PARAM_MESSAGE_4_CARRY_4_KS_PBS
    });

    //=============================================================
    // Scalar signed comparison tests
    //=============================================================

    fn integer_signed_unchecked_scalar_min_parallelized_i128(
        params: crate::shortint::ClassicPBSParameters,
    ) {
        test_signed_unchecked_scalar_function(
            params,
            2,
            ServerKey::unchecked_scalar_min_parallelized,
            std::cmp::min::<i128>,
        );
    }

    fn integer_signed_unchecked_scalar_max_parallelized_i128(
        params: crate::shortint::ClassicPBSParameters,
    ) {
        test_signed_unchecked_scalar_function(
            params,
            2,
            ServerKey::unchecked_scalar_max_parallelized,
            std::cmp::max::<i128>,
        );
    }

    fn integer_signed_smart_scalar_min_parallelized_i128(
        params: crate::shortint::ClassicPBSParameters,
    ) {
        test_signed_smart_scalar_function(
            params,
            2,
            ServerKey::smart_scalar_min_parallelized,
            std::cmp::min::<i128>,
        );
    }

    fn integer_signed_smart_scalar_max_parallelized_i128(
        params: crate::shortint::ClassicPBSParameters,
    ) {
        test_signed_smart_scalar_function(
            params,
            2,
            ServerKey::smart_scalar_max_parallelized,
            std::cmp::max::<i128>,
        );
    }

    fn integer_signed_scalar_min_parallelized_i128(params: crate::shortint::ClassicPBSParameters) {
        test_signed_default_scalar_function(
            params,
            2,
            ServerKey::scalar_min_parallelized,
            std::cmp::min::<i128>,
        );
    }

    fn integer_signed_scalar_max_parallelized_i128(params: crate::shortint::ClassicPBSParameters) {
        test_signed_default_scalar_function(
            params,
            2,
            ServerKey::scalar_max_parallelized,
            std::cmp::max::<i128>,
        );
    }

    create_parametrized_test!(integer_signed_unchecked_scalar_max_parallelized_i128 {
        PARAM_MESSAGE_2_CARRY_2_KS_PBS,
        PARAM_MESSAGE_3_CARRY_3_KS_PBS,
        PARAM_MESSAGE_4_CARRY_4_KS_PBS
    });
    create_parametrized_test!(integer_signed_unchecked_scalar_min_parallelized_i128 {
        PARAM_MESSAGE_2_CARRY_2_KS_PBS,
        PARAM_MESSAGE_3_CARRY_3_KS_PBS,
        PARAM_MESSAGE_4_CARRY_4_KS_PBS
    });
    create_parametrized_test!(integer_signed_smart_scalar_max_parallelized_i128 {
        PARAM_MESSAGE_2_CARRY_2_KS_PBS,
        // We don't use PARAM_MESSAGE_3_CARRY_3_KS_PBS,
        // as default test might overflow values
        // and when using 3_3 to represent 256 we actually have more than 256 bits
        // of message so the overflow behaviour is not the same, leading to false negatives
        PARAM_MESSAGE_4_CARRY_4_KS_PBS
    });
    create_parametrized_test!(integer_signed_smart_scalar_min_parallelized_i128 {
        PARAM_MESSAGE_2_CARRY_2_KS_PBS,
        // We don't use PARAM_MESSAGE_3_CARRY_3_KS_PBS,
        // as default test might overflow values
        // and when using 3_3 to represent 256 we actually have more than 256 bits
        // of message so the overflow behaviour is not the same, leading to false negatives
        PARAM_MESSAGE_4_CARRY_4_KS_PBS
    });
    create_parametrized_test!(integer_signed_scalar_max_parallelized_i128 {
        PARAM_MESSAGE_2_CARRY_2_KS_PBS,
        // We don't use PARAM_MESSAGE_3_CARRY_3_KS_PBS,
        // as default test might overflow values
        // and when using 3_3 to represent 256 we actually have more than 256 bits
        // of message so the overflow behaviour is not the same, leading to false negatives
        PARAM_MESSAGE_4_CARRY_4_KS_PBS
    });
    create_parametrized_test!(integer_signed_scalar_min_parallelized_i128 {
        PARAM_MESSAGE_2_CARRY_2_KS_PBS,
        // We don't use PARAM_MESSAGE_3_CARRY_3_KS_PBS,
        // as default test might overflow values
        // and when using 3_3 to represent 256 we actually have more than 256 bits
        // of message so the overflow behaviour is not the same, leading to false negatives
        PARAM_MESSAGE_4_CARRY_4_KS_PBS
    });

    define_signed_scalar_comparison_test_functions!(eq, i128);
    define_signed_scalar_comparison_test_functions!(ne, i128);
    define_signed_scalar_comparison_test_functions!(lt, i128);
    define_signed_scalar_comparison_test_functions!(le, i128);
    define_signed_scalar_comparison_test_functions!(gt, i128);
    define_signed_scalar_comparison_test_functions!(ge, i128);

    create_parametrized_test!(integer_signed_is_scalar_out_of_bounds {
        PARAM_MESSAGE_2_CARRY_2_KS_PBS,
        // We don't use PARAM_MESSAGE_3_CARRY_3_KS_PBS,
        // as the test relies on the ciphertext to encrypt 128bits
        // but with param 3_3 we actually encrypt more that 128bits
        PARAM_MESSAGE_4_CARRY_4_KS_PBS,
    });
}

// Smaller integers are used in coverage to speed-up execution.
#[cfg(tarpaulin)]
mod coverage {
    use super::*;

    //=============================================================
    // Unsigned comparison tests
    //=============================================================

    fn integer_unchecked_min_parallelized_u8(params: crate::shortint::ClassicPBSParameters) {
        test_unchecked_function(
            params,
            1,
            ServerKey::unchecked_min_parallelized,
            std::cmp::min::<u8>,
        );
    }

    fn integer_unchecked_max_parallelized_u8(params: crate::shortint::ClassicPBSParameters) {
        test_unchecked_function(
            params,
            1,
            ServerKey::unchecked_max_parallelized,
            std::cmp::max::<u8>,
        );
    }

    fn integer_smart_min_parallelized_u8(params: crate::shortint::ClassicPBSParameters) {
        test_smart_function(
            params,
            1,
            ServerKey::smart_min_parallelized,
            std::cmp::min::<u8>,
        );
    }

    fn integer_smart_max_parallelized_u8(params: crate::shortint::ClassicPBSParameters) {
        test_smart_function(
            params,
            1,
            ServerKey::smart_max_parallelized,
            std::cmp::max::<u8>,
        );
    }

    fn integer_min_parallelized_u8(params: crate::shortint::ClassicPBSParameters) {
        test_default_function(params, 1, ServerKey::min_parallelized, std::cmp::min::<u8>);
    }

    fn integer_max_parallelized_u8(params: crate::shortint::ClassicPBSParameters) {
        test_default_function(params, 1, ServerKey::max_parallelized, std::cmp::max::<u8>);
    }

    create_parametrized_test!(integer_unchecked_min_parallelized_u8);
    create_parametrized_test!(integer_unchecked_max_parallelized_u8);
    create_parametrized_test!(integer_smart_min_parallelized_u8);
    create_parametrized_test!(integer_smart_max_parallelized_u8);
    create_parametrized_test!(integer_min_parallelized_u8);
    create_parametrized_test!(integer_max_parallelized_u8);

    define_comparison_test_functions!(eq, u8);
    define_comparison_test_functions!(ne, u8);
    define_comparison_test_functions!(lt, u8);
    define_comparison_test_functions!(le, u8);
    define_comparison_test_functions!(gt, u8);
    define_comparison_test_functions!(ge, u8);

    //=============================================================
    // Signed comparison tests
    //=============================================================

    fn integer_signed_unchecked_min_parallelized_8_bits(
        params: crate::shortint::ClassicPBSParameters,
    ) {
        test_signed_unchecked_function(
            params,
            1,
            ServerKey::unchecked_min_parallelized,
            std::cmp::min::<i8>,
        )
    }

    fn integer_signed_unchecked_max_parallelized_8_bits(
        params: crate::shortint::ClassicPBSParameters,
    ) {
        test_signed_unchecked_function(
            params,
            1,
            ServerKey::unchecked_max_parallelized,
            std::cmp::max::<i8>,
        )
    }

    fn integer_signed_smart_min_parallelized_8_bits(params: crate::shortint::ClassicPBSParameters) {
        test_signed_smart_function(
            params,
            1,
            ServerKey::smart_min_parallelized,
            std::cmp::min::<i8>,
        )
    }

    fn integer_signed_smart_max_parallelized_8_bits(params: crate::shortint::ClassicPBSParameters) {
        test_signed_smart_function(
            params,
            1,
            ServerKey::smart_max_parallelized,
            std::cmp::max::<i8>,
        )
    }

    fn integer_signed_min_parallelized_8_bits(params: crate::shortint::ClassicPBSParameters) {
        test_signed_default_function(params, 1, ServerKey::min_parallelized, std::cmp::min::<i8>)
    }

    fn integer_signed_max_parallelized_8_bits(params: crate::shortint::ClassicPBSParameters) {
        test_signed_default_function(params, 1, ServerKey::max_parallelized, std::cmp::max::<i8>)
    }

    create_parametrized_test!(integer_signed_unchecked_max_parallelized_8_bits);
    create_parametrized_test!(integer_signed_unchecked_min_parallelized_8_bits);
    create_parametrized_test!(integer_signed_smart_max_parallelized_8_bits);
    create_parametrized_test!(integer_signed_smart_min_parallelized_8_bits);
    create_parametrized_test!(integer_signed_max_parallelized_8_bits);
    create_parametrized_test!(integer_signed_min_parallelized_8_bits);

    define_signed_comparison_test_functions!(eq, i8);
    define_signed_comparison_test_functions!(ne, i8);
    define_signed_comparison_test_functions!(lt, i8);
    define_signed_comparison_test_functions!(le, i8);
    define_signed_comparison_test_functions!(gt, i8);
    define_signed_comparison_test_functions!(ge, i8);

    //=============================================================
    // Scalar unsigned comparison tests
    //=============================================================

    fn integer_unchecked_scalar_min_parallelized_u8(params: crate::shortint::ClassicPBSParameters) {
        test_unchecked_scalar_function(
            params,
            1,
            ServerKey::unchecked_scalar_min_parallelized,
            std::cmp::min::<u8>,
        );
    }

    fn integer_unchecked_scalar_max_parallelized_u8(params: crate::shortint::ClassicPBSParameters) {
        test_unchecked_scalar_function(
            params,
            1,
            ServerKey::unchecked_scalar_max_parallelized,
            std::cmp::max::<u8>,
        );
    }

    fn integer_smart_scalar_min_parallelized_u8(params: crate::shortint::ClassicPBSParameters) {
        test_smart_scalar_function(
            params,
            1,
            ServerKey::smart_scalar_min_parallelized,
            std::cmp::min::<u8>,
        );
    }
    fn integer_smart_scalar_max_parallelized_u8(params: crate::shortint::ClassicPBSParameters) {
        test_smart_scalar_function(
            params,
            1,
            ServerKey::smart_scalar_max_parallelized,
            std::cmp::max::<u8>,
        );
    }

    fn integer_scalar_min_parallelized_u8(params: crate::shortint::ClassicPBSParameters) {
        test_default_scalar_function(
            params,
            1,
            ServerKey::scalar_min_parallelized,
            std::cmp::min::<u8>,
        );
    }

    fn integer_scalar_max_parallelized_u8(params: crate::shortint::ClassicPBSParameters) {
        test_default_scalar_function(
            params,
            1,
            ServerKey::scalar_max_parallelized,
            std::cmp::max::<u8>,
        );
    }

    create_parametrized_test!(integer_unchecked_scalar_min_parallelized_u8);
    create_parametrized_test!(integer_unchecked_scalar_max_parallelized_u8);
    create_parametrized_test!(integer_smart_scalar_min_parallelized_u8);
    create_parametrized_test!(integer_smart_scalar_max_parallelized_u8);
    create_parametrized_test!(integer_scalar_min_parallelized_u8);
    create_parametrized_test!(integer_scalar_max_parallelized_u8);

    define_scalar_comparison_test_functions!(eq, u8);
    define_scalar_comparison_test_functions!(ne, u8);
    define_scalar_comparison_test_functions!(lt, u8);
    define_scalar_comparison_test_functions!(le, u8);
    define_scalar_comparison_test_functions!(gt, u8);
    define_scalar_comparison_test_functions!(ge, u8);

    create_parametrized_test!(integer_unchecked_scalar_comparisons_edge);

    create_parametrized_test!(integer_is_scalar_out_of_bounds);

    //=============================================================
    // Scalar signed comparison tests
    //=============================================================

    fn integer_signed_unchecked_scalar_min_parallelized_i8(
        params: crate::shortint::ClassicPBSParameters,
    ) {
        test_signed_unchecked_scalar_function(
            params,
            1,
            ServerKey::unchecked_scalar_min_parallelized,
            std::cmp::min::<i8>,
        );
    }

    fn integer_signed_unchecked_scalar_max_parallelized_i8(
        params: crate::shortint::ClassicPBSParameters,
    ) {
        test_signed_unchecked_scalar_function(
            params,
            1,
            ServerKey::unchecked_scalar_max_parallelized,
            std::cmp::max::<i8>,
        );
    }
    fn integer_signed_smart_scalar_min_parallelized_i8(
        params: crate::shortint::ClassicPBSParameters,
    ) {
        test_signed_smart_scalar_function(
            params,
            1,
            ServerKey::smart_scalar_min_parallelized,
            std::cmp::min::<i8>,
        );
    }

    fn integer_signed_smart_scalar_max_parallelized_i8(
        params: crate::shortint::ClassicPBSParameters,
    ) {
        test_signed_smart_scalar_function(
            params,
            1,
            ServerKey::smart_scalar_max_parallelized,
            std::cmp::max::<i8>,
        );
    }

    fn integer_signed_scalar_min_parallelized_i8(params: crate::shortint::ClassicPBSParameters) {
        test_signed_default_scalar_function(
            params,
            1,
            ServerKey::scalar_min_parallelized,
            std::cmp::min::<i8>,
        );
    }

    fn integer_signed_scalar_max_parallelized_i8(params: crate::shortint::ClassicPBSParameters) {
        test_signed_default_scalar_function(
            params,
            1,
            ServerKey::scalar_max_parallelized,
            std::cmp::max::<i8>,
        );
    }

    create_parametrized_test!(integer_signed_unchecked_scalar_min_parallelized_i8);
    create_parametrized_test!(integer_signed_unchecked_scalar_max_parallelized_i8);
    create_parametrized_test!(integer_signed_smart_scalar_min_parallelized_i8);
    create_parametrized_test!(integer_signed_smart_scalar_max_parallelized_i8);
    create_parametrized_test!(integer_signed_scalar_min_parallelized_i8);
    create_parametrized_test!(integer_signed_scalar_max_parallelized_i8);

    define_signed_scalar_comparison_test_functions!(eq, i8);
    define_signed_scalar_comparison_test_functions!(ne, i8);
    define_signed_scalar_comparison_test_functions!(lt, i8);
    define_signed_scalar_comparison_test_functions!(le, i8);
    define_signed_scalar_comparison_test_functions!(gt, i8);
    define_signed_scalar_comparison_test_functions!(ge, i8);

    create_parametrized_test!(integer_signed_is_scalar_out_of_bounds);
}
