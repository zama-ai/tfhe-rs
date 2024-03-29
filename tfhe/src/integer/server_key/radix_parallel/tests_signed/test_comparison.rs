use crate::core_crypto::prelude::SignedNumeric;
use crate::integer::block_decomposition::DecomposableInto;
use crate::integer::ciphertext::SignedRadixCiphertext;
use crate::integer::client_key::RecomposableSignedInteger;
use crate::integer::keycache::KEY_CACHE;
use crate::integer::server_key::radix_parallel::tests_cases_unsigned::FunctionExecutor;
use crate::integer::server_key::radix_parallel::tests_unsigned::CpuFunctionExecutor;
use crate::integer::tests::create_parametrized_test;
use crate::integer::{BooleanBlock, IntegerKeyKind, RadixClientKey, ServerKey};
#[cfg(tarpaulin)]
use crate::shortint::parameters::coverage_parameters::*;
use crate::shortint::parameters::*;
use rand::distributions::Standard;
use rand::prelude::*;
use rand_distr::num_traits::WrappingAdd;
use std::ops::Neg;
use std::sync::Arc;

/// Function to test an "unchecked" comparator function.
///
/// This calls the `unchecked_server_key_method` with fresh ciphertexts
/// and compares that it gives the same results as the `clear_fn`.
pub(crate) fn test_signed_unchecked_function<P, T, ClearF, Scalar>(
    param: P,
    num_test: usize,
    mut executor: T,
    clear_fn: ClearF,
) where
    P: Into<PBSParameters>,
    Scalar: SignedNumeric
        + RecomposableSignedInteger
        + DecomposableInto<u64>
        + WrappingAdd
        + Neg
        + From<bool>,
    T: for<'a> FunctionExecutor<
        (&'a SignedRadixCiphertext, &'a SignedRadixCiphertext),
        BooleanBlock,
    >,
    ClearF: Fn(Scalar, Scalar) -> Scalar,
    Standard: Distribution<Scalar>,
{
    let mut rng = rand::thread_rng();

    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let sks = Arc::new(sks);
    let num_block = Scalar::BITS.div_ceil(cks.parameters().message_modulus().0.ilog2() as usize);
    let cks = RadixClientKey::from((cks, num_block));

    executor.setup(&cks, sks);

    // Some hard coded tests
    let pairs = [
        (Scalar::ONE, Scalar::TWO),
        (Scalar::TWO, Scalar::ONE),
        (-Scalar::ONE, Scalar::ONE),
        (Scalar::ONE, -Scalar::ONE),
        (-Scalar::ONE, -Scalar::TWO),
        (-Scalar::TWO, -Scalar::ONE),
        (Scalar::ZERO, -Scalar::ONE),
        (Scalar::MAX, Scalar::ZERO),
    ];
    for (clear_a, clear_b) in pairs {
        let a = cks.encrypt_signed(clear_a);
        let b = cks.encrypt_signed(clear_b);

        let result = executor.execute((&a, &b));
        let decrypted: Scalar = cks.decrypt_bool(&result).into();
        let expected_result = clear_fn(clear_a, clear_b);
        assert_eq!(decrypted, expected_result);
    }

    for _ in 0..num_test {
        let clear_a = rng.gen::<Scalar>();
        let clear_b = rng.gen::<Scalar>();

        let a = cks.encrypt_signed(clear_a);
        let b = cks.encrypt_signed(clear_b);

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

/// Function to test a "smart" server_key function for signed inputs
///
/// This calls the `smart_server_key_method` with non-fresh ciphertexts,
/// that is ciphertexts that have non-zero carries, and compares that the result is
/// the same as the one of`clear_fn`.
pub(crate) fn test_signed_smart_function<P, T, ClearF, Scalar>(
    param: P,
    num_test: usize,
    mut executor: T,
    clear_fn: ClearF,
) where
    P: Into<PBSParameters>,
    Scalar: SignedNumeric
        + RecomposableSignedInteger
        + DecomposableInto<u64>
        + WrappingAdd
        + From<bool>,
    T: for<'a> FunctionExecutor<
        (&'a mut SignedRadixCiphertext, &'a mut SignedRadixCiphertext),
        BooleanBlock,
    >,
    ClearF: Fn(Scalar, Scalar) -> Scalar,
    Standard: Distribution<Scalar>,
{
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let num_block = Scalar::BITS.div_ceil(cks.parameters().message_modulus().0.ilog2() as usize);
    assert_eq!(
        Scalar::BITS as u32 % cks.parameters().message_modulus().0.ilog2(),
        0,
        "bit width must be a multiple of number of bit in a block"
    );
    let cks = RadixClientKey::from((cks, num_block));
    let sks = Arc::new(sks);

    let mut rng = rand::thread_rng();

    executor.setup(&cks, sks.clone());

    for _ in 0..num_test {
        let mut clear_0 = rng.gen::<Scalar>();
        let mut clear_1 = rng.gen::<Scalar>();
        let mut ct_0 = cks.encrypt_signed(clear_0);
        let mut ct_1 = cks.encrypt_signed(clear_1);

        // Raise the degree, so as to ensure worst case path in operations
        while ct_0.block_carries_are_empty() {
            let clear_2 = rng.gen::<Scalar>();
            let ct_2 = cks.encrypt_signed(clear_2);
            sks.unchecked_add_assign(&mut ct_0, &ct_2);
            clear_0 = clear_0.wrapping_add(&clear_2);
        }

        while ct_1.block_carries_are_empty() {
            let clear_2 = rng.gen::<Scalar>();
            let ct_2 = cks.encrypt_signed(clear_2);
            sks.unchecked_add_assign(&mut ct_1, &ct_2);
            clear_1 = clear_1.wrapping_add(&clear_2);
        }

        // Sanity decryption checks
        {
            let a: Scalar = cks.decrypt_signed(&ct_0);
            assert_eq!(a, clear_0);

            let b: Scalar = cks.decrypt_signed(&ct_1);
            assert_eq!(b, clear_1);
        }

        assert!(!ct_0.block_carries_are_empty());
        assert!(!ct_1.block_carries_are_empty());
        let encrypted_result = executor.execute((&mut ct_0, &mut ct_1));
        assert!(ct_0.block_carries_are_empty());
        assert!(ct_1.block_carries_are_empty());

        // Sanity decryption checks
        {
            let a: Scalar = cks.decrypt_signed(&ct_0);
            assert_eq!(a, clear_0);

            let b: Scalar = cks.decrypt_signed(&ct_1);
            assert_eq!(b, clear_1);
        }

        let decrypted_result: Scalar = cks.decrypt_bool(&encrypted_result).into();

        let expected_result = clear_fn(clear_0, clear_1);
        assert_eq!(decrypted_result, expected_result);
    }
}

/// Function to test a "default" server_key function for signed inputs.
///
/// This calls the `server_key_method` with non-fresh ciphertexts,
/// that is ciphertexts that have non-zero carries, and compares that the result is
/// the same as the one of`clear_fn`.
pub(crate) fn test_signed_default_function<P, T, ClearF, Scalar>(
    param: P,
    num_test: usize,
    mut executor: T,
    clear_fn: ClearF,
) where
    P: Into<PBSParameters>,
    Scalar: SignedNumeric
        + RecomposableSignedInteger
        + DecomposableInto<u64>
        + WrappingAdd
        + From<bool>,
    T: for<'a> FunctionExecutor<
        (&'a SignedRadixCiphertext, &'a SignedRadixCiphertext),
        BooleanBlock,
    >,
    ClearF: Fn(Scalar, Scalar) -> Scalar,
    Standard: Distribution<Scalar>,
{
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let num_block = Scalar::BITS.div_ceil(cks.parameters().message_modulus().0.ilog2() as usize);
    assert_eq!(
        Scalar::BITS as u32 % cks.parameters().message_modulus().0.ilog2(),
        0,
        "bit width must be a multiple of number of bit in a block"
    );
    let sks = Arc::new(sks);
    let cks = RadixClientKey::from((cks, num_block));

    let mut rng = rand::thread_rng();

    executor.setup(&cks, sks.clone());

    for _ in 0..num_test {
        let mut clear_0 = rng.gen::<Scalar>();
        let mut clear_1 = rng.gen::<Scalar>();
        let mut ct_0 = cks.encrypt_signed(clear_0);
        let mut ct_1 = cks.encrypt_signed(clear_1);

        // Raise the degree, so as to ensure worst case path in operations
        while ct_0.block_carries_are_empty() {
            let clear_2 = rng.gen::<Scalar>();
            let ct_2 = cks.encrypt_signed(clear_2);
            sks.unchecked_add_assign(&mut ct_0, &ct_2);
            clear_0 = clear_0.wrapping_add(&clear_2);
        }

        while ct_1.block_carries_are_empty() {
            let clear_2 = rng.gen::<Scalar>();
            let ct_2 = cks.encrypt_signed(clear_2);
            sks.unchecked_add_assign(&mut ct_1, &ct_2);
            clear_1 = clear_1.wrapping_add(&clear_2);
        }

        // Sanity decryption checks
        {
            let a: Scalar = cks.decrypt_signed(&ct_0);
            assert_eq!(a, clear_0);

            let b: Scalar = cks.decrypt_signed(&ct_1);
            assert_eq!(b, clear_1);
        }

        assert!(!ct_0.block_carries_are_empty());
        assert!(!ct_1.block_carries_are_empty());
        let encrypted_result = executor.execute((&ct_0, &ct_1));

        // Sanity decryption checks
        {
            let a: Scalar = cks.decrypt_signed(&ct_0);
            assert_eq!(a, clear_0);

            let b: Scalar = cks.decrypt_signed(&ct_1);
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
macro_rules! define_signed_comparison_test_functions {
    ($comparison_name:ident, $clear_type:ty) => {
        ::paste::paste!{
            // Fist we "specialialize" the test_signed fns

            fn [<integer_signed_unchecked_ $comparison_name _ $clear_type>]<P>(param: P) where P: Into<PBSParameters> {
                let num_tests = 1;
                let executor = CpuFunctionExecutor::new(&ServerKey::[<unchecked_ $comparison_name>]);
                test_signed_unchecked_function(
                    param,
                    num_tests,
                    executor,
                    |lhs, rhs| $clear_type::from(<$clear_type>::$comparison_name(&lhs, &rhs) as $clear_type),
                )
            }

            fn [<integer_signed_unchecked_ $comparison_name _parallelized_ $clear_type>]<P>(param: P) where P: Into<PBSParameters> {
                let num_tests = 1;
                let executor = CpuFunctionExecutor::new(&ServerKey::[<unchecked_ $comparison_name _parallelized>]);
                test_signed_unchecked_function(
                    param,
                    num_tests,
                    executor,
                    |lhs, rhs| $clear_type::from(<$clear_type>::$comparison_name(&lhs, &rhs) as $clear_type),
                )
            }

            fn [<integer_signed_smart_ $comparison_name _ $clear_type>]<P>(param: P) where P: Into<PBSParameters> {
                let num_tests = 1;
                let executor = CpuFunctionExecutor::new(&ServerKey::[<smart_ $comparison_name>]);
                test_signed_smart_function(
                    param,
                    num_tests,
                    executor,
                    |lhs, rhs| $clear_type::from(<$clear_type>::$comparison_name(&lhs, &rhs) as $clear_type),
                )
            }

            fn [<integer_signed_smart_ $comparison_name _parallelized_ $clear_type>]<P>(param: P) where P: Into<PBSParameters> {
                let num_tests = 1;
                let executor = CpuFunctionExecutor::new(&ServerKey::[<smart_ $comparison_name _parallelized>]);
                test_signed_smart_function(
                    param,
                    num_tests,
                    executor,
                    |lhs, rhs| $clear_type::from(<$clear_type>::$comparison_name(&lhs, &rhs) as $clear_type),
                )
            }

            fn [<integer_signed_default_ $comparison_name _parallelized_ $clear_type>]<P>(param: P) where P: Into<PBSParameters> {
                let num_tests = 1;
                let executor = CpuFunctionExecutor::new(&ServerKey::[<$comparison_name _parallelized>]);
                test_signed_default_function(
                    param,
                    num_tests,
                    executor,
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

/// Function to test an "unchecked" comparator function.
///
/// This calls the `unchecked_server_key_method` with fresh ciphertexts
/// and compares that it gives the same results as the `clear_fn`.
pub(crate) fn test_signed_unchecked_minmax<P, T, ClearF, Scalar>(
    param: P,
    num_test: usize,
    mut executor: T,
    clear_fn: ClearF,
) where
    P: Into<PBSParameters>,
    Scalar: SignedNumeric
        + RecomposableSignedInteger
        + DecomposableInto<u64>
        + WrappingAdd
        + Neg
        + From<bool>,
    T: for<'a> FunctionExecutor<
        (&'a SignedRadixCiphertext, &'a SignedRadixCiphertext),
        SignedRadixCiphertext,
    >,
    ClearF: Fn(Scalar, Scalar) -> Scalar,
    Standard: Distribution<Scalar>,
{
    let mut rng = rand::thread_rng();

    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let sks = Arc::new(sks);
    let num_block = Scalar::BITS.div_ceil(cks.parameters().message_modulus().0.ilog2() as usize);
    let cks = RadixClientKey::from((cks, num_block));

    executor.setup(&cks, sks);

    // Some hard coded tests
    let pairs = [
        (Scalar::ONE, Scalar::TWO),
        (Scalar::TWO, Scalar::ONE),
        (-Scalar::ONE, Scalar::ONE),
        (Scalar::ONE, -Scalar::ONE),
        (-Scalar::ONE, -Scalar::TWO),
        (-Scalar::TWO, -Scalar::ONE),
        (Scalar::ZERO, -Scalar::ONE),
        (Scalar::MAX, Scalar::ZERO),
    ];
    for (clear_a, clear_b) in pairs {
        let a = cks.encrypt_signed(clear_a);
        let b = cks.encrypt_signed(clear_b);

        let result = executor.execute((&a, &b));
        let decrypted: Scalar = cks.decrypt_signed(&result);
        let expected_result = clear_fn(clear_a, clear_b);
        assert_eq!(decrypted, expected_result);
    }

    for _ in 0..num_test {
        let clear_a = rng.gen::<Scalar>();
        let clear_b = rng.gen::<Scalar>();

        let a = cks.encrypt_signed(clear_a);
        let b = cks.encrypt_signed(clear_b);

        {
            let result = executor.execute((&a, &b));
            let decrypted: Scalar = cks.decrypt_signed(&result);
            let expected_result = clear_fn(clear_a, clear_b);
            assert_eq!(decrypted, expected_result);
        }

        {
            // Force case where lhs == rhs
            let result = executor.execute((&a, &a));
            let decrypted: Scalar = cks.decrypt_signed(&result);
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
pub(crate) fn test_signed_smart_minmax<P, T, ClearF, Scalar>(
    param: P,
    num_test: usize,
    mut executor: T,
    clear_fn: ClearF,
) where
    P: Into<PBSParameters>,
    Scalar: SignedNumeric
        + RecomposableSignedInteger
        + DecomposableInto<u64>
        + WrappingAdd
        + From<bool>,
    T: for<'a> FunctionExecutor<
        (&'a mut SignedRadixCiphertext, &'a mut SignedRadixCiphertext),
        SignedRadixCiphertext,
    >,
    ClearF: Fn(Scalar, Scalar) -> Scalar,
    Standard: Distribution<Scalar>,
{
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let num_block = Scalar::BITS.div_ceil(cks.parameters().message_modulus().0.ilog2() as usize);
    assert_eq!(
        Scalar::BITS as u32 % cks.parameters().message_modulus().0.ilog2(),
        0,
        "bit width must be a multiple of number of bit in a block"
    );
    let cks = RadixClientKey::from((cks, num_block));
    let sks = Arc::new(sks);

    let mut rng = rand::thread_rng();

    executor.setup(&cks, sks.clone());

    for _ in 0..num_test {
        let mut clear_0 = rng.gen::<Scalar>();
        let mut clear_1 = rng.gen::<Scalar>();
        let mut ct_0 = cks.encrypt_signed(clear_0);
        let mut ct_1 = cks.encrypt_signed(clear_1);

        // Raise the degree, so as to ensure worst case path in operations
        while ct_0.block_carries_are_empty() {
            let clear_2 = rng.gen::<Scalar>();
            let ct_2 = cks.encrypt_signed(clear_2);
            sks.unchecked_add_assign(&mut ct_0, &ct_2);
            clear_0 = clear_0.wrapping_add(&clear_2);
        }

        while ct_1.block_carries_are_empty() {
            let clear_2 = rng.gen::<Scalar>();
            let ct_2 = cks.encrypt_signed(clear_2);
            sks.unchecked_add_assign(&mut ct_1, &ct_2);
            clear_1 = clear_1.wrapping_add(&clear_2);
        }

        // Sanity decryption checks
        {
            let a: Scalar = cks.decrypt_signed(&ct_0);
            assert_eq!(a, clear_0);

            let b: Scalar = cks.decrypt_signed(&ct_1);
            assert_eq!(b, clear_1);
        }

        assert!(!ct_0.block_carries_are_empty());
        assert!(!ct_1.block_carries_are_empty());
        let encrypted_result = executor.execute((&mut ct_0, &mut ct_1));
        assert!(ct_0.block_carries_are_empty());
        assert!(ct_1.block_carries_are_empty());

        // Sanity decryption checks
        {
            let a: Scalar = cks.decrypt_signed(&ct_0);
            assert_eq!(a, clear_0);

            let b: Scalar = cks.decrypt_signed(&ct_1);
            assert_eq!(b, clear_1);
        }

        let decrypted_result: Scalar = cks.decrypt_signed(&encrypted_result);

        let expected_result = clear_fn(clear_0, clear_1);
        assert_eq!(decrypted_result, expected_result);
    }
}

/// Function to test a "default" server_key function for signed inputs.
///
/// This calls the `server_key_method` with non-fresh ciphertexts,
/// that is ciphertexts that have non-zero carries, and compares that the result is
/// the same as the one of`clear_fn`.
pub(crate) fn test_signed_default_minmax<P, T, ClearF, Scalar>(
    param: P,
    num_test: usize,
    mut executor: T,
    clear_fn: ClearF,
) where
    P: Into<PBSParameters>,
    Scalar: SignedNumeric
        + RecomposableSignedInteger
        + DecomposableInto<u64>
        + WrappingAdd
        + From<bool>,
    T: for<'a> FunctionExecutor<
        (&'a SignedRadixCiphertext, &'a SignedRadixCiphertext),
        SignedRadixCiphertext,
    >,
    ClearF: Fn(Scalar, Scalar) -> Scalar,
    Standard: Distribution<Scalar>,
{
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let num_block = Scalar::BITS.div_ceil(cks.parameters().message_modulus().0.ilog2() as usize);
    assert_eq!(
        Scalar::BITS as u32 % cks.parameters().message_modulus().0.ilog2(),
        0,
        "bit width must be a multiple of number of bit in a block"
    );
    let sks = Arc::new(sks);
    let cks = RadixClientKey::from((cks, num_block));

    let mut rng = rand::thread_rng();

    executor.setup(&cks, sks.clone());

    for _ in 0..num_test {
        let mut clear_0 = rng.gen::<Scalar>();
        let mut clear_1 = rng.gen::<Scalar>();
        let mut ct_0 = cks.encrypt_signed(clear_0);
        let mut ct_1 = cks.encrypt_signed(clear_1);

        // Raise the degree, so as to ensure worst case path in operations
        while ct_0.block_carries_are_empty() {
            let clear_2 = rng.gen::<Scalar>();
            let ct_2 = cks.encrypt_signed(clear_2);
            sks.unchecked_add_assign(&mut ct_0, &ct_2);
            clear_0 = clear_0.wrapping_add(&clear_2);
        }

        while ct_1.block_carries_are_empty() {
            let clear_2 = rng.gen::<Scalar>();
            let ct_2 = cks.encrypt_signed(clear_2);
            sks.unchecked_add_assign(&mut ct_1, &ct_2);
            clear_1 = clear_1.wrapping_add(&clear_2);
        }

        // Sanity decryption checks
        {
            let a: Scalar = cks.decrypt_signed(&ct_0);
            assert_eq!(a, clear_0);

            let b: Scalar = cks.decrypt_signed(&ct_1);
            assert_eq!(b, clear_1);
        }

        assert!(!ct_0.block_carries_are_empty());
        assert!(!ct_1.block_carries_are_empty());
        let encrypted_result = executor.execute((&ct_0, &ct_1));
        assert!(encrypted_result.block_carries_are_empty());

        // Sanity decryption checks
        {
            let a: Scalar = cks.decrypt_signed(&ct_0);
            assert_eq!(a, clear_0);

            let b: Scalar = cks.decrypt_signed(&ct_1);
            assert_eq!(b, clear_1);
        }

        let decrypted_result: Scalar = cks.decrypt_signed(&encrypted_result);

        let expected_result = clear_fn(clear_0, clear_1);
        assert_eq!(decrypted_result, expected_result);
    }
}

#[cfg(not(tarpaulin))]
mod no_coverage {
    use super::*;

    fn integer_signed_unchecked_min_parallelized_128_bits(
        params: crate::shortint::ClassicPBSParameters,
    ) {
        let executor = CpuFunctionExecutor::new(&ServerKey::unchecked_min_parallelized);
        test_signed_unchecked_minmax(params, 2, executor, std::cmp::min::<i128>)
    }

    fn integer_signed_unchecked_max_parallelized_128_bits(
        params: crate::shortint::ClassicPBSParameters,
    ) {
        let executor = CpuFunctionExecutor::new(&ServerKey::unchecked_max_parallelized);
        test_signed_unchecked_minmax(params, 2, executor, std::cmp::max::<i128>)
    }

    fn integer_signed_smart_min_parallelized_128_bits(
        params: crate::shortint::ClassicPBSParameters,
    ) {
        let executor = CpuFunctionExecutor::new(&ServerKey::smart_min_parallelized);
        test_signed_smart_minmax(params, 2, executor, std::cmp::min::<i128>);
    }

    fn integer_signed_smart_max_parallelized_128_bits(
        params: crate::shortint::ClassicPBSParameters,
    ) {
        let executor = CpuFunctionExecutor::new(&ServerKey::smart_max_parallelized);
        test_signed_smart_minmax(params, 2, executor, std::cmp::max::<i128>);
    }

    fn integer_signed_min_parallelized_128_bits(params: crate::shortint::ClassicPBSParameters) {
        let executor = CpuFunctionExecutor::new(&ServerKey::min_parallelized);
        test_signed_default_minmax(params, 2, executor, std::cmp::min::<i128>);
    }

    fn integer_signed_max_parallelized_128_bits(params: crate::shortint::ClassicPBSParameters) {
        let executor = CpuFunctionExecutor::new(&ServerKey::max_parallelized);
        test_signed_default_minmax(params, 2, executor, std::cmp::max::<i128>);
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
}

// Smaller integers are used in coverage to speed-up execution.
#[cfg(tarpaulin)]
mod coverage {
    use super::*;
    use crate::integer::tests::create_parametrized_test_classical_params;

    fn integer_signed_unchecked_min_parallelized_8_bits(
        params: crate::shortint::ClassicPBSParameters,
    ) {
        let executor = CpuFunctionExecutor::new(&ServerKey::unchecked_min_parallelized);
        test_signed_unchecked_minmax(params, 1, executor, std::cmp::min::<i8>)
    }

    fn integer_signed_unchecked_max_parallelized_8_bits(
        params: crate::shortint::ClassicPBSParameters,
    ) {
        let executor = CpuFunctionExecutor::new(&ServerKey::unchecked_max_parallelized);
        test_signed_unchecked_minmax(params, 1, executor, std::cmp::max::<i8>)
    }

    fn integer_signed_smart_min_parallelized_8_bits(params: crate::shortint::ClassicPBSParameters) {
        let executor = CpuFunctionExecutor::new(&ServerKey::smart_min_parallelized);
        test_signed_smart_minmax(params, 1, executor, std::cmp::min::<i8>)
    }

    fn integer_signed_smart_max_parallelized_8_bits(params: crate::shortint::ClassicPBSParameters) {
        let executor = CpuFunctionExecutor::new(&ServerKey::smart_max_parallelized);
        test_signed_smart_minmax(params, 1, executor, std::cmp::max::<i8>)
    }

    fn integer_signed_min_parallelized_8_bits(params: crate::shortint::ClassicPBSParameters) {
        let executor = CpuFunctionExecutor::new(&ServerKey::min_parallelized);
        test_signed_default_minmax(params, 1, executor, std::cmp::min::<i8>)
    }

    fn integer_signed_max_parallelized_8_bits(params: crate::shortint::ClassicPBSParameters) {
        let executor = CpuFunctionExecutor::new(&ServerKey::max_parallelized);
        test_signed_default_minmax(params, 1, executor, std::cmp::max::<i8>)
    }

    create_parametrized_test_classical_params!(integer_signed_unchecked_max_parallelized_8_bits);
    create_parametrized_test_classical_params!(integer_signed_unchecked_min_parallelized_8_bits);
    create_parametrized_test_classical_params!(integer_signed_smart_max_parallelized_8_bits);
    create_parametrized_test_classical_params!(integer_signed_smart_min_parallelized_8_bits);
    create_parametrized_test_classical_params!(integer_signed_max_parallelized_8_bits);
    create_parametrized_test_classical_params!(integer_signed_min_parallelized_8_bits);

    define_signed_comparison_test_functions!(eq, i8);
    define_signed_comparison_test_functions!(ne, i8);
    define_signed_comparison_test_functions!(lt, i8);
    define_signed_comparison_test_functions!(le, i8);
    define_signed_comparison_test_functions!(gt, i8);
    define_signed_comparison_test_functions!(ge, i8);
}
