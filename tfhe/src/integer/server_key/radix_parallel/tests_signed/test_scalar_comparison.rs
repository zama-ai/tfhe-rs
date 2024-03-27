use crate::core_crypto::prelude::SignedNumeric;
use crate::integer::block_decomposition::DecomposableInto;
use crate::integer::ciphertext::SignedRadixCiphertext;
use crate::integer::client_key::RecomposableSignedInteger;
use crate::integer::keycache::KEY_CACHE;
use crate::integer::server_key::radix_parallel::tests_cases_unsigned::FunctionExecutor;
use crate::integer::server_key::radix_parallel::tests_unsigned::CpuFunctionExecutor;
use crate::integer::tests::create_parametrized_test;
use crate::integer::{BooleanBlock, IntegerKeyKind, RadixClientKey, ServerKey, I256};
#[cfg(tarpaulin)]
use crate::shortint::parameters::coverage_parameters::*;
use crate::shortint::parameters::*;
use rand::distributions::Standard;
use rand::prelude::*;
use rand_distr::num_traits::WrappingAdd;
use std::sync::Arc;

/// Function to test an "unchecked_scalar" comparator function.
///
/// This calls the `unchecked_scalar_server_key_method` with fresh ciphertexts
/// and compares that it gives the same results as the `clear_fn`.
pub(crate) fn test_signed_unchecked_scalar_function<P, T, ClearF, Scalar>(
    param: P,
    num_test: usize,
    mut executor: T,
    clear_fn: ClearF,
) where
    P: Into<PBSParameters>,
    Scalar: SignedNumeric + RecomposableSignedInteger + DecomposableInto<u64> + From<bool>,
    T: for<'a> FunctionExecutor<(&'a SignedRadixCiphertext, Scalar), BooleanBlock>,
    ClearF: Fn(Scalar, Scalar) -> Scalar,
    Standard: Distribution<Scalar>,
{
    let mut rng = rand::thread_rng();

    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let num_block = Scalar::BITS.div_ceil(cks.parameters().message_modulus().0.ilog2() as usize);

    let sks = Arc::new(sks);
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

        let result = executor.execute((&a, clear_b));
        let decrypted: Scalar = cks.decrypt_bool(&result).into();
        let expected_result = clear_fn(clear_a, clear_b);
        assert_eq!(decrypted, expected_result);
    }

    for _ in 0..num_test {
        let clear_a = rng.gen::<Scalar>();
        let clear_b = rng.gen::<Scalar>();

        let a = cks.encrypt_signed(clear_a);

        {
            let result = executor.execute((&a, clear_b));
            let decrypted: Scalar = cks.decrypt_bool(&result).into();
            let expected_result = clear_fn(clear_a, clear_b);
            assert_eq!(decrypted, expected_result);
        }

        {
            // Force case where lhs == rhs
            let result = executor.execute((&a, clear_a));
            let decrypted: Scalar = cks.decrypt_bool(&result).into();
            let expected_result = clear_fn(clear_a, clear_a);
            assert_eq!(decrypted, expected_result);
        }
    }
}

/// Function to test a "smart_scalar" server_key function.
pub(crate) fn test_signed_smart_scalar_function<P, T, ClearF, Scalar>(
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
    T: for<'a> FunctionExecutor<(&'a mut SignedRadixCiphertext, Scalar), BooleanBlock>,
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

    executor.setup(&cks, sks.clone());

    let mut rng = rand::thread_rng();

    for _ in 0..num_test {
        let mut clear_0 = rng.gen::<Scalar>();
        let clear_1 = rng.gen::<Scalar>();
        let mut ct_0 = cks.encrypt_signed(clear_0);

        // Raise the degree, so as to ensure worst case path in operations
        while ct_0.block_carries_are_empty() {
            let clear_2 = rng.gen::<Scalar>();
            let ct_2 = cks.encrypt_signed(clear_2);
            sks.unchecked_add_assign(&mut ct_0, &ct_2);
            clear_0 = clear_0.wrapping_add(&clear_2);
        }

        // Sanity decryption checks
        {
            let a: Scalar = cks.decrypt_signed(&ct_0);
            assert_eq!(a, clear_0);
        }

        assert!(!ct_0.block_carries_are_empty());
        let encrypted_result = executor.execute((&mut ct_0, clear_1));

        // Sanity decryption checks
        {
            let a: Scalar = cks.decrypt_signed(&ct_0);
            assert_eq!(a, clear_0);
        }

        let decrypted_result: Scalar = cks.decrypt_bool(&encrypted_result).into();

        let expected_result = clear_fn(clear_0, clear_1);
        assert_eq!(decrypted_result, expected_result);
    }
}

/// Function to test a "default_scalar" server_key function.
pub(crate) fn test_signed_default_scalar_function<P, T, ClearF, Scalar>(
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
    T: for<'a> FunctionExecutor<(&'a SignedRadixCiphertext, Scalar), BooleanBlock>,
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

    executor.setup(&cks, sks.clone());

    let mut rng = rand::thread_rng();

    for _ in 0..num_test {
        let mut clear_0 = rng.gen::<Scalar>();
        let clear_1 = rng.gen::<Scalar>();

        let mut ct_0 = cks.encrypt_signed(clear_0);

        // Raise the degree, so as to ensure worst case path in operations
        while ct_0.block_carries_are_empty() {
            let clear_2 = rng.gen::<Scalar>();
            let ct_2 = cks.encrypt_signed(clear_2);
            sks.unchecked_add_assign(&mut ct_0, &ct_2);
            clear_0 = clear_0.wrapping_add(&clear_2);
        }

        // Sanity decryption checks
        {
            let a: Scalar = cks.decrypt_signed(&ct_0);
            assert_eq!(a, clear_0);
        }

        assert!(!ct_0.block_carries_are_empty());
        let encrypted_result = executor.execute((&ct_0, clear_1));

        // Sanity decryption checks
        {
            let a: Scalar = cks.decrypt_signed(&ct_0);
            assert_eq!(a, clear_0);
        }

        let decrypted_result: Scalar = cks.decrypt_bool(&encrypted_result).into();

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
        ::paste::paste!{
            fn [<integer_signed_unchecked_scalar_ $comparison_name _parallelized_  $clear_type>]<P>(param: P) where P: Into<PBSParameters>{
                let num_tests = 2;
                let executor = CpuFunctionExecutor::new(&ServerKey::[<unchecked_scalar_ $comparison_name _parallelized>]);
                test_signed_unchecked_scalar_function(
                    param,
                    num_tests,
                    executor,
                    |lhs, rhs| $clear_type::from(<$clear_type>::$comparison_name(&lhs, &rhs)),
                )
            }

            fn [<integer_signed_smart_scalar_ $comparison_name _parallelized_  $clear_type>]<P>(param: P) where P: Into<PBSParameters>{
                let num_tests = 2;
                let executor = CpuFunctionExecutor::new(&ServerKey::[<smart_scalar_ $comparison_name _parallelized>]);
                test_signed_smart_scalar_function(
                    param,
                    num_tests,
                    executor,
                    |lhs, rhs| $clear_type::from(<$clear_type>::$comparison_name(&lhs, &rhs)),
                )
            }

            fn [<integer_signed_default_scalar_ $comparison_name _parallelized_  $clear_type>]<P>(param: P) where P: Into<PBSParameters>{
                let num_tests = 2;
                let executor = CpuFunctionExecutor::new(&ServerKey::[<scalar_ $comparison_name _parallelized>]);
                test_signed_default_scalar_function(
                    param,
                    num_tests,
                    executor,
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

/// Function to test an "unchecked_scalar" comparator min or max.
///
/// This calls the `unchecked_scalar_server_key_method` with fresh ciphertexts
/// and compares that it gives the same results as the `clear_fn`.
pub(crate) fn test_signed_unchecked_scalar_minmax<P, T, ClearF, Scalar>(
    param: P,
    num_test: usize,
    mut executor: T,
    clear_fn: ClearF,
) where
    P: Into<PBSParameters>,
    Scalar: SignedNumeric + RecomposableSignedInteger + DecomposableInto<u64>,
    T: for<'a> FunctionExecutor<(&'a SignedRadixCiphertext, Scalar), SignedRadixCiphertext>,
    ClearF: Fn(Scalar, Scalar) -> Scalar,
    Standard: Distribution<Scalar>,
{
    let mut rng = rand::thread_rng();

    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let num_block = Scalar::BITS.div_ceil(cks.parameters().message_modulus().0.ilog2() as usize);

    let sks = Arc::new(sks);
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

        let result = executor.execute((&a, clear_b));
        let decrypted: Scalar = cks.decrypt_signed(&result);
        let expected_result = clear_fn(clear_a, clear_b);
        assert_eq!(decrypted, expected_result);
    }

    for _ in 0..num_test {
        let clear_a = rng.gen::<Scalar>();
        let clear_b = rng.gen::<Scalar>();

        let a = cks.encrypt_signed(clear_a);

        {
            let result = executor.execute((&a, clear_b));
            let decrypted: Scalar = cks.decrypt_signed(&result);
            let expected_result = clear_fn(clear_a, clear_b);
            assert_eq!(decrypted, expected_result);
        }

        {
            // Force case where lhs == rhs
            let result = executor.execute((&a, clear_a));
            let decrypted: Scalar = cks.decrypt_signed(&result);
            let expected_result = clear_fn(clear_a, clear_a);
            assert_eq!(decrypted, expected_result);
        }
    }
}

/// Function to test a "smart_scalar" server_key function.
pub(crate) fn test_signed_smart_scalar_minmax<P, T, ClearF, Scalar>(
    param: P,
    num_test: usize,
    mut executor: T,
    clear_fn: ClearF,
) where
    P: Into<PBSParameters>,
    Scalar: SignedNumeric + RecomposableSignedInteger + DecomposableInto<u64> + WrappingAdd,
    T: for<'a> FunctionExecutor<(&'a mut SignedRadixCiphertext, Scalar), SignedRadixCiphertext>,
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

    executor.setup(&cks, sks.clone());

    let mut rng = rand::thread_rng();

    for _ in 0..num_test {
        let mut clear_0 = rng.gen::<Scalar>();
        let clear_1 = rng.gen::<Scalar>();
        let mut ct_0 = cks.encrypt_signed(clear_0);

        // Raise the degree, so as to ensure worst case path in operations
        while ct_0.block_carries_are_empty() {
            let clear_2 = rng.gen::<Scalar>();
            let ct_2 = cks.encrypt_signed(clear_2);
            sks.unchecked_add_assign(&mut ct_0, &ct_2);
            clear_0 = clear_0.wrapping_add(&clear_2);
        }

        // Sanity decryption checks
        {
            let a: Scalar = cks.decrypt_signed(&ct_0);
            assert_eq!(a, clear_0);
        }

        assert!(!ct_0.block_carries_are_empty());
        let encrypted_result = executor.execute((&mut ct_0, clear_1));

        // Sanity decryption checks
        {
            let a: Scalar = cks.decrypt_signed(&ct_0);
            assert_eq!(a, clear_0);
        }

        let decrypted_result: Scalar = cks.decrypt_signed(&encrypted_result);

        let expected_result = clear_fn(clear_0, clear_1);
        assert_eq!(decrypted_result, expected_result);
    }
}

/// Function to test a "default_scalar" server_key function.
pub(crate) fn test_signed_default_scalar_minmax<P, T, ClearF, Scalar>(
    param: P,
    num_test: usize,
    mut executor: T,
    clear_fn: ClearF,
) where
    P: Into<PBSParameters>,
    Scalar: SignedNumeric + RecomposableSignedInteger + DecomposableInto<u64> + WrappingAdd,
    T: for<'a> FunctionExecutor<(&'a SignedRadixCiphertext, Scalar), SignedRadixCiphertext>,
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

    executor.setup(&cks, sks.clone());

    let mut rng = rand::thread_rng();

    for _ in 0..num_test {
        let mut clear_0 = rng.gen::<Scalar>();
        let clear_1 = rng.gen::<Scalar>();

        let mut ct_0 = cks.encrypt_signed(clear_0);

        // Raise the degree, so as to ensure worst case path in operations
        while ct_0.block_carries_are_empty() {
            let clear_2 = rng.gen::<Scalar>();
            let ct_2 = cks.encrypt_signed(clear_2);
            sks.unchecked_add_assign(&mut ct_0, &ct_2);
            clear_0 = clear_0.wrapping_add(&clear_2);
        }

        // Sanity decryption checks
        {
            let a: Scalar = cks.decrypt_signed(&ct_0);
            assert_eq!(a, clear_0);
        }

        assert!(!ct_0.block_carries_are_empty());
        let encrypted_result = executor.execute((&ct_0, clear_1));

        // Sanity decryption checks
        {
            let a: Scalar = cks.decrypt_signed(&ct_0);
            assert_eq!(a, clear_0);
        }

        let decrypted_result: Scalar = cks.decrypt_signed(&encrypted_result);

        let expected_result = clear_fn(clear_0, clear_1);
        assert_eq!(decrypted_result, expected_result);
    }
}

#[cfg(not(tarpaulin))]
mod no_coverage {
    use super::*;

    fn integer_signed_unchecked_scalar_min_parallelized_i128(
        params: crate::shortint::ClassicPBSParameters,
    ) {
        let executor = CpuFunctionExecutor::new(&ServerKey::unchecked_scalar_min_parallelized);
        test_signed_unchecked_scalar_minmax(params, 2, executor, std::cmp::min::<i128>);
    }

    fn integer_signed_unchecked_scalar_max_parallelized_i128(
        params: crate::shortint::ClassicPBSParameters,
    ) {
        let executor = CpuFunctionExecutor::new(&ServerKey::unchecked_scalar_max_parallelized);
        test_signed_unchecked_scalar_minmax(params, 2, executor, std::cmp::max::<i128>);
    }

    fn integer_signed_smart_scalar_min_parallelized_i128(
        params: crate::shortint::ClassicPBSParameters,
    ) {
        let executor = CpuFunctionExecutor::new(&ServerKey::smart_scalar_min_parallelized);
        test_signed_smart_scalar_minmax(params, 2, executor, std::cmp::min::<i128>);
    }

    fn integer_signed_smart_scalar_max_parallelized_i128(
        params: crate::shortint::ClassicPBSParameters,
    ) {
        let executor = CpuFunctionExecutor::new(&ServerKey::smart_scalar_max_parallelized);
        test_signed_smart_scalar_minmax(params, 2, executor, std::cmp::max::<i128>);
    }

    fn integer_signed_scalar_min_parallelized_i128(params: crate::shortint::ClassicPBSParameters) {
        let executor = CpuFunctionExecutor::new(&ServerKey::scalar_min_parallelized);
        test_signed_default_scalar_minmax(params, 2, executor, std::cmp::min::<i128>);
    }

    fn integer_signed_scalar_max_parallelized_i128(params: crate::shortint::ClassicPBSParameters) {
        let executor = CpuFunctionExecutor::new(&ServerKey::scalar_max_parallelized);
        test_signed_default_scalar_minmax(params, 2, executor, std::cmp::max::<i128>);
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
    use crate::integer::tests::create_parametrized_test_classical_params;

    fn integer_signed_unchecked_scalar_min_parallelized_i8(
        params: crate::shortint::ClassicPBSParameters,
    ) {
        let executor = CpuFunctionExecutor::new(&ServerKey::unchecked_scalar_min_parallelized);
        test_signed_unchecked_scalar_minmax(params, 1, executor, std::cmp::min::<i8>);
    }

    fn integer_signed_unchecked_scalar_max_parallelized_i8(
        params: crate::shortint::ClassicPBSParameters,
    ) {
        let executor = CpuFunctionExecutor::new(&ServerKey::unchecked_scalar_max_parallelized);
        test_signed_unchecked_scalar_minmax(params, 1, executor, std::cmp::max::<i8>);
    }
    fn integer_signed_smart_scalar_min_parallelized_i8(
        params: crate::shortint::ClassicPBSParameters,
    ) {
        let executor = CpuFunctionExecutor::new(&ServerKey::smart_scalar_min_parallelized);
        test_signed_smart_scalar_minmax(params, 1, executor, std::cmp::min::<i8>);
    }

    fn integer_signed_smart_scalar_max_parallelized_i8(
        params: crate::shortint::ClassicPBSParameters,
    ) {
        let executor = CpuFunctionExecutor::new(&ServerKey::smart_scalar_max_parallelized);
        test_signed_smart_scalar_minmax(params, 1, executor, std::cmp::max::<i8>);
    }

    fn integer_signed_scalar_min_parallelized_i8(params: crate::shortint::ClassicPBSParameters) {
        let executor = CpuFunctionExecutor::new(&ServerKey::scalar_min_parallelized);
        test_signed_default_scalar_minmax(params, 1, executor, std::cmp::min::<i8>);
    }

    fn integer_signed_scalar_max_parallelized_i8(params: crate::shortint::ClassicPBSParameters) {
        let executor = CpuFunctionExecutor::new(&ServerKey::scalar_max_parallelized);
        test_signed_default_scalar_minmax(params, 1, executor, std::cmp::max::<i8>);
    }

    create_parametrized_test_classical_params!(integer_signed_unchecked_scalar_min_parallelized_i8);
    create_parametrized_test_classical_params!(integer_signed_unchecked_scalar_max_parallelized_i8);
    create_parametrized_test_classical_params!(integer_signed_smart_scalar_min_parallelized_i8);
    create_parametrized_test_classical_params!(integer_signed_smart_scalar_max_parallelized_i8);
    create_parametrized_test_classical_params!(integer_signed_scalar_min_parallelized_i8);
    create_parametrized_test_classical_params!(integer_signed_scalar_max_parallelized_i8);

    define_signed_scalar_comparison_test_functions!(eq, i8);
    define_signed_scalar_comparison_test_functions!(ne, i8);
    define_signed_scalar_comparison_test_functions!(lt, i8);
    define_signed_scalar_comparison_test_functions!(le, i8);
    define_signed_scalar_comparison_test_functions!(gt, i8);
    define_signed_scalar_comparison_test_functions!(ge, i8);

    create_parametrized_test_classical_params!(integer_signed_is_scalar_out_of_bounds);
}
