use crate::core_crypto::prelude::UnsignedNumeric;
use crate::integer::block_decomposition::{DecomposableInto, RecomposableFrom};
use crate::integer::ciphertext::RadixCiphertext;
use crate::integer::keycache::KEY_CACHE;
use crate::integer::server_key::radix_parallel::tests_cases_unsigned::FunctionExecutor;
use crate::integer::server_key::radix_parallel::tests_unsigned::{CpuFunctionExecutor, NB_CTXT};
use crate::integer::tests::create_parameterized_test;
use crate::integer::{BooleanBlock, IntegerKeyKind, RadixClientKey, ServerKey, I256, U256};
#[cfg(tarpaulin)]
use crate::shortint::parameters::coverage_parameters::*;
use crate::shortint::parameters::test_params::*;
use crate::shortint::parameters::*;
use rand::distributions::Standard;
use rand::prelude::*;
use std::ops::AddAssign;
use std::sync::Arc;

/// Function to test an "unchecked_scalar" comparator function.
///
/// This calls the `unchecked_scalar_server_key_method` with fresh ciphertexts
/// and compares that it gives the same results as the `clear_fn`.
pub(crate) fn test_unchecked_scalar_function<P, T, ClearF, Scalar>(
    param: P,
    num_test: usize,
    mut executor: T,
    clear_fn: ClearF,
) where
    P: Into<TestParameters>,
    Scalar: UnsignedNumeric + DecomposableInto<u64> + RecomposableFrom<u64> + From<bool>,
    T: for<'a> FunctionExecutor<(&'a RadixCiphertext, Scalar), BooleanBlock>,
    ClearF: Fn(Scalar, Scalar) -> Scalar,
    Standard: Distribution<Scalar>,
{
    let mut rng = rand::rng();

    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let num_block = Scalar::BITS.div_ceil(cks.parameters().message_modulus().0.ilog2() as usize);
    let sks = Arc::new(sks);
    let cks = RadixClientKey::from((cks, num_block));

    executor.setup(&cks, sks);

    for _ in 0..num_test {
        let clear_a = rng.gen::<Scalar>();
        let clear_b = rng.gen::<Scalar>();

        let a = cks.encrypt(clear_a);

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
pub(crate) fn test_smart_scalar_function<P, T, ClearF, Scalar>(
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
    T: for<'a> FunctionExecutor<(&'a mut RadixCiphertext, Scalar), BooleanBlock>,
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

    let mut rng = rand::rng();

    let sks = Arc::new(sks);
    let cks = RadixClientKey::from((cks, num_block));

    executor.setup(&cks, sks.clone());

    for _ in 0..num_test {
        let mut clear_0 = rng.gen::<Scalar>();
        let clear_1 = rng.gen::<Scalar>();
        let mut ct_0 = cks.encrypt(clear_0);

        // Raise the degree, so as to ensure worst case path in operations
        while ct_0.block_carries_are_empty() {
            let clear_2 = rng.gen::<Scalar>();
            let ct_2 = cks.encrypt(clear_2);
            sks.unchecked_add_assign(&mut ct_0, &ct_2);
            clear_0 += clear_2;
        }

        // Sanity decryption checks
        {
            let a: Scalar = cks.decrypt(&ct_0);
            assert_eq!(a, clear_0);
        }

        assert!(!ct_0.block_carries_are_empty());
        let encrypted_result = executor.execute((&mut ct_0, clear_1));

        // Sanity decryption checks
        {
            let a: Scalar = cks.decrypt(&ct_0);
            assert_eq!(a, clear_0);
        }

        let decrypted_result: Scalar = cks.decrypt_bool(&encrypted_result).into();

        let expected_result = clear_fn(clear_0, clear_1);
        assert_eq!(decrypted_result, expected_result);
    }
}

/// Function to test a "default_scalar" server_key function.
pub(crate) fn test_default_scalar_function<P, T, ClearF, Scalar>(
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
    T: for<'a> FunctionExecutor<(&'a RadixCiphertext, Scalar), BooleanBlock>,
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

    let mut rng = rand::rng();

    let sks = Arc::new(sks);
    let cks = RadixClientKey::from((cks, num_block));

    executor.setup(&cks, sks.clone());

    for _ in 0..num_test {
        let mut clear_0 = rng.gen::<Scalar>();
        let clear_1 = rng.gen::<Scalar>();

        let mut ct_0 = cks.encrypt(clear_0);

        // Raise the degree, so as to ensure worst case path in operations
        while ct_0.block_carries_are_empty() {
            let clear_2 = rng.gen::<Scalar>();
            let ct_2 = cks.encrypt(clear_2);
            sks.unchecked_add_assign(&mut ct_0, &ct_2);
            clear_0 += clear_2;
        }

        // Sanity decryption checks
        {
            let a: Scalar = cks.decrypt(&ct_0);
            assert_eq!(a, clear_0);
        }

        assert!(!ct_0.block_carries_are_empty());
        let encrypted_result = executor.execute((&ct_0, clear_1));

        // Sanity decryption checks
        {
            let a: Scalar = cks.decrypt(&ct_0);
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
macro_rules! define_scalar_comparison_test_functions {
    ($comparison_name:ident, $clear_type:ty) => {
        ::paste::paste!{
            fn [<integer_unchecked_scalar_ $comparison_name _parallelized_ $clear_type:lower>]<P>(param: P) where P: Into<TestParameters>{
                let num_tests = 1;
                let executor = CpuFunctionExecutor::new(&ServerKey::[<unchecked_scalar_ $comparison_name _parallelized>]);
                test_unchecked_scalar_function(
                    param,
                    num_tests,
                    executor,
                    |lhs, rhs| $clear_type::from(<$clear_type>::$comparison_name(&lhs, &rhs)),
                )
            }

            fn [<integer_smart_scalar_ $comparison_name _parallelized_ $clear_type:lower>]<P>(param: P) where P: Into<TestParameters>{
                let num_tests = 1;
                let executor = CpuFunctionExecutor::new(&ServerKey::[<smart_scalar_ $comparison_name _parallelized>]);
                test_smart_scalar_function(
                    param,
                    num_tests,
                    executor,
                    |lhs, rhs| $clear_type::from(<$clear_type>::$comparison_name(&lhs, &rhs)),
                )
            }

            fn [<integer_default_scalar_ $comparison_name _parallelized_ $clear_type:lower>]<P>(param: P) where P: Into<TestParameters>{
                let num_tests = 1;
                let executor = CpuFunctionExecutor::new(&ServerKey::[<scalar_ $comparison_name _parallelized>]);
                test_default_scalar_function(
                    param,
                    num_tests,
                    executor,
                    |lhs, rhs| $clear_type::from(<$clear_type>::$comparison_name(&lhs, &rhs)),
                )
            }

            create_parameterized_test!([<integer_unchecked_scalar_ $comparison_name _parallelized_ $clear_type:lower>]
            {

                TEST_PARAM_MESSAGE_1_CARRY_1_KS_PBS_GAUSSIAN_2M128,

                PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,

                TEST_PARAM_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M128,

                // 2M128 is too slow for 4_4, it is estimated to be 2x slower
                TEST_PARAM_MESSAGE_4_CARRY_4_KS_PBS_GAUSSIAN_2M64,
                #[cfg(tarpaulin)]
                COVERAGE_PARAM_MESSAGE_2_CARRY_2_KS_PBS
            });

            create_parameterized_test!([<integer_smart_scalar_ $comparison_name _parallelized_ $clear_type:lower>]
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

            create_parameterized_test!([<integer_default_scalar_ $comparison_name _parallelized_ $clear_type:lower>]
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

/// The goal of this function is to ensure that scalar comparisons
/// work when the scalar type used is either bigger or smaller (in bit size)
/// compared to the ciphertext
fn integer_unchecked_scalar_comparisons_edge(param: ClassicPBSParameters) {
    let mut rng = rand::rng();

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

fn integer_unchecked_scalar_comparisons_edge_one_block(param: ClassicPBSParameters) {
    let mut rng = rand::rng();

    let num_block = 1;

    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let message_modulus = cks.parameters().message_modulus().0;

    for _ in 0..4 {
        let clear_a = rng.gen_range(0..message_modulus);
        let clear_b = rng.gen_range(0..message_modulus);

        let a = cks.encrypt_radix(clear_a, num_block);

        // >=
        {
            let result = sks.unchecked_scalar_ge_parallelized(&a, clear_b);
            let decrypted = cks.decrypt_bool(&result);
            assert_eq!(decrypted, clear_a >= clear_b);
        }

        // >
        {
            let result = sks.unchecked_scalar_gt_parallelized(&a, clear_b);
            let decrypted = cks.decrypt_bool(&result);
            assert_eq!(decrypted, clear_a > clear_b);
        }

        // <=
        {
            let result = sks.unchecked_scalar_le_parallelized(&a, clear_b);
            let decrypted = cks.decrypt_bool(&result);
            assert_eq!(decrypted, clear_a <= clear_b);
        }

        // <
        {
            let result = sks.unchecked_scalar_lt_parallelized(&a, clear_b);
            let decrypted = cks.decrypt_bool(&result);
            assert_eq!(decrypted, clear_a < clear_b);
        }

        // ==
        {
            let result = sks.unchecked_scalar_eq_parallelized(&a, clear_b);
            let decrypted = cks.decrypt_bool(&result);
            assert_eq!(decrypted, clear_a == clear_b);
        }

        // !=
        {
            let result = sks.unchecked_scalar_ne_parallelized(&a, clear_b);
            let decrypted = cks.decrypt_bool(&result);
            assert_eq!(decrypted, clear_a != clear_b);
        }

        // Here the goal is to test, the branching
        // made in the scalar sign function
        //
        // We are forcing one of the two branches to work on empty slices
        {
            let result = sks.unchecked_scalar_lt_parallelized(&a, 0);
            let decrypted = cks.decrypt_bool(&result);
            assert!(!decrypted);

            let result = sks.unchecked_scalar_lt_parallelized(&a, message_modulus);
            let decrypted = cks.decrypt_bool(&result);
            assert_eq!(decrypted, clear_a < message_modulus);

            // == (as it does not share same code)
            let result = sks.unchecked_scalar_eq_parallelized(&a, 0);
            let decrypted = cks.decrypt_bool(&result);
            assert_eq!(decrypted, clear_a == 0);

            // != (as it does not share same code)
            let result = sks.unchecked_scalar_ne_parallelized(&a, message_modulus);
            let decrypted = cks.decrypt_bool(&result);
            assert_eq!(decrypted, clear_a != message_modulus);
        }
    }
}

// Given a ciphertext that consists of empty blocks,
// the function tests whether comparisons still hold.
fn integer_comparisons_for_empty_blocks(param: ClassicPBSParameters) {
    let mut rng = rand::rng();
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);

    let scalar = rng.gen::<u64>();
    let ct: RadixCiphertext = sks.create_trivial_radix(scalar, 0);

    {
        let result = sks.unchecked_scalar_ge_parallelized(&ct, scalar);
        let decrypted = cks.decrypt_bool(&result);
        // Scalar is u64, so it can't be smaller than 0
        assert_eq!(decrypted, 0 == scalar);
    }

    {
        let result = sks.unchecked_scalar_le_parallelized(&ct, scalar);
        let decrypted = cks.decrypt_bool(&result);
        assert!(decrypted);
    }

    {
        let result = sks.unchecked_scalar_gt_parallelized(&ct, scalar);
        let decrypted = cks.decrypt_bool(&result);
        assert!(!decrypted);
    }

    {
        let result = sks.unchecked_scalar_lt_parallelized(&ct, scalar);
        let decrypted = cks.decrypt_bool(&result);
        assert_eq!(decrypted, 0 < scalar);
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
        assert_eq!(res, std::cmp::Ordering::Equal);

        let scalar = U256::from(u128::MAX) + U256::ONE;
        let res = sks.is_scalar_out_of_bounds(&ct, scalar);
        assert_eq!(res, std::cmp::Ordering::Greater);

        let scalar = U256::from(u128::MAX) + U256::from(rng.gen_range(2u128..=u128::MAX));
        let res = sks.is_scalar_out_of_bounds(&ct, scalar);
        assert_eq!(res, std::cmp::Ordering::Greater);

        let scalar = U256::from(u128::MAX) + U256::from(u128::MAX);
        let res = sks.is_scalar_out_of_bounds(&ct, scalar);
        assert_eq!(res, std::cmp::Ordering::Greater);
    }

    // Negative scalars
    {
        let res = sks.is_scalar_out_of_bounds(&ct, -1i128);
        assert_eq!(res, std::cmp::Ordering::Less);

        let scalar = I256::from(i128::MIN) - I256::ONE;
        let res = sks.is_scalar_out_of_bounds(&ct, scalar);
        assert_eq!(res, std::cmp::Ordering::Less);

        let scalar = I256::from(i128::MIN) + I256::from(rng.gen_range(i128::MIN..=-2));
        let res = sks.is_scalar_out_of_bounds(&ct, scalar);
        assert_eq!(res, std::cmp::Ordering::Less);

        let scalar = I256::from(i128::MIN) + I256::from(i128::MIN);
        let res = sks.is_scalar_out_of_bounds(&ct, scalar);
        assert_eq!(res, std::cmp::Ordering::Less);

        let scalar = I256::from(i128::MIN) - I256::from(rng.gen_range(2..=i128::MAX));
        let res = sks.is_scalar_out_of_bounds(&ct, scalar);
        assert_eq!(res, std::cmp::Ordering::Less);

        let scalar = I256::from(i128::MIN) - I256::from(i128::MAX);
        let res = sks.is_scalar_out_of_bounds(&ct, scalar);
        assert_eq!(res, std::cmp::Ordering::Less);
    }

    // Negative scalar
    {
        // Case where scalar will have less blocks when decomposed than
        // the ciphertext has
        let bigger_ct = cks.encrypt_signed_radix(-1i128, num_block);
        let scalar = i64::MIN;
        let res = sks.is_scalar_out_of_bounds(&bigger_ct, scalar);
        assert_eq!(res, std::cmp::Ordering::Equal);
    }
}

/// Function to test an "unchecked_scalar" min or max function.
///
/// This calls the `unchecked_scalar_server_key_method` with fresh ciphertexts
/// and compares that it gives the same results as the `clear_fn`.
pub(crate) fn test_unchecked_scalar_minmax<P, T, ClearF, Scalar>(
    param: P,
    num_test: usize,
    mut executor: T,
    clear_fn: ClearF,
) where
    P: Into<TestParameters>,
    Scalar: UnsignedNumeric + DecomposableInto<u64> + RecomposableFrom<u64>,
    T: for<'a> FunctionExecutor<(&'a RadixCiphertext, Scalar), RadixCiphertext>,
    ClearF: Fn(Scalar, Scalar) -> Scalar,
    Standard: Distribution<Scalar>,
{
    let mut rng = rand::rng();

    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let num_block = Scalar::BITS.div_ceil(cks.parameters().message_modulus().0.ilog2() as usize);
    let sks = Arc::new(sks);
    let cks = RadixClientKey::from((cks, num_block));

    executor.setup(&cks, sks);

    for _ in 0..num_test {
        let clear_a = rng.gen::<Scalar>();
        let clear_b = rng.gen::<Scalar>();

        let a = cks.encrypt(clear_a);

        {
            let result = executor.execute((&a, clear_b));
            let decrypted: Scalar = cks.decrypt(&result);
            let expected_result = clear_fn(clear_a, clear_b);
            assert_eq!(decrypted, expected_result);
        }

        {
            // Force case where lhs == rhs
            let result = executor.execute((&a, clear_a));
            let decrypted: Scalar = cks.decrypt(&result);
            let expected_result = clear_fn(clear_a, clear_a);
            assert_eq!(decrypted, expected_result);
        }
    }
}

/// Function to test a "smart_scalar" server_key function.
pub(crate) fn test_smart_scalar_minmax<P, T, ClearF, Scalar>(
    param: P,
    num_test: usize,
    mut executor: T,
    clear_fn: ClearF,
) where
    P: Into<TestParameters>,
    Scalar: UnsignedNumeric + AddAssign<Scalar> + DecomposableInto<u64> + RecomposableFrom<u64>,
    T: for<'a> FunctionExecutor<(&'a mut RadixCiphertext, Scalar), RadixCiphertext>,
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

    let mut rng = rand::rng();

    let sks = Arc::new(sks);
    let cks = RadixClientKey::from((cks, num_block));

    executor.setup(&cks, sks.clone());

    for _ in 0..num_test {
        let mut clear_0 = rng.gen::<Scalar>();
        let clear_1 = rng.gen::<Scalar>();
        let mut ct_0 = cks.encrypt(clear_0);

        // Raise the degree, so as to ensure worst case path in operations
        while ct_0.block_carries_are_empty() {
            let clear_2 = rng.gen::<Scalar>();
            let ct_2 = cks.encrypt(clear_2);
            sks.unchecked_add_assign(&mut ct_0, &ct_2);
            clear_0 += clear_2;
        }

        // Sanity decryption checks
        {
            let a: Scalar = cks.decrypt(&ct_0);
            assert_eq!(a, clear_0);
        }

        assert!(!ct_0.block_carries_are_empty());
        let encrypted_result = executor.execute((&mut ct_0, clear_1));

        // Sanity decryption checks
        {
            let a: Scalar = cks.decrypt(&ct_0);
            assert_eq!(a, clear_0);
        }

        let decrypted_result: Scalar = cks.decrypt(&encrypted_result);

        let expected_result = clear_fn(clear_0, clear_1);
        assert_eq!(decrypted_result, expected_result);
    }
}

/// Function to test a "default_scalar" server_key function.
pub(crate) fn test_default_scalar_minmax<P, T, ClearF, Scalar>(
    param: P,
    num_test: usize,
    mut executor: T,
    clear_fn: ClearF,
) where
    P: Into<TestParameters>,
    Scalar: UnsignedNumeric + AddAssign<Scalar> + DecomposableInto<u64> + RecomposableFrom<u64>,
    T: for<'a> FunctionExecutor<(&'a RadixCiphertext, Scalar), RadixCiphertext>,
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

    let mut rng = rand::rng();

    let sks = Arc::new(sks);
    let cks = RadixClientKey::from((cks, num_block));

    executor.setup(&cks, sks.clone());

    for _ in 0..num_test {
        let mut clear_0 = rng.gen::<Scalar>();
        let clear_1 = rng.gen::<Scalar>();

        let mut ct_0 = cks.encrypt(clear_0);

        // Raise the degree, so as to ensure worst case path in operations
        while ct_0.block_carries_are_empty() {
            let clear_2 = rng.gen::<Scalar>();
            let ct_2 = cks.encrypt(clear_2);
            sks.unchecked_add_assign(&mut ct_0, &ct_2);
            clear_0 += clear_2;
        }

        // Sanity decryption checks
        {
            let a: Scalar = cks.decrypt(&ct_0);
            assert_eq!(a, clear_0);
        }

        assert!(!ct_0.block_carries_are_empty());
        let encrypted_result = executor.execute((&ct_0, clear_1));

        // Sanity decryption checks
        {
            let a: Scalar = cks.decrypt(&ct_0);
            assert_eq!(a, clear_0);
        }

        let decrypted_result: Scalar = cks.decrypt(&encrypted_result);

        let expected_result = clear_fn(clear_0, clear_1);
        assert_eq!(decrypted_result, expected_result);
    }
}

#[cfg(not(tarpaulin))]
mod no_coverage {
    use super::*;

    fn integer_unchecked_scalar_min_parallelized_u256(
        params: crate::shortint::ClassicPBSParameters,
    ) {
        let executor = CpuFunctionExecutor::new(&ServerKey::unchecked_scalar_min_parallelized);
        test_unchecked_scalar_minmax(params, 2, executor, std::cmp::min::<U256>);
    }

    fn integer_unchecked_scalar_max_parallelized_u256(
        params: crate::shortint::ClassicPBSParameters,
    ) {
        let executor = CpuFunctionExecutor::new(&ServerKey::unchecked_scalar_max_parallelized);
        test_unchecked_scalar_minmax(params, 2, executor, std::cmp::max::<U256>);
    }

    fn integer_smart_scalar_min_parallelized_u256(params: crate::shortint::ClassicPBSParameters) {
        let executor = CpuFunctionExecutor::new(&ServerKey::smart_scalar_min_parallelized);
        test_smart_scalar_minmax(params, 2, executor, std::cmp::min::<U256>);
    }

    fn integer_smart_scalar_max_parallelized_u256(params: crate::shortint::ClassicPBSParameters) {
        let executor = CpuFunctionExecutor::new(&ServerKey::smart_scalar_max_parallelized);
        test_smart_scalar_minmax(params, 2, executor, std::cmp::max::<U256>);
    }

    fn integer_scalar_min_parallelized_u256(params: crate::shortint::ClassicPBSParameters) {
        let executor = CpuFunctionExecutor::new(&ServerKey::scalar_min_parallelized);
        test_default_scalar_minmax(params, 2, executor, std::cmp::min::<U256>);
    }

    fn integer_scalar_max_parallelized_u256(params: crate::shortint::ClassicPBSParameters) {
        let executor = CpuFunctionExecutor::new(&ServerKey::scalar_max_parallelized);
        test_default_scalar_minmax(params, 2, executor, std::cmp::max::<U256>);
    }

    create_parameterized_test!(integer_unchecked_scalar_min_parallelized_u256 {
        TEST_PARAM_MESSAGE_1_CARRY_1_KS_PBS_GAUSSIAN_2M128,
        PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        TEST_PARAM_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M128,
        // 2M128 is too slow for 4_4, it is estimated to be 2x slower
        TEST_PARAM_MESSAGE_4_CARRY_4_KS_PBS_GAUSSIAN_2M64
    });
    create_parameterized_test!(integer_unchecked_scalar_max_parallelized_u256 {
        TEST_PARAM_MESSAGE_1_CARRY_1_KS_PBS_GAUSSIAN_2M128,
        PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        TEST_PARAM_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M128,
        // 2M128 is too slow for 4_4, it is estimated to be 2x slower
        TEST_PARAM_MESSAGE_4_CARRY_4_KS_PBS_GAUSSIAN_2M64
    });
    create_parameterized_test!(integer_smart_scalar_min_parallelized_u256 {
        TEST_PARAM_MESSAGE_1_CARRY_1_KS_PBS_GAUSSIAN_2M128,
        PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        // No test for 3_3, see define_scalar_comparison_test_functions macro
        // 2M128 is too slow for 4_4, it is estimated to be 2x slower
        TEST_PARAM_MESSAGE_4_CARRY_4_KS_PBS_GAUSSIAN_2M64
    });
    create_parameterized_test!(integer_smart_scalar_max_parallelized_u256 {
        TEST_PARAM_MESSAGE_1_CARRY_1_KS_PBS_GAUSSIAN_2M128,
        PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        // No test for 3_3, see define_scalar_comparison_test_functions macro
        // 2M128 is too slow for 4_4, it is estimated to be 2x slower
        TEST_PARAM_MESSAGE_4_CARRY_4_KS_PBS_GAUSSIAN_2M64
    });

    create_parameterized_test!(integer_scalar_min_parallelized_u256 {
        TEST_PARAM_MESSAGE_1_CARRY_1_KS_PBS_GAUSSIAN_2M128,
        PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        // No test for 3_3, see define_scalar_comparison_test_functions macro
        // 2M128 is too slow for 4_4, it is estimated to be 2x slower
        TEST_PARAM_MESSAGE_4_CARRY_4_KS_PBS_GAUSSIAN_2M64
    });
    create_parameterized_test!(integer_scalar_max_parallelized_u256 {
        TEST_PARAM_MESSAGE_1_CARRY_1_KS_PBS_GAUSSIAN_2M128,
        PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        // No test for 3_3, see define_scalar_comparison_test_functions macro
        // 2M128 is too slow for 4_4, it is estimated to be 2x slower
        TEST_PARAM_MESSAGE_4_CARRY_4_KS_PBS_GAUSSIAN_2M64
    });

    define_scalar_comparison_test_functions!(eq, U256);
    define_scalar_comparison_test_functions!(ne, U256);
    define_scalar_comparison_test_functions!(lt, U256);
    define_scalar_comparison_test_functions!(le, U256);
    define_scalar_comparison_test_functions!(gt, U256);
    define_scalar_comparison_test_functions!(ge, U256);

    create_parameterized_test!(integer_unchecked_scalar_comparisons_edge {
        TEST_PARAM_MESSAGE_1_CARRY_1_KS_PBS_GAUSSIAN_2M128,
        PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        TEST_PARAM_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M128,
        // 2M128 is too slow for 4_4, it is estimated to be 2x slower
        TEST_PARAM_MESSAGE_4_CARRY_4_KS_PBS_GAUSSIAN_2M64
    });

    create_parameterized_test!(integer_unchecked_scalar_comparisons_edge_one_block {
        TEST_PARAM_MESSAGE_1_CARRY_1_KS_PBS_GAUSSIAN_2M128,
        PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        TEST_PARAM_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M128,
        // 2M128 is too slow for 4_4, it is estimated to be 2x slower
        TEST_PARAM_MESSAGE_4_CARRY_4_KS_PBS_GAUSSIAN_2M64
    });

    create_parameterized_test!(integer_is_scalar_out_of_bounds {
        PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        // We don't use PARAM_MESSAGE_3_CARRY_3_KS_PBS,
        // as the test relies on the ciphertext to encrypt 128bits
        // but with param 3_3 we actually encrypt more that 128bits
        // 2M128 is too slow for 4_4, it is estimated to be 2x slower
        TEST_PARAM_MESSAGE_4_CARRY_4_KS_PBS_GAUSSIAN_2M64
    });

    create_parameterized_test!(integer_comparisons_for_empty_blocks {
        TEST_PARAM_MESSAGE_1_CARRY_1_KS_PBS_GAUSSIAN_2M128,
        PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        TEST_PARAM_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M128,
        // 2M128 is too slow for 4_4, it is estimated to be 2x slower
        TEST_PARAM_MESSAGE_4_CARRY_4_KS_PBS_GAUSSIAN_2M64,
    });
}

// Smaller integers are used in coverage to speed-up execution.
#[cfg(tarpaulin)]
mod coverage {
    use super::*;
    use crate::integer::tests::create_parameterized_test_classical_params;

    fn integer_unchecked_scalar_min_parallelized_u8(params: crate::shortint::ClassicPBSParameters) {
        let executor = CpuFunctionExecutor::new(&ServerKey::unchecked_scalar_min_parallelized);
        test_unchecked_scalar_minmax(params, 1, executor, std::cmp::min::<u8>);
    }

    fn integer_unchecked_scalar_max_parallelized_u8(params: crate::shortint::ClassicPBSParameters) {
        let executor = CpuFunctionExecutor::new(&ServerKey::unchecked_scalar_max_parallelized);
        test_unchecked_scalar_minmax(params, 1, executor, std::cmp::max::<u8>);
    }

    fn integer_smart_scalar_min_parallelized_u8(params: crate::shortint::ClassicPBSParameters) {
        let executor = CpuFunctionExecutor::new(&ServerKey::smart_scalar_min_parallelized);
        test_smart_scalar_minmax(params, 1, executor, std::cmp::min::<u8>);
    }

    fn integer_smart_scalar_max_parallelized_u8(params: crate::shortint::ClassicPBSParameters) {
        let executor = CpuFunctionExecutor::new(&ServerKey::smart_scalar_max_parallelized);
        test_smart_scalar_minmax(params, 1, executor, std::cmp::max::<u8>);
    }

    fn integer_scalar_min_parallelized_u8(params: crate::shortint::ClassicPBSParameters) {
        let executor = CpuFunctionExecutor::new(&ServerKey::scalar_min_parallelized);
        test_default_scalar_minmax(params, 1, executor, std::cmp::min::<u8>);
    }

    fn integer_scalar_max_parallelized_u8(params: crate::shortint::ClassicPBSParameters) {
        let executor = CpuFunctionExecutor::new(&ServerKey::scalar_max_parallelized);
        test_default_scalar_minmax(params, 1, executor, std::cmp::max::<u8>);
    }

    create_parameterized_test_classical_params!(integer_unchecked_scalar_min_parallelized_u8);
    create_parameterized_test_classical_params!(integer_unchecked_scalar_max_parallelized_u8);
    create_parameterized_test_classical_params!(integer_smart_scalar_min_parallelized_u8);
    create_parameterized_test_classical_params!(integer_smart_scalar_max_parallelized_u8);
    create_parameterized_test_classical_params!(integer_scalar_min_parallelized_u8);
    create_parameterized_test_classical_params!(integer_scalar_max_parallelized_u8);

    define_scalar_comparison_test_functions!(eq, u8);
    define_scalar_comparison_test_functions!(ne, u8);
    define_scalar_comparison_test_functions!(lt, u8);
    define_scalar_comparison_test_functions!(le, u8);
    define_scalar_comparison_test_functions!(gt, u8);
    define_scalar_comparison_test_functions!(ge, u8);

    create_parameterized_test_classical_params!(integer_unchecked_scalar_comparisons_edge);

    create_parameterized_test_classical_params!(integer_is_scalar_out_of_bounds);

    create_parameterized_test_classical_params!(integer_comparisons_for_empty_blocks);
}

create_parameterized_test!(integer_extensive_trivial_default_scalar_comparisons);

fn integer_extensive_trivial_default_scalar_comparisons(params: impl Into<TestParameters>) {
    let lt_executor = CpuFunctionExecutor::new(&ServerKey::scalar_lt_parallelized);
    let le_executor = CpuFunctionExecutor::new(&ServerKey::scalar_le_parallelized);
    let gt_executor = CpuFunctionExecutor::new(&ServerKey::scalar_gt_parallelized);
    let ge_executor = CpuFunctionExecutor::new(&ServerKey::scalar_ge_parallelized);
    let min_executor = CpuFunctionExecutor::new(&ServerKey::scalar_min_parallelized);
    let max_executor = CpuFunctionExecutor::new(&ServerKey::scalar_max_parallelized);

    extensive_trivial_default_scalar_comparisons_test(
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
pub(crate) fn extensive_trivial_default_scalar_comparisons_test<P, E1, E2, E3, E4, E5, E6>(
    param: P,
    mut lt_executor: E1,
    mut le_executor: E2,
    mut gt_executor: E3,
    mut ge_executor: E4,
    mut min_executor: E5,
    mut max_executor: E6,
) where
    P: Into<TestParameters>,
    E1: for<'a> FunctionExecutor<(&'a RadixCiphertext, u128), BooleanBlock>,
    E2: for<'a> FunctionExecutor<(&'a RadixCiphertext, u128), BooleanBlock>,
    E3: for<'a> FunctionExecutor<(&'a RadixCiphertext, u128), BooleanBlock>,
    E4: for<'a> FunctionExecutor<(&'a RadixCiphertext, u128), BooleanBlock>,
    E5: for<'a> FunctionExecutor<(&'a RadixCiphertext, u128), RadixCiphertext>,
    E6: for<'a> FunctionExecutor<(&'a RadixCiphertext, u128), RadixCiphertext>,
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
        println!("num_blocks: {num_blocks}");
        let Some(modulus) = (params.message_modulus().0 as u128).checked_pow(num_blocks as u32)
        else {
            break;
        };
        for _ in 0..25 {
            let clear_a = rng.gen_range(0..modulus);
            let clear_b = rng.gen_range(0..modulus);

            let a: RadixCiphertext = sks.create_trivial_radix(clear_a, num_blocks);

            {
                let result = lt_executor.execute((&a, clear_b));
                let result = cks.decrypt_bool(&result);
                assert_eq!(result, clear_a < clear_b, "{clear_a} < {clear_b}");

                let result = lt_executor.execute((&a, clear_a));
                let result = cks.decrypt_bool(&result);
                assert_eq!(result, clear_a < clear_a, "{clear_a} < {clear_a}");
            }

            {
                let result = le_executor.execute((&a, clear_b));
                let result = cks.decrypt_bool(&result);
                assert_eq!(result, clear_a <= clear_b, "{clear_a} <= {clear_b}");

                let result = le_executor.execute((&a, clear_a));
                let result = cks.decrypt_bool(&result);
                assert_eq!(result, clear_a <= clear_a, "{clear_a} <= {clear_a}");
            }

            {
                let result = gt_executor.execute((&a, clear_b));
                let result = cks.decrypt_bool(&result);
                assert_eq!(result, clear_a > clear_b, "{clear_a} > {clear_b}");

                let result = gt_executor.execute((&a, clear_a));
                let result = cks.decrypt_bool(&result);
                assert_eq!(result, clear_a > clear_a, "{clear_a} > {clear_a}");
            }

            {
                let result = ge_executor.execute((&a, clear_b));
                let result = cks.decrypt_bool(&result);
                assert_eq!(result, clear_a >= clear_b, "{clear_a} >= {clear_b}");

                let result = ge_executor.execute((&a, clear_a));
                let result = cks.decrypt_bool(&result);
                assert_eq!(result, clear_a >= clear_a, "{clear_a} >= {clear_a}");
            }

            {
                let result = min_executor.execute((&a, clear_b));
                let result: u128 = cks.decrypt(&result);
                assert_eq!(result, clear_a.min(clear_b), "{clear_a}.min({clear_b})");

                let result = min_executor.execute((&a, clear_a));
                let result: u128 = cks.decrypt(&result);
                assert_eq!(result, clear_a.min(clear_a), "{clear_a}.min({clear_a})");
            }

            {
                let result = max_executor.execute((&a, clear_b));
                let result: u128 = cks.decrypt(&result);
                assert_eq!(result, clear_a.max(clear_b), "{clear_a}.max({clear_b})");

                let result = max_executor.execute((&a, clear_a));
                let result: u128 = cks.decrypt(&result);
                assert_eq!(result, clear_a.max(clear_a), "{clear_a}.max({clear_a})");
            }
        }
    }
}
