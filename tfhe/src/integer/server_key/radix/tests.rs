use crate::integer::keycache::KEY_CACHE;
use crate::integer::server_key::radix_parallel::tests_cases_unsigned::*;
use crate::integer::server_key::radix_parallel::tests_unsigned::test_add::smart_add_test;
use crate::integer::server_key::radix_parallel::tests_unsigned::test_comparison::test_unchecked_minmax;
use crate::integer::server_key::radix_parallel::tests_unsigned::test_neg::smart_neg_test;
use crate::integer::server_key::radix_parallel::tests_unsigned::test_slice::{
    default_scalar_bitslice_assign_test, default_scalar_bitslice_test,
    scalar_blockslice_assign_test, scalar_blockslice_test, smart_scalar_bitslice_assign_test,
    smart_scalar_bitslice_test, unchecked_scalar_bitslice_assign_test,
    unchecked_scalar_bitslice_test,
};
use crate::integer::server_key::radix_parallel::tests_unsigned::test_sub::{
    default_overflowing_sub_test, smart_sub_test,
};
use crate::integer::server_key::radix_parallel::tests_unsigned::CpuFunctionExecutor;
use crate::integer::tests::{
    create_parameterized_test, create_parameterized_test_classical_params,
};
use crate::integer::{IntegerKeyKind, RadixCiphertext, ServerKey, SignedRadixCiphertext, U256};
#[cfg(tarpaulin)]
use crate::shortint::parameters::coverage_parameters::*;
use crate::shortint::parameters::test_params::*;
use crate::shortint::parameters::*;
use rand::Rng;

/// Number of loop iteration within randomized tests
#[cfg(not(tarpaulin))]
pub(crate) const NB_TESTS: usize = 30;
/// Smaller number of loop iteration within randomized test,
/// meant for test where the function tested is more expensive
#[cfg(not(tarpaulin))]
const NB_TESTS_SMALLER: usize = 10;

// Use lower numbers for coverage to ensure fast tests to counter balance slowdown due to code
// instrumentation
#[cfg(tarpaulin)]
pub(crate) const NB_TESTS: usize = 1;
#[cfg(tarpaulin)]
const NB_TESTS_SMALLER: usize = 1;

#[cfg(not(tarpaulin))]
const NB_CTXT: usize = 4;
#[cfg(tarpaulin)]
const NB_CTXT: usize = 2;

create_parameterized_test_classical_params!(integer_encrypt_decrypt);
create_parameterized_test_classical_params!(integer_encrypt_decrypt_128_bits);
create_parameterized_test_classical_params!(integer_encrypt_decrypt_128_bits_specific_values);
create_parameterized_test_classical_params!(integer_encrypt_decrypt_256_bits_specific_values);
create_parameterized_test_classical_params!(integer_encrypt_decrypt_256_bits);
create_parameterized_test_classical_params!(integer_encrypt_auto_cast);
create_parameterized_test_classical_params!(integer_unchecked_add);
create_parameterized_test_classical_params!(integer_smart_add);
create_parameterized_test!(
    integer_smart_add_128_bits {
        coverage => {
            COVERAGE_PARAM_MESSAGE_2_CARRY_2_KS_PBS
        },
        no_coverage => {
            // Skip the 1_1 params for the smart add 128 bits which proved to be the slowest test in our test
            // suite
            TEST_PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128,
            TEST_PARAM_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M128,
            // 2M128 is too slow for 4_4, it is estimated to be 2x slower
            TEST_PARAM_MESSAGE_4_CARRY_4_KS_PBS_GAUSSIAN_2M64
        }
    }
);
create_parameterized_test_classical_params!(integer_unchecked_bitand);
create_parameterized_test_classical_params!(integer_unchecked_bitor);
create_parameterized_test_classical_params!(integer_unchecked_bitxor);
create_parameterized_test_classical_params!(integer_smart_bitand);
create_parameterized_test_classical_params!(integer_smart_bitor);
create_parameterized_test_classical_params!(integer_smart_bitxor);
create_parameterized_test_classical_params!(integer_unchecked_small_scalar_mul);
create_parameterized_test_classical_params!(integer_smart_small_scalar_mul);
create_parameterized_test_classical_params!(integer_blockshift);
create_parameterized_test_classical_params!(integer_blockshift_right);
create_parameterized_test_classical_params!(integer_smart_scalar_mul);
create_parameterized_test_classical_params!(integer_unchecked_scalar_left_shift);
create_parameterized_test_classical_params!(integer_unchecked_scalar_right_shift);
create_parameterized_test_classical_params!(integer_unchecked_neg);
create_parameterized_test_classical_params!(integer_smart_neg);
create_parameterized_test_classical_params!(integer_unchecked_sub);
create_parameterized_test_classical_params!(integer_smart_sub);
#[cfg(not(tarpaulin))]
create_parameterized_test_classical_params!(integer_default_overflowing_sub);
create_parameterized_test_classical_params!(integer_unchecked_block_mul);
create_parameterized_test_classical_params!(integer_smart_block_mul);
create_parameterized_test_classical_params!(integer_smart_mul);
create_parameterized_test_classical_params!(integer_unchecked_mul);

create_parameterized_test_classical_params!(integer_smart_scalar_sub);
create_parameterized_test_classical_params!(integer_smart_scalar_add);
create_parameterized_test_classical_params!(integer_unchecked_scalar_sub);
create_parameterized_test_classical_params!(integer_unchecked_scalar_add);

create_parameterized_test_classical_params!(integer_unchecked_scalar_decomposition_overflow);

create_parameterized_test!(
    integer_full_propagate {
        coverage => {
            COVERAGE_PARAM_MESSAGE_2_CARRY_2_KS_PBS,
            COVERAGE_PARAM_MESSAGE_2_CARRY_3_KS_PBS, // Test case where carry_modulus > message_modulus
        },
        no_coverage => {
            TEST_PARAM_MESSAGE_1_CARRY_1_KS_PBS_GAUSSIAN_2M128,
            TEST_PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128,
            TEST_PARAM_MESSAGE_2_CARRY_3_KS_PBS_GAUSSIAN_2M128, // Test case where carry_modulus > message_modulus
            TEST_PARAM_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M128,
            // 2M128 is too slow for 4_4, it is estimated to be 2x slower
            TEST_PARAM_MESSAGE_4_CARRY_4_KS_PBS_GAUSSIAN_2M64
        }
    }
);

create_parameterized_test_classical_params!(integer_create_trivial_min_max);
create_parameterized_test_classical_params!(integer_signed_decryption_correctly_sign_extend);
create_parameterized_test_classical_params!(integer_scalar_blockslice);
create_parameterized_test_classical_params!(integer_scalar_blockslice_assign);
create_parameterized_test_classical_params!(integer_unchecked_scalar_slice);
create_parameterized_test_classical_params!(integer_unchecked_scalar_slice_assign);
create_parameterized_test_classical_params!(integer_default_scalar_slice);
create_parameterized_test_classical_params!(integer_default_scalar_slice_assign);
create_parameterized_test_classical_params!(integer_smart_scalar_slice);
create_parameterized_test_classical_params!(integer_smart_scalar_slice_assign);
create_parameterized_test!(integer_unchecked_min {
    coverage => {
        COVERAGE_PARAM_MESSAGE_2_CARRY_2_KS_PBS
    },
    no_coverage => {
        PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        TEST_PARAM_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M128,
        // 2M128 is too slow for 4_4, it is estimated to be 2x slower
        TEST_PARAM_MESSAGE_4_CARRY_4_KS_PBS_GAUSSIAN_2M64
    }
});

fn integer_encrypt_decrypt(param: ClassicPBSParameters) {
    let (cks, _) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);

    let mut rng = rand::rng();

    let modulus = param.message_modulus.0.pow(NB_CTXT as u32);

    for _ in 0..NB_TESTS {
        let clear = rng.gen::<u64>() % modulus;

        let ct = cks.encrypt_radix(clear, NB_CTXT);

        let dec: u64 = cks.decrypt_radix(&ct);

        assert_eq!(clear, dec);
    }
}

fn integer_encrypt_decrypt_128_bits(param: ClassicPBSParameters) {
    let (cks, _) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);

    let mut rng = rand::rng();
    let num_block = 128u32.div_ceil(param.message_modulus.0.ilog2()) as usize;
    for _ in 0..10 {
        let clear = rng.gen::<u128>();

        let ct = cks.encrypt_radix(clear, num_block);

        let dec: u128 = cks.decrypt_radix(&ct);

        assert_eq!(clear, dec);
    }
}

fn integer_encrypt_decrypt_128_bits_specific_values(param: ClassicPBSParameters) {
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);

    let num_block = 128u32.div_ceil(param.message_modulus.0.ilog2()) as usize;
    {
        let a = u64::MAX as u128;
        let ct = cks.encrypt_radix(a, num_block);

        let dec: u128 = cks.decrypt_radix(&ct);

        assert_eq!(a, dec);
    }
    {
        let a = (u64::MAX as u128) << 64;
        let ct = cks.encrypt_radix(a, num_block);

        let dec: u128 = cks.decrypt_radix(&ct);

        assert_eq!(a, dec);
    }

    {
        let clear_0 = ((u64::MAX as u128) << 64) + 1;
        let clear_1 = 1u128 << 64;

        let mut ct = cks.encrypt_radix(clear_0, num_block);
        let mut ct2 = cks.encrypt_radix(clear_1, num_block);
        let ct = sks.smart_add(&mut ct, &mut ct2);

        let dec: u128 = cks.decrypt_radix(&ct);

        assert_eq!(clear_0.wrapping_add(clear_1), dec);
    }

    {
        let clear_0 = 330885270518284254268036566988540330316u128;
        let clear_1 = 296783836660960220449461214688067032122u128;

        let mut ct = cks.encrypt_radix(clear_0, num_block);
        let mut ct2 = cks.encrypt_radix(clear_1, num_block);
        let ct = sks.smart_add(&mut ct, &mut ct2);

        let dec: u128 = cks.decrypt_radix(&ct);

        assert_eq!(clear_0.wrapping_add(clear_1), dec);
    }
}

fn integer_encrypt_decrypt_256_bits_specific_values(param: ClassicPBSParameters) {
    let (cks, _) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);

    let num_block = 256u32.div_ceil(param.message_modulus.0.ilog2()) as usize;
    {
        let a = (u64::MAX as u128) << 64;
        let b = 0;
        let clear = crate::integer::U256::from((a, b));
        let ct = cks.encrypt_radix(clear, num_block);

        let dec: U256 = cks.decrypt_radix(&ct);
        assert_eq!(clear, dec);
    }
    {
        let a = 0;
        let b = u128::MAX;
        let clear = crate::integer::U256::from((a, b));
        let ct = cks.encrypt_radix(clear, num_block);

        let dec: U256 = cks.decrypt_radix(&ct);
        assert_eq!(clear, dec);
    }
}

fn integer_encrypt_decrypt_256_bits(param: ClassicPBSParameters) {
    let (cks, _) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);

    let mut rng = rand::rng();
    let num_block = 256u32.div_ceil(param.message_modulus.0.ilog2()) as usize;

    for _ in 0..10 {
        let clear0 = rng.gen::<u128>();
        let clear1 = rng.gen::<u128>();

        let clear = crate::integer::U256::from((clear0, clear1));

        let ct = cks.encrypt_radix(clear, num_block);

        let dec: U256 = cks.decrypt_radix(&ct);

        assert_eq!(clear, dec);
    }
}

fn integer_encrypt_auto_cast(param: ClassicPBSParameters) {
    // The goal is to test that encrypting a value stored in a type
    // for which the bit count does not match the target block count of the encrypted
    // radix properly applies upcasting/downcasting

    let (cks, _) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let mut rng = rand::rng();

    let num_blocks = 32u32.div_ceil(param.message_modulus.0.ilog2()) as usize;

    // Positive signed value
    let value = rng.gen_range(0..=i32::MAX);
    let ct = cks.encrypt_signed_radix(value, num_blocks * 2);
    let d: i64 = cks.decrypt_signed_radix(&ct);
    assert_eq!(i64::from(value), d);

    let ct = cks.encrypt_signed_radix(value, num_blocks.div_ceil(2));
    let d: i16 = cks.decrypt_signed_radix(&ct);
    assert_eq!(value as i16, d);

    let odd_block_count = if num_blocks % 2 == 1 {
        num_blocks
    } else {
        num_blocks + 1
    };

    // Negative signed value
    for block_count in [odd_block_count, num_blocks * 2, num_blocks.div_ceil(2)] {
        let value = rng.gen_range(i8::MIN..0);
        let ct = cks.encrypt_signed_radix(value, block_count);
        let d: i64 = cks.decrypt_signed_radix(&ct);
        assert_eq!(i64::from(value), d);

        let ct = cks.encrypt_signed_radix(value, block_count);
        let d: i16 = cks.decrypt_signed_radix(&ct);
        assert_eq!(value as i16, d);
    }

    // Unsigned value
    let value = rng.gen::<u32>();
    let ct = cks.encrypt_radix(value, num_blocks * 2);
    let d: u64 = cks.decrypt_radix(&ct);
    assert_eq!(u64::from(value), d);

    let ct = cks.encrypt_radix(value, num_blocks.div_ceil(2));
    let d: u16 = cks.decrypt_radix(&ct);
    assert_eq!(value as u16, d);
}

fn integer_smart_add_128_bits(param: ClassicPBSParameters) {
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);

    let mut rng = rand::rng();
    let num_block = 128u32.div_ceil(param.message_modulus.0.ilog2()) as usize;

    for _ in 0..100 {
        let clear_0 = rng.gen::<u128>();

        let clear_1 = rng.gen::<u128>();

        println!("{clear_0} {clear_1}");

        let mut ctxt_0 = cks.encrypt_radix(clear_0, num_block);

        let mut ctxt_1 = cks.encrypt_radix(clear_1, num_block);

        // add the two ciphertexts
        let mut ct_res = sks.smart_add(&mut ctxt_0, &mut ctxt_1);

        let mut clear_result = clear_0.wrapping_add(clear_1);

        // println!("clear_0 = {}, clear_1 = {}", clear_0, clear_1);
        //add multiple times to raise the degree
        for _ in 0..2 {
            ct_res = sks.smart_add(&mut ct_res, &mut ctxt_0);
            clear_result = clear_result.wrapping_add(clear_0);

            let dec_res: u128 = cks.decrypt_radix(&ct_res);
            // println!("clear = {}, dec_res = {}", clear, dec_res);
            assert_eq!(clear_result, dec_res);
        }
    }
}

fn integer_unchecked_add(param: ClassicPBSParameters) {
    let executor = CpuFunctionExecutor::new(&ServerKey::unchecked_add);
    unchecked_add_test(param, executor);
}

fn integer_smart_add(param: ClassicPBSParameters) {
    let executor = CpuFunctionExecutor::new(&ServerKey::smart_add);
    smart_add_test(param, executor);
}

fn integer_unchecked_bitand<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::unchecked_bitand);
    unchecked_bitand_test(param, executor);
}

fn integer_unchecked_bitor<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::unchecked_bitor);
    unchecked_bitor_test(param, executor);
}

fn integer_unchecked_bitxor<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::unchecked_bitxor);
    unchecked_bitxor_test(param, executor);
}

fn integer_smart_bitand<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::smart_bitand);
    smart_bitand_test(param, executor);
}

fn integer_smart_bitor<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::smart_bitor);
    smart_bitor_test(param, executor);
}

fn integer_smart_bitxor<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::smart_bitxor);
    smart_bitxor_test(param, executor);
}

fn integer_unchecked_small_scalar_mul(param: ClassicPBSParameters) {
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);

    let mut rng = rand::rng();

    // message_modulus^vec_length
    let modulus = param.message_modulus.0.pow(NB_CTXT as u32);

    let scalar_modulus = param.message_modulus.0;

    for _ in 0..NB_TESTS {
        let clear = rng.gen::<u64>() % modulus;

        let scalar = rng.gen::<u64>() % scalar_modulus;

        let ct = cks.encrypt_radix(clear, NB_CTXT);

        // add the two ciphertexts
        let ct_res = sks.unchecked_small_scalar_mul(&ct, scalar);

        let dec_res: u64 = cks.decrypt_radix(&ct_res);

        assert_eq!((clear * scalar) % modulus, dec_res);
    }
}

fn integer_smart_small_scalar_mul(param: ClassicPBSParameters) {
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);

    let mut rng = rand::rng();

    // message_modulus^vec_length
    let modulus = param.message_modulus.0.pow(NB_CTXT as u32);

    let scalar_modulus = param.message_modulus.0;

    let mut clear_res;
    for _ in 0..NB_TESTS_SMALLER {
        let clear = rng.gen::<u64>() % modulus;

        let scalar = rng.gen::<u64>() % scalar_modulus;

        let mut ct = cks.encrypt_radix(clear, NB_CTXT);

        let mut ct_res = sks.smart_small_scalar_mul(&mut ct, scalar);

        clear_res = clear * scalar;
        for _ in 0..NB_TESTS_SMALLER {
            // scalar multiplication
            ct_res = sks.smart_small_scalar_mul(&mut ct_res, scalar);
            clear_res *= scalar;
        }

        let dec_res: u64 = cks.decrypt_radix(&ct_res);

        assert_eq!(clear_res % modulus, dec_res);
    }
}

fn integer_blockshift(param: ClassicPBSParameters) {
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);

    let mut rng = rand::rng();

    // message_modulus^vec_length
    let modulus = param.message_modulus.0.pow(NB_CTXT as u32);

    for _ in 0..NB_TESTS {
        let clear = rng.gen::<u64>() % modulus;

        let power = rng.gen::<u64>() % NB_CTXT as u64;

        let ct = cks.encrypt_radix(clear, NB_CTXT);

        // add the two ciphertexts
        let ct_res = sks.blockshift(&ct, power as usize);

        let dec_res: u64 = cks.decrypt_radix(&ct_res);

        assert_eq!(
            (clear * param.message_modulus.0.pow(power as u32) as u64) % modulus,
            dec_res
        );
    }
}

fn integer_blockshift_right(param: ClassicPBSParameters) {
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);

    let mut rng = rand::rng();

    // message_modulus^vec_length
    let modulus = param.message_modulus.0.pow(NB_CTXT as u32);

    for _ in 0..NB_TESTS {
        let clear = rng.gen::<u64>() % modulus;

        let power = rng.gen::<u64>() % NB_CTXT as u64;

        let ct = cks.encrypt_radix(clear, NB_CTXT);

        // add the two ciphertexts
        let ct_res = sks.blockshift_right(&ct, power as usize);

        let dec_res: u64 = cks.decrypt_radix(&ct_res);

        assert_eq!(
            (clear / param.message_modulus.0.pow(power as u32) as u64) % modulus,
            dec_res
        );
    }
}

fn integer_smart_scalar_mul(param: ClassicPBSParameters) {
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);

    let mut rng = rand::rng();

    // message_modulus^vec_length
    let modulus = param.message_modulus.0.pow(NB_CTXT as u32);

    for _ in 0..NB_TESTS {
        let clear = rng.gen::<u64>() % modulus;

        let scalar = rng.gen::<u64>() % modulus;

        let mut ct = cks.encrypt_radix(clear, NB_CTXT);

        // scalar mul
        let ct_res = sks.smart_scalar_mul(&mut ct, scalar);

        let dec_res: u64 = cks.decrypt_radix(&ct_res);

        assert_eq!((clear * scalar) % modulus, dec_res);
    }
}

fn integer_unchecked_scalar_left_shift<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::unchecked_scalar_left_shift);
    unchecked_scalar_left_shift_test(param, executor);
}

fn integer_unchecked_scalar_right_shift<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::unchecked_scalar_right_shift);
    unchecked_scalar_right_shift_test(param, executor);
}

fn integer_unchecked_neg<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::unchecked_neg);
    unchecked_neg_test(param, executor);
}

fn integer_smart_neg(param: ClassicPBSParameters) {
    let executor = CpuFunctionExecutor::new(&ServerKey::smart_neg);
    smart_neg_test(param, executor);
}

fn integer_unchecked_sub<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::unchecked_sub);
    unchecked_sub_test(param, executor);
}

fn integer_smart_sub(param: ClassicPBSParameters) {
    let executor = CpuFunctionExecutor::new(&ServerKey::smart_sub);
    smart_sub_test(param, executor);
}

fn integer_unchecked_block_mul<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::unchecked_block_mul);
    unchecked_block_mul_test(param, executor);
}

fn integer_smart_block_mul(param: ClassicPBSParameters) {
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);

    let mut rng = rand::rng();

    // message_modulus^vec_length
    let modulus = param.message_modulus.0.pow(NB_CTXT as u32);

    let block_modulus = param.message_modulus.0;

    for _ in 0..5 {
        // Define the cleartexts
        let clear1 = rng.gen::<u64>() % modulus;
        let clear2 = rng.gen::<u64>() % block_modulus;

        // Encrypt the integers
        let ctxt_1 = cks.encrypt_radix(clear1, NB_CTXT);
        let mut ctxt_2 = cks.encrypt_one_block(clear2);

        let mut res = ctxt_1.clone();
        let mut clear = clear1;

        res = sks.smart_block_mul(&mut res, &mut ctxt_2, 0);
        for _ in 0..5 {
            res = sks.smart_block_mul(&mut res, &mut ctxt_2, 0);
            clear = (clear * clear2) % modulus;
        }
        let dec: u64 = cks.decrypt_radix(&res);

        clear = (clear * clear2) % modulus;

        // Check the correctness
        assert_eq!(clear, dec);
    }
}

fn integer_unchecked_mul<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::unchecked_mul);
    unchecked_mul_test(param, executor);
}

fn integer_smart_mul<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::smart_mul);
    smart_mul_test(param, executor);
}

fn integer_unchecked_scalar_add<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::unchecked_scalar_add);
    unchecked_scalar_add_test(param, executor);
}

fn integer_smart_scalar_add<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::smart_scalar_add);
    smart_scalar_add_test(param, executor);
}

fn integer_unchecked_scalar_sub<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::unchecked_scalar_sub);
    unchecked_scalar_sub_test(param, executor);
}

fn integer_smart_scalar_sub<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::smart_scalar_sub);
    smart_scalar_sub_test(param, executor);
}

fn integer_unchecked_scalar_decomposition_overflow(param: ClassicPBSParameters) {
    // This is a regression test.
    //
    // The purpose here is to check the behaviour when the scalar value has less bits
    // than the ciphertext.

    let mut rng = rand::rng();

    let num_block = (128_f64 / (param.message_modulus.0 as f64).log(2.0)).ceil() as usize;

    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);

    // Check addition
    // --------------
    let scalar = rng.gen::<u64>();
    let clear_0 = rng.gen::<u128>();
    let ct_0 = cks.encrypt_radix(clear_0, num_block);

    let ct_res = sks.unchecked_scalar_add(&ct_0, scalar);
    let dec_res = cks.decrypt_radix(&ct_res);

    assert_eq!(clear_0.wrapping_add(scalar as u128), dec_res);

    // Check subtraction
    // -----------------
    let scalar = rng.gen::<u64>();
    let clear_0 = rng.gen::<u128>();
    let ct_0 = cks.encrypt_radix(clear_0, num_block);

    let ct_res = sks.unchecked_scalar_sub(&ct_0, scalar);
    let dec_res = cks.decrypt_radix(&ct_res);

    assert_eq!(clear_0.wrapping_sub(scalar as u128), dec_res);
}

#[test]
#[cfg(not(tarpaulin))]
fn integer_smart_scalar_mul_decomposition_overflow() {
    // This is a regression test. The purpose here is to check if the number of decomposition
    // blocks doesn't exceed 64 bits. This is why we test only 128 bits size.
    // Since smart_scalar_mul is a slow operation, we test against only one parameters set.
    // If overflow occurs the test case will panic.

    let mut rng = rand::rng();

    let param = TEST_PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128;

    let num_block = (128_f64 / (param.message_modulus.0 as f64).log(2.0)).ceil() as usize;

    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);

    let scalar = rng.gen::<u64>();
    let clear_0 = rng.gen::<u128>();
    let mut ct_0 = cks.encrypt_radix(clear_0, num_block);

    let ct_res = sks.smart_scalar_mul(&mut ct_0, scalar);
    let dec_res = cks.decrypt_radix(&ct_res);

    assert_eq!(clear_0.wrapping_mul(scalar as u128), dec_res);
}

fn integer_default_overflowing_sub<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::unsigned_overflowing_sub);
    default_overflowing_sub_test(param, executor);
}

fn integer_full_propagate<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::full_propagate);
    full_propagate_test(param, executor);
}

fn integer_create_trivial_min_max(param: impl Into<TestParameters>) {
    let (_, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);

    let num_bits_in_one_block = sks.message_modulus().0.ilog2();
    // The test only involves trivial types so we can afford to test more
    for bit_size in 1..=127 {
        assert!(bit_size < i128::BITS);
        let num_blocks = bit_size.div_ceil(num_bits_in_one_block);
        // If num_bits_in_one_block is not a multiple of bit_size, then
        // the actual number of bits is not the same as bit size (we end up with more)
        let actual_num_bits = num_blocks * num_bits_in_one_block;
        if actual_num_bits >= i128::BITS {
            break;
        }

        // Unsigned
        {
            let expected_unsigned_max = 2u128.pow(actual_num_bits) - 1;
            let expected_unsigned_min = 0;

            let trivial_unsigned_max: RadixCiphertext =
                sks.create_trivial_max_radix(num_blocks as usize);
            let trivial_unsigned_min: RadixCiphertext =
                sks.create_trivial_min_radix(num_blocks as usize);

            assert_eq!(
                trivial_unsigned_max.decrypt_trivial::<u128>().unwrap(),
                expected_unsigned_max
            );
            assert_eq!(
                trivial_unsigned_min.decrypt_trivial::<u128>().unwrap(),
                expected_unsigned_min
            );
        }

        // Signed
        {
            let expected_signed_max = 2i128.pow(actual_num_bits - 1) - 1;
            let expected_signed_min = -(2i128.pow(actual_num_bits - 1));

            let trivial_signed_max: SignedRadixCiphertext =
                sks.create_trivial_max_radix(num_blocks as usize);
            let trivial_signed_min: SignedRadixCiphertext =
                sks.create_trivial_min_radix(num_blocks as usize);

            assert_eq!(
                trivial_signed_max.decrypt_trivial::<i128>().unwrap(),
                expected_signed_max
            );
            assert_eq!(
                trivial_signed_min.decrypt_trivial::<i128>().unwrap(),
                expected_signed_min
            );
        }
    }
}

fn integer_signed_decryption_correctly_sign_extend(param: impl Into<TestParameters>) {
    // Test that when decrypting a negative SignedRadixCiphertext of N bits to a
    // clear type of M bits where M > N, the sign extension is correctly done
    //
    // Specifically here we take N = 64 bits, M = 128 bits
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);

    let num_bits_in_one_block = sks.message_modulus().0.ilog2();
    let num_blocks = 64u32.div_ceil(num_bits_in_one_block);
    let value = -1i64;

    let encrypted = cks.encrypt_signed_radix(value, num_blocks as usize);
    let decrypted: i128 = cks.decrypt_signed_radix(&encrypted);
    assert_eq!(decrypted, value as i128);

    let trivial: SignedRadixCiphertext = sks.create_trivial_radix(value, num_blocks as usize);
    assert_eq!(trivial.decrypt_trivial::<i128>().unwrap(), value as i128);
}

fn integer_scalar_blockslice(param: ClassicPBSParameters) {
    let executor = CpuFunctionExecutor::new(&ServerKey::scalar_blockslice);
    scalar_blockslice_test(param, executor);
}

fn integer_scalar_blockslice_assign(param: ClassicPBSParameters) {
    let executor = CpuFunctionExecutor::new(&ServerKey::scalar_blockslice_assign);
    scalar_blockslice_assign_test(param, executor);
}

fn integer_unchecked_scalar_slice(param: ClassicPBSParameters) {
    let executor = CpuFunctionExecutor::new(&ServerKey::unchecked_scalar_bitslice);
    unchecked_scalar_bitslice_test(param, executor);
}

fn integer_unchecked_scalar_slice_assign(param: ClassicPBSParameters) {
    let executor = CpuFunctionExecutor::new(&ServerKey::unchecked_scalar_bitslice_assign);
    unchecked_scalar_bitslice_assign_test(param, executor);
}

fn integer_default_scalar_slice(param: ClassicPBSParameters) {
    let executor = CpuFunctionExecutor::new(&ServerKey::scalar_bitslice);
    default_scalar_bitslice_test(param, executor);
}

fn integer_default_scalar_slice_assign(param: ClassicPBSParameters) {
    let executor = CpuFunctionExecutor::new(&ServerKey::scalar_bitslice_assign);
    default_scalar_bitslice_assign_test(param, executor);
}

fn integer_smart_scalar_slice(param: ClassicPBSParameters) {
    let executor = CpuFunctionExecutor::new(&ServerKey::smart_scalar_bitslice);
    smart_scalar_bitslice_test(param, executor);
}

fn integer_smart_scalar_slice_assign(param: ClassicPBSParameters) {
    let executor = CpuFunctionExecutor::new(&ServerKey::smart_scalar_bitslice_assign);
    smart_scalar_bitslice_assign_test(param, executor);
}

fn integer_unchecked_min(param: ClassicPBSParameters) {
    let executor = CpuFunctionExecutor::new(&ServerKey::unchecked_min);
    test_unchecked_minmax(param, 2, executor, std::cmp::min::<u64>);
}
