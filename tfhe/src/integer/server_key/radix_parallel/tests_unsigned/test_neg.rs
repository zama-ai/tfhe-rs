use crate::integer::keycache::KEY_CACHE;
use crate::integer::server_key::radix::neg::NegatedDegreeIter;
use crate::integer::server_key::radix_parallel::tests_cases_unsigned::{FunctionExecutor, NB_CTXT};
use crate::integer::server_key::radix_parallel::tests_unsigned::{
    nb_tests_for_params, nb_tests_smaller_for_params,
    panic_if_any_block_info_exceeds_max_degree_or_noise, panic_if_any_block_is_not_clean,
    panic_if_any_block_values_exceeds_its_degree, random_non_zero_value, unsigned_modulus,
    CpuFunctionExecutor, ExpectedDegrees, ExpectedNoiseLevels, MAX_NB_CTXT,
};
use crate::integer::tests::create_parameterized_test;
use crate::integer::{BooleanBlock, IntegerKeyKind, RadixCiphertext, RadixClientKey, ServerKey};
#[cfg(tarpaulin)]
use crate::shortint::parameters::coverage_parameters::*;
use crate::shortint::parameters::test_params::*;
use crate::shortint::parameters::*;
use rand::Rng;
use std::sync::Arc;

create_parameterized_test!(integer_smart_neg);
create_parameterized_test!(integer_default_neg);
create_parameterized_test!(integer_default_overflowing_neg);

fn integer_smart_neg<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::smart_neg_parallelized);
    smart_neg_test(param, executor);
}

fn integer_default_neg<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::neg_parallelized);
    default_neg_test(param, executor);
}

fn integer_default_overflowing_neg<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::overflowing_neg_parallelized);
    default_overflowing_neg_test(param, executor);
}

impl ExpectedDegrees {
    fn after_unchecked_neg(&mut self, lhs: &RadixCiphertext) -> &Self {
        self.set_with(NegatedDegreeIter::new(
            lhs.blocks
                .iter()
                .map(|block| (block.degree, block.message_modulus)),
        ));
        self
    }
}

//=============================================================================
// Unchecked Tests
//=============================================================================

pub(crate) fn unchecked_neg_test<P, T>(param: P, mut executor: T)
where
    P: Into<TestParameters>,
    T: for<'a> FunctionExecutor<&'a RadixCiphertext, RadixCiphertext>,
{
    let param = param.into();
    let nb_tests = nb_tests_for_params(param);
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let sks = Arc::new(sks);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    let mut rng = rand::rng();

    let modulus = unsigned_modulus(cks.parameters().message_modulus(), NB_CTXT as u32);

    let max_noise_level = sks.key.max_noise_level;
    let max_degree = sks.key.max_degree;

    let trivial0 = sks.create_trivial_radix(0u64, NB_CTXT);
    executor.setup(&cks, sks);

    // negation involves either scalar operation or pbs, noise is always nominal
    let expected_noise_levels = ExpectedNoiseLevels::new(NoiseLevel::NOMINAL, NB_CTXT);
    let mut expected_degrees = ExpectedDegrees::new(Degree::new(0), NB_CTXT);

    for _ in 0..nb_tests {
        let clear = rng.gen::<u64>() % modulus;

        let ctxt = cks.encrypt(clear);

        let encrypted_result = executor.execute(&ctxt);

        expected_noise_levels.panic_if_any_is_not_equal(&encrypted_result);
        expected_degrees
            .after_unchecked_neg(&ctxt)
            .panic_if_any_is_not_equal(&encrypted_result);
        panic_if_any_block_values_exceeds_its_degree(&encrypted_result, &cks);
        panic_if_any_block_info_exceeds_max_degree_or_noise(
            &encrypted_result,
            max_degree,
            max_noise_level,
        );

        let decrypted_result: u64 = cks.decrypt(&encrypted_result);
        let expected_result = clear.wrapping_neg() % modulus;
        assert_eq!(decrypted_result, expected_result);
    }

    // negation of trivial 0
    {
        let ct_res = executor.execute(&trivial0);
        let dec_res: u64 = cks.decrypt(&ct_res);
        assert_eq!(0, dec_res);
    }
}

//=============================================================================
// Smart Tests
//=============================================================================

pub(crate) fn smart_neg_test<P, T>(param: P, mut executor: T)
where
    P: Into<TestParameters>,
    T: for<'a> FunctionExecutor<&'a mut RadixCiphertext, RadixCiphertext>,
{
    let param = param.into();
    let nb_tests_smaller = nb_tests_smaller_for_params(param);
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let sks = Arc::new(sks);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    let mut rng = rand::rng();

    let modulus = unsigned_modulus(cks.parameters().message_modulus(), NB_CTXT as u32);

    let max_noise_level = sks.key.max_noise_level;
    let max_degree = sks.key.max_degree;

    executor.setup(&cks, sks);

    // negation involves either scalar operation or pbs, noise is always nominal
    let expected_noise_levels = ExpectedNoiseLevels::new(NoiseLevel::NOMINAL, NB_CTXT);

    for _ in 0..nb_tests_smaller {
        let clear = rng.gen::<u64>() % modulus;

        let mut ctxt = cks.encrypt(clear);

        let mut ct_res = executor.execute(&mut ctxt);
        let mut clear_res = clear.wrapping_neg() % modulus;
        let dec: u64 = cks.decrypt(&ct_res);
        assert_eq!(clear_res, dec);

        for _ in 0..nb_tests_smaller {
            ct_res = executor.execute(&mut ct_res);

            expected_noise_levels.panic_if_any_is_not_equal(&ct_res);
            panic_if_any_block_info_exceeds_max_degree_or_noise(
                &ct_res,
                max_degree,
                max_noise_level,
            );
            panic_if_any_block_values_exceeds_its_degree(&ct_res, &cks);

            clear_res = clear_res.wrapping_neg() % modulus;
            let dec: u64 = cks.decrypt(&ct_res);
            assert_eq!(clear_res, dec);
        }
    }
}

//=============================================================================
// Default Tests
//=============================================================================

pub(crate) fn default_neg_test<P, T>(param: P, mut neg: T)
where
    P: Into<TestParameters>,
    T: for<'a> FunctionExecutor<&'a RadixCiphertext, RadixCiphertext>,
{
    let param = param.into();
    let nb_tests_smaller = nb_tests_smaller_for_params(param);
    let (cks, mut sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    sks.set_deterministic_pbs_execution(true);
    let sks = Arc::new(sks.clone());

    let mut rng = rand::rng();

    neg.setup(&cks, sks.clone());

    let cks: crate::integer::ClientKey = cks.into();

    for num_blocks in 1..MAX_NB_CTXT {
        let modulus = unsigned_modulus(cks.parameters().message_modulus(), num_blocks as u32);

        for _ in 0..nb_tests_smaller {
            let mut clear = rng.gen_range(0..modulus);
            let mut ctxt = cks.encrypt_radix(clear, num_blocks);

            let ct_res = neg.execute(&ctxt);
            panic_if_any_block_is_not_clean(&ct_res, &cks);

            let dec_ct: u64 = cks.decrypt_radix(&ct_res);
            let expected = clear.wrapping_neg() % modulus;
            assert_eq!(
                dec_ct, expected,
                "Invalid result for neg({clear}),\n\
                Expected {expected}, got {dec_ct}\n\
                num_blocks: {num_blocks}, modulus: {modulus}"
            );

            let ct_res2 = neg.execute(&ctxt);
            assert_eq!(ct_res, ct_res2, "Failed determinism check");

            // Test with non clean carries
            let random_non_zero = random_non_zero_value(&mut rng, modulus);
            sks.unchecked_scalar_add_assign(&mut ctxt, random_non_zero);
            clear = clear.wrapping_add(random_non_zero) % modulus;

            let ct_res = neg.execute(&ctxt);
            panic_if_any_block_is_not_clean(&ct_res, &cks);

            let dec_ct: u64 = cks.decrypt_radix(&ct_res);
            let expected = clear.wrapping_neg() % modulus;
            assert_eq!(
                dec_ct, expected,
                "Invalid result for neg({clear}),\n\
                Expected {expected}, got {dec_ct}\n\
                num_blocks: {num_blocks}, modulus: {modulus}"
            );
            let ct_res2 = neg.execute(&ctxt);
            assert_eq!(ct_res, ct_res2, "Failed determinism check");
        }
    }
}

pub(crate) fn default_overflowing_neg_test<P, T>(param: P, mut overflowing_neg: T)
where
    P: Into<TestParameters>,
    T: for<'a> FunctionExecutor<&'a RadixCiphertext, (RadixCiphertext, BooleanBlock)>,
{
    let param = param.into();
    let nb_tests_smaller = nb_tests_smaller_for_params(param);
    let (cks, mut sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    sks.set_deterministic_pbs_execution(true);
    let sks = Arc::new(sks);

    let mut rng = rand::rng();

    overflowing_neg.setup(&cks, sks);

    let cks: crate::integer::ClientKey = cks.into();

    for num_blocks in 1..MAX_NB_CTXT {
        let modulus = unsigned_modulus(cks.parameters().message_modulus(), num_blocks as u32);

        for _ in 0..nb_tests_smaller {
            let clear = rng.gen_range(1..modulus);
            let ctxt = cks.encrypt_radix(clear, num_blocks);

            let (ct_res, flag) = overflowing_neg.execute(&ctxt);

            panic_if_any_block_is_not_clean(&ct_res, &cks);
            assert_eq!(flag.0.noise_level(), NoiseLevel::NOMINAL);
            assert_eq!(flag.0.degree.get(), 1);

            let dec_flag = cks.decrypt_bool(&flag);
            assert!(
                dec_flag,
                "Invalid value for overflowing_neg flag, expected true, got false"
            );

            let dec_ct: u64 = cks.decrypt_radix(&ct_res);
            let expected = clear.wrapping_neg() % modulus;
            assert_eq!(
                dec_ct, expected,
                "Invalid result for overflowing_neg({clear}),\n\
                Expected {expected}, got {dec_ct}\n\
                num_blocks: {num_blocks}, modulus: {modulus}"
            );

            let (ct_res2, flag2) = overflowing_neg.execute(&ctxt);
            assert_eq!(ct_res, ct_res2, "Failed determinism check");
            assert_eq!(flag, flag2, "Failed determinism check");
        }

        // The only case where unsigned neg does not overflows
        let ctxt = cks.encrypt_radix(0u32, num_blocks);

        let (ct_res, flag) = overflowing_neg.execute(&ctxt);

        panic_if_any_block_is_not_clean(&ct_res, &cks);
        assert_eq!(flag.0.noise_level(), NoiseLevel::NOMINAL);
        assert_eq!(flag.0.degree.get(), 1);

        let dec_flag = cks.decrypt_bool(&flag);
        assert!(
            !dec_flag,
            "Invalid value for overflowing_neg flag, expected false, got true"
        );

        let dec_ct: u64 = cks.decrypt_radix(&ct_res);
        assert_eq!(
            dec_ct, 0,
            "Invalid result for overflowing_neg(0),\n\
                Expected 0, got {dec_ct}\n\
                num_blocks: {num_blocks}, modulus: {modulus}"
        );
    }
}
