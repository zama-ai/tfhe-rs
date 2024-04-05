use crate::integer::keycache::KEY_CACHE;
use crate::integer::server_key::radix::neg::NegatedDegreeIter;
use crate::integer::server_key::radix_parallel::tests_cases_unsigned::{
    FunctionExecutor, NB_CTXT, NB_TESTS, NB_TESTS_SMALLER,
};
use crate::integer::server_key::radix_parallel::tests_unsigned::{
    panic_if_any_block_info_exceeds_max_degree_or_noise, panic_if_any_block_is_not_clean,
    panic_if_any_block_values_exceeds_its_degree, unsigned_modulus, CpuFunctionExecutor,
    ExpectedDegrees, ExpectedNoiseLevels,
};
use crate::integer::tests::create_parametrized_test;
use crate::integer::{IntegerKeyKind, RadixCiphertext, RadixClientKey, ServerKey};
#[cfg(tarpaulin)]
use crate::shortint::parameters::coverage_parameters::*;
use crate::shortint::parameters::*;
use rand::Rng;
use std::sync::Arc;

create_parametrized_test!(integer_smart_neg);
create_parametrized_test!(integer_default_neg);

fn integer_smart_neg<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::smart_neg_parallelized);
    smart_neg_test(param, executor);
}

fn integer_default_neg<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::neg_parallelized);
    default_neg_test(param, executor);
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
    P: Into<PBSParameters>,
    T: for<'a> FunctionExecutor<&'a RadixCiphertext, RadixCiphertext>,
{
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let sks = Arc::new(sks);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    let mut rng = rand::thread_rng();

    let modulus = unsigned_modulus(cks.parameters().message_modulus(), NB_CTXT as u32);

    let max_noise_level = sks.key.max_noise_level;
    let max_degree = sks.key.max_degree;

    let trivial0 = sks.create_trivial_radix(0u64, NB_CTXT);
    executor.setup(&cks, sks);

    // negation involves either scalar operation or pbs, noise is always nominal
    let expected_noise_levels = ExpectedNoiseLevels::new(NoiseLevel::NOMINAL, NB_CTXT);
    let mut expected_degrees = ExpectedDegrees::new(Degree::new(0), NB_CTXT);

    for _ in 0..NB_TESTS {
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
    P: Into<PBSParameters>,
    T: for<'a> FunctionExecutor<&'a mut RadixCiphertext, RadixCiphertext>,
{
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let sks = Arc::new(sks);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    let mut rng = rand::thread_rng();

    let modulus = unsigned_modulus(cks.parameters().message_modulus(), NB_CTXT as u32);

    let max_noise_level = sks.key.max_noise_level;
    let max_degree = sks.key.max_degree;

    executor.setup(&cks, sks);

    // negation involves either scalar operation or pbs, noise is always nominal
    let expected_noise_levels = ExpectedNoiseLevels::new(NoiseLevel::NOMINAL, NB_CTXT);

    for _ in 0..NB_TESTS_SMALLER {
        let clear = rng.gen::<u64>() % modulus;

        let mut ctxt = cks.encrypt(clear);

        let mut ct_res = executor.execute(&mut ctxt);
        let mut clear_res = clear.wrapping_neg() % modulus;
        let dec: u64 = cks.decrypt(&ct_res);
        assert_eq!(clear_res, dec);

        for _ in 0..NB_TESTS_SMALLER {
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

pub(crate) fn default_neg_test<P, T>(param: P, mut executor: T)
where
    P: Into<PBSParameters>,
    T: for<'a> FunctionExecutor<&'a RadixCiphertext, RadixCiphertext>,
{
    let (cks, mut sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    sks.set_deterministic_pbs_execution(true);
    let sks = Arc::new(sks);

    let mut rng = rand::thread_rng();

    let modulus = unsigned_modulus(cks.parameters().message_modulus(), NB_CTXT as u32);

    executor.setup(&cks, sks);

    for _ in 0..NB_TESTS_SMALLER {
        let clear = rng.gen::<u64>() % modulus;

        let ctxt = cks.encrypt(clear);
        panic_if_any_block_is_not_clean(&ctxt, &cks);

        let ct_res = executor.execute(&ctxt);
        let tmp = executor.execute(&ctxt);
        assert!(ct_res.block_carries_are_empty());
        assert_eq!(ct_res, tmp);

        let dec: u64 = cks.decrypt(&ct_res);
        let clear_result = clear.wrapping_neg() % modulus;
        assert_eq!(clear_result, dec);
    }
}
