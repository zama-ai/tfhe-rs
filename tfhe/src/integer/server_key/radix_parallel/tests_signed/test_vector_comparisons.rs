use crate::integer::keycache::KEY_CACHE;
use crate::integer::server_key::radix_parallel::tests_cases_unsigned::FunctionExecutor;
use crate::integer::server_key::radix_parallel::tests_unsigned::{CpuFunctionExecutor, NB_CTXT};
use crate::integer::{
    BooleanBlock, IntegerKeyKind, RadixClientKey, ServerKey, SignedRadixCiphertext,
};
use crate::shortint::parameters::*;
use std::sync::Arc;

use crate::integer::server_key::radix_parallel::tests_unsigned::test_vector_comparisons::{
    default_all_eq_slices_test_case_impl, unchecked_all_eq_slices_test_case_impl,
};
use crate::integer::tests::create_parametrized_test;

create_parametrized_test!(integer_signed_unchecked_all_eq_slices_test_case);
create_parametrized_test!(integer_signed_default_all_eq_slices_test_case);

fn integer_signed_unchecked_all_eq_slices_test_case<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::unchecked_all_eq_slices_parallelized);
    unchecked_all_eq_slices_test_case(param, executor);
}

pub(crate) fn unchecked_all_eq_slices_test_case<P, E>(params: P, mut executor: E)
where
    P: Into<PBSParameters>,
    E: for<'a> FunctionExecutor<
        (&'a [SignedRadixCiphertext], &'a [SignedRadixCiphertext]),
        BooleanBlock,
    >,
{
    let (cks, sks) = KEY_CACHE.get_from_params(params, IntegerKeyKind::Radix);
    let sks = Arc::new(sks);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    let modulus = (cks.parameters().message_modulus().0.pow(NB_CTXT as u32) / 2) as i64;

    executor.setup(&cks, sks);

    unchecked_all_eq_slices_test_case_impl(
        executor,
        &cks,
        -modulus..modulus,
        RadixClientKey::encrypt_signed,
    );
}

fn integer_signed_default_all_eq_slices_test_case<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::all_eq_slices_parallelized);
    default_all_eq_slices_test_case(param, executor);
}

pub(crate) fn default_all_eq_slices_test_case<P, E>(params: P, mut executor: E)
where
    P: Into<PBSParameters>,
    E: for<'a> FunctionExecutor<
        (&'a [SignedRadixCiphertext], &'a [SignedRadixCiphertext]),
        BooleanBlock,
    >,
{
    let (cks, mut sks) = KEY_CACHE.get_from_params(params, IntegerKeyKind::Radix);
    sks.set_deterministic_pbs_execution(true);

    let sks = Arc::new(sks);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    let modulus = (cks.parameters().message_modulus().0.pow(NB_CTXT as u32) / 2) as i64;

    executor.setup(&cks, sks.clone());

    default_all_eq_slices_test_case_impl(
        executor,
        &sks,
        &cks,
        -modulus..modulus,
        RadixClientKey::encrypt_signed,
    );
}
