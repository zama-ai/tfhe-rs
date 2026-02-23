use crate::integer::keycache::KEY_CACHE;
use crate::integer::server_key::radix_parallel::tests_cases_unsigned::FunctionExecutor;
use crate::integer::server_key::radix_parallel::tests_signed::{signed_mul_under_modulus, NB_CTXT};
use crate::integer::server_key::radix_parallel::tests_unsigned::{
    nb_tests_for_params, CpuFunctionExecutor,
};
use crate::integer::tests::create_parameterized_test;
use crate::integer::{IntegerKeyKind, RadixClientKey, ServerKey, SignedRadixCiphertext};
#[cfg(tarpaulin)]
use crate::shortint::parameters::coverage_parameters::*;
use crate::shortint::parameters::test_params::*;
use crate::shortint::parameters::*;
use rand::Rng;
use std::sync::Arc;

create_parameterized_test!(integer_signed_unchecked_scalar_mul);

fn integer_signed_unchecked_scalar_mul<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::unchecked_scalar_mul_parallelized);
    signed_unchecked_scalar_mul_test(param, executor);
}

pub(crate) fn signed_unchecked_scalar_mul_test<P, T>(param: P, mut executor: T)
where
    P: Into<TestParameters>,
    T: for<'a> FunctionExecutor<(&'a SignedRadixCiphertext, i64), SignedRadixCiphertext>,
{
    let param = param.into();
    let nb_tests = nb_tests_for_params(param);
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let sks = Arc::new(sks);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    let mut rng = rand::rng();

    let modulus = (cks.parameters().message_modulus().0.pow(NB_CTXT as u32) / 2) as i64;

    executor.setup(&cks, sks);

    for _ in 0..nb_tests {
        let clear_0 = rng.gen::<i64>() % modulus;
        let clear_1 = rng.gen::<i64>() % modulus;

        let ctxt_0 = cks.encrypt_signed(clear_0);

        let ct_res = executor.execute((&ctxt_0, clear_1));
        let dec_res: i64 = cks.decrypt_signed(&ct_res);
        let clear_res = signed_mul_under_modulus(clear_0, clear_1, modulus);
        assert_eq!(clear_res, dec_res);
    }
}
