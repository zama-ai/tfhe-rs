use crate::integer::server_key::radix_parallel::tests_cases_signed::{
    signed_default_neg_test, signed_smart_neg_test, signed_unchecked_neg_test,
};
use crate::integer::server_key::radix_parallel::tests_unsigned::CpuFunctionExecutor;
use crate::integer::tests::create_parametrized_test;
use crate::integer::ServerKey;
#[cfg(tarpaulin)]
use crate::shortint::parameters::coverage_parameters::*;
use crate::shortint::parameters::*;

create_parametrized_test!(integer_signed_unchecked_neg);
create_parametrized_test!(integer_signed_smart_neg);
create_parametrized_test!(integer_signed_default_neg);

fn integer_signed_unchecked_neg<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::unchecked_neg);
    signed_unchecked_neg_test(param, executor);
}

fn integer_signed_smart_neg<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::smart_neg_parallelized);
    signed_smart_neg_test(param, executor);
}

fn integer_signed_default_neg<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::neg_parallelized);
    signed_default_neg_test(param, executor);
}
