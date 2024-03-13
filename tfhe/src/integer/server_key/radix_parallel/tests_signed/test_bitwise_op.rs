use crate::integer::server_key::radix_parallel::tests_cases_signed::{
    signed_default_bitand_test, signed_default_bitnot_test, signed_default_bitor_test,
    signed_default_bitxor_test, signed_unchecked_bitand_test, signed_unchecked_bitor_test,
    signed_unchecked_bitxor_test,
};
use crate::integer::server_key::radix_parallel::tests_unsigned::CpuFunctionExecutor;
use crate::integer::ServerKey;
#[cfg(tarpaulin)]
use crate::shortint::parameters::coverage_parameters::*;
use crate::shortint::parameters::*;

create_parametrized_test!(integer_signed_unchecked_bitand);
create_parametrized_test!(integer_signed_unchecked_bitor);
create_parametrized_test!(integer_signed_unchecked_bitxor);
create_parametrized_test!(integer_signed_default_bitnot);
create_parametrized_test!(integer_signed_default_bitand);
create_parametrized_test!(integer_signed_default_bitor);
create_parametrized_test!(integer_signed_default_bitxor);

fn integer_signed_unchecked_bitand<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::unchecked_bitand_parallelized);
    signed_unchecked_bitand_test(param, executor);
}

fn integer_signed_unchecked_bitor<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::unchecked_bitor_parallelized);
    signed_unchecked_bitor_test(param, executor);
}

fn integer_signed_unchecked_bitxor<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::unchecked_bitxor_parallelized);
    signed_unchecked_bitxor_test(param, executor);
}

fn integer_signed_default_bitnot<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::bitnot);
    signed_default_bitnot_test(param, executor);
}

fn integer_signed_default_bitand<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::bitand_parallelized);
    signed_default_bitand_test(param, executor);
}

fn integer_signed_default_bitor<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::bitor_parallelized);
    signed_default_bitor_test(param, executor);
}

fn integer_signed_default_bitxor<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::bitxor_parallelized);
    signed_default_bitxor_test(param, executor);
}
