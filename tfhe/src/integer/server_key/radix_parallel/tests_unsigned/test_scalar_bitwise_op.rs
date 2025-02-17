use crate::integer::server_key::radix_parallel::tests_cases_unsigned::{
    default_scalar_bitand_test, default_scalar_bitor_test, default_scalar_bitxor_test,
};
use crate::integer::server_key::radix_parallel::tests_unsigned::CpuFunctionExecutor;
use crate::integer::tests::create_parameterized_test;
use crate::integer::ServerKey;
#[cfg(tarpaulin)]
use crate::shortint::parameters::coverage_parameters::*;
use crate::shortint::parameters::current_params::*;
use crate::shortint::parameters::*;

create_parameterized_test!(integer_default_scalar_bitand);
create_parameterized_test!(integer_default_scalar_bitor);
create_parameterized_test!(integer_default_scalar_bitxor);

fn integer_default_scalar_bitand<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::scalar_bitand_parallelized);
    default_scalar_bitand_test(param, executor);
}

fn integer_default_scalar_bitor<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::scalar_bitor_parallelized);
    default_scalar_bitor_test(param, executor);
}

fn integer_default_scalar_bitxor<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::scalar_bitxor_parallelized);
    default_scalar_bitxor_test(param, executor);
}
