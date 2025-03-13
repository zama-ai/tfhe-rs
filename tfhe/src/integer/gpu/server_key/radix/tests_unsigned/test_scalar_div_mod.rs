use crate::integer::gpu::server_key::radix::tests_unsigned::{
    create_gpu_parameterized_test, GpuFunctionExecutor,
};
use crate::integer::gpu::CudaServerKey;
use crate::integer::server_key::radix_parallel::tests_unsigned::test_scalar_div_mod::default_scalar_div_rem_test;
use crate::shortint::parameters::current_params::*;
use crate::shortint::parameters::current_params_gpu::*;
use crate::shortint::parameters::*;

create_gpu_parameterized_test!(integer_scalar_div_rem);

fn integer_scalar_div_rem<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::scalar_div_rem);
    default_scalar_div_rem_test(param, executor);
}
