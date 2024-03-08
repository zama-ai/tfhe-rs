use crate::core_crypto::gpu::{CudaDevice, CudaStream};
use crate::integer::gpu::ciphertext::CudaUnsignedRadixCiphertext;
use crate::integer::gpu::server_key::radix::tests_unsigned::{
    create_gpu_parametrized_test, GpuFunctionExecutor,
};
use crate::integer::gpu::CudaServerKey;
use crate::integer::server_key::radix_parallel::tests_cases_unsigned::{
    default_add_test, default_sum_ciphertexts_vec_test, unchecked_add_assign_test,
    unchecked_add_test,
};
use crate::shortint::parameters::*;

create_gpu_parametrized_test!(integer_unchecked_add);
create_gpu_parametrized_test!(integer_unchecked_add_assign);
create_gpu_parametrized_test!(integer_add);
create_gpu_parametrized_test!(integer_sum_ciphertexts_vec);

fn integer_unchecked_add<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::unchecked_add);
    unchecked_add_test(param, executor);
}

fn integer_unchecked_add_assign<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::unchecked_add_assign);
    unchecked_add_assign_test(param, executor);
}

fn integer_add<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::add);
    default_add_test(param, executor);
}

fn integer_sum_ciphertexts_vec<P>(param: P)
where
    P: Into<PBSParameters>,
{
    // Without this the compiler seems lost, and outputs errors about
    // 'one type is more general than the other' probably because the
    // `sum_ciphertexts_parallelized` is generic over the input collection
    let sum_vec = |sks: &CudaServerKey,
                   ctxt: Vec<CudaUnsignedRadixCiphertext>|
     -> Option<CudaUnsignedRadixCiphertext> {
        let stream = CudaStream::new_unchecked(CudaDevice::new(0));
        sks.sum_ciphertexts(ctxt, &stream)
    };
    let executor = GpuFunctionExecutor::new(sum_vec);
    default_sum_ciphertexts_vec_test(param, executor);
}
