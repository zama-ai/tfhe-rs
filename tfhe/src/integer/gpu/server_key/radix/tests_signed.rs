use std::sync::Arc;
use crate::core_crypto::gpu::CudaStream;
use crate::integer::gpu::ciphertext::CudaRadixCiphertext;
use super::tests::{create_gpu_parametrized_test, GpuFunctionExecutor};
use crate::integer::gpu::CudaServerKey;
use crate::integer::{RadixClientKey, ServerKey, SignedRadixCiphertext};
use crate::integer::server_key::radix_parallel::test_cases_signed::{integer_signed_default_add_test, integer_signed_unchecked_add_test};
use crate::integer::server_key::radix_parallel::tests_cases_unsigned::FunctionExecutor;
use crate::shortint::parameters::*;

// Unchecked operations
create_gpu_parametrized_test!(integer_signed_unchecked_add);

// Default operations
create_gpu_parametrized_test!(integer_signed_add);

/// For default/unchecked binary functions
impl<'a, F> FunctionExecutor<(&'a SignedRadixCiphertext, &'a SignedRadixCiphertext), SignedRadixCiphertext>
for GpuFunctionExecutor<F>
    where
        F: Fn(
            &CudaServerKey,
            &CudaRadixCiphertext,
            &CudaRadixCiphertext,
            &CudaStream,
        ) -> CudaRadixCiphertext,
{
    fn setup(&mut self, cks: &RadixClientKey, sks: Arc<ServerKey>) {
        self.setup_from_keys(cks, &sks);
    }

    fn execute(&mut self, input: (&'a SignedRadixCiphertext, &'a SignedRadixCiphertext)) -> SignedRadixCiphertext {
        let context = self
            .context
            .as_ref()
            .expect("setup was not properly called");

        let d_ctxt_1 = CudaRadixCiphertext::from_signed_radix_ciphertext(input.0, &context.stream);
        let d_ctxt_2 = CudaRadixCiphertext::from_signed_radix_ciphertext(input.1, &context.stream);

        let gpu_result = (self.func)(&context.sks, &d_ctxt_1, &d_ctxt_2, &context.stream);

        gpu_result.to_signed_radix_ciphertext(&context.stream)
    }
}

fn integer_signed_unchecked_add<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::unchecked_add);
    integer_signed_unchecked_add_test(param, executor);
}

fn integer_signed_add<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::add);
    integer_signed_default_add_test(param, executor);
}
