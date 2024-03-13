pub(crate) mod test_add;
pub(crate) mod test_bitwise_op;
pub(crate) mod test_mul;
pub(crate) mod test_neg;
pub(crate) mod test_scalar_add;
pub(crate) mod test_scalar_bitwise_op;
pub(crate) mod test_scalar_sub;
pub(crate) mod test_sub;

use crate::core_crypto::gpu::CudaStream;
use crate::integer::gpu::ciphertext::CudaSignedRadixCiphertext;
use crate::integer::gpu::server_key::radix::tests_unsigned::GpuFunctionExecutor;
use crate::integer::gpu::CudaServerKey;
use crate::integer::server_key::radix_parallel::tests_cases_unsigned::FunctionExecutor;
use crate::integer::{RadixClientKey, ServerKey, SignedRadixCiphertext};
use std::sync::Arc;

/// For default/unchecked unary functions
impl<'a, F> FunctionExecutor<&'a SignedRadixCiphertext, SignedRadixCiphertext>
    for GpuFunctionExecutor<F>
where
    F: Fn(&CudaServerKey, &CudaSignedRadixCiphertext, &CudaStream) -> CudaSignedRadixCiphertext,
{
    fn setup(&mut self, cks: &RadixClientKey, sks: Arc<ServerKey>) {
        self.setup_from_keys(cks, &sks);
    }

    fn execute(&mut self, input: &'a SignedRadixCiphertext) -> SignedRadixCiphertext {
        let context = self
            .context
            .as_ref()
            .expect("setup was not properly called");

        let d_ctxt =
            CudaSignedRadixCiphertext::from_signed_radix_ciphertext(input, &context.stream);

        let gpu_result = (self.func)(&context.sks, &d_ctxt, &context.stream);

        gpu_result.to_signed_radix_ciphertext(&context.stream)
    }
}

/// For default/unchecked binary functions
impl<'a, F>
    FunctionExecutor<(&'a SignedRadixCiphertext, &'a SignedRadixCiphertext), SignedRadixCiphertext>
    for GpuFunctionExecutor<F>
where
    F: Fn(
        &CudaServerKey,
        &CudaSignedRadixCiphertext,
        &CudaSignedRadixCiphertext,
        &CudaStream,
    ) -> CudaSignedRadixCiphertext,
{
    fn setup(&mut self, cks: &RadixClientKey, sks: Arc<ServerKey>) {
        self.setup_from_keys(cks, &sks);
    }

    fn execute(
        &mut self,
        input: (&'a SignedRadixCiphertext, &'a SignedRadixCiphertext),
    ) -> SignedRadixCiphertext {
        let context = self
            .context
            .as_ref()
            .expect("setup was not properly called");

        let d_ctxt_1 =
            CudaSignedRadixCiphertext::from_signed_radix_ciphertext(input.0, &context.stream);
        let d_ctxt_2 =
            CudaSignedRadixCiphertext::from_signed_radix_ciphertext(input.1, &context.stream);

        let gpu_result = (self.func)(&context.sks, &d_ctxt_1, &d_ctxt_2, &context.stream);

        gpu_result.to_signed_radix_ciphertext(&context.stream)
    }
}

/// For unchecked/default assign binary functions
impl<'a, F> FunctionExecutor<(&'a mut SignedRadixCiphertext, &'a SignedRadixCiphertext), ()>
    for GpuFunctionExecutor<F>
where
    F: Fn(&CudaServerKey, &mut CudaSignedRadixCiphertext, &CudaSignedRadixCiphertext, &CudaStream),
{
    fn setup(&mut self, cks: &RadixClientKey, sks: Arc<ServerKey>) {
        self.setup_from_keys(cks, &sks);
    }

    fn execute(&mut self, input: (&'a mut SignedRadixCiphertext, &'a SignedRadixCiphertext)) {
        let context = self
            .context
            .as_ref()
            .expect("setup was not properly called");

        let mut d_ctxt_1 =
            CudaSignedRadixCiphertext::from_signed_radix_ciphertext(input.0, &context.stream);
        let d_ctxt_2 =
            CudaSignedRadixCiphertext::from_signed_radix_ciphertext(input.1, &context.stream);

        (self.func)(&context.sks, &mut d_ctxt_1, &d_ctxt_2, &context.stream);

        *input.0 = d_ctxt_1.to_signed_radix_ciphertext(&context.stream);
    }
}

/// For unchecked/default binary functions with one scalar input
impl<'a, F> FunctionExecutor<(&'a SignedRadixCiphertext, i64), SignedRadixCiphertext>
    for GpuFunctionExecutor<F>
where
    F: Fn(
        &CudaServerKey,
        &CudaSignedRadixCiphertext,
        i64,
        &CudaStream,
    ) -> CudaSignedRadixCiphertext,
{
    fn setup(&mut self, cks: &RadixClientKey, sks: Arc<ServerKey>) {
        self.setup_from_keys(cks, &sks);
    }

    fn execute(&mut self, input: (&'a SignedRadixCiphertext, i64)) -> SignedRadixCiphertext {
        let context = self
            .context
            .as_ref()
            .expect("setup was not properly called");

        let d_ctxt_1 =
            CudaSignedRadixCiphertext::from_signed_radix_ciphertext(input.0, &context.stream);

        let gpu_result = (self.func)(&context.sks, &d_ctxt_1, input.1, &context.stream);

        gpu_result.to_signed_radix_ciphertext(&context.stream)
    }
}

/// For unchecked/default binary functions with one scalar input
impl<F> FunctionExecutor<(SignedRadixCiphertext, i64), SignedRadixCiphertext>
    for GpuFunctionExecutor<F>
where
    F: Fn(
        &CudaServerKey,
        &CudaSignedRadixCiphertext,
        i64,
        &CudaStream,
    ) -> CudaSignedRadixCiphertext,
{
    fn setup(&mut self, cks: &RadixClientKey, sks: Arc<ServerKey>) {
        self.setup_from_keys(cks, &sks);
    }

    fn execute(&mut self, input: (SignedRadixCiphertext, i64)) -> SignedRadixCiphertext {
        let context = self
            .context
            .as_ref()
            .expect("setup was not properly called");

        let d_ctxt_1 =
            CudaSignedRadixCiphertext::from_signed_radix_ciphertext(&input.0, &context.stream);

        let gpu_result = (self.func)(&context.sks, &d_ctxt_1, input.1, &context.stream);

        gpu_result.to_signed_radix_ciphertext(&context.stream)
    }
}
