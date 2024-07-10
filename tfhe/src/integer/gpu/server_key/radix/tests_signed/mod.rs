pub(crate) mod test_add;
pub(crate) mod test_bitwise_op;
pub(crate) mod test_cmux;
pub(crate) mod test_comparison;
pub(crate) mod test_mul;
pub(crate) mod test_neg;
pub(crate) mod test_rotate;
pub(crate) mod test_scalar_add;
pub(crate) mod test_scalar_bitwise_op;
pub(crate) mod test_scalar_comparison;
pub(crate) mod test_scalar_mul;
pub(crate) mod test_scalar_rotate;
pub(crate) mod test_scalar_shift;
pub(crate) mod test_scalar_sub;
pub(crate) mod test_shift;
pub(crate) mod test_sub;

use crate::core_crypto::gpu::CudaStreams;
use crate::integer::gpu::ciphertext::boolean_value::CudaBooleanBlock;
use crate::integer::gpu::ciphertext::{CudaSignedRadixCiphertext, CudaUnsignedRadixCiphertext};
use crate::integer::gpu::server_key::radix::tests_unsigned::GpuFunctionExecutor;
use crate::integer::gpu::CudaServerKey;
use crate::integer::server_key::radix_parallel::tests_cases_unsigned::FunctionExecutor;
use crate::integer::{
    BooleanBlock, RadixCiphertext, RadixClientKey, ServerKey, SignedRadixCiphertext,
};
use std::sync::Arc;

/// For default/unchecked unary functions
impl<'a, F> FunctionExecutor<&'a SignedRadixCiphertext, SignedRadixCiphertext>
    for GpuFunctionExecutor<F>
where
    F: Fn(&CudaServerKey, &CudaSignedRadixCiphertext, &CudaStreams) -> CudaSignedRadixCiphertext,
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
            CudaSignedRadixCiphertext::from_signed_radix_ciphertext(input, &context.streams);

        let gpu_result = (self.func)(&context.sks, &d_ctxt, &context.streams);

        gpu_result.to_signed_radix_ciphertext(&context.streams)
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
        &CudaStreams,
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
            CudaSignedRadixCiphertext::from_signed_radix_ciphertext(input.0, &context.streams);
        let d_ctxt_2 =
            CudaSignedRadixCiphertext::from_signed_radix_ciphertext(input.1, &context.streams);

        let gpu_result = (self.func)(&context.sks, &d_ctxt_1, &d_ctxt_2, &context.streams);

        gpu_result.to_signed_radix_ciphertext(&context.streams)
    }
}

/// For default/unchecked binary functions
impl<'a, F>
    FunctionExecutor<(&'a SignedRadixCiphertext, &'a RadixCiphertext), SignedRadixCiphertext>
    for GpuFunctionExecutor<F>
where
    F: Fn(
        &CudaServerKey,
        &CudaSignedRadixCiphertext,
        &CudaUnsignedRadixCiphertext,
        &CudaStreams,
    ) -> CudaSignedRadixCiphertext,
{
    fn setup(&mut self, cks: &RadixClientKey, sks: Arc<ServerKey>) {
        self.setup_from_keys(cks, &sks);
    }

    fn execute(
        &mut self,
        input: (&'a SignedRadixCiphertext, &'a RadixCiphertext),
    ) -> SignedRadixCiphertext {
        let context = self
            .context
            .as_ref()
            .expect("setup was not properly called");

        let d_ctxt_1 =
            CudaSignedRadixCiphertext::from_signed_radix_ciphertext(input.0, &context.streams);
        let d_ctxt_2 =
            CudaUnsignedRadixCiphertext::from_radix_ciphertext(input.1, &context.streams);

        let gpu_result = (self.func)(&context.sks, &d_ctxt_1, &d_ctxt_2, &context.streams);

        gpu_result.to_signed_radix_ciphertext(&context.streams)
    }
}

/// For unchecked/default assign binary functions
impl<'a, F> FunctionExecutor<(&'a mut SignedRadixCiphertext, &'a SignedRadixCiphertext), ()>
    for GpuFunctionExecutor<F>
where
    F: Fn(&CudaServerKey, &mut CudaSignedRadixCiphertext, &CudaSignedRadixCiphertext, &CudaStreams),
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
            CudaSignedRadixCiphertext::from_signed_radix_ciphertext(input.0, &context.streams);
        let d_ctxt_2 =
            CudaSignedRadixCiphertext::from_signed_radix_ciphertext(input.1, &context.streams);

        (self.func)(&context.sks, &mut d_ctxt_1, &d_ctxt_2, &context.streams);

        *input.0 = d_ctxt_1.to_signed_radix_ciphertext(&context.streams);
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
        &CudaStreams,
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
            CudaSignedRadixCiphertext::from_signed_radix_ciphertext(input.0, &context.streams);

        let gpu_result = (self.func)(&context.sks, &d_ctxt_1, input.1, &context.streams);

        gpu_result.to_signed_radix_ciphertext(&context.streams)
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
        &CudaStreams,
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
            CudaSignedRadixCiphertext::from_signed_radix_ciphertext(&input.0, &context.streams);

        let gpu_result = (self.func)(&context.sks, &d_ctxt_1, input.1, &context.streams);

        gpu_result.to_signed_radix_ciphertext(&context.streams)
    }
}

impl<'a, F> FunctionExecutor<(&'a SignedRadixCiphertext, &'a SignedRadixCiphertext), BooleanBlock>
    for GpuFunctionExecutor<F>
where
    F: Fn(
        &CudaServerKey,
        &CudaSignedRadixCiphertext,
        &CudaSignedRadixCiphertext,
        &CudaStreams,
    ) -> CudaBooleanBlock,
{
    fn setup(&mut self, cks: &RadixClientKey, sks: Arc<ServerKey>) {
        self.setup_from_keys(cks, &sks);
    }

    fn execute(
        &mut self,
        input: (&'a SignedRadixCiphertext, &'a SignedRadixCiphertext),
    ) -> BooleanBlock {
        let context = self
            .context
            .as_ref()
            .expect("setup was not properly called");

        let d_ctxt_1: CudaSignedRadixCiphertext =
            CudaSignedRadixCiphertext::from_signed_radix_ciphertext(input.0, &context.streams);
        let d_ctxt_2: CudaSignedRadixCiphertext =
            CudaSignedRadixCiphertext::from_signed_radix_ciphertext(input.1, &context.streams);

        let d_res = (self.func)(&context.sks, &d_ctxt_1, &d_ctxt_2, &context.streams);

        d_res.to_boolean_block(&context.streams)
    }
}

impl<'a, F> FunctionExecutor<(&'a SignedRadixCiphertext, i128), BooleanBlock>
    for GpuFunctionExecutor<F>
where
    F: Fn(&CudaServerKey, &CudaSignedRadixCiphertext, i128, &CudaStreams) -> CudaBooleanBlock,
{
    fn setup(&mut self, cks: &RadixClientKey, sks: Arc<ServerKey>) {
        self.setup_from_keys(cks, &sks);
    }

    fn execute(&mut self, input: (&'a SignedRadixCiphertext, i128)) -> BooleanBlock {
        let context = self
            .context
            .as_ref()
            .expect("setup was not properly called");

        let d_ctxt_1: CudaSignedRadixCiphertext =
            CudaSignedRadixCiphertext::from_signed_radix_ciphertext(input.0, &context.streams);

        let d_res = (self.func)(&context.sks, &d_ctxt_1, input.1, &context.streams);

        d_res.to_boolean_block(&context.streams)
    }
}

impl<'a, F> FunctionExecutor<(&'a SignedRadixCiphertext, i128), SignedRadixCiphertext>
    for GpuFunctionExecutor<F>
where
    F: Fn(
        &CudaServerKey,
        &CudaSignedRadixCiphertext,
        i128,
        &CudaStreams,
    ) -> CudaSignedRadixCiphertext,
{
    fn setup(&mut self, cks: &RadixClientKey, sks: Arc<ServerKey>) {
        self.setup_from_keys(cks, &sks);
    }

    fn execute(&mut self, input: (&'a SignedRadixCiphertext, i128)) -> SignedRadixCiphertext {
        let context = self
            .context
            .as_ref()
            .expect("setup was not properly called");

        let d_ctxt_1: CudaSignedRadixCiphertext =
            CudaSignedRadixCiphertext::from_signed_radix_ciphertext(input.0, &context.streams);

        let d_res = (self.func)(&context.sks, &d_ctxt_1, input.1, &context.streams);

        d_res.to_signed_radix_ciphertext(&context.streams)
    }
}

impl<'a, F>
    FunctionExecutor<
        (
            &'a BooleanBlock,
            &'a SignedRadixCiphertext,
            &'a SignedRadixCiphertext,
        ),
        SignedRadixCiphertext,
    > for GpuFunctionExecutor<F>
where
    F: Fn(
        &CudaServerKey,
        &CudaBooleanBlock,
        &CudaSignedRadixCiphertext,
        &CudaSignedRadixCiphertext,
        &CudaStreams,
    ) -> CudaSignedRadixCiphertext,
{
    fn setup(&mut self, cks: &RadixClientKey, sks: Arc<ServerKey>) {
        self.setup_from_keys(cks, &sks);
    }

    fn execute(
        &mut self,
        input: (
            &'a BooleanBlock,
            &'a SignedRadixCiphertext,
            &'a SignedRadixCiphertext,
        ),
    ) -> SignedRadixCiphertext {
        let context = self
            .context
            .as_ref()
            .expect("setup was not properly called");

        let d_ctxt_1: CudaBooleanBlock =
            CudaBooleanBlock::from_boolean_block(input.0, &context.streams);
        let d_ctxt_2: CudaSignedRadixCiphertext =
            CudaSignedRadixCiphertext::from_signed_radix_ciphertext(input.1, &context.streams);
        let d_ctxt_3: CudaSignedRadixCiphertext =
            CudaSignedRadixCiphertext::from_signed_radix_ciphertext(input.2, &context.streams);

        let d_res = (self.func)(
            &context.sks,
            &d_ctxt_1,
            &d_ctxt_2,
            &d_ctxt_3,
            &context.streams,
        );

        d_res.to_signed_radix_ciphertext(&context.streams)
    }
}
impl<'a, F>
    FunctionExecutor<
        (&'a SignedRadixCiphertext, &'a SignedRadixCiphertext),
        (SignedRadixCiphertext, BooleanBlock),
    > for GpuFunctionExecutor<F>
where
    F: Fn(
        &CudaServerKey,
        &CudaSignedRadixCiphertext,
        &CudaSignedRadixCiphertext,
        &CudaStreams,
    ) -> (CudaSignedRadixCiphertext, CudaBooleanBlock),
{
    fn setup(&mut self, cks: &RadixClientKey, sks: Arc<ServerKey>) {
        self.setup_from_keys(cks, &sks);
    }

    fn execute(
        &mut self,
        input: (&'a SignedRadixCiphertext, &'a SignedRadixCiphertext),
    ) -> (SignedRadixCiphertext, BooleanBlock) {
        let context = self
            .context
            .as_ref()
            .expect("setup was not properly called");

        let d_ctxt_1: CudaSignedRadixCiphertext =
            CudaSignedRadixCiphertext::from_signed_radix_ciphertext(input.0, &context.streams);
        let d_ctxt_2: CudaSignedRadixCiphertext =
            CudaSignedRadixCiphertext::from_signed_radix_ciphertext(input.1, &context.streams);

        let (d_res, d_res_bool) = (self.func)(&context.sks, &d_ctxt_1, &d_ctxt_2, &context.streams);

        (
            d_res.to_signed_radix_ciphertext(&context.streams),
            d_res_bool.to_boolean_block(&context.streams),
        )
    }
}
