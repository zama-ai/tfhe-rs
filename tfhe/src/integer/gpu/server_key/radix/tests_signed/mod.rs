pub(crate) mod test_abs;
pub(crate) mod test_add;
pub(crate) mod test_bitwise_op;
pub(crate) mod test_cmux;
pub(crate) mod test_comparison;
pub(crate) mod test_div_mod;
pub(crate) mod test_ilog2;
pub(crate) mod test_mul;
pub(crate) mod test_neg;
mod test_oprf;
pub(crate) mod test_rotate;
pub(crate) mod test_scalar_add;
pub(crate) mod test_scalar_bitwise_op;
pub(crate) mod test_scalar_comparison;
pub(crate) mod test_scalar_div_mod;
pub(crate) mod test_scalar_mul;
pub(crate) mod test_scalar_rotate;
pub(crate) mod test_scalar_shift;
pub(crate) mod test_scalar_sub;
pub(crate) mod test_shift;
pub(crate) mod test_sub;
pub(crate) mod test_vector_comparisons;

use crate::core_crypto::gpu::{get_number_of_gpus, CudaStreams};
use crate::integer::gpu::ciphertext::boolean_value::CudaBooleanBlock;
use crate::integer::gpu::ciphertext::{CudaSignedRadixCiphertext, CudaUnsignedRadixCiphertext};
use crate::integer::gpu::server_key::radix::tests_unsigned::{GpuContext, GpuFunctionExecutor};
use crate::integer::gpu::CudaServerKey;
use crate::integer::server_key::radix_parallel::tests_cases_unsigned::FunctionExecutor;
use crate::integer::{
    BooleanBlock, RadixCiphertext, RadixClientKey, ServerKey, SignedRadixCiphertext, U256,
};
use crate::GpuIndex;
use rand::seq::SliceRandom;
use rand::Rng;
use std::sync::Arc;
use tfhe_csprng::seeders::Seed;

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
//For ilog2
impl<'a, F> FunctionExecutor<&'a SignedRadixCiphertext, RadixCiphertext> for GpuFunctionExecutor<F>
where
    F: Fn(&CudaServerKey, &CudaSignedRadixCiphertext, &CudaStreams) -> CudaUnsignedRadixCiphertext,
{
    fn setup(&mut self, cks: &RadixClientKey, sks: Arc<ServerKey>) {
        self.setup_from_keys(cks, &sks);
    }

    fn execute(&mut self, input: &'a SignedRadixCiphertext) -> RadixCiphertext {
        let context = self
            .context
            .as_ref()
            .expect("setup was not properly called");

        let d_ctxt =
            CudaSignedRadixCiphertext::from_signed_radix_ciphertext(input, &context.streams);

        let gpu_result = (self.func)(&context.sks, &d_ctxt, &context.streams);

        gpu_result.to_radix_ciphertext(&context.streams)
    }
}

impl<'a, F> FunctionExecutor<&'a SignedRadixCiphertext, (SignedRadixCiphertext, BooleanBlock)>
    for GpuFunctionExecutor<F>
where
    F: Fn(
        &CudaServerKey,
        &CudaSignedRadixCiphertext,
        &CudaStreams,
    ) -> (CudaSignedRadixCiphertext, CudaBooleanBlock),
{
    fn setup(&mut self, cks: &RadixClientKey, sks: Arc<ServerKey>) {
        self.setup_from_keys(cks, &sks);
    }

    fn execute(
        &mut self,
        input: &'a SignedRadixCiphertext,
    ) -> (SignedRadixCiphertext, BooleanBlock) {
        let context = self
            .context
            .as_ref()
            .expect("setup was not properly called");

        let d_ctxt =
            CudaSignedRadixCiphertext::from_signed_radix_ciphertext(input, &context.streams);

        let (gpu_result_0, gpu_result_1) = (self.func)(&context.sks, &d_ctxt, &context.streams);

        (
            gpu_result_0.to_signed_radix_ciphertext(&context.streams),
            gpu_result_1.to_boolean_block(&context.streams),
        )
    }
}

impl<'a, F> FunctionExecutor<&'a SignedRadixCiphertext, (RadixCiphertext, BooleanBlock)>
    for GpuFunctionExecutor<F>
where
    F: Fn(
        &CudaServerKey,
        &CudaSignedRadixCiphertext,
        &CudaStreams,
    ) -> (CudaUnsignedRadixCiphertext, CudaBooleanBlock),
{
    fn setup(&mut self, cks: &RadixClientKey, sks: Arc<ServerKey>) {
        self.setup_from_keys(cks, &sks);
    }

    fn execute(&mut self, input: &'a SignedRadixCiphertext) -> (RadixCiphertext, BooleanBlock) {
        let context = self
            .context
            .as_ref()
            .expect("setup was not properly called");

        let d_ctxt =
            CudaSignedRadixCiphertext::from_signed_radix_ciphertext(input, &context.streams);

        let gpu_result = (self.func)(&context.sks, &d_ctxt, &context.streams);

        (
            gpu_result.0.to_radix_ciphertext(&context.streams),
            gpu_result.1.to_boolean_block(&context.streams),
        )
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

/// For unchecked/default binary functions with one scalar input and two encrypted outputs
impl<'a, F>
    FunctionExecutor<
        (&'a SignedRadixCiphertext, i64),
        (SignedRadixCiphertext, SignedRadixCiphertext),
    > for GpuFunctionExecutor<F>
where
    F: Fn(
        &CudaServerKey,
        &CudaSignedRadixCiphertext,
        i64,
        &CudaStreams,
    ) -> (CudaSignedRadixCiphertext, CudaSignedRadixCiphertext),
{
    fn setup(&mut self, cks: &RadixClientKey, sks: Arc<ServerKey>) {
        self.setup_from_keys(cks, &sks);
    }

    fn execute(
        &mut self,
        input: (&'a SignedRadixCiphertext, i64),
    ) -> (SignedRadixCiphertext, SignedRadixCiphertext) {
        let context = self
            .context
            .as_ref()
            .expect("setup was not properly called");

        let d_ctxt_1 =
            CudaSignedRadixCiphertext::from_signed_radix_ciphertext(input.0, &context.streams);

        let (gpu_result_1, gpu_result_2) =
            (self.func)(&context.sks, &d_ctxt_1, input.1, &context.streams);

        (
            gpu_result_1.to_signed_radix_ciphertext(&context.streams),
            gpu_result_2.to_signed_radix_ciphertext(&context.streams),
        )
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

// for signed overflowing scalar ops
impl<'a, F>
    FunctionExecutor<(&'a SignedRadixCiphertext, i64), (SignedRadixCiphertext, BooleanBlock)>
    for GpuFunctionExecutor<F>
where
    F: Fn(
        &CudaServerKey,
        &CudaSignedRadixCiphertext,
        i64,
        &CudaStreams,
    ) -> (CudaSignedRadixCiphertext, CudaBooleanBlock),
{
    fn setup(&mut self, cks: &RadixClientKey, sks: Arc<ServerKey>) {
        self.setup_from_keys(cks, &sks);
    }

    fn execute(
        &mut self,
        input: (&'a SignedRadixCiphertext, i64),
    ) -> (SignedRadixCiphertext, BooleanBlock) {
        let context = self
            .context
            .as_ref()
            .expect("setup was not properly called");

        let d_ctxt_1: CudaSignedRadixCiphertext =
            CudaSignedRadixCiphertext::from_signed_radix_ciphertext(input.0, &context.streams);

        let (d_res, d_res_bool) = (self.func)(&context.sks, &d_ctxt_1, input.1, &context.streams);

        (
            d_res.to_signed_radix_ciphertext(&context.streams),
            d_res_bool.to_boolean_block(&context.streams),
        )
    }
}

// for signed div_rem
impl<'a, F>
    FunctionExecutor<
        (&'a SignedRadixCiphertext, &'a SignedRadixCiphertext),
        (SignedRadixCiphertext, SignedRadixCiphertext),
    > for GpuFunctionExecutor<F>
where
    F: Fn(
        &CudaServerKey,
        &CudaSignedRadixCiphertext,
        &CudaSignedRadixCiphertext,
        &CudaStreams,
    ) -> (CudaSignedRadixCiphertext, CudaSignedRadixCiphertext),
{
    fn setup(&mut self, cks: &RadixClientKey, sks: Arc<ServerKey>) {
        self.setup_from_keys(cks, &sks);
    }

    fn execute(
        &mut self,
        input: (&'a SignedRadixCiphertext, &'a SignedRadixCiphertext),
    ) -> (SignedRadixCiphertext, SignedRadixCiphertext) {
        let context = self
            .context
            .as_ref()
            .expect("setup was not properly called");

        let d_ctxt_1: CudaSignedRadixCiphertext =
            CudaSignedRadixCiphertext::from_signed_radix_ciphertext(input.0, &context.streams);
        let d_ctxt_2: CudaSignedRadixCiphertext =
            CudaSignedRadixCiphertext::from_signed_radix_ciphertext(input.1, &context.streams);

        let d_res = (self.func)(&context.sks, &d_ctxt_1, &d_ctxt_2, &context.streams);

        (
            d_res.0.to_signed_radix_ciphertext(&context.streams),
            d_res.1.to_signed_radix_ciphertext(&context.streams),
        )
    }
}
impl<'a, F>
    FunctionExecutor<(&'a [SignedRadixCiphertext], &'a [SignedRadixCiphertext]), BooleanBlock>
    for GpuFunctionExecutor<F>
where
    F: Fn(
        &CudaServerKey,
        &[CudaSignedRadixCiphertext],
        &[CudaSignedRadixCiphertext],
        &CudaStreams,
    ) -> CudaBooleanBlock,
{
    fn setup(&mut self, cks: &RadixClientKey, sks: Arc<ServerKey>) {
        self.setup_from_keys(cks, &sks);
    }

    fn execute(
        &mut self,
        input: (&'a [SignedRadixCiphertext], &'a [SignedRadixCiphertext]),
    ) -> BooleanBlock {
        let context = self
            .context
            .as_ref()
            .expect("setup was not properly called");

        let mut d_ctxs1 = Vec::<CudaSignedRadixCiphertext>::with_capacity(input.0.len());
        for ctx in input.0 {
            d_ctxs1.push(CudaSignedRadixCiphertext::from_signed_radix_ciphertext(
                ctx,
                &context.streams,
            ));
        }
        let mut d_ctxs2 = Vec::<CudaSignedRadixCiphertext>::with_capacity(input.0.len());
        for ctx in input.1 {
            d_ctxs2.push(CudaSignedRadixCiphertext::from_signed_radix_ciphertext(
                ctx,
                &context.streams,
            ));
        }

        let d_block = (self.func)(&context.sks, &d_ctxs1, &d_ctxs2, &context.streams);
        d_block.to_boolean_block(&context.streams)
    }
}

pub(crate) struct GpuMultiDeviceFunctionExecutor<F> {
    pub(crate) context: Option<GpuContext>,
    pub(crate) func: F,
}

impl<F> GpuMultiDeviceFunctionExecutor<F> {
    pub(crate) fn new(func: F) -> Self {
        Self {
            context: None,
            func,
        }
    }
}

impl<F> GpuMultiDeviceFunctionExecutor<F> {
    pub(crate) fn setup_from_keys(&mut self, cks: &RadixClientKey, _sks: &Arc<ServerKey>) {
        // Sample a random subset of 1-N gpus, where N is the number of available GPUs
        // A GPU index should not appear twice in the subset
        let num_gpus = get_number_of_gpus();
        let mut rng = rand::rng();
        let num_gpus_to_use = rng.gen_range(1..=num_gpus as usize);
        let mut all_gpu_indexes: Vec<u32> = (0..num_gpus).collect();
        all_gpu_indexes.shuffle(&mut rng);
        let gpu_indexes_to_use = &all_gpu_indexes[..num_gpus_to_use];
        let gpu_indexes: Vec<GpuIndex> = gpu_indexes_to_use
            .iter()
            .map(|idx| GpuIndex::new(*idx))
            .collect();
        println!("Setting up server key on GPUs: [{gpu_indexes_to_use:?}]");

        let streams = CudaStreams::new_multi_gpu_with_indexes(&gpu_indexes);

        let sks = CudaServerKey::new(cks.as_ref(), &streams);
        streams.synchronize();
        let context = GpuContext { streams, sks };
        self.context = Some(context);
    }
}

/// For default/unchecked binary signed functions
impl<'a, F>
    FunctionExecutor<(&'a SignedRadixCiphertext, &'a SignedRadixCiphertext), SignedRadixCiphertext>
    for GpuMultiDeviceFunctionExecutor<F>
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

impl<F> FunctionExecutor<(Seed, u64), SignedRadixCiphertext> for GpuMultiDeviceFunctionExecutor<F>
where
    F: Fn(&CudaServerKey, Seed, u64, &CudaStreams) -> CudaSignedRadixCiphertext,
{
    fn setup(&mut self, cks: &RadixClientKey, sks: Arc<ServerKey>) {
        self.setup_from_keys(cks, &sks);
    }

    fn execute(&mut self, input: (Seed, u64)) -> SignedRadixCiphertext {
        let context = self
            .context
            .as_ref()
            .expect("setup was not properly called");

        let gpu_result = (self.func)(&context.sks, input.0, input.1, &context.streams);

        gpu_result.to_signed_radix_ciphertext(&context.streams)
    }
}

impl<F> FunctionExecutor<(Seed, u64, u64), SignedRadixCiphertext>
    for GpuMultiDeviceFunctionExecutor<F>
where
    F: Fn(&CudaServerKey, Seed, u64, u64, &CudaStreams) -> CudaSignedRadixCiphertext,
{
    fn setup(&mut self, cks: &RadixClientKey, sks: Arc<ServerKey>) {
        self.setup_from_keys(cks, &sks);
    }

    fn execute(&mut self, input: (Seed, u64, u64)) -> SignedRadixCiphertext {
        let context = self
            .context
            .as_ref()
            .expect("setup was not properly called");

        let gpu_result = (self.func)(&context.sks, input.0, input.1, input.2, &context.streams);

        gpu_result.to_signed_radix_ciphertext(&context.streams)
    }
}

impl<'a, F>
    FunctionExecutor<(&'a SignedRadixCiphertext, &'a RadixCiphertext), SignedRadixCiphertext>
    for GpuMultiDeviceFunctionExecutor<F>
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
    for GpuMultiDeviceFunctionExecutor<F>
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
    for GpuMultiDeviceFunctionExecutor<F>
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
impl<'a, F> FunctionExecutor<(&'a SignedRadixCiphertext, u64), SignedRadixCiphertext>
    for GpuMultiDeviceFunctionExecutor<F>
where
    F: Fn(
        &CudaServerKey,
        &CudaSignedRadixCiphertext,
        u64,
        &CudaStreams,
    ) -> CudaSignedRadixCiphertext,
{
    fn setup(&mut self, cks: &RadixClientKey, sks: Arc<ServerKey>) {
        self.setup_from_keys(cks, &sks);
    }

    fn execute(&mut self, input: (&'a SignedRadixCiphertext, u64)) -> SignedRadixCiphertext {
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
    for GpuMultiDeviceFunctionExecutor<F>
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

// Unary Function
impl<'a, F> FunctionExecutor<&'a SignedRadixCiphertext, SignedRadixCiphertext>
    for GpuMultiDeviceFunctionExecutor<F>
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

        let d_ctxt_1 =
            CudaSignedRadixCiphertext::from_signed_radix_ciphertext(input, &context.streams);

        let gpu_result = (self.func)(&context.sks, &d_ctxt_1, &context.streams);

        gpu_result.to_signed_radix_ciphertext(&context.streams)
    }
}

impl<'a, F> FunctionExecutor<&'a SignedRadixCiphertext, RadixCiphertext>
    for GpuMultiDeviceFunctionExecutor<F>
where
    F: Fn(&CudaServerKey, &CudaSignedRadixCiphertext, &CudaStreams) -> CudaUnsignedRadixCiphertext,
{
    fn setup(&mut self, cks: &RadixClientKey, sks: Arc<ServerKey>) {
        self.setup_from_keys(cks, &sks);
    }

    fn execute(&mut self, input: &'a SignedRadixCiphertext) -> RadixCiphertext {
        let context = self
            .context
            .as_ref()
            .expect("setup was not properly called");

        let d_ctxt_1 =
            CudaSignedRadixCiphertext::from_signed_radix_ciphertext(input, &context.streams);

        let gpu_result = (self.func)(&context.sks, &d_ctxt_1, &context.streams);

        gpu_result.to_radix_ciphertext(&context.streams)
    }
}

// Unary assign Function
impl<'a, F> FunctionExecutor<&'a mut SignedRadixCiphertext, ()>
    for GpuMultiDeviceFunctionExecutor<F>
where
    F: Fn(&CudaServerKey, &mut CudaSignedRadixCiphertext, &CudaStreams),
{
    fn setup(&mut self, cks: &RadixClientKey, sks: Arc<ServerKey>) {
        self.setup_from_keys(cks, &sks);
    }

    fn execute(&mut self, input: &'a mut SignedRadixCiphertext) {
        let context = self
            .context
            .as_ref()
            .expect("setup was not properly called");

        let mut d_ctxt_1 =
            CudaSignedRadixCiphertext::from_signed_radix_ciphertext(input, &context.streams);

        (self.func)(&context.sks, &mut d_ctxt_1, &context.streams);

        *input = d_ctxt_1.to_signed_radix_ciphertext(&context.streams)
    }
}

impl<'a, F> FunctionExecutor<&'a Vec<SignedRadixCiphertext>, Option<SignedRadixCiphertext>>
    for GpuMultiDeviceFunctionExecutor<F>
where
    F: Fn(&CudaServerKey, Vec<CudaSignedRadixCiphertext>) -> Option<CudaSignedRadixCiphertext>,
{
    fn setup(&mut self, cks: &RadixClientKey, sks: Arc<ServerKey>) {
        self.setup_from_keys(cks, &sks);
    }

    fn execute(&mut self, input: &'a Vec<SignedRadixCiphertext>) -> Option<SignedRadixCiphertext> {
        let context = self
            .context
            .as_ref()
            .expect("setup was not properly called");

        let d_ctxt_1: Vec<CudaSignedRadixCiphertext> = input
            .iter()
            .map(|ct| CudaSignedRadixCiphertext::from_signed_radix_ciphertext(ct, &context.streams))
            .collect();

        let d_res = (self.func)(&context.sks, d_ctxt_1);

        Some(d_res.unwrap().to_signed_radix_ciphertext(&context.streams))
    }
}

impl<'a, F>
    FunctionExecutor<
        (&'a SignedRadixCiphertext, &'a SignedRadixCiphertext),
        (SignedRadixCiphertext, BooleanBlock),
    > for GpuMultiDeviceFunctionExecutor<F>
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

        let d_res = (self.func)(&context.sks, &d_ctxt_1, &d_ctxt_2, &context.streams);

        (
            d_res.0.to_signed_radix_ciphertext(&context.streams),
            d_res.1.to_boolean_block(&context.streams),
        )
    }
}

/// For unchecked/default unsigned overflowing scalar operations
impl<'a, F>
    FunctionExecutor<(&'a SignedRadixCiphertext, i64), (SignedRadixCiphertext, BooleanBlock)>
    for GpuMultiDeviceFunctionExecutor<F>
where
    F: Fn(
        &CudaServerKey,
        &CudaSignedRadixCiphertext,
        i64,
        &CudaStreams,
    ) -> (CudaSignedRadixCiphertext, CudaBooleanBlock),
{
    fn setup(&mut self, cks: &RadixClientKey, sks: Arc<ServerKey>) {
        self.setup_from_keys(cks, &sks);
    }

    fn execute(
        &mut self,
        input: (&'a SignedRadixCiphertext, i64),
    ) -> (SignedRadixCiphertext, BooleanBlock) {
        let context = self
            .context
            .as_ref()
            .expect("setup was not properly called");

        let d_ctxt_1: CudaSignedRadixCiphertext =
            CudaSignedRadixCiphertext::from_signed_radix_ciphertext(input.0, &context.streams);

        let d_res = (self.func)(&context.sks, &d_ctxt_1, input.1, &context.streams);

        (
            d_res.0.to_signed_radix_ciphertext(&context.streams),
            d_res.1.to_boolean_block(&context.streams),
        )
    }
}

impl<'a, F> FunctionExecutor<&'a SignedRadixCiphertext, (SignedRadixCiphertext, BooleanBlock)>
    for GpuMultiDeviceFunctionExecutor<F>
where
    F: Fn(
        &CudaServerKey,
        &CudaSignedRadixCiphertext,
        &CudaStreams,
    ) -> (CudaSignedRadixCiphertext, CudaBooleanBlock),
{
    fn setup(&mut self, cks: &RadixClientKey, sks: Arc<ServerKey>) {
        self.setup_from_keys(cks, &sks);
    }

    fn execute(
        &mut self,
        input: &'a SignedRadixCiphertext,
    ) -> (SignedRadixCiphertext, BooleanBlock) {
        let context = self
            .context
            .as_ref()
            .expect("setup was not properly called");

        let d_ctxt_1: CudaSignedRadixCiphertext =
            CudaSignedRadixCiphertext::from_signed_radix_ciphertext(input, &context.streams);

        let d_res = (self.func)(&context.sks, &d_ctxt_1, &context.streams);

        (
            d_res.0.to_signed_radix_ciphertext(&context.streams),
            d_res.1.to_boolean_block(&context.streams),
        )
    }
}

impl<'a, F>
    FunctionExecutor<
        (&'a SignedRadixCiphertext, &'a SignedRadixCiphertext),
        (SignedRadixCiphertext, SignedRadixCiphertext),
    > for GpuMultiDeviceFunctionExecutor<F>
where
    F: Fn(
        &CudaServerKey,
        &CudaSignedRadixCiphertext,
        &CudaSignedRadixCiphertext,
        &CudaStreams,
    ) -> (CudaSignedRadixCiphertext, CudaSignedRadixCiphertext),
{
    fn setup(&mut self, cks: &RadixClientKey, sks: Arc<ServerKey>) {
        self.setup_from_keys(cks, &sks);
    }

    fn execute(
        &mut self,
        input: (&'a SignedRadixCiphertext, &'a SignedRadixCiphertext),
    ) -> (SignedRadixCiphertext, SignedRadixCiphertext) {
        let context = self
            .context
            .as_ref()
            .expect("setup was not properly called");

        let d_ctxt_1: CudaSignedRadixCiphertext =
            CudaSignedRadixCiphertext::from_signed_radix_ciphertext(input.0, &context.streams);
        let d_ctxt_2: CudaSignedRadixCiphertext =
            CudaSignedRadixCiphertext::from_signed_radix_ciphertext(input.1, &context.streams);

        let d_res = (self.func)(&context.sks, &d_ctxt_1, &d_ctxt_2, &context.streams);

        (
            d_res.0.to_signed_radix_ciphertext(&context.streams),
            d_res.1.to_signed_radix_ciphertext(&context.streams),
        )
    }
}

impl<'a, F>
    FunctionExecutor<
        (&'a SignedRadixCiphertext, i64),
        (SignedRadixCiphertext, SignedRadixCiphertext),
    > for GpuMultiDeviceFunctionExecutor<F>
where
    F: Fn(
        &CudaServerKey,
        &CudaSignedRadixCiphertext,
        i64,
        &CudaStreams,
    ) -> (CudaSignedRadixCiphertext, CudaSignedRadixCiphertext),
{
    fn setup(&mut self, cks: &RadixClientKey, sks: Arc<ServerKey>) {
        self.setup_from_keys(cks, &sks);
    }

    fn execute(
        &mut self,
        input: (&'a SignedRadixCiphertext, i64),
    ) -> (SignedRadixCiphertext, SignedRadixCiphertext) {
        let context = self
            .context
            .as_ref()
            .expect("setup was not properly called");

        let d_ctxt_1: CudaSignedRadixCiphertext =
            CudaSignedRadixCiphertext::from_signed_radix_ciphertext(input.0, &context.streams);

        let d_res = (self.func)(&context.sks, &d_ctxt_1, input.1, &context.streams);

        (
            d_res.0.to_signed_radix_ciphertext(&context.streams),
            d_res.1.to_signed_radix_ciphertext(&context.streams),
        )
    }
}

impl<'a, F> FunctionExecutor<(&'a SignedRadixCiphertext, &'a SignedRadixCiphertext), BooleanBlock>
    for GpuMultiDeviceFunctionExecutor<F>
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

impl<'a, F> FunctionExecutor<(&'a SignedRadixCiphertext, i64), BooleanBlock>
    for GpuMultiDeviceFunctionExecutor<F>
where
    F: Fn(&CudaServerKey, &CudaSignedRadixCiphertext, i64, &CudaStreams) -> CudaBooleanBlock,
{
    fn setup(&mut self, cks: &RadixClientKey, sks: Arc<ServerKey>) {
        self.setup_from_keys(cks, &sks);
    }

    fn execute(&mut self, input: (&'a SignedRadixCiphertext, i64)) -> BooleanBlock {
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

impl<'a, F> FunctionExecutor<(&'a SignedRadixCiphertext, U256), BooleanBlock>
    for GpuMultiDeviceFunctionExecutor<F>
where
    F: Fn(&CudaServerKey, &CudaSignedRadixCiphertext, U256, &CudaStreams) -> CudaBooleanBlock,
{
    fn setup(&mut self, cks: &RadixClientKey, sks: Arc<ServerKey>) {
        self.setup_from_keys(cks, &sks);
    }

    fn execute(&mut self, input: (&'a SignedRadixCiphertext, U256)) -> BooleanBlock {
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

impl<'a, F> FunctionExecutor<(&'a SignedRadixCiphertext, U256), SignedRadixCiphertext>
    for GpuMultiDeviceFunctionExecutor<F>
where
    F: Fn(
        &CudaServerKey,
        &CudaSignedRadixCiphertext,
        U256,
        &CudaStreams,
    ) -> CudaSignedRadixCiphertext,
{
    fn setup(&mut self, cks: &RadixClientKey, sks: Arc<ServerKey>) {
        self.setup_from_keys(cks, &sks);
    }

    fn execute(&mut self, input: (&'a SignedRadixCiphertext, U256)) -> SignedRadixCiphertext {
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
    > for GpuMultiDeviceFunctionExecutor<F>
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
