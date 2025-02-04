use crate::core_crypto::gpu::vec::GpuIndex;
use crate::core_crypto::gpu::{get_number_of_gpus, CudaStreams};
use crate::integer::gpu::ciphertext::boolean_value::CudaBooleanBlock;
use crate::integer::gpu::ciphertext::{CudaSignedRadixCiphertext, CudaUnsignedRadixCiphertext};
use crate::integer::gpu::server_key::radix::tests_unsigned::GpuContext;
use crate::integer::gpu::CudaServerKey;
use crate::integer::server_key::radix_parallel::tests_cases_unsigned::FunctionExecutor;
use crate::integer::{
    BooleanBlock, RadixCiphertext, RadixClientKey, ServerKey, SignedRadixCiphertext, U256,
};
use rand::Rng;
use std::sync::Arc;

pub(crate) mod test_erc20;
pub(crate) mod test_random_op_sequence;
pub(crate) mod test_signed_erc20;
pub(crate) mod test_signed_random_op_sequence;

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
        let num_gpus = get_number_of_gpus();
        let gpu_index = GpuIndex::new(rand::thread_rng().gen_range(0..num_gpus));
        let streams = CudaStreams::new_single_gpu(gpu_index);

        let sks = CudaServerKey::new(cks.as_ref(), &streams);
        streams.synchronize();
        let context = GpuContext { streams, sks };
        self.context = Some(context);
    }
}

/// For default/unchecked binary functions
impl<'a, F> FunctionExecutor<(&'a RadixCiphertext, &'a RadixCiphertext), RadixCiphertext>
    for GpuMultiDeviceFunctionExecutor<F>
where
    F: Fn(
        &CudaServerKey,
        &CudaUnsignedRadixCiphertext,
        &CudaUnsignedRadixCiphertext,
        &CudaStreams,
    ) -> CudaUnsignedRadixCiphertext,
{
    fn setup(&mut self, cks: &RadixClientKey, sks: Arc<ServerKey>) {
        self.setup_from_keys(cks, &sks);
    }

    fn execute(&mut self, input: (&'a RadixCiphertext, &'a RadixCiphertext)) -> RadixCiphertext {
        let context = self
            .context
            .as_ref()
            .expect("setup was not properly called");

        let d_ctxt_1 =
            CudaUnsignedRadixCiphertext::from_radix_ciphertext(input.0, &context.streams);
        let d_ctxt_2 =
            CudaUnsignedRadixCiphertext::from_radix_ciphertext(input.1, &context.streams);

        let gpu_result = (self.func)(&context.sks, &d_ctxt_1, &d_ctxt_2, &context.streams);

        gpu_result.to_radix_ciphertext(&context.streams)
    }
}

/// For unchecked/default assign binary functions
impl<'a, F> FunctionExecutor<(&'a mut RadixCiphertext, &'a RadixCiphertext), ()>
    for GpuMultiDeviceFunctionExecutor<F>
where
    F: Fn(
        &CudaServerKey,
        &mut CudaUnsignedRadixCiphertext,
        &CudaUnsignedRadixCiphertext,
        &CudaStreams,
    ),
{
    fn setup(&mut self, cks: &RadixClientKey, sks: Arc<ServerKey>) {
        self.setup_from_keys(cks, &sks);
    }

    fn execute(&mut self, input: (&'a mut RadixCiphertext, &'a RadixCiphertext)) {
        let context = self
            .context
            .as_ref()
            .expect("setup was not properly called");

        let mut d_ctxt_1 =
            CudaUnsignedRadixCiphertext::from_radix_ciphertext(input.0, &context.streams);
        let d_ctxt_2 =
            CudaUnsignedRadixCiphertext::from_radix_ciphertext(input.1, &context.streams);

        (self.func)(&context.sks, &mut d_ctxt_1, &d_ctxt_2, &context.streams);

        *input.0 = d_ctxt_1.to_radix_ciphertext(&context.streams);
    }
}

/// For unchecked/default binary functions with one scalar input
impl<'a, F> FunctionExecutor<(&'a RadixCiphertext, u64), RadixCiphertext>
    for GpuMultiDeviceFunctionExecutor<F>
where
    F: Fn(
        &CudaServerKey,
        &CudaUnsignedRadixCiphertext,
        u64,
        &CudaStreams,
    ) -> CudaUnsignedRadixCiphertext,
{
    fn setup(&mut self, cks: &RadixClientKey, sks: Arc<ServerKey>) {
        self.setup_from_keys(cks, &sks);
    }

    fn execute(&mut self, input: (&'a RadixCiphertext, u64)) -> RadixCiphertext {
        let context = self
            .context
            .as_ref()
            .expect("setup was not properly called");

        let d_ctxt_1 =
            CudaUnsignedRadixCiphertext::from_radix_ciphertext(input.0, &context.streams);

        let gpu_result = (self.func)(&context.sks, &d_ctxt_1, input.1, &context.streams);

        gpu_result.to_radix_ciphertext(&context.streams)
    }
}

/// For unchecked/default binary functions with one scalar input
impl<F> FunctionExecutor<(RadixCiphertext, u64), RadixCiphertext>
    for GpuMultiDeviceFunctionExecutor<F>
where
    F: Fn(
        &CudaServerKey,
        &CudaUnsignedRadixCiphertext,
        u64,
        &CudaStreams,
    ) -> CudaUnsignedRadixCiphertext,
{
    fn setup(&mut self, cks: &RadixClientKey, sks: Arc<ServerKey>) {
        self.setup_from_keys(cks, &sks);
    }

    fn execute(&mut self, input: (RadixCiphertext, u64)) -> RadixCiphertext {
        let context = self
            .context
            .as_ref()
            .expect("setup was not properly called");

        let d_ctxt_1 =
            CudaUnsignedRadixCiphertext::from_radix_ciphertext(&input.0, &context.streams);

        let gpu_result = (self.func)(&context.sks, &d_ctxt_1, input.1, &context.streams);

        gpu_result.to_radix_ciphertext(&context.streams)
    }
}

// Unary Function
impl<'a, F> FunctionExecutor<&'a RadixCiphertext, RadixCiphertext>
    for GpuMultiDeviceFunctionExecutor<F>
where
    F: Fn(
        &CudaServerKey,
        &CudaUnsignedRadixCiphertext,
        &CudaStreams,
    ) -> CudaUnsignedRadixCiphertext,
{
    fn setup(&mut self, cks: &RadixClientKey, sks: Arc<ServerKey>) {
        self.setup_from_keys(cks, &sks);
    }

    fn execute(&mut self, input: &'a RadixCiphertext) -> RadixCiphertext {
        let context = self
            .context
            .as_ref()
            .expect("setup was not properly called");

        let d_ctxt_1 = CudaUnsignedRadixCiphertext::from_radix_ciphertext(input, &context.streams);

        let gpu_result = (self.func)(&context.sks, &d_ctxt_1, &context.streams);

        gpu_result.to_radix_ciphertext(&context.streams)
    }
}

// Unary assign Function
impl<'a, F> FunctionExecutor<&'a mut RadixCiphertext, ()> for GpuMultiDeviceFunctionExecutor<F>
where
    F: Fn(&CudaServerKey, &mut CudaUnsignedRadixCiphertext, &CudaStreams),
{
    fn setup(&mut self, cks: &RadixClientKey, sks: Arc<ServerKey>) {
        self.setup_from_keys(cks, &sks);
    }

    fn execute(&mut self, input: &'a mut RadixCiphertext) {
        let context = self
            .context
            .as_ref()
            .expect("setup was not properly called");

        let mut d_ctxt_1 =
            CudaUnsignedRadixCiphertext::from_radix_ciphertext(input, &context.streams);

        (self.func)(&context.sks, &mut d_ctxt_1, &context.streams);

        *input = d_ctxt_1.to_radix_ciphertext(&context.streams)
    }
}

impl<'a, F> FunctionExecutor<&'a Vec<RadixCiphertext>, Option<RadixCiphertext>>
    for GpuMultiDeviceFunctionExecutor<F>
where
    F: Fn(&CudaServerKey, Vec<CudaUnsignedRadixCiphertext>) -> Option<CudaUnsignedRadixCiphertext>,
{
    fn setup(&mut self, cks: &RadixClientKey, sks: Arc<ServerKey>) {
        self.setup_from_keys(cks, &sks);
    }

    fn execute(&mut self, input: &'a Vec<RadixCiphertext>) -> Option<RadixCiphertext> {
        let context = self
            .context
            .as_ref()
            .expect("setup was not properly called");

        let d_ctxt_1: Vec<CudaUnsignedRadixCiphertext> = input
            .iter()
            .map(|ct| CudaUnsignedRadixCiphertext::from_radix_ciphertext(ct, &context.streams))
            .collect();

        let d_res = (self.func)(&context.sks, d_ctxt_1);

        Some(d_res.unwrap().to_radix_ciphertext(&context.streams))
    }
}

impl<'a, F>
    FunctionExecutor<(&'a RadixCiphertext, &'a RadixCiphertext), (RadixCiphertext, BooleanBlock)>
    for GpuMultiDeviceFunctionExecutor<F>
where
    F: Fn(
        &CudaServerKey,
        &CudaUnsignedRadixCiphertext,
        &CudaUnsignedRadixCiphertext,
        &CudaStreams,
    ) -> (CudaUnsignedRadixCiphertext, CudaBooleanBlock),
{
    fn setup(&mut self, cks: &RadixClientKey, sks: Arc<ServerKey>) {
        self.setup_from_keys(cks, &sks);
    }

    fn execute(
        &mut self,
        input: (&'a RadixCiphertext, &'a RadixCiphertext),
    ) -> (RadixCiphertext, BooleanBlock) {
        let context = self
            .context
            .as_ref()
            .expect("setup was not properly called");

        let d_ctxt_1: CudaUnsignedRadixCiphertext =
            CudaUnsignedRadixCiphertext::from_radix_ciphertext(input.0, &context.streams);
        let d_ctxt_2: CudaUnsignedRadixCiphertext =
            CudaUnsignedRadixCiphertext::from_radix_ciphertext(input.1, &context.streams);

        let d_res = (self.func)(&context.sks, &d_ctxt_1, &d_ctxt_2, &context.streams);

        (
            d_res.0.to_radix_ciphertext(&context.streams),
            d_res.1.to_boolean_block(&context.streams),
        )
    }
}

/// For unchecked/default unsigned overflowing scalar operations
impl<'a, F> FunctionExecutor<(&'a RadixCiphertext, u64), (RadixCiphertext, BooleanBlock)>
    for GpuMultiDeviceFunctionExecutor<F>
where
    F: Fn(
        &CudaServerKey,
        &CudaUnsignedRadixCiphertext,
        u64,
        &CudaStreams,
    ) -> (CudaUnsignedRadixCiphertext, CudaBooleanBlock),
{
    fn setup(&mut self, cks: &RadixClientKey, sks: Arc<ServerKey>) {
        self.setup_from_keys(cks, &sks);
    }

    fn execute(&mut self, input: (&'a RadixCiphertext, u64)) -> (RadixCiphertext, BooleanBlock) {
        let context = self
            .context
            .as_ref()
            .expect("setup was not properly called");

        let d_ctxt_1: CudaUnsignedRadixCiphertext =
            CudaUnsignedRadixCiphertext::from_radix_ciphertext(input.0, &context.streams);

        let d_res = (self.func)(&context.sks, &d_ctxt_1, input.1, &context.streams);

        (
            d_res.0.to_radix_ciphertext(&context.streams),
            d_res.1.to_boolean_block(&context.streams),
        )
    }
}

/// For ilog operation
impl<'a, F> FunctionExecutor<&'a RadixCiphertext, (RadixCiphertext, BooleanBlock)>
    for GpuMultiDeviceFunctionExecutor<F>
where
    F: Fn(
        &CudaServerKey,
        &CudaUnsignedRadixCiphertext,
        &CudaStreams,
    ) -> (CudaUnsignedRadixCiphertext, CudaBooleanBlock),
{
    fn setup(&mut self, cks: &RadixClientKey, sks: Arc<ServerKey>) {
        self.setup_from_keys(cks, &sks);
    }

    fn execute(&mut self, input: &'a RadixCiphertext) -> (RadixCiphertext, BooleanBlock) {
        let context = self
            .context
            .as_ref()
            .expect("setup was not properly called");

        let d_ctxt_1: CudaUnsignedRadixCiphertext =
            CudaUnsignedRadixCiphertext::from_radix_ciphertext(input, &context.streams);

        let d_res = (self.func)(&context.sks, &d_ctxt_1, &context.streams);

        (
            d_res.0.to_radix_ciphertext(&context.streams),
            d_res.1.to_boolean_block(&context.streams),
        )
    }
}

impl<'a, F>
    FunctionExecutor<(&'a RadixCiphertext, &'a RadixCiphertext), (RadixCiphertext, RadixCiphertext)>
    for GpuMultiDeviceFunctionExecutor<F>
where
    F: Fn(
        &CudaServerKey,
        &CudaUnsignedRadixCiphertext,
        &CudaUnsignedRadixCiphertext,
        &CudaStreams,
    ) -> (CudaUnsignedRadixCiphertext, CudaUnsignedRadixCiphertext),
{
    fn setup(&mut self, cks: &RadixClientKey, sks: Arc<ServerKey>) {
        self.setup_from_keys(cks, &sks);
    }

    fn execute(
        &mut self,
        input: (&'a RadixCiphertext, &'a RadixCiphertext),
    ) -> (RadixCiphertext, RadixCiphertext) {
        let context = self
            .context
            .as_ref()
            .expect("setup was not properly called");

        let d_ctxt_1: CudaUnsignedRadixCiphertext =
            CudaUnsignedRadixCiphertext::from_radix_ciphertext(input.0, &context.streams);
        let d_ctxt_2: CudaUnsignedRadixCiphertext =
            CudaUnsignedRadixCiphertext::from_radix_ciphertext(input.1, &context.streams);

        let d_res = (self.func)(&context.sks, &d_ctxt_1, &d_ctxt_2, &context.streams);

        (
            d_res.0.to_radix_ciphertext(&context.streams),
            d_res.1.to_radix_ciphertext(&context.streams),
        )
    }
}

impl<'a, F> FunctionExecutor<(&'a RadixCiphertext, u64), (RadixCiphertext, RadixCiphertext)>
    for GpuMultiDeviceFunctionExecutor<F>
where
    F: Fn(
        &CudaServerKey,
        &CudaUnsignedRadixCiphertext,
        u64,
        &CudaStreams,
    ) -> (CudaUnsignedRadixCiphertext, CudaUnsignedRadixCiphertext),
{
    fn setup(&mut self, cks: &RadixClientKey, sks: Arc<ServerKey>) {
        self.setup_from_keys(cks, &sks);
    }

    fn execute(&mut self, input: (&'a RadixCiphertext, u64)) -> (RadixCiphertext, RadixCiphertext) {
        let context = self
            .context
            .as_ref()
            .expect("setup was not properly called");

        let d_ctxt_1: CudaUnsignedRadixCiphertext =
            CudaUnsignedRadixCiphertext::from_radix_ciphertext(input.0, &context.streams);

        let d_res = (self.func)(&context.sks, &d_ctxt_1, input.1, &context.streams);

        (
            d_res.0.to_radix_ciphertext(&context.streams),
            d_res.1.to_radix_ciphertext(&context.streams),
        )
    }
}

impl<'a, F> FunctionExecutor<(&'a RadixCiphertext, &'a RadixCiphertext), BooleanBlock>
    for GpuMultiDeviceFunctionExecutor<F>
where
    F: Fn(
        &CudaServerKey,
        &CudaUnsignedRadixCiphertext,
        &CudaUnsignedRadixCiphertext,
        &CudaStreams,
    ) -> CudaBooleanBlock,
{
    fn setup(&mut self, cks: &RadixClientKey, sks: Arc<ServerKey>) {
        self.setup_from_keys(cks, &sks);
    }

    fn execute(&mut self, input: (&'a RadixCiphertext, &'a RadixCiphertext)) -> BooleanBlock {
        let context = self
            .context
            .as_ref()
            .expect("setup was not properly called");

        let d_ctxt_1: CudaUnsignedRadixCiphertext =
            CudaUnsignedRadixCiphertext::from_radix_ciphertext(input.0, &context.streams);
        let d_ctxt_2: CudaUnsignedRadixCiphertext =
            CudaUnsignedRadixCiphertext::from_radix_ciphertext(input.1, &context.streams);

        let d_res = (self.func)(&context.sks, &d_ctxt_1, &d_ctxt_2, &context.streams);

        d_res.to_boolean_block(&context.streams)
    }
}

impl<'a, F> FunctionExecutor<(&'a RadixCiphertext, u64), BooleanBlock>
    for GpuMultiDeviceFunctionExecutor<F>
where
    F: Fn(&CudaServerKey, &CudaUnsignedRadixCiphertext, u64, &CudaStreams) -> CudaBooleanBlock,
{
    fn setup(&mut self, cks: &RadixClientKey, sks: Arc<ServerKey>) {
        self.setup_from_keys(cks, &sks);
    }

    fn execute(&mut self, input: (&'a RadixCiphertext, u64)) -> BooleanBlock {
        let context = self
            .context
            .as_ref()
            .expect("setup was not properly called");

        let d_ctxt_1: CudaUnsignedRadixCiphertext =
            CudaUnsignedRadixCiphertext::from_radix_ciphertext(input.0, &context.streams);

        let d_res = (self.func)(&context.sks, &d_ctxt_1, input.1, &context.streams);

        d_res.to_boolean_block(&context.streams)
    }
}

impl<'a, F> FunctionExecutor<(&'a RadixCiphertext, U256), BooleanBlock>
    for GpuMultiDeviceFunctionExecutor<F>
where
    F: Fn(&CudaServerKey, &CudaUnsignedRadixCiphertext, U256, &CudaStreams) -> CudaBooleanBlock,
{
    fn setup(&mut self, cks: &RadixClientKey, sks: Arc<ServerKey>) {
        self.setup_from_keys(cks, &sks);
    }

    fn execute(&mut self, input: (&'a RadixCiphertext, U256)) -> BooleanBlock {
        let context = self
            .context
            .as_ref()
            .expect("setup was not properly called");

        let d_ctxt_1: CudaUnsignedRadixCiphertext =
            CudaUnsignedRadixCiphertext::from_radix_ciphertext(input.0, &context.streams);

        let d_res = (self.func)(&context.sks, &d_ctxt_1, input.1, &context.streams);

        d_res.to_boolean_block(&context.streams)
    }
}

impl<'a, F> FunctionExecutor<(&'a RadixCiphertext, U256), RadixCiphertext>
    for GpuMultiDeviceFunctionExecutor<F>
where
    F: Fn(
        &CudaServerKey,
        &CudaUnsignedRadixCiphertext,
        U256,
        &CudaStreams,
    ) -> CudaUnsignedRadixCiphertext,
{
    fn setup(&mut self, cks: &RadixClientKey, sks: Arc<ServerKey>) {
        self.setup_from_keys(cks, &sks);
    }

    fn execute(&mut self, input: (&'a RadixCiphertext, U256)) -> RadixCiphertext {
        let context = self
            .context
            .as_ref()
            .expect("setup was not properly called");

        let d_ctxt_1: CudaUnsignedRadixCiphertext =
            CudaUnsignedRadixCiphertext::from_radix_ciphertext(input.0, &context.streams);

        let d_res = (self.func)(&context.sks, &d_ctxt_1, input.1, &context.streams);

        d_res.to_radix_ciphertext(&context.streams)
    }
}

impl<'a, F>
    FunctionExecutor<(&'a BooleanBlock, &'a RadixCiphertext, &'a RadixCiphertext), RadixCiphertext>
    for GpuMultiDeviceFunctionExecutor<F>
where
    F: Fn(
        &CudaServerKey,
        &CudaBooleanBlock,
        &CudaUnsignedRadixCiphertext,
        &CudaUnsignedRadixCiphertext,
        &CudaStreams,
    ) -> CudaUnsignedRadixCiphertext,
{
    fn setup(&mut self, cks: &RadixClientKey, sks: Arc<ServerKey>) {
        self.setup_from_keys(cks, &sks);
    }

    fn execute(
        &mut self,
        input: (&'a BooleanBlock, &'a RadixCiphertext, &'a RadixCiphertext),
    ) -> RadixCiphertext {
        let context = self
            .context
            .as_ref()
            .expect("setup was not properly called");

        let d_ctxt_1: CudaBooleanBlock =
            CudaBooleanBlock::from_boolean_block(input.0, &context.streams);
        let d_ctxt_2: CudaUnsignedRadixCiphertext =
            CudaUnsignedRadixCiphertext::from_radix_ciphertext(input.1, &context.streams);
        let d_ctxt_3: CudaUnsignedRadixCiphertext =
            CudaUnsignedRadixCiphertext::from_radix_ciphertext(input.2, &context.streams);

        let d_res = (self.func)(
            &context.sks,
            &d_ctxt_1,
            &d_ctxt_2,
            &d_ctxt_3,
            &context.streams,
        );

        d_res.to_radix_ciphertext(&context.streams)
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
