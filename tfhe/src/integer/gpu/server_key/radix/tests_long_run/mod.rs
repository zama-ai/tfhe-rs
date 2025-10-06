use crate::core_crypto::commons::generators::DeterministicSeeder;
use crate::core_crypto::gpu::{get_number_of_gpus, CudaStreams};
use crate::integer::gpu::ciphertext::boolean_value::CudaBooleanBlock;
use crate::integer::gpu::ciphertext::{CudaSignedRadixCiphertext, CudaUnsignedRadixCiphertext};
use crate::integer::gpu::server_key::radix::tests_unsigned::GpuContext;
use crate::integer::gpu::CudaServerKey;
use crate::integer::server_key::radix_parallel::tests_long_run::OpSequenceFunctionExecutor;
use crate::integer::{BooleanBlock, RadixCiphertext, RadixClientKey, SignedRadixCiphertext, U256};
use crate::{CompressedServerKey, CudaGpuChoice, CustomMultiGpuIndexes, GpuIndex};
use tfhe_csprng::generators::DefaultRandomGenerator;
use tfhe_csprng::seeders::{Seed, Seeder};

pub(crate) mod test_erc20;
pub(crate) mod test_random_op_sequence;
pub(crate) mod test_signed_erc20;
pub(crate) mod test_signed_random_op_sequence;

/// Fisher-Yates shuffle using the seeded random number generator
fn seeded_shuffle(v: &mut [u32], datagen: &mut DeterministicSeeder<DefaultRandomGenerator>) {
    for i in (1..v.len()).rev() {
        let j = datagen.seed().0 as usize % (i + 1);
        v.swap(i, j);
    }
}
fn make_random_gpu_set(datagen: &mut DeterministicSeeder<DefaultRandomGenerator>) -> CudaGpuChoice {
    // Sample a random subset of 1-N gpus, where N is the number of available GPUs
    // A GPU index should not appear twice in the subset
    #[cfg(not(feature = "gpu-debug-fake-multi-gpu"))]
    let num_gpus = get_number_of_gpus();

    #[cfg(feature = "gpu-debug-fake-multi-gpu")]
    let num_gpus_to_use = 2;

    #[cfg(not(feature = "gpu-debug-fake-multi-gpu"))]
    let num_gpus_to_use = if num_gpus > 1 {
        (1 + datagen.seed().0 as u32 % (num_gpus - 1)) as usize
    } else {
        1usize
    };

    #[cfg(feature = "gpu-debug-fake-multi-gpu")]
    let mut all_gpu_indexes: Vec<u32> = vec![0; num_gpus_to_use];

    #[cfg(not(feature = "gpu-debug-fake-multi-gpu"))]
    let mut all_gpu_indexes: Vec<u32> = (0..num_gpus).collect();
    seeded_shuffle(&mut all_gpu_indexes, datagen);

    let gpu_indexes_to_use = &all_gpu_indexes[..num_gpus_to_use];
    let gpu_indexes = CustomMultiGpuIndexes::new(
        gpu_indexes_to_use
            .iter()
            .map(|idx| GpuIndex::new(*idx))
            .collect(),
    );
    println!("Setting up server key on GPUs: [{gpu_indexes_to_use:?}]");

    gpu_indexes.into()
}

// Executor for GPU based operations in the random op sequence tests
pub(crate) struct OpSequenceGpuMultiDeviceFunctionExecutor<F> {
    pub(crate) context: Option<GpuContext>,
    pub(crate) func: F,
}

impl<F> OpSequenceGpuMultiDeviceFunctionExecutor<F> {
    pub(crate) fn new(func: F) -> Self {
        Self {
            context: None,
            func,
        }
    }
}

impl<F> OpSequenceGpuMultiDeviceFunctionExecutor<F> {
    pub(crate) fn setup_from_gpu_keys(
        &mut self,
        _cks: &RadixClientKey,
        sks: &CompressedServerKey,
        seeder: &mut DeterministicSeeder<DefaultRandomGenerator>,
    ) {
        let gpu_choice = make_random_gpu_set(seeder);
        let streams = gpu_choice.build_streams();

        let cuda_key = CudaServerKey::decompress_from_cpu(&sks.integer_key.key, &streams);

        let context = GpuContext {
            streams,
            sks: cuda_key,
        };
        self.context = Some(context);
    }
}

/// For default/unchecked binary functions
impl<'a, F> OpSequenceFunctionExecutor<(&'a RadixCiphertext, &'a RadixCiphertext), RadixCiphertext>
    for OpSequenceGpuMultiDeviceFunctionExecutor<F>
where
    F: Fn(
        &CudaServerKey,
        &CudaUnsignedRadixCiphertext,
        &CudaUnsignedRadixCiphertext,
        &CudaStreams,
    ) -> CudaUnsignedRadixCiphertext,
{
    fn setup(
        &mut self,
        cks: &RadixClientKey,
        sks: &CompressedServerKey,
        seeder: &mut DeterministicSeeder<DefaultRandomGenerator>,
    ) {
        self.setup_from_gpu_keys(cks, sks, seeder);
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
impl<'a, F> OpSequenceFunctionExecutor<(&'a mut RadixCiphertext, &'a RadixCiphertext), ()>
    for OpSequenceGpuMultiDeviceFunctionExecutor<F>
where
    F: Fn(
        &CudaServerKey,
        &mut CudaUnsignedRadixCiphertext,
        &CudaUnsignedRadixCiphertext,
        &CudaStreams,
    ),
{
    fn setup(
        &mut self,
        cks: &RadixClientKey,
        sks: &CompressedServerKey,
        seeder: &mut DeterministicSeeder<DefaultRandomGenerator>,
    ) {
        self.setup_from_gpu_keys(cks, sks, seeder);
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
impl<'a, F> OpSequenceFunctionExecutor<(&'a RadixCiphertext, u64), RadixCiphertext>
    for OpSequenceGpuMultiDeviceFunctionExecutor<F>
where
    F: Fn(
        &CudaServerKey,
        &CudaUnsignedRadixCiphertext,
        u64,
        &CudaStreams,
    ) -> CudaUnsignedRadixCiphertext,
{
    fn setup(
        &mut self,
        cks: &RadixClientKey,
        sks: &CompressedServerKey,
        seeder: &mut DeterministicSeeder<DefaultRandomGenerator>,
    ) {
        self.setup_from_gpu_keys(cks, sks, seeder);
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
impl<F> OpSequenceFunctionExecutor<(RadixCiphertext, u64), RadixCiphertext>
    for OpSequenceGpuMultiDeviceFunctionExecutor<F>
where
    F: Fn(
        &CudaServerKey,
        &CudaUnsignedRadixCiphertext,
        u64,
        &CudaStreams,
    ) -> CudaUnsignedRadixCiphertext,
{
    fn setup(
        &mut self,
        cks: &RadixClientKey,
        sks: &CompressedServerKey,
        seeder: &mut DeterministicSeeder<DefaultRandomGenerator>,
    ) {
        self.setup_from_gpu_keys(cks, sks, seeder);
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
impl<'a, F> OpSequenceFunctionExecutor<&'a RadixCiphertext, RadixCiphertext>
    for OpSequenceGpuMultiDeviceFunctionExecutor<F>
where
    F: Fn(
        &CudaServerKey,
        &CudaUnsignedRadixCiphertext,
        &CudaStreams,
    ) -> CudaUnsignedRadixCiphertext,
{
    fn setup(
        &mut self,
        cks: &RadixClientKey,
        sks: &CompressedServerKey,
        seeder: &mut DeterministicSeeder<DefaultRandomGenerator>,
    ) {
        self.setup_from_gpu_keys(cks, sks, seeder);
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
impl<'a, F> OpSequenceFunctionExecutor<&'a mut RadixCiphertext, ()>
    for OpSequenceGpuMultiDeviceFunctionExecutor<F>
where
    F: Fn(&CudaServerKey, &mut CudaUnsignedRadixCiphertext, &CudaStreams),
{
    fn setup(
        &mut self,
        cks: &RadixClientKey,
        sks: &CompressedServerKey,
        seeder: &mut DeterministicSeeder<DefaultRandomGenerator>,
    ) {
        self.setup_from_gpu_keys(cks, sks, seeder);
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

impl<'a, F> OpSequenceFunctionExecutor<&'a Vec<RadixCiphertext>, Option<RadixCiphertext>>
    for OpSequenceGpuMultiDeviceFunctionExecutor<F>
where
    F: Fn(&CudaServerKey, Vec<CudaUnsignedRadixCiphertext>) -> Option<CudaUnsignedRadixCiphertext>,
{
    fn setup(
        &mut self,
        cks: &RadixClientKey,
        sks: &CompressedServerKey,
        seeder: &mut DeterministicSeeder<DefaultRandomGenerator>,
    ) {
        self.setup_from_gpu_keys(cks, sks, seeder);
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
    OpSequenceFunctionExecutor<
        (&'a RadixCiphertext, &'a RadixCiphertext),
        (RadixCiphertext, BooleanBlock),
    > for OpSequenceGpuMultiDeviceFunctionExecutor<F>
where
    F: Fn(
        &CudaServerKey,
        &CudaUnsignedRadixCiphertext,
        &CudaUnsignedRadixCiphertext,
        &CudaStreams,
    ) -> (CudaUnsignedRadixCiphertext, CudaBooleanBlock),
{
    fn setup(
        &mut self,
        cks: &RadixClientKey,
        sks: &CompressedServerKey,
        seeder: &mut DeterministicSeeder<DefaultRandomGenerator>,
    ) {
        self.setup_from_gpu_keys(cks, sks, seeder);
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
impl<'a, F> OpSequenceFunctionExecutor<(&'a RadixCiphertext, u64), (RadixCiphertext, BooleanBlock)>
    for OpSequenceGpuMultiDeviceFunctionExecutor<F>
where
    F: Fn(
        &CudaServerKey,
        &CudaUnsignedRadixCiphertext,
        u64,
        &CudaStreams,
    ) -> (CudaUnsignedRadixCiphertext, CudaBooleanBlock),
{
    fn setup(
        &mut self,
        cks: &RadixClientKey,
        sks: &CompressedServerKey,
        seeder: &mut DeterministicSeeder<DefaultRandomGenerator>,
    ) {
        self.setup_from_gpu_keys(cks, sks, seeder);
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
impl<'a, F> OpSequenceFunctionExecutor<&'a RadixCiphertext, (RadixCiphertext, BooleanBlock)>
    for OpSequenceGpuMultiDeviceFunctionExecutor<F>
where
    F: Fn(
        &CudaServerKey,
        &CudaUnsignedRadixCiphertext,
        &CudaStreams,
    ) -> (CudaUnsignedRadixCiphertext, CudaBooleanBlock),
{
    fn setup(
        &mut self,
        cks: &RadixClientKey,
        sks: &CompressedServerKey,
        seeder: &mut DeterministicSeeder<DefaultRandomGenerator>,
    ) {
        self.setup_from_gpu_keys(cks, sks, seeder);
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
    OpSequenceFunctionExecutor<
        (&'a RadixCiphertext, &'a RadixCiphertext),
        (RadixCiphertext, RadixCiphertext),
    > for OpSequenceGpuMultiDeviceFunctionExecutor<F>
where
    F: Fn(
        &CudaServerKey,
        &CudaUnsignedRadixCiphertext,
        &CudaUnsignedRadixCiphertext,
        &CudaStreams,
    ) -> (CudaUnsignedRadixCiphertext, CudaUnsignedRadixCiphertext),
{
    fn setup(
        &mut self,
        cks: &RadixClientKey,
        sks: &CompressedServerKey,
        seeder: &mut DeterministicSeeder<DefaultRandomGenerator>,
    ) {
        self.setup_from_gpu_keys(cks, sks, seeder);
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

impl<'a, F>
    OpSequenceFunctionExecutor<(&'a RadixCiphertext, u64), (RadixCiphertext, RadixCiphertext)>
    for OpSequenceGpuMultiDeviceFunctionExecutor<F>
where
    F: Fn(
        &CudaServerKey,
        &CudaUnsignedRadixCiphertext,
        u64,
        &CudaStreams,
    ) -> (CudaUnsignedRadixCiphertext, CudaUnsignedRadixCiphertext),
{
    fn setup(
        &mut self,
        cks: &RadixClientKey,
        sks: &CompressedServerKey,
        seeder: &mut DeterministicSeeder<DefaultRandomGenerator>,
    ) {
        self.setup_from_gpu_keys(cks, sks, seeder);
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

impl<'a, F> OpSequenceFunctionExecutor<(&'a RadixCiphertext, &'a RadixCiphertext), BooleanBlock>
    for OpSequenceGpuMultiDeviceFunctionExecutor<F>
where
    F: Fn(
        &CudaServerKey,
        &CudaUnsignedRadixCiphertext,
        &CudaUnsignedRadixCiphertext,
        &CudaStreams,
    ) -> CudaBooleanBlock,
{
    fn setup(
        &mut self,
        cks: &RadixClientKey,
        sks: &CompressedServerKey,
        seeder: &mut DeterministicSeeder<DefaultRandomGenerator>,
    ) {
        self.setup_from_gpu_keys(cks, sks, seeder);
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

impl<'a, F> OpSequenceFunctionExecutor<(&'a RadixCiphertext, u64), BooleanBlock>
    for OpSequenceGpuMultiDeviceFunctionExecutor<F>
where
    F: Fn(&CudaServerKey, &CudaUnsignedRadixCiphertext, u64, &CudaStreams) -> CudaBooleanBlock,
{
    fn setup(
        &mut self,
        cks: &RadixClientKey,
        sks: &CompressedServerKey,
        seeder: &mut DeterministicSeeder<DefaultRandomGenerator>,
    ) {
        self.setup_from_gpu_keys(cks, sks, seeder);
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

impl<'a, F> OpSequenceFunctionExecutor<(&'a RadixCiphertext, U256), BooleanBlock>
    for OpSequenceGpuMultiDeviceFunctionExecutor<F>
where
    F: Fn(&CudaServerKey, &CudaUnsignedRadixCiphertext, U256, &CudaStreams) -> CudaBooleanBlock,
{
    fn setup(
        &mut self,
        cks: &RadixClientKey,
        sks: &CompressedServerKey,
        seeder: &mut DeterministicSeeder<DefaultRandomGenerator>,
    ) {
        self.setup_from_gpu_keys(cks, sks, seeder);
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

impl<'a, F> OpSequenceFunctionExecutor<(&'a RadixCiphertext, U256), RadixCiphertext>
    for OpSequenceGpuMultiDeviceFunctionExecutor<F>
where
    F: Fn(
        &CudaServerKey,
        &CudaUnsignedRadixCiphertext,
        U256,
        &CudaStreams,
    ) -> CudaUnsignedRadixCiphertext,
{
    fn setup(
        &mut self,
        cks: &RadixClientKey,
        sks: &CompressedServerKey,
        seeder: &mut DeterministicSeeder<DefaultRandomGenerator>,
    ) {
        self.setup_from_gpu_keys(cks, sks, seeder);
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
    OpSequenceFunctionExecutor<
        (&'a BooleanBlock, &'a RadixCiphertext, &'a RadixCiphertext),
        RadixCiphertext,
    > for OpSequenceGpuMultiDeviceFunctionExecutor<F>
where
    F: Fn(
        &CudaServerKey,
        &CudaBooleanBlock,
        &CudaUnsignedRadixCiphertext,
        &CudaUnsignedRadixCiphertext,
        &CudaStreams,
    ) -> CudaUnsignedRadixCiphertext,
{
    fn setup(
        &mut self,
        cks: &RadixClientKey,
        sks: &CompressedServerKey,
        seeder: &mut DeterministicSeeder<DefaultRandomGenerator>,
    ) {
        self.setup_from_gpu_keys(cks, sks, seeder);
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
    OpSequenceFunctionExecutor<
        (&'a SignedRadixCiphertext, &'a SignedRadixCiphertext),
        SignedRadixCiphertext,
    > for OpSequenceGpuMultiDeviceFunctionExecutor<F>
where
    F: Fn(
        &CudaServerKey,
        &CudaSignedRadixCiphertext,
        &CudaSignedRadixCiphertext,
        &CudaStreams,
    ) -> CudaSignedRadixCiphertext,
{
    fn setup(
        &mut self,
        cks: &RadixClientKey,
        sks: &CompressedServerKey,
        seeder: &mut DeterministicSeeder<DefaultRandomGenerator>,
    ) {
        self.setup_from_gpu_keys(cks, sks, seeder);
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
    OpSequenceFunctionExecutor<
        (&'a SignedRadixCiphertext, &'a RadixCiphertext),
        SignedRadixCiphertext,
    > for OpSequenceGpuMultiDeviceFunctionExecutor<F>
where
    F: Fn(
        &CudaServerKey,
        &CudaSignedRadixCiphertext,
        &CudaUnsignedRadixCiphertext,
        &CudaStreams,
    ) -> CudaSignedRadixCiphertext,
{
    fn setup(
        &mut self,
        cks: &RadixClientKey,
        sks: &CompressedServerKey,
        seeder: &mut DeterministicSeeder<DefaultRandomGenerator>,
    ) {
        self.setup_from_gpu_keys(cks, sks, seeder);
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
impl<'a, F>
    OpSequenceFunctionExecutor<(&'a mut SignedRadixCiphertext, &'a SignedRadixCiphertext), ()>
    for OpSequenceGpuMultiDeviceFunctionExecutor<F>
where
    F: Fn(&CudaServerKey, &mut CudaSignedRadixCiphertext, &CudaSignedRadixCiphertext, &CudaStreams),
{
    fn setup(
        &mut self,
        cks: &RadixClientKey,
        sks: &CompressedServerKey,
        seeder: &mut DeterministicSeeder<DefaultRandomGenerator>,
    ) {
        self.setup_from_gpu_keys(cks, sks, seeder);
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
impl<'a, F> OpSequenceFunctionExecutor<(&'a SignedRadixCiphertext, i64), SignedRadixCiphertext>
    for OpSequenceGpuMultiDeviceFunctionExecutor<F>
where
    F: Fn(
        &CudaServerKey,
        &CudaSignedRadixCiphertext,
        i64,
        &CudaStreams,
    ) -> CudaSignedRadixCiphertext,
{
    fn setup(
        &mut self,
        cks: &RadixClientKey,
        sks: &CompressedServerKey,
        seeder: &mut DeterministicSeeder<DefaultRandomGenerator>,
    ) {
        self.setup_from_gpu_keys(cks, sks, seeder);
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
impl<'a, F> OpSequenceFunctionExecutor<(&'a SignedRadixCiphertext, u64), SignedRadixCiphertext>
    for OpSequenceGpuMultiDeviceFunctionExecutor<F>
where
    F: Fn(
        &CudaServerKey,
        &CudaSignedRadixCiphertext,
        u64,
        &CudaStreams,
    ) -> CudaSignedRadixCiphertext,
{
    fn setup(
        &mut self,
        cks: &RadixClientKey,
        sks: &CompressedServerKey,
        seeder: &mut DeterministicSeeder<DefaultRandomGenerator>,
    ) {
        self.setup_from_gpu_keys(cks, sks, seeder);
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
impl<F> OpSequenceFunctionExecutor<(SignedRadixCiphertext, i64), SignedRadixCiphertext>
    for OpSequenceGpuMultiDeviceFunctionExecutor<F>
where
    F: Fn(
        &CudaServerKey,
        &CudaSignedRadixCiphertext,
        i64,
        &CudaStreams,
    ) -> CudaSignedRadixCiphertext,
{
    fn setup(
        &mut self,
        cks: &RadixClientKey,
        sks: &CompressedServerKey,
        seeder: &mut DeterministicSeeder<DefaultRandomGenerator>,
    ) {
        self.setup_from_gpu_keys(cks, sks, seeder);
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
impl<'a, F> OpSequenceFunctionExecutor<&'a SignedRadixCiphertext, SignedRadixCiphertext>
    for OpSequenceGpuMultiDeviceFunctionExecutor<F>
where
    F: Fn(&CudaServerKey, &CudaSignedRadixCiphertext, &CudaStreams) -> CudaSignedRadixCiphertext,
{
    fn setup(
        &mut self,
        cks: &RadixClientKey,
        sks: &CompressedServerKey,
        seeder: &mut DeterministicSeeder<DefaultRandomGenerator>,
    ) {
        self.setup_from_gpu_keys(cks, sks, seeder);
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

impl<'a, F> OpSequenceFunctionExecutor<&'a SignedRadixCiphertext, RadixCiphertext>
    for OpSequenceGpuMultiDeviceFunctionExecutor<F>
where
    F: Fn(&CudaServerKey, &CudaSignedRadixCiphertext, &CudaStreams) -> CudaUnsignedRadixCiphertext,
{
    fn setup(
        &mut self,
        cks: &RadixClientKey,
        sks: &CompressedServerKey,
        seeder: &mut DeterministicSeeder<DefaultRandomGenerator>,
    ) {
        self.setup_from_gpu_keys(cks, sks, seeder);
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
impl<'a, F> OpSequenceFunctionExecutor<&'a mut SignedRadixCiphertext, ()>
    for OpSequenceGpuMultiDeviceFunctionExecutor<F>
where
    F: Fn(&CudaServerKey, &mut CudaSignedRadixCiphertext, &CudaStreams),
{
    fn setup(
        &mut self,
        cks: &RadixClientKey,
        sks: &CompressedServerKey,
        seeder: &mut DeterministicSeeder<DefaultRandomGenerator>,
    ) {
        self.setup_from_gpu_keys(cks, sks, seeder);
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

impl<'a, F>
    OpSequenceFunctionExecutor<&'a Vec<SignedRadixCiphertext>, Option<SignedRadixCiphertext>>
    for OpSequenceGpuMultiDeviceFunctionExecutor<F>
where
    F: Fn(&CudaServerKey, Vec<CudaSignedRadixCiphertext>) -> Option<CudaSignedRadixCiphertext>,
{
    fn setup(
        &mut self,
        cks: &RadixClientKey,
        sks: &CompressedServerKey,
        seeder: &mut DeterministicSeeder<DefaultRandomGenerator>,
    ) {
        self.setup_from_gpu_keys(cks, sks, seeder);
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
    OpSequenceFunctionExecutor<
        (&'a SignedRadixCiphertext, &'a SignedRadixCiphertext),
        (SignedRadixCiphertext, BooleanBlock),
    > for OpSequenceGpuMultiDeviceFunctionExecutor<F>
where
    F: Fn(
        &CudaServerKey,
        &CudaSignedRadixCiphertext,
        &CudaSignedRadixCiphertext,
        &CudaStreams,
    ) -> (CudaSignedRadixCiphertext, CudaBooleanBlock),
{
    fn setup(
        &mut self,
        cks: &RadixClientKey,
        sks: &CompressedServerKey,
        seeder: &mut DeterministicSeeder<DefaultRandomGenerator>,
    ) {
        self.setup_from_gpu_keys(cks, sks, seeder);
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
    OpSequenceFunctionExecutor<
        (&'a SignedRadixCiphertext, i64),
        (SignedRadixCiphertext, BooleanBlock),
    > for OpSequenceGpuMultiDeviceFunctionExecutor<F>
where
    F: Fn(
        &CudaServerKey,
        &CudaSignedRadixCiphertext,
        i64,
        &CudaStreams,
    ) -> (CudaSignedRadixCiphertext, CudaBooleanBlock),
{
    fn setup(
        &mut self,
        cks: &RadixClientKey,
        sks: &CompressedServerKey,
        seeder: &mut DeterministicSeeder<DefaultRandomGenerator>,
    ) {
        self.setup_from_gpu_keys(cks, sks, seeder);
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

impl<'a, F>
    OpSequenceFunctionExecutor<&'a SignedRadixCiphertext, (SignedRadixCiphertext, BooleanBlock)>
    for OpSequenceGpuMultiDeviceFunctionExecutor<F>
where
    F: Fn(
        &CudaServerKey,
        &CudaSignedRadixCiphertext,
        &CudaStreams,
    ) -> (CudaSignedRadixCiphertext, CudaBooleanBlock),
{
    fn setup(
        &mut self,
        cks: &RadixClientKey,
        sks: &CompressedServerKey,
        seeder: &mut DeterministicSeeder<DefaultRandomGenerator>,
    ) {
        self.setup_from_gpu_keys(cks, sks, seeder);
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
    OpSequenceFunctionExecutor<
        (&'a SignedRadixCiphertext, &'a SignedRadixCiphertext),
        (SignedRadixCiphertext, SignedRadixCiphertext),
    > for OpSequenceGpuMultiDeviceFunctionExecutor<F>
where
    F: Fn(
        &CudaServerKey,
        &CudaSignedRadixCiphertext,
        &CudaSignedRadixCiphertext,
        &CudaStreams,
    ) -> (CudaSignedRadixCiphertext, CudaSignedRadixCiphertext),
{
    fn setup(
        &mut self,
        cks: &RadixClientKey,
        sks: &CompressedServerKey,
        seeder: &mut DeterministicSeeder<DefaultRandomGenerator>,
    ) {
        self.setup_from_gpu_keys(cks, sks, seeder);
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
    OpSequenceFunctionExecutor<
        (&'a SignedRadixCiphertext, i64),
        (SignedRadixCiphertext, SignedRadixCiphertext),
    > for OpSequenceGpuMultiDeviceFunctionExecutor<F>
where
    F: Fn(
        &CudaServerKey,
        &CudaSignedRadixCiphertext,
        i64,
        &CudaStreams,
    ) -> (CudaSignedRadixCiphertext, CudaSignedRadixCiphertext),
{
    fn setup(
        &mut self,
        cks: &RadixClientKey,
        sks: &CompressedServerKey,
        seeder: &mut DeterministicSeeder<DefaultRandomGenerator>,
    ) {
        self.setup_from_gpu_keys(cks, sks, seeder);
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

impl<'a, F>
    OpSequenceFunctionExecutor<(&'a SignedRadixCiphertext, &'a SignedRadixCiphertext), BooleanBlock>
    for OpSequenceGpuMultiDeviceFunctionExecutor<F>
where
    F: Fn(
        &CudaServerKey,
        &CudaSignedRadixCiphertext,
        &CudaSignedRadixCiphertext,
        &CudaStreams,
    ) -> CudaBooleanBlock,
{
    fn setup(
        &mut self,
        cks: &RadixClientKey,
        sks: &CompressedServerKey,
        seeder: &mut DeterministicSeeder<DefaultRandomGenerator>,
    ) {
        self.setup_from_gpu_keys(cks, sks, seeder);
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

impl<'a, F> OpSequenceFunctionExecutor<(&'a SignedRadixCiphertext, i64), BooleanBlock>
    for OpSequenceGpuMultiDeviceFunctionExecutor<F>
where
    F: Fn(&CudaServerKey, &CudaSignedRadixCiphertext, i64, &CudaStreams) -> CudaBooleanBlock,
{
    fn setup(
        &mut self,
        cks: &RadixClientKey,
        sks: &CompressedServerKey,
        seeder: &mut DeterministicSeeder<DefaultRandomGenerator>,
    ) {
        self.setup_from_gpu_keys(cks, sks, seeder);
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

impl<'a, F> OpSequenceFunctionExecutor<(&'a SignedRadixCiphertext, U256), BooleanBlock>
    for OpSequenceGpuMultiDeviceFunctionExecutor<F>
where
    F: Fn(&CudaServerKey, &CudaSignedRadixCiphertext, U256, &CudaStreams) -> CudaBooleanBlock,
{
    fn setup(
        &mut self,
        cks: &RadixClientKey,
        sks: &CompressedServerKey,
        seeder: &mut DeterministicSeeder<DefaultRandomGenerator>,
    ) {
        self.setup_from_gpu_keys(cks, sks, seeder);
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

impl<'a, F> OpSequenceFunctionExecutor<(&'a SignedRadixCiphertext, U256), SignedRadixCiphertext>
    for OpSequenceGpuMultiDeviceFunctionExecutor<F>
where
    F: Fn(
        &CudaServerKey,
        &CudaSignedRadixCiphertext,
        U256,
        &CudaStreams,
    ) -> CudaSignedRadixCiphertext,
{
    fn setup(
        &mut self,
        cks: &RadixClientKey,
        sks: &CompressedServerKey,
        seeder: &mut DeterministicSeeder<DefaultRandomGenerator>,
    ) {
        self.setup_from_gpu_keys(cks, sks, seeder);
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
    OpSequenceFunctionExecutor<
        (
            &'a BooleanBlock,
            &'a SignedRadixCiphertext,
            &'a SignedRadixCiphertext,
        ),
        SignedRadixCiphertext,
    > for OpSequenceGpuMultiDeviceFunctionExecutor<F>
where
    F: Fn(
        &CudaServerKey,
        &CudaBooleanBlock,
        &CudaSignedRadixCiphertext,
        &CudaSignedRadixCiphertext,
        &CudaStreams,
    ) -> CudaSignedRadixCiphertext,
{
    fn setup(
        &mut self,
        cks: &RadixClientKey,
        sks: &CompressedServerKey,
        seeder: &mut DeterministicSeeder<DefaultRandomGenerator>,
    ) {
        self.setup_from_gpu_keys(cks, sks, seeder);
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

/// For OPRF functions
impl<F> OpSequenceFunctionExecutor<(Seed, u64), RadixCiphertext>
    for OpSequenceGpuMultiDeviceFunctionExecutor<F>
where
    F: Fn(&CudaServerKey, Seed, u64, &CudaStreams) -> CudaUnsignedRadixCiphertext,
{
    fn setup(
        &mut self,
        cks: &RadixClientKey,
        sks: &CompressedServerKey,
        seeder: &mut DeterministicSeeder<DefaultRandomGenerator>,
    ) {
        self.setup_from_gpu_keys(cks, sks, seeder);
    }

    fn execute(&mut self, input: (Seed, u64)) -> RadixCiphertext {
        let context = self
            .context
            .as_ref()
            .expect("setup was not properly called");

        let gpu_result = (self.func)(&context.sks, input.0, input.1, &context.streams);

        gpu_result.to_radix_ciphertext(&context.streams)
    }
}

/// For bounded OPRF functions
impl<F> OpSequenceFunctionExecutor<(Seed, u64, u64), RadixCiphertext>
    for OpSequenceGpuMultiDeviceFunctionExecutor<F>
where
    F: Fn(&CudaServerKey, Seed, u64, u64, &CudaStreams) -> CudaUnsignedRadixCiphertext,
{
    fn setup(
        &mut self,
        cks: &RadixClientKey,
        sks: &CompressedServerKey,
        seeder: &mut DeterministicSeeder<DefaultRandomGenerator>,
    ) {
        self.setup_from_gpu_keys(cks, sks, seeder);
    }

    fn execute(&mut self, input: (Seed, u64, u64)) -> RadixCiphertext {
        let context = self
            .context
            .as_ref()
            .expect("setup was not properly called");

        let gpu_result = (self.func)(&context.sks, input.0, input.1, input.2, &context.streams);

        gpu_result.to_radix_ciphertext(&context.streams)
    }
}

/// For custom range OPRF functions (signature placeholder)
impl<F> OpSequenceFunctionExecutor<(Seed, u64, u64, u64), RadixCiphertext>
    for OpSequenceGpuMultiDeviceFunctionExecutor<F>
where
    F: Fn(&CudaServerKey, Seed, u64, u64, u64, &CudaStreams) -> CudaUnsignedRadixCiphertext,
{
    fn setup(
        &mut self,
        cks: &RadixClientKey,
        sks: &CompressedServerKey,
        seeder: &mut DeterministicSeeder<DefaultRandomGenerator>,
    ) {
        self.setup_from_gpu_keys(cks, sks, seeder);
    }

    fn execute(&mut self, input: (Seed, u64, u64, u64)) -> RadixCiphertext {
        let context = self
            .context
            .as_ref()
            .expect("setup was not properly called");

        let gpu_result = (self.func)(
            &context.sks,
            input.0,
            input.1,
            input.2,
            input.3,
            &context.streams,
        );

        gpu_result.to_radix_ciphertext(&context.streams)
    }
}

/// For Signed OPRF functions
impl<F> OpSequenceFunctionExecutor<(Seed, u64), SignedRadixCiphertext>
    for OpSequenceGpuMultiDeviceFunctionExecutor<F>
where
    F: Fn(&CudaServerKey, Seed, u64, &CudaStreams) -> CudaSignedRadixCiphertext,
{
    fn setup(
        &mut self,
        cks: &RadixClientKey,
        sks: &CompressedServerKey,
        seeder: &mut DeterministicSeeder<DefaultRandomGenerator>,
    ) {
        self.setup_from_gpu_keys(cks, sks, seeder);
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

/// For Bounded Signed OPRF functions
impl<F> OpSequenceFunctionExecutor<(Seed, u64, u64), SignedRadixCiphertext>
    for OpSequenceGpuMultiDeviceFunctionExecutor<F>
where
    F: Fn(&CudaServerKey, Seed, u64, u64, &CudaStreams) -> CudaSignedRadixCiphertext,
{
    fn setup(
        &mut self,
        cks: &RadixClientKey,
        sks: &CompressedServerKey,
        seeder: &mut DeterministicSeeder<DefaultRandomGenerator>,
    ) {
        self.setup_from_gpu_keys(cks, sks, seeder);
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
