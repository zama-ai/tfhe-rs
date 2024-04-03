pub(crate) mod test_add;
pub(crate) mod test_bitwise_op;
pub(crate) mod test_comparison;
pub(crate) mod test_div_mod;
pub(crate) mod test_mul;
pub(crate) mod test_neg;
pub(crate) mod test_rotate;
pub(crate) mod test_scalar_add;
pub(crate) mod test_scalar_bitwise_op;
pub(crate) mod test_scalar_comparison;
pub(crate) mod test_scalar_mul;
pub(crate) mod test_scalar_shift;
pub(crate) mod test_scalar_sub;
pub(crate) mod test_shift;
pub(crate) mod test_sub;

use crate::core_crypto::gpu::{CudaDevice, CudaStream};
use crate::integer::gpu::ciphertext::boolean_value::CudaBooleanBlock;
use crate::integer::gpu::ciphertext::CudaUnsignedRadixCiphertext;
use crate::integer::gpu::{gen_keys_gpu, CudaServerKey};
use crate::integer::{BooleanBlock, RadixCiphertext, RadixClientKey, ServerKey, U256};
use crate::shortint::parameters::*;
use rand::Rng;
use std::sync::Arc;

// Macro to generate tests for all parameter sets
macro_rules! create_gpu_parametrized_test{
    ($name:ident { $($param:ident),* $(,)? }) => {
        ::paste::paste! {
            $(
            #[test]
            fn [<test_gpu_ $name _ $param:lower>]() {
                $name($param)
            }
            )*
        }
    };
    ($name:ident)=> {
        create_gpu_parametrized_test!($name
        {
            // PARAM_MESSAGE_1_CARRY_1_KS_PBS,
            PARAM_MESSAGE_2_CARRY_2_KS_PBS,
            // PARAM_MESSAGE_3_CARRY_3_KS_PBS,
            // PARAM_MESSAGE_4_CARRY_4_KS_PBS,
            PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_3_KS_PBS
        });
    };
}
pub(crate) use create_gpu_parametrized_test;

pub(crate) struct GpuContext {
    pub(crate) _device: CudaDevice,
    pub(crate) stream: CudaStream,
    pub(crate) sks: CudaServerKey,
}
pub(crate) struct GpuFunctionExecutor<F> {
    pub(crate) context: Option<GpuContext>,
    pub(crate) func: F,
}

impl<F> GpuFunctionExecutor<F> {
    pub(crate) fn new(func: F) -> Self {
        Self {
            context: None,
            func,
        }
    }
}

impl<F> GpuFunctionExecutor<F> {
    pub(crate) fn setup_from_keys(&mut self, cks: &RadixClientKey, _sks: &Arc<ServerKey>) {
        let gpu_index = 0;
        let device = CudaDevice::new(gpu_index);
        let stream = CudaStream::new_unchecked(device);

        let sks = CudaServerKey::new(cks.as_ref(), &stream);
        stream.synchronize();
        let context = GpuContext {
            _device: device,
            stream,
            sks,
        };
        self.context = Some(context);
    }
}

// Unchecked operations
create_gpu_parametrized_test!(integer_unchecked_if_then_else);
create_gpu_parametrized_test!(integer_unchecked_scalar_rotate_left);
create_gpu_parametrized_test!(integer_unchecked_scalar_rotate_right);

// Default operations
create_gpu_parametrized_test!(integer_if_then_else);

/// Number of loop iteration within randomized tests
const NB_TEST: usize = 1000;

/// Smaller number of loop iteration within randomized test,
/// meant for test where the function tested is more expensive
// const NB_TEST_SMALLER: usize = 10;
const NB_CTXT: usize = 4;
use crate::integer::server_key::radix_parallel::tests_cases_unsigned::*;

/// For default/unchecked binary functions
impl<'a, F> FunctionExecutor<(&'a RadixCiphertext, &'a RadixCiphertext), RadixCiphertext>
    for GpuFunctionExecutor<F>
where
    F: Fn(
        &CudaServerKey,
        &CudaUnsignedRadixCiphertext,
        &CudaUnsignedRadixCiphertext,
        &CudaStream,
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

        let d_ctxt_1 = CudaUnsignedRadixCiphertext::from_radix_ciphertext(input.0, &context.stream);
        let d_ctxt_2 = CudaUnsignedRadixCiphertext::from_radix_ciphertext(input.1, &context.stream);

        let gpu_result = (self.func)(&context.sks, &d_ctxt_1, &d_ctxt_2, &context.stream);

        gpu_result.to_radix_ciphertext(&context.stream)
    }
}

/// For unchecked/default assign binary functions
impl<'a, F> FunctionExecutor<(&'a mut RadixCiphertext, &'a RadixCiphertext), ()>
    for GpuFunctionExecutor<F>
where
    F: Fn(
        &CudaServerKey,
        &mut CudaUnsignedRadixCiphertext,
        &CudaUnsignedRadixCiphertext,
        &CudaStream,
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
            CudaUnsignedRadixCiphertext::from_radix_ciphertext(input.0, &context.stream);
        let d_ctxt_2 = CudaUnsignedRadixCiphertext::from_radix_ciphertext(input.1, &context.stream);

        (self.func)(&context.sks, &mut d_ctxt_1, &d_ctxt_2, &context.stream);

        *input.0 = d_ctxt_1.to_radix_ciphertext(&context.stream);
    }
}

/// For unchecked/default binary functions with one scalar input
impl<'a, F> FunctionExecutor<(&'a RadixCiphertext, u64), RadixCiphertext> for GpuFunctionExecutor<F>
where
    F: Fn(
        &CudaServerKey,
        &CudaUnsignedRadixCiphertext,
        u64,
        &CudaStream,
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

        let d_ctxt_1 = CudaUnsignedRadixCiphertext::from_radix_ciphertext(input.0, &context.stream);

        let gpu_result = (self.func)(&context.sks, &d_ctxt_1, input.1, &context.stream);

        gpu_result.to_radix_ciphertext(&context.stream)
    }
}

/// For unchecked/default binary functions with one scalar input
impl<F> FunctionExecutor<(RadixCiphertext, u64), RadixCiphertext> for GpuFunctionExecutor<F>
where
    F: Fn(
        &CudaServerKey,
        &CudaUnsignedRadixCiphertext,
        u64,
        &CudaStream,
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
            CudaUnsignedRadixCiphertext::from_radix_ciphertext(&input.0, &context.stream);

        let gpu_result = (self.func)(&context.sks, &d_ctxt_1, input.1, &context.stream);

        gpu_result.to_radix_ciphertext(&context.stream)
    }
}

// Unary Function
impl<'a, F> FunctionExecutor<&'a RadixCiphertext, RadixCiphertext> for GpuFunctionExecutor<F>
where
    F: Fn(&CudaServerKey, &CudaUnsignedRadixCiphertext, &CudaStream) -> CudaUnsignedRadixCiphertext,
{
    fn setup(&mut self, cks: &RadixClientKey, sks: Arc<ServerKey>) {
        self.setup_from_keys(cks, &sks);
    }

    fn execute(&mut self, input: &'a RadixCiphertext) -> RadixCiphertext {
        let context = self
            .context
            .as_ref()
            .expect("setup was not properly called");

        let d_ctxt_1 = CudaUnsignedRadixCiphertext::from_radix_ciphertext(input, &context.stream);

        let gpu_result = (self.func)(&context.sks, &d_ctxt_1, &context.stream);

        gpu_result.to_radix_ciphertext(&context.stream)
    }
}

// Unary assign Function
impl<'a, F> FunctionExecutor<&'a mut RadixCiphertext, ()> for GpuFunctionExecutor<F>
where
    F: Fn(&CudaServerKey, &mut CudaUnsignedRadixCiphertext, &CudaStream),
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
            CudaUnsignedRadixCiphertext::from_radix_ciphertext(input, &context.stream);

        (self.func)(&context.sks, &mut d_ctxt_1, &context.stream);

        *input = d_ctxt_1.to_radix_ciphertext(&context.stream)
    }
}

impl<'a, F> FunctionExecutor<&'a Vec<RadixCiphertext>, Option<RadixCiphertext>>
    for GpuFunctionExecutor<F>
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
            .map(|ct| CudaUnsignedRadixCiphertext::from_radix_ciphertext(ct, &context.stream))
            .collect();

        let d_res = (self.func)(&context.sks, d_ctxt_1);

        Some(d_res.unwrap().to_radix_ciphertext(&context.stream))
    }
}

impl<'a, F>
    FunctionExecutor<(&'a RadixCiphertext, &'a RadixCiphertext), (RadixCiphertext, BooleanBlock)>
    for GpuFunctionExecutor<F>
where
    F: Fn(
        &CudaServerKey,
        &CudaUnsignedRadixCiphertext,
        &CudaUnsignedRadixCiphertext,
        &CudaStream,
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
            CudaUnsignedRadixCiphertext::from_radix_ciphertext(input.0, &context.stream);
        let d_ctxt_2: CudaUnsignedRadixCiphertext =
            CudaUnsignedRadixCiphertext::from_radix_ciphertext(input.1, &context.stream);

        let d_res = (self.func)(&context.sks, &d_ctxt_1, &d_ctxt_2, &context.stream);

        (
            d_res.0.to_radix_ciphertext(&context.stream),
            d_res.1.to_boolean_block(&context.stream),
        )
    }
}

impl<'a, F>
    FunctionExecutor<(&'a RadixCiphertext, &'a RadixCiphertext), (RadixCiphertext, RadixCiphertext)>
    for GpuFunctionExecutor<F>
where
    F: Fn(
        &CudaServerKey,
        &CudaUnsignedRadixCiphertext,
        &CudaUnsignedRadixCiphertext,
        &CudaStream,
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
            CudaUnsignedRadixCiphertext::from_radix_ciphertext(input.0, &context.stream);
        let d_ctxt_2: CudaUnsignedRadixCiphertext =
            CudaUnsignedRadixCiphertext::from_radix_ciphertext(input.1, &context.stream);

        let d_res = (self.func)(&context.sks, &d_ctxt_1, &d_ctxt_2, &context.stream);

        (
            d_res.0.to_radix_ciphertext(&context.stream),
            d_res.1.to_radix_ciphertext(&context.stream),
        )
    }
}

impl<'a, F> FunctionExecutor<(&'a RadixCiphertext, &'a RadixCiphertext), BooleanBlock>
    for GpuFunctionExecutor<F>
where
    F: Fn(
        &CudaServerKey,
        &CudaUnsignedRadixCiphertext,
        &CudaUnsignedRadixCiphertext,
        &CudaStream,
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
            CudaUnsignedRadixCiphertext::from_radix_ciphertext(input.0, &context.stream);
        let d_ctxt_2: CudaUnsignedRadixCiphertext =
            CudaUnsignedRadixCiphertext::from_radix_ciphertext(input.1, &context.stream);

        let d_res = (self.func)(&context.sks, &d_ctxt_1, &d_ctxt_2, &context.stream);

        d_res.to_boolean_block(&context.stream)
    }
}

impl<'a, F> FunctionExecutor<(&'a RadixCiphertext, u64), BooleanBlock> for GpuFunctionExecutor<F>
where
    F: Fn(&CudaServerKey, &CudaUnsignedRadixCiphertext, u64, &CudaStream) -> CudaBooleanBlock,
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
            CudaUnsignedRadixCiphertext::from_radix_ciphertext(input.0, &context.stream);

        let d_res = (self.func)(&context.sks, &d_ctxt_1, input.1, &context.stream);

        d_res.to_boolean_block(&context.stream)
    }
}

impl<'a, F> FunctionExecutor<(&'a RadixCiphertext, U256), BooleanBlock> for GpuFunctionExecutor<F>
where
    F: Fn(&CudaServerKey, &CudaUnsignedRadixCiphertext, U256, &CudaStream) -> CudaBooleanBlock,
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
            CudaUnsignedRadixCiphertext::from_radix_ciphertext(input.0, &context.stream);

        let d_res = (self.func)(&context.sks, &d_ctxt_1, input.1, &context.stream);

        d_res.to_boolean_block(&context.stream)
    }
}

impl<'a, F> FunctionExecutor<(&'a RadixCiphertext, U256), RadixCiphertext>
    for GpuFunctionExecutor<F>
where
    F: Fn(
        &CudaServerKey,
        &CudaUnsignedRadixCiphertext,
        U256,
        &CudaStream,
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
            CudaUnsignedRadixCiphertext::from_radix_ciphertext(input.0, &context.stream);

        let d_res = (self.func)(&context.sks, &d_ctxt_1, input.1, &context.stream);

        d_res.to_radix_ciphertext(&context.stream)
    }
}

fn integer_unchecked_if_then_else<P>(param: P)
where
    P: Into<PBSParameters> + Copy,
{
    let gpu_index = 0;
    let device = CudaDevice::new(gpu_index);
    let stream = CudaStream::new_unchecked(device);

    let (cks, sks) = gen_keys_gpu(param, &stream);

    let mut rng = rand::thread_rng();

    // message_modulus^vec_length
    let modulus = cks.parameters().message_modulus().0.pow(NB_CTXT as u32) as u64;

    for _ in 0..NB_TEST {
        // Define the cleartexts
        let clear1 = rng.gen::<u64>() % modulus;
        let clear2 = rng.gen::<u64>() % modulus;
        let clear_condition = rng.gen_range(0u64..2);

        // Encrypt the integers;;
        let ctxt_1 = cks.encrypt_radix(clear1, NB_CTXT);
        let ctxt_2 = cks.encrypt_radix(clear2, NB_CTXT);
        let ctxt_condition = cks.encrypt_radix(clear_condition, 1);

        // Copy to the GPU
        let d_ctxt_1 = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ctxt_1, &stream);
        let d_ctxt_2 = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ctxt_2, &stream);
        let d_ctxt_condition =
            CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ctxt_condition, &stream);

        let d_ct_res = sks.unchecked_if_then_else(&d_ctxt_condition, &d_ctxt_1, &d_ctxt_2, &stream);

        let ct_res = d_ct_res.to_radix_ciphertext(&stream);
        let dec_res: u64 = cks.decrypt_radix(&ct_res);

        // Check the correctness
        assert_eq!(dec_res, if clear_condition == 1 { clear1 } else { clear2 });
    }
}

fn integer_unchecked_scalar_rotate_left<P>(param: P)
where
    P: Into<PBSParameters> + Copy,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::unchecked_scalar_rotate_left);
    unchecked_scalar_rotate_left_test(param, executor);
}

fn integer_unchecked_scalar_rotate_right<P>(param: P)
where
    P: Into<PBSParameters> + Copy,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::unchecked_scalar_rotate_right);
    unchecked_scalar_rotate_right_test(param, executor);
}

fn integer_if_then_else<P>(param: P)
where
    P: Into<PBSParameters> + Copy,
{
    let gpu_index = 0;
    let device = CudaDevice::new(gpu_index);
    let stream = CudaStream::new_unchecked(device);

    let (cks, sks) = gen_keys_gpu(param, &stream);

    let mut rng = rand::thread_rng();

    // message_modulus^vec_length
    let modulus = cks.parameters().message_modulus().0.pow(NB_CTXT as u32) as u64;

    for _ in 0..NB_TEST {
        // Define the cleartexts
        let clear1 = rng.gen::<u64>() % modulus;
        let clear2 = rng.gen::<u64>() % modulus;
        let clear_condition = rng.gen_range(0u64..2);

        // Encrypt the integers;;
        let ctxt_1 = cks.encrypt_radix(clear1, NB_CTXT);
        let ctxt_2 = cks.encrypt_radix(clear2, NB_CTXT);
        let ctxt_condition = cks.encrypt_radix(clear_condition, 1);

        // Copy to the GPU
        let d_ctxt_1 = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ctxt_1, &stream);
        let d_ctxt_2 = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ctxt_2, &stream);
        let d_ctxt_condition =
            CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ctxt_condition, &stream);

        let d_ct_res = sks.if_then_else(&d_ctxt_condition, &d_ctxt_1, &d_ctxt_2, &stream);

        let ct_res = d_ct_res.to_radix_ciphertext(&stream);
        let dec_res: u64 = cks.decrypt_radix(&ct_res);

        // Check the correctness
        assert_eq!(dec_res, if clear_condition == 1 { clear1 } else { clear2 });
    }
}
