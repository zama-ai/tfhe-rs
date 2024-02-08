#[cfg(test)]
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
use crate::core_crypto::gpu::{CudaDevice, CudaStream};
use crate::integer::gpu::ciphertext::CudaRadixCiphertext;
use crate::integer::gpu::CudaServerKey;
use crate::integer::server_key::radix_parallel::tests_cases_unsigned::FunctionExecutor;
use crate::integer::{RadixCiphertext, RadixClientKey, ServerKey};
pub(crate) use create_gpu_parametrized_test;
use std::sync::Arc;

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

/// For default/unchecked binary functions
impl<'a, F> FunctionExecutor<(&'a RadixCiphertext, &'a RadixCiphertext), RadixCiphertext>
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

    fn execute(&mut self, input: (&'a RadixCiphertext, &'a RadixCiphertext)) -> RadixCiphertext {
        let context = self
            .context
            .as_ref()
            .expect("setup was not properly called");

        let d_ctxt_1 = CudaRadixCiphertext::from_radix_ciphertext(input.0, &context.stream);
        let d_ctxt_2 = CudaRadixCiphertext::from_radix_ciphertext(input.1, &context.stream);

        let gpu_result = (self.func)(&context.sks, &d_ctxt_1, &d_ctxt_2, &context.stream);

        gpu_result.to_radix_ciphertext(&context.stream)
    }
}

/// For unchecked/default assign binary functions
impl<'a, F> FunctionExecutor<(&'a mut RadixCiphertext, &'a RadixCiphertext), ()>
    for GpuFunctionExecutor<F>
where
    F: Fn(&CudaServerKey, &mut CudaRadixCiphertext, &CudaRadixCiphertext, &CudaStream),
{
    fn setup(&mut self, cks: &RadixClientKey, sks: Arc<ServerKey>) {
        self.setup_from_keys(cks, &sks);
    }

    fn execute(&mut self, input: (&'a mut RadixCiphertext, &'a RadixCiphertext)) {
        let context = self
            .context
            .as_ref()
            .expect("setup was not properly called");

        let mut d_ctxt_1 = CudaRadixCiphertext::from_radix_ciphertext(input.0, &context.stream);
        let d_ctxt_2 = CudaRadixCiphertext::from_radix_ciphertext(input.1, &context.stream);

        (self.func)(&context.sks, &mut d_ctxt_1, &d_ctxt_2, &context.stream);

        *input.0 = d_ctxt_1.to_radix_ciphertext(&context.stream);
    }
}

/// For unchecked/default binary functions with one scalar input
impl<'a, F> FunctionExecutor<(&'a RadixCiphertext, u64), RadixCiphertext>
    for GpuFunctionExecutor<F>
where
    F: Fn(&CudaServerKey, &CudaRadixCiphertext, u64, &CudaStream) -> CudaRadixCiphertext,
{
    fn setup(&mut self, cks: &RadixClientKey, sks: Arc<ServerKey>) {
        self.setup_from_keys(cks, &sks);
    }

    fn execute(&mut self, input: (&'a RadixCiphertext, u64)) -> RadixCiphertext {
        let context = self
            .context
            .as_ref()
            .expect("setup was not properly called");

        let d_ctxt_1 = CudaRadixCiphertext::from_radix_ciphertext(input.0, &context.stream);

        let gpu_result = (self.func)(&context.sks, &d_ctxt_1, input.1, &context.stream);

        gpu_result.to_radix_ciphertext(&context.stream)
    }
}

/// For unchecked/default binary functions with one scalar input
impl<F> FunctionExecutor<(RadixCiphertext, u64), RadixCiphertext> for GpuFunctionExecutor<F>
where
    F: Fn(&CudaServerKey, &CudaRadixCiphertext, u64, &CudaStream) -> CudaRadixCiphertext,
{
    fn setup(&mut self, cks: &RadixClientKey, sks: Arc<ServerKey>) {
        self.setup_from_keys(cks, &sks);
    }

    fn execute(&mut self, input: (RadixCiphertext, u64)) -> RadixCiphertext {
        let context = self
            .context
            .as_ref()
            .expect("setup was not properly called");

        let d_ctxt_1 = CudaRadixCiphertext::from_radix_ciphertext(&input.0, &context.stream);

        let gpu_result = (self.func)(&context.sks, &d_ctxt_1, input.1, &context.stream);

        gpu_result.to_radix_ciphertext(&context.stream)
    }
}

// Unary Function
impl<'a, F> FunctionExecutor<&'a RadixCiphertext, RadixCiphertext> for GpuFunctionExecutor<F>
where
    F: Fn(&CudaServerKey, &CudaRadixCiphertext, &CudaStream) -> CudaRadixCiphertext,
{
    fn setup(&mut self, cks: &RadixClientKey, sks: Arc<ServerKey>) {
        self.setup_from_keys(cks, &sks);
    }

    fn execute(&mut self, input: &'a RadixCiphertext) -> RadixCiphertext {
        let context = self
            .context
            .as_ref()
            .expect("setup was not properly called");

        let d_ctxt_1 = CudaRadixCiphertext::from_radix_ciphertext(input, &context.stream);

        let gpu_result = (self.func)(&context.sks, &d_ctxt_1, &context.stream);

        gpu_result.to_radix_ciphertext(&context.stream)
    }
}

// Unary assign Function
impl<'a, F> FunctionExecutor<&'a mut RadixCiphertext, ()> for GpuFunctionExecutor<F>
where
    F: Fn(&CudaServerKey, &mut CudaRadixCiphertext, &CudaStream),
{
    fn setup(&mut self, cks: &RadixClientKey, sks: Arc<ServerKey>) {
        self.setup_from_keys(cks, &sks);
    }

    fn execute(&mut self, input: &'a mut RadixCiphertext) {
        let context = self
            .context
            .as_ref()
            .expect("setup was not properly called");

        let mut d_ctxt_1 = CudaRadixCiphertext::from_radix_ciphertext(input, &context.stream);

        (self.func)(&context.sks, &mut d_ctxt_1, &context.stream);

        *input = d_ctxt_1.to_radix_ciphertext(&context.stream)
    }
}
