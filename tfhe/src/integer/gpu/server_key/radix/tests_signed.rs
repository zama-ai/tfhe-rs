use crate::core_crypto::gpu::CudaStream;
use crate::integer::gpu::ciphertext::CudaSignedRadixCiphertext;
use crate::integer::gpu::server_key::radix::tests::GpuFunctionExecutor;
use crate::integer::gpu::CudaServerKey;
use crate::integer::server_key::radix_parallel::tests_cases_signed::*;
use crate::integer::server_key::radix_parallel::tests_cases_unsigned::FunctionExecutor;
use crate::integer::{RadixClientKey, ServerKey, SignedRadixCiphertext};
use crate::shortint::parameters::*;
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

// Unchecked operations
create_gpu_parametrized_test!(integer_unchecked_add);

// Default operations
create_gpu_parametrized_test!(integer_add);

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
impl<'a, F> FunctionExecutor<(&'a SignedRadixCiphertext, u64), SignedRadixCiphertext>
    for GpuFunctionExecutor<F>
where
    F: Fn(
        &CudaServerKey,
        &CudaSignedRadixCiphertext,
        u64,
        &CudaStream,
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
            CudaSignedRadixCiphertext::from_signed_radix_ciphertext(input.0, &context.stream);

        let gpu_result = (self.func)(&context.sks, &d_ctxt_1, input.1, &context.stream);

        gpu_result.to_signed_radix_ciphertext(&context.stream)
    }
}

fn integer_unchecked_add<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::unchecked_add);
    signed_unchecked_add_test(param, executor);
}

fn integer_add<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::add);
    signed_default_add_test(param, executor);
}
