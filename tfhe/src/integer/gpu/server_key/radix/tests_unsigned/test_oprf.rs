use crate::core_crypto::gpu::CudaStreams;
use crate::integer::ciphertext::{
    PrfReRandomizationContext, RadixCiphertext, SignedRadixCiphertext,
};
use crate::integer::gpu::ciphertext::re_randomization::CudaReRandomizationKey;
use crate::integer::gpu::server_key::radix::tests_long_run::OpSequenceGpuMultiDeviceFunctionExecutor;
use crate::integer::gpu::server_key::radix::tests_unsigned::create_gpu_parameterized_test;
use crate::integer::gpu::{CudaOprfServerKey, CudaServerKey};
use crate::integer::oprf::{CompressedOprfServerKey, OprfPrivateKey};
use crate::integer::server_key::radix_parallel::tests_unsigned::test_oprf::{
    oprf_almost_uniformity_test, oprf_any_range_test, oprf_compare_plain_test,
    oprf_uniformity_test, pseudo_random_integer_and_rerand_test, OprfReRandTestRunner,
};
use crate::integer::{ClientKey, CompactPrivateKey, CompactPublicKey};
use crate::shortint::oprf::OprfSeed;
use crate::shortint::parameters::test_params::TEST_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
use crate::shortint::parameters::{
    TestParameters, PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
};
use core::num::NonZeroU64;

create_gpu_parameterized_test!(oprf_uniformity_unsigned {
    PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128
});
create_gpu_parameterized_test!(oprf_any_range_unsigned {
    PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128
});
create_gpu_parameterized_test!(oprf_almost_uniformity_unsigned {
    PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128
});

create_gpu_parameterized_test!(pseudo_random_integer_and_rerand {
    PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    TEST_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
});

create_gpu_parameterized_test!(oprf_compare_plain_unsigned {
    PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    TEST_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
});

fn oprf_uniformity_unsigned<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = OpSequenceGpuMultiDeviceFunctionExecutor::new(
        &CudaOprfServerKey::par_generate_oblivious_pseudo_random_unsigned_integer_bounded,
    );
    oprf_uniformity_test(param, executor);
}

fn oprf_any_range_unsigned<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = OpSequenceGpuMultiDeviceFunctionExecutor::new(
        &CudaOprfServerKey::par_generate_oblivious_pseudo_random_unsigned_custom_range,
    );
    oprf_any_range_test(param, executor);
}

fn oprf_almost_uniformity_unsigned<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = OpSequenceGpuMultiDeviceFunctionExecutor::new(
        &CudaOprfServerKey::par_generate_oblivious_pseudo_random_unsigned_custom_range,
    );
    oprf_almost_uniformity_test(param, executor);
}

fn oprf_compare_plain_unsigned<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = OpSequenceGpuMultiDeviceFunctionExecutor::new(
        &CudaOprfServerKey::par_generate_oblivious_pseudo_random_unsigned_integer,
    );
    oprf_compare_plain_test(param, executor, |cks, img| cks.decrypt::<u64>(img) as i128);
}

// PRF + rerand

/// GPU implementation of [`OprfReRandTestRunner`].
///
/// Uses a derived compact public key (no key-switch) for re-randomization, mirroring the CPU
/// executor.
struct GpuOprfReRandTestRunner {
    state: Option<GpuOprfReRandState>,
}

struct GpuOprfReRandState {
    streams: CudaStreams,
    sks: CudaServerKey,
    oprf_sks: CudaOprfServerKey,
    rerand_cpk: CompactPublicKey,
}

impl GpuOprfReRandState {
    fn rerand_key(&self) -> CudaReRandomizationKey<'_> {
        CudaReRandomizationKey::DerivedCPKWithoutKeySwitch {
            cpk: &self.rerand_cpk,
        }
    }
}

impl GpuOprfReRandTestRunner {
    fn new() -> Self {
        Self { state: None }
    }

    fn state(&self) -> &GpuOprfReRandState {
        self.state.as_ref().expect("setup was not properly called")
    }
}

impl OprfReRandTestRunner for GpuOprfReRandTestRunner {
    fn setup(&mut self, param: TestParameters) -> ClientKey {
        let cks = ClientKey::new(param);

        let streams = CudaStreams::new_multi_gpu();

        let sks = CudaServerKey::new(&cks, &streams);

        // Derived compact public key, re-using the compute secret key
        // legacy rerand not covered by this test
        let privk: CompactPrivateKey<&[u64]> = (&cks).try_into().unwrap();
        let rerand_cpk = CompactPublicKey::new(&privk);

        let oprf_pk = OprfPrivateKey::new(&cks);
        let compressed_oprf_sk = CompressedOprfServerKey::new(&oprf_pk, &cks).unwrap();
        let oprf_sks = CudaOprfServerKey::decompress_from_cpu(&compressed_oprf_sk, &streams);

        self.state = Some(GpuOprfReRandState {
            streams,
            sks,
            oprf_sks,
            rerand_cpk,
        });

        cks
    }

    fn unsigned_full(
        &mut self,
        prf_seed: impl OprfSeed,
        num_blocks: u64,
        prf_re_randomization_context: &PrfReRandomizationContext,
    ) -> (RadixCiphertext, RadixCiphertext) {
        let state = self.state();
        let rerand_key = state.rerand_key();

        let prf_seed = prf_seed.into_bytes();
        let prf_seed = prf_seed.as_ref();

        let prf_not_rerand = state
            .oprf_sks
            .par_generate_oblivious_pseudo_random_unsigned_integer(
                prf_seed,
                num_blocks,
                &state.sks,
                &state.streams,
            );
        let prf_rerand = state
            .oprf_sks
            .par_generate_oblivious_pseudo_random_unsigned_integer_and_re_randomize(
                prf_seed,
                num_blocks,
                &state.sks,
                &rerand_key,
                prf_re_randomization_context,
                &state.streams,
            )
            .unwrap();

        (
            prf_not_rerand.to_radix_ciphertext(&state.streams),
            prf_rerand.to_radix_ciphertext(&state.streams),
        )
    }

    fn unsigned_bounded(
        &mut self,
        prf_seed: impl OprfSeed,
        random_bit_count: u64,
        num_blocks: u64,
        prf_re_randomization_context: &PrfReRandomizationContext,
    ) -> (RadixCiphertext, RadixCiphertext) {
        let state = self.state();
        let rerand_key = state.rerand_key();

        let prf_seed = prf_seed.into_bytes();
        let prf_seed = prf_seed.as_ref();

        let prf_not_rerand = state
            .oprf_sks
            .par_generate_oblivious_pseudo_random_unsigned_integer_bounded(
                prf_seed,
                random_bit_count,
                num_blocks,
                &state.sks,
                &state.streams,
            );
        let prf_rerand = state
            .oprf_sks
            .par_generate_oblivious_pseudo_random_unsigned_integer_bounded_and_re_randomize(
                prf_seed,
                random_bit_count,
                num_blocks,
                &state.sks,
                &rerand_key,
                prf_re_randomization_context,
                &state.streams,
            )
            .unwrap();

        (
            prf_not_rerand.to_radix_ciphertext(&state.streams),
            prf_rerand.to_radix_ciphertext(&state.streams),
        )
    }

    fn unsigned_custom_range(
        &mut self,
        prf_seed: impl OprfSeed,
        num_input_random_bits: u64,
        excluded_upper_bound: NonZeroU64,
        num_blocks_output: u64,
        prf_re_randomization_context: &PrfReRandomizationContext,
    ) -> (RadixCiphertext, RadixCiphertext) {
        let state = self.state();
        let rerand_key = state.rerand_key();

        let prf_seed = prf_seed.into_bytes();
        let prf_seed = prf_seed.as_ref();

        let prf_not_rerand = state
            .oprf_sks
            .par_generate_oblivious_pseudo_random_unsigned_custom_range(
                prf_seed,
                num_input_random_bits,
                excluded_upper_bound,
                num_blocks_output,
                &state.sks,
                &state.streams,
            );
        let prf_rerand = state
            .oprf_sks
            .par_generate_oblivious_pseudo_random_unsigned_custom_range_and_re_randomize(
                prf_seed,
                num_input_random_bits,
                excluded_upper_bound,
                num_blocks_output,
                &state.sks,
                &rerand_key,
                prf_re_randomization_context,
                &state.streams,
            )
            .unwrap();

        (
            prf_not_rerand.to_radix_ciphertext(&state.streams),
            prf_rerand.to_radix_ciphertext(&state.streams),
        )
    }

    fn signed_full(
        &mut self,
        prf_seed: impl OprfSeed,
        num_blocks: u64,
        prf_re_randomization_context: &PrfReRandomizationContext,
    ) -> (SignedRadixCiphertext, SignedRadixCiphertext) {
        let state = self.state();
        let rerand_key = state.rerand_key();

        let prf_seed = prf_seed.into_bytes();
        let prf_seed = prf_seed.as_ref();

        let prf_not_rerand = state
            .oprf_sks
            .par_generate_oblivious_pseudo_random_signed_integer(
                prf_seed,
                num_blocks,
                &state.sks,
                &state.streams,
            );
        let prf_rerand = state
            .oprf_sks
            .par_generate_oblivious_pseudo_random_signed_integer_and_re_randomize(
                prf_seed,
                num_blocks,
                &state.sks,
                &rerand_key,
                prf_re_randomization_context,
                &state.streams,
            )
            .unwrap();

        (
            prf_not_rerand.to_signed_radix_ciphertext(&state.streams),
            prf_rerand.to_signed_radix_ciphertext(&state.streams),
        )
    }

    fn signed_bounded(
        &mut self,
        prf_seed: impl OprfSeed,
        random_bit_count: u64,
        num_blocks: u64,
        prf_re_randomization_context: &PrfReRandomizationContext,
    ) -> (SignedRadixCiphertext, SignedRadixCiphertext) {
        let state = self.state();
        let rerand_key = state.rerand_key();

        let prf_seed = prf_seed.into_bytes();
        let prf_seed = prf_seed.as_ref();

        let prf_not_rerand = state
            .oprf_sks
            .par_generate_oblivious_pseudo_random_signed_integer_bounded(
                prf_seed,
                random_bit_count,
                num_blocks,
                &state.sks,
                &state.streams,
            );
        let prf_rerand = state
            .oprf_sks
            .par_generate_oblivious_pseudo_random_signed_integer_bounded_and_re_randomize(
                prf_seed,
                random_bit_count,
                num_blocks,
                &state.sks,
                &rerand_key,
                prf_re_randomization_context,
                &state.streams,
            )
            .unwrap();

        (
            prf_not_rerand.to_signed_radix_ciphertext(&state.streams),
            prf_rerand.to_signed_radix_ciphertext(&state.streams),
        )
    }
}

fn pseudo_random_integer_and_rerand<P>(param: P)
where
    P: Into<TestParameters>,
{
    pseudo_random_integer_and_rerand_test(param, GpuOprfReRandTestRunner::new());
}
