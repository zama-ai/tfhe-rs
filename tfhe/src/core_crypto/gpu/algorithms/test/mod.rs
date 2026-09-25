use crate::core_crypto::algorithms::test::*;
use crate::core_crypto::gpu::lwe_ciphertext_list::CudaLweCiphertextList;
use crate::core_crypto::gpu::CudaStreams;
use crate::core_crypto::prelude::*;

mod fft;
mod glwe_dot_product_with_clear;
mod glwe_sample_extraction;
mod halfhalf_lwe_programmable_bootstrapping_128;
mod lwe_keyswitch;
mod lwe_multi_bit_programmable_bootstrapping;
mod lwe_multi_bit_programmable_bootstrapping_128;
mod lwe_packing_keyswitch;
mod lwe_programmable_bootstrapping;
mod lwe_programmable_bootstrapping_128;
mod modulus_switch;
mod noise_distribution;
mod params;
mod pbs128_golden;
mod pbs_golden;
pub struct CudaPackingKeySwitchKeys<Scalar: UnsignedInteger> {
    pub lwe_sk: LweSecretKey<Vec<Scalar>>,
    pub glwe_sk: GlweSecretKey<Vec<Scalar>>,
    pub pksk: CudaLwePackingKeyswitchKey<Scalar>,
}

/// Asserts that two executions of the same GPU operator over the same input
/// produced bit-identical output, the way the integer GPU tests do it.
///
/// The correctness asserts of these tests compare *decoded* messages, and
/// `round_decode` throws away exactly the low order bits where a race, an
/// uninitialized read or a reordered floating point accumulation would show up.
/// This compares the raw ciphertext containers instead, and reports a
/// determinism failure rather than a wrong result: a single differing least
/// significant bit and a fully different output are very different bugs, so the
/// message says how much differs and where.
pub(crate) fn assert_gpu_determinism<Scalar: UnsignedInteger>(
    first_run: &[Scalar],
    second_run: &[Scalar],
    operator: &str,
) {
    assert_eq!(
        first_run.len(),
        second_run.len(),
        "Failed determinism check for {operator}: output lengths differ ({} vs {})",
        first_run.len(),
        second_run.len()
    );

    let Some(first_diff) = first_run
        .iter()
        .zip(second_run)
        .position(|(lhs, rhs)| lhs != rhs)
    else {
        return;
    };

    let diff_count = first_run
        .iter()
        .zip(second_run)
        .filter(|(lhs, rhs)| lhs != rhs)
        .count();

    panic!(
        "Failed determinism check for {operator}: running it twice on the same input gave \
        different outputs, {diff_count}/{} coefficients differ, first at index {first_diff} \
        ({:?} vs {:?})",
        first_run.len(),
        first_run[first_diff],
        second_run[first_diff],
    );
}

/// Tells whether the bootstrap tests should run their determinism check for these parameters.
///
/// The check bootstraps a second time, so it doubles the runtime of the test it belongs to. The
/// bigger parameter sets go through the very same kernels as the 2_2 ones, so paying that cost on
/// all of them would slow the test suite down without covering anything new: only the 2_2
/// parameter sets, i.e. those with 2 bits of message and 2 bits of carry, run it.
pub(crate) fn should_check_determinism(message_modulus_log: MessageModulusLog) -> bool {
    message_modulus_log == MessageModulusLog(4)
}

pub(crate) fn is_sanitizer_run() -> bool {
    std::env::var("TFHE_RS_COMPUTE_SANITIZER").is_ok_and(|v| v == "1")
}

/// Replicates one input LWE ciphertext into a device list of `batch_size` identical copies.
///
/// A fixed input replicated across the batch lets every lane of a batched run be compared against
/// a single CPU reference bootstrap.
pub(crate) fn replicated_input(
    lwe_ciphertext_in: &LweCiphertextOwned<u64>,
    stream: &CudaStreams,
    batch_size: usize,
) -> CudaLweCiphertextList<u64> {
    let lwe_size = lwe_ciphertext_in.lwe_size();
    let mut container = Vec::with_capacity(lwe_size.0 * batch_size);
    for _ in 0..batch_size {
        container.extend_from_slice(lwe_ciphertext_in.as_ref());
    }
    let h_input = LweCiphertextList::from_container(
        container,
        lwe_size,
        lwe_ciphertext_in.ciphertext_modulus(),
    );
    CudaLweCiphertextList::from_lwe_ciphertext_list(&h_input, stream)
}

/// Uploads a list of distinct input LWE ciphertexts as a single batch.
pub(crate) fn batched_input(
    lwe_ciphertexts_in: &[LweCiphertextOwned<u64>],
    streams: &CudaStreams,
) -> CudaLweCiphertextList<u64> {
    let lwe_size = lwe_ciphertexts_in[0].lwe_size();
    let mut container = Vec::with_capacity(lwe_size.0 * lwe_ciphertexts_in.len());
    for ct in lwe_ciphertexts_in {
        assert_eq!(
            ct.lwe_size(),
            lwe_size,
            "every lane must share the same LWE size"
        );
        container.extend_from_slice(ct.as_ref());
    }
    let h_input = LweCiphertextList::from_container(
        container,
        lwe_size,
        lwe_ciphertexts_in[0].ciphertext_modulus(),
    );
    CudaLweCiphertextList::from_lwe_ciphertext_list(&h_input, streams)
}

/// Counterpart of [`MULTI_BIT_2_2_2_PARAMS`] and [`MULTI_BIT_2_2_3_PARAMS`] for a grouping factor
/// of 4, which only the GPU backend implements: the parameters actually used with it.
pub const MULTI_BIT_2_2_4_PARAMS: MultiBitTestParams<u64> =
    PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;

pub const MULTI_BIT_2_2_2_KS32_PARAMS: MultiBitTestKS32Params<u64> = MultiBitTestKS32Params {
    lwe_dimension: LweDimension(920),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(13),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(17),
    pbs_base_log: DecompositionBaseLog(22),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(5),
    message_modulus_log: MessageModulusLog(2),
    log2_p_fail: -134.345,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(4),
    deterministic_execution: false,
};

// Macro to generate tests for all parameter sets
macro_rules! create_gpu_parameterized_test{
    ($name:ident { $($param:ident),* }) => {
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
        create_gpu_parameterized_test!($name
        {
            TEST_PARAMS_4_BITS_NATIVE_U64
        });
    };
}
macro_rules! create_gpu_multi_bit_parameterized_test{
    ($name:ident { $($param:ident),* }) => {
        ::paste::paste! {
            $(
            #[test]
            fn [<test_gpu_ $name _ $param:lower>]() {
                $name(&$param)
            }
            )*
        }
    };
    ($name:ident)=> {
        create_gpu_multi_bit_parameterized_test!($name
        {
            MULTI_BIT_2_2_2_PARAMS,
            MULTI_BIT_2_2_3_PARAMS,
            MULTI_BIT_3_3_2_PARAMS,
            MULTI_BIT_3_3_3_PARAMS
        });
    };
}
macro_rules! create_gpu_multi_bit_ks32_parameterized_test{
    ($name:ident { $($param:ident),* }) => {
        ::paste::paste! {
            $(
            #[test]
            fn [<test_gpu_ $name _ $param:lower>]() {
                $name(&$param)
            }
            )*
        }
    };
    ($name:ident)=> {
        create_gpu_multi_bit_ks32_parameterized_test!($name
        {
            MULTI_BIT_2_2_2_KS32_PARAMS
        });
    };
}
use crate::core_crypto::gpu::algorithms::test::params::MultiBitTestKS32Params;
use crate::core_crypto::gpu::lwe_packing_keyswitch_key::CudaLwePackingKeyswitchKey;
use create_gpu_multi_bit_ks32_parameterized_test;
use create_gpu_multi_bit_parameterized_test;
use create_gpu_parameterized_test;
