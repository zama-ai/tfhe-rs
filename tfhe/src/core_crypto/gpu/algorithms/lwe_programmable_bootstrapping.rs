use crate::core_crypto::gpu::entities::glwe_ciphertext_list::CudaGlweCiphertextList;
use crate::core_crypto::gpu::entities::lwe_bootstrap_key::CudaLweBootstrapKey;
use crate::core_crypto::gpu::entities::lwe_ciphertext_list::CudaLweCiphertextList;
use crate::core_crypto::gpu::vec::CudaVec;
use crate::core_crypto::gpu::{
    programmable_bootstrap_128_async, programmable_bootstrap_async, CudaStreams,
};
use crate::core_crypto::prelude::{CastInto, LweCiphertextCount, UnsignedTorus};

/// # Safety
///
/// - `streams` __must__ be synchronized to guarantee computation has finished, and inputs must not
///   be dropped until streams is synchronised
#[allow(clippy::too_many_arguments)]
pub unsafe fn cuda_programmable_bootstrap_lwe_ciphertext_async<Scalar>(
    input: &CudaLweCiphertextList<Scalar>,
    output: &mut CudaLweCiphertextList<Scalar>,
    accumulator: &CudaGlweCiphertextList<Scalar>,
    lut_indexes: &CudaVec<Scalar>,
    output_indexes: &CudaVec<Scalar>,
    input_indexes: &CudaVec<Scalar>,
    num_samples: LweCiphertextCount,
    bsk: &CudaLweBootstrapKey,
    streams: &CudaStreams,
) where
    // CastInto required for PBS modulus switch which returns a usize
    Scalar: UnsignedTorus + CastInto<usize>,
{
    assert_eq!(
        input.lwe_dimension(),
        bsk.input_lwe_dimension(),
        "Mismatched input LweDimension. LweCiphertext input LweDimension {:?}. \
        FourierLweMultiBitBootstrapKey input LweDimension {:?}.",
        input.lwe_dimension(),
        bsk.input_lwe_dimension(),
    );

    assert_eq!(
        output.lwe_dimension(),
        bsk.output_lwe_dimension(),
        "Mismatched output LweDimension. LweCiphertext output LweDimension {:?}. \
        FourierLweMultiBitBootstrapKey output LweDimension {:?}.",
        output.lwe_dimension(),
        bsk.output_lwe_dimension(),
    );

    assert_eq!(
        accumulator.glwe_dimension(),
        bsk.glwe_dimension(),
        "Mismatched GlweSize. Accumulator GlweSize {:?}. \
        FourierLweMultiBitBootstrapKey GlweSize {:?}.",
        accumulator.glwe_dimension(),
        bsk.glwe_dimension(),
    );

    assert_eq!(
        accumulator.polynomial_size(),
        bsk.polynomial_size(),
        "Mismatched PolynomialSize. Accumulator PolynomialSize {:?}. \
        FourierLweMultiBitBootstrapKey PolynomialSize {:?}.",
        accumulator.polynomial_size(),
        bsk.polynomial_size(),
    );

    assert_eq!(
        input.ciphertext_modulus(),
        output.ciphertext_modulus(),
        "Mismatched CiphertextModulus between input ({:?}) and output ({:?})",
        input.ciphertext_modulus(),
        output.ciphertext_modulus(),
    );

    assert_eq!(
        input.ciphertext_modulus(),
        accumulator.ciphertext_modulus(),
        "Mismatched CiphertextModulus between input ({:?}) and accumulator ({:?})",
        input.ciphertext_modulus(),
        accumulator.ciphertext_modulus(),
    );
    assert_eq!(
        streams.gpu_indexes[0],
        bsk.d_vec.gpu_index(0),
        "GPU error: first stream is on GPU {}, first bsk pointer is on GPU {}",
        streams.gpu_indexes[0].get(),
        bsk.d_vec.gpu_index(0).get(),
    );
    assert_eq!(
        streams.gpu_indexes[0],
        input.0.d_vec.gpu_index(0),
        "GPU error: first stream is on GPU {}, first input pointer is on GPU {}",
        streams.gpu_indexes[0].get(),
        input.0.d_vec.gpu_index(0).get(),
    );
    assert_eq!(
        streams.gpu_indexes[0],
        output.0.d_vec.gpu_index(0),
        "GPU error: first stream is on GPU {}, first output pointer is on GPU {}",
        streams.gpu_indexes[0].get(),
        output.0.d_vec.gpu_index(0).get(),
    );
    assert_eq!(
        streams.gpu_indexes[0],
        accumulator.0.d_vec.gpu_index(0),
        "GPU error: first stream is on GPU {}, first accumulator pointer is on GPU {}",
        streams.gpu_indexes[0].get(),
        accumulator.0.d_vec.gpu_index(0).get(),
    );
    assert_eq!(
        streams.gpu_indexes[0],
        input_indexes.gpu_index(0),
        "GPU error: first stream is on GPU {}, first input indexes pointer is on GPU {}",
        streams.gpu_indexes[0].get(),
        input_indexes.gpu_index(0).get(),
    );
    assert_eq!(
        streams.gpu_indexes[0],
        output_indexes.gpu_index(0),
        "GPU error: first stream is on GPU {}, first output indexes pointer is on GPU {}",
        streams.gpu_indexes[0].get(),
        output_indexes.gpu_index(0).get(),
    );
    assert_eq!(
        streams.gpu_indexes[0],
        lut_indexes.gpu_index(0),
        "GPU error: first stream is on GPU {}, first lut indexes pointer is on GPU {}",
        streams.gpu_indexes[0].get(),
        lut_indexes.gpu_index(0).get(),
    );

    let lwe_dimension = input.lwe_dimension();
    let ct_modulus = input.ciphertext_modulus().raw_modulus_float();

    programmable_bootstrap_async(
        streams,
        &mut output.0.d_vec,
        output_indexes,
        &accumulator.0.d_vec,
        lut_indexes,
        &input.0.d_vec,
        input_indexes,
        &bsk.d_vec,
        lwe_dimension,
        bsk.glwe_dimension(),
        bsk.polynomial_size(),
        bsk.decomp_base_log(),
        bsk.decomp_level_count(),
        num_samples.0 as u32,
        bsk.d_ms_noise_reduction_key.as_ref(),
        ct_modulus,
    );
}

/// # Safety
///
/// - `streams` __must__ be synchronized to guarantee computation has finished, and inputs must not
///   be dropped until streams is synchronised
#[allow(clippy::too_many_arguments)]
pub unsafe fn cuda_programmable_bootstrap_128_lwe_ciphertext_async<Scalar>(
    input: &CudaLweCiphertextList<Scalar>,
    output: &mut CudaLweCiphertextList<Scalar>,
    accumulator: &CudaGlweCiphertextList<Scalar>,
    num_samples: LweCiphertextCount,
    bsk: &CudaLweBootstrapKey,
    streams: &CudaStreams,
) where
    // CastInto required for PBS128 modulus switch which returns a usize
    Scalar: UnsignedTorus + CastInto<usize>,
{
    assert_eq!(
        size_of::<Scalar>(),
        16,
        "Wrong Scalar size: {:?}. \
        Required Scalar size: 16.",
        size_of::<Scalar>(),
    );

    assert_eq!(
        accumulator.0.glwe_ciphertext_count.0,
        1,
        "Wrong lut count: {:?}. \
        Required lut count: 1.",
        size_of::<Scalar>(),
    );

    assert_eq!(
        input.lwe_dimension(),
        bsk.input_lwe_dimension(),
        "Mismatched input LweDimension. LweCiphertext input LweDimension {:?}. \
        FourierLweMultiBitBootstrapKey input LweDimension {:?}.",
        input.lwe_dimension(),
        bsk.input_lwe_dimension(),
    );

    assert_eq!(
        output.lwe_dimension(),
        bsk.output_lwe_dimension(),
        "Mismatched output LweDimension. LweCiphertext output LweDimension {:?}. \
        FourierLweMultiBitBootstrapKey output LweDimension {:?}.",
        output.lwe_dimension(),
        bsk.output_lwe_dimension(),
    );

    assert_eq!(
        accumulator.glwe_dimension(),
        bsk.glwe_dimension(),
        "Mismatched GlweSize. Accumulator GlweSize {:?}. \
        FourierLweMultiBitBootstrapKey GlweSize {:?}.",
        accumulator.glwe_dimension(),
        bsk.glwe_dimension(),
    );

    assert_eq!(
        accumulator.polynomial_size(),
        bsk.polynomial_size(),
        "Mismatched PolynomialSize. Accumulator PolynomialSize {:?}. \
        FourierLweMultiBitBootstrapKey PolynomialSize {:?}.",
        accumulator.polynomial_size(),
        bsk.polynomial_size(),
    );

    assert_eq!(
        input.ciphertext_modulus(),
        output.ciphertext_modulus(),
        "Mismatched CiphertextModulus between input ({:?}) and output ({:?})",
        input.ciphertext_modulus(),
        output.ciphertext_modulus(),
    );

    assert_eq!(
        input.ciphertext_modulus(),
        accumulator.ciphertext_modulus(),
        "Mismatched CiphertextModulus between input ({:?}) and accumulator ({:?})",
        input.ciphertext_modulus(),
        accumulator.ciphertext_modulus(),
    );
    assert_eq!(
        streams.gpu_indexes[0],
        bsk.d_vec.gpu_index(0),
        "GPU error: first stream is on GPU {}, first bsk pointer is on GPU {}",
        streams.gpu_indexes[0].get(),
        bsk.d_vec.gpu_index(0).get(),
    );
    assert_eq!(
        streams.gpu_indexes[0],
        input.0.d_vec.gpu_index(0),
        "GPU error: first stream is on GPU {}, first input pointer is on GPU {}",
        streams.gpu_indexes[0].get(),
        input.0.d_vec.gpu_index(0).get(),
    );
    assert_eq!(
        streams.gpu_indexes[0],
        output.0.d_vec.gpu_index(0),
        "GPU error: first stream is on GPU {}, first output pointer is on GPU {}",
        streams.gpu_indexes[0].get(),
        output.0.d_vec.gpu_index(0).get(),
    );
    assert_eq!(
        streams.gpu_indexes[0],
        accumulator.0.d_vec.gpu_index(0),
        "GPU error: first stream is on GPU {}, first accumulator pointer is on GPU {}",
        streams.gpu_indexes[0].get(),
        accumulator.0.d_vec.gpu_index(0).get(),
    );
    let lwe_dimension = input.lwe_dimension();
    let ct_modulus = input.ciphertext_modulus().raw_modulus_float();
    programmable_bootstrap_128_async(
        streams,
        &mut output.0.d_vec,
        &accumulator.0.d_vec,
        &input.0.d_vec,
        &bsk.d_vec,
        lwe_dimension,
        bsk.glwe_dimension(),
        bsk.polynomial_size(),
        bsk.decomp_base_log(),
        bsk.decomp_level_count(),
        num_samples.0 as u32,
        bsk.d_ms_noise_reduction_key.as_ref(),
        ct_modulus,
    );
}

#[allow(clippy::too_many_arguments)]
pub fn cuda_programmable_bootstrap_lwe_ciphertext<Scalar>(
    input: &CudaLweCiphertextList<Scalar>,
    output: &mut CudaLweCiphertextList<Scalar>,
    accumulator: &CudaGlweCiphertextList<Scalar>,
    lut_indexes: &CudaVec<Scalar>,
    output_indexes: &CudaVec<Scalar>,
    input_indexes: &CudaVec<Scalar>,
    num_samples: LweCiphertextCount,
    bsk: &CudaLweBootstrapKey,
    streams: &CudaStreams,
) where
    Scalar: UnsignedTorus + CastInto<usize>,
{
    unsafe {
        cuda_programmable_bootstrap_lwe_ciphertext_async(
            input,
            output,
            accumulator,
            lut_indexes,
            output_indexes,
            input_indexes,
            num_samples,
            bsk,
            streams,
        );
    }
    streams.synchronize();
}

/// Performs a programmable bootstrap (PBS) on a list of 128-bit LWE ciphertexts,
/// storing the result back into the provided `output` list at matching indices.
///
/// # Behavior
///
/// - **Single-GLWE requirement**: The `accumulator` must contain exactly **one** GLWE ciphertext
///   (i.e., one LUT).
/// - **One LUT for all inputs**: That single LUT is applied uniformly to every LWE ciphertext in
///   `input`.
/// - **Index matching**: Each LWE ciphertext in `input` is transformed and stored at the **same
///   index** in `output`.
#[allow(clippy::too_many_arguments)]
pub fn cuda_programmable_bootstrap_128_lwe_ciphertext<Scalar>(
    input: &CudaLweCiphertextList<Scalar>,
    output: &mut CudaLweCiphertextList<Scalar>,
    accumulator: &CudaGlweCiphertextList<Scalar>,
    num_samples: LweCiphertextCount,
    bsk: &CudaLweBootstrapKey,
    streams: &CudaStreams,
) where
    Scalar: UnsignedTorus + CastInto<usize>,
{
    unsafe {
        cuda_programmable_bootstrap_128_lwe_ciphertext_async(
            input,
            output,
            accumulator,
            num_samples,
            bsk,
            streams,
        );
    }
    streams.synchronize();
}
