#![deny(clippy::cast_possible_truncation)]
use crate::core_crypto::gpu::entities::glwe_ciphertext_list::CudaGlweCiphertextList;
use crate::core_crypto::gpu::entities::lwe_bootstrap_key::CudaLweBootstrapKey;
use crate::core_crypto::gpu::entities::lwe_ciphertext_list::CudaLweCiphertextList;
use crate::core_crypto::gpu::vec::CudaVec;
use crate::core_crypto::gpu::{
    programmable_bootstrap_128_async, programmable_bootstrap_async, CudaStreams,
};
use crate::core_crypto::prelude::{CastInto, UnsignedTorus};

#[allow(clippy::too_many_arguments)]
pub fn cuda_programmable_bootstrap_lwe_ciphertext<Scalar>(
    input: &CudaLweCiphertextList<Scalar>,
    output: &mut CudaLweCiphertextList<Scalar>,
    accumulator: &CudaGlweCiphertextList<Scalar>,
    lut_indexes: &CudaVec<Scalar>,
    output_indexes: &CudaVec<Scalar>,
    input_indexes: &CudaVec<Scalar>,
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
        output.ciphertext_modulus(),
        accumulator.ciphertext_modulus(),
        "Mismatched CiphertextModulus between output ({:?}) and accumulator ({:?})",
        output.ciphertext_modulus(),
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
    let num_samples = input.lwe_ciphertext_count();
    unsafe {
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
            u32::try_from(num_samples.0).unwrap(),
            bsk.ms_noise_reduction_configuration.as_ref(),
        );
        streams.synchronize();
    }
}

/// Performs a programmable bootstrap (PBS) on a list of 128-bit LWE ciphertexts,
/// storing the result back into the provided `output` list.
///
/// # Behavior
///
/// - **Single-GLWE requirement**: The `accumulator` must contain exactly **one** GLWE ciphertext
///   (i.e., one LUT).
/// - **One LUT for all inputs**: That single LUT is applied uniformly to every LWE ciphertext in
///   `input`.
#[allow(clippy::too_many_arguments)]
pub fn cuda_programmable_bootstrap_128_lwe_ciphertext<Scalar>(
    input: &CudaLweCiphertextList<u64>,
    output: &mut CudaLweCiphertextList<Scalar>,
    accumulator: &CudaGlweCiphertextList<Scalar>,
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
        output.ciphertext_modulus(),
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
    let num_samples = input.lwe_ciphertext_count();
    unsafe {
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
            u32::try_from(num_samples.0).unwrap(),
            bsk.ms_noise_reduction_configuration.as_ref(),
        );
        streams.synchronize();
    }
}
