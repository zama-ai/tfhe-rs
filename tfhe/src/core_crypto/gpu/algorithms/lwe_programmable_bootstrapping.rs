use crate::core_crypto::gpu::entities::glwe_ciphertext_list::CudaGlweCiphertextList;
use crate::core_crypto::gpu::entities::lwe_bootstrap_key::CudaLweBootstrapKey;
use crate::core_crypto::gpu::entities::lwe_ciphertext_list::CudaLweCiphertextList;
use crate::core_crypto::gpu::vec::CudaVec;
use crate::core_crypto::gpu::{programmable_bootstrap_async, CudaStreams};
use crate::core_crypto::prelude::{CastInto, LweCiphertextCount, UnsignedTorus};

/// # Safety
///
/// - `stream` __must__ be synchronized to guarantee computation has finished, and inputs must not
///   be dropped until stream is synchronised
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
    stream: &CudaStreams,
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

    programmable_bootstrap_async(
        stream,
        &mut output.0.d_vec,
        output_indexes,
        &accumulator.0.d_vec,
        lut_indexes,
        &input.0.d_vec,
        input_indexes,
        &bsk.d_vec,
        input.lwe_dimension(),
        bsk.glwe_dimension(),
        bsk.polynomial_size(),
        bsk.decomp_base_log(),
        bsk.decomp_level_count(),
        num_samples.0 as u32,
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
    stream: &CudaStreams,
) where
    // CastInto required for PBS modulus switch which returns a usize
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
            stream,
        );
    }
    stream.synchronize();
}
