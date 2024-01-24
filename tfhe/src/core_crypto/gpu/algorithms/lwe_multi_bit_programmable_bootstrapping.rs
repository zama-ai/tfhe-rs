use crate::core_crypto::gpu::entities::glwe_ciphertext_list::CudaGlweCiphertextList;
use crate::core_crypto::gpu::entities::lwe_ciphertext_list::CudaLweCiphertextList;
use crate::core_crypto::gpu::entities::lwe_multi_bit_bootstrap_key::CudaLweMultiBitBootstrapKey;
use crate::core_crypto::gpu::vec::CudaVec;
use crate::core_crypto::gpu::CudaStream;
use crate::core_crypto::prelude::{CastInto, LweCiphertextIndex, UnsignedTorus};

/// # Safety
///
/// - `stream` __must__ be synchronized to guarantee computation has finished, and inputs must not
///   be dropped until stream is synchronised
#[allow(clippy::too_many_arguments)]
pub unsafe fn cuda_multi_bit_programmable_bootstrap_lwe_ciphertext_async<Scalar>(
    input: &CudaLweCiphertextList<Scalar>,
    output: &mut CudaLweCiphertextList<Scalar>,
    accumulator: &CudaGlweCiphertextList<Scalar>,
    lut_indexes: &CudaVec<Scalar>,
    output_indexes: &CudaVec<Scalar>,
    input_indexes: &CudaVec<Scalar>,
    multi_bit_bsk: &CudaLweMultiBitBootstrapKey,
    stream: &CudaStream,
) where
    // CastInto required for PBS modulus switch which returns a usize
    Scalar: UnsignedTorus + CastInto<usize>,
{
    assert_eq!(
        input.lwe_dimension(),
        multi_bit_bsk.input_lwe_dimension(),
        "Mimatched input LweDimension. LweCiphertext input LweDimension {:?}. \
        FourierLweMultiBitBootstrapKey input LweDimension {:?}.",
        input.lwe_dimension(),
        multi_bit_bsk.input_lwe_dimension(),
    );

    assert_eq!(
        output.lwe_dimension(),
        multi_bit_bsk.output_lwe_dimension(),
        "Mimatched output LweDimension. LweCiphertext output LweDimension {:?}. \
        FourierLweMultiBitBootstrapKey output LweDimension {:?}.",
        output.lwe_dimension(),
        multi_bit_bsk.output_lwe_dimension(),
    );

    assert_eq!(
        accumulator.glwe_dimension(),
        multi_bit_bsk.glwe_dimension(),
        "Mimatched GlweSize. Accumulator GlweSize {:?}. \
        FourierLweMultiBitBootstrapKey GlweSize {:?}.",
        accumulator.glwe_dimension(),
        multi_bit_bsk.glwe_dimension(),
    );

    assert_eq!(
        accumulator.polynomial_size(),
        multi_bit_bsk.polynomial_size(),
        "Mimatched PolynomialSize. Accumulator PolynomialSize {:?}. \
        FourierLweMultiBitBootstrapKey PolynomialSize {:?}.",
        accumulator.polynomial_size(),
        multi_bit_bsk.polynomial_size(),
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

    stream.bootstrap_multi_bit_async(
        &mut output.0.d_vec,
        output_indexes,
        &accumulator.0.d_vec,
        lut_indexes,
        &input.0.d_vec,
        input_indexes,
        &multi_bit_bsk.d_vec,
        input.lwe_dimension(),
        multi_bit_bsk.glwe_dimension(),
        multi_bit_bsk.polynomial_size(),
        multi_bit_bsk.decomp_base_log(),
        multi_bit_bsk.decomp_level_count(),
        multi_bit_bsk.grouping_factor(),
        input.lwe_ciphertext_count().0 as u32,
        LweCiphertextIndex(0),
    );
}

#[allow(clippy::too_many_arguments)]
pub fn cuda_multi_bit_programmable_bootstrap_lwe_ciphertext<Scalar>(
    input: &CudaLweCiphertextList<Scalar>,
    output: &mut CudaLweCiphertextList<Scalar>,
    accumulator: &CudaGlweCiphertextList<Scalar>,
    lut_indexes: &CudaVec<Scalar>,
    output_indexes: &CudaVec<Scalar>,
    input_indexes: &CudaVec<Scalar>,
    multi_bit_bsk: &CudaLweMultiBitBootstrapKey,
    stream: &CudaStream,
) where
    // CastInto required for PBS modulus switch which returns a usize
    Scalar: UnsignedTorus + CastInto<usize>,
{
    unsafe {
        cuda_multi_bit_programmable_bootstrap_lwe_ciphertext_async(
            input,
            output,
            accumulator,
            lut_indexes,
            output_indexes,
            input_indexes,
            multi_bit_bsk,
            stream,
        );
    }
    stream.synchronize();
}
