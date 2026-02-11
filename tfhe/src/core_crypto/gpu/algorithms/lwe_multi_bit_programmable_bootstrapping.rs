#![deny(clippy::cast_possible_truncation)]
use crate::core_crypto::gpu::entities::glwe_ciphertext_list::CudaGlweCiphertextList;
use crate::core_crypto::gpu::entities::lwe_ciphertext_list::CudaLweCiphertextList;
use crate::core_crypto::gpu::entities::lwe_multi_bit_bootstrap_key::CudaLweMultiBitBootstrapKey;
use crate::core_crypto::gpu::vec::CudaVec;
use crate::core_crypto::gpu::{programmable_bootstrap_multi_bit, CudaStreams};
use crate::core_crypto::prelude::{CastInto, UnsignedTorus};

#[allow(clippy::too_many_arguments)]
pub fn cuda_multi_bit_programmable_bootstrap_lwe_ciphertext<Scalar>(
    input: &CudaLweCiphertextList<Scalar>,
    output: &mut CudaLweCiphertextList<Scalar>,
    accumulator: &CudaGlweCiphertextList<Scalar>,
    lut_indexes: &CudaVec<Scalar>,
    output_indexes: &CudaVec<Scalar>,
    input_indexes: &CudaVec<Scalar>,
    multi_bit_bsk: &CudaLweMultiBitBootstrapKey<Scalar>,
    streams: &CudaStreams,
) where
    // CastInto required for PBS modulus switch which returns a usize
    Scalar: UnsignedTorus + CastInto<usize>,
{
    assert_eq!(
        input.lwe_dimension(),
        multi_bit_bsk.input_lwe_dimension(),
        "Mismatched input LweDimension. LweCiphertext input LweDimension {:?}. \
        FourierLweMultiBitBootstrapKey input LweDimension {:?}.",
        input.lwe_dimension(),
        multi_bit_bsk.input_lwe_dimension(),
    );

    assert_eq!(
        output.lwe_dimension(),
        multi_bit_bsk.output_lwe_dimension(),
        "Mismatched output LweDimension. LweCiphertext output LweDimension {:?}. \
        FourierLweMultiBitBootstrapKey output LweDimension {:?}.",
        output.lwe_dimension(),
        multi_bit_bsk.output_lwe_dimension(),
    );

    assert_eq!(
        accumulator.glwe_dimension(),
        multi_bit_bsk.glwe_dimension(),
        "Mismatched GlweSize. Accumulator GlweSize {:?}. \
        FourierLweMultiBitBootstrapKey GlweSize {:?}.",
        accumulator.glwe_dimension(),
        multi_bit_bsk.glwe_dimension(),
    );

    assert_eq!(
        accumulator.polynomial_size(),
        multi_bit_bsk.polynomial_size(),
        "Mismatched PolynomialSize. Accumulator PolynomialSize {:?}. \
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
    assert_eq!(
        streams.gpu_indexes[0],
        multi_bit_bsk.d_vec.gpu_index(0),
        "GPU error: first stream is on GPU {}, first bsk pointer is on GPU {}",
        streams.gpu_indexes[0].get(),
        multi_bit_bsk.d_vec.gpu_index(0).get(),
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

    unsafe {
        programmable_bootstrap_multi_bit(
            streams,
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
            u32::try_from(input.lwe_ciphertext_count().0).unwrap(),
        );
        streams.synchronize();
    }
}

#[allow(clippy::too_many_arguments)]
pub fn cuda_multi_bit_programmable_bootstrap_128_lwe_ciphertext<OutputScalar>(
    input: &CudaLweCiphertextList<u64>,
    output: &mut CudaLweCiphertextList<OutputScalar>,
    accumulator: &CudaGlweCiphertextList<OutputScalar>,
    lut_indexes: &CudaVec<u64>,
    output_indexes: &CudaVec<u64>,
    input_indexes: &CudaVec<u64>,
    multi_bit_bsk: &CudaLweMultiBitBootstrapKey<OutputScalar>,
    streams: &CudaStreams,
) where
    // CastInto required for PBS modulus switch which returns a usize
    OutputScalar: UnsignedTorus + CastInto<usize>,
{
    assert_eq!(
        input.lwe_dimension(),
        multi_bit_bsk.input_lwe_dimension(),
        "Mismatched input LweDimension. LweCiphertext input LweDimension {:?}. \
        FourierLweMultiBitBootstrapKey input LweDimension {:?}.",
        input.lwe_dimension(),
        multi_bit_bsk.input_lwe_dimension(),
    );

    assert_eq!(
        output.lwe_dimension(),
        multi_bit_bsk.output_lwe_dimension(),
        "Mismatched output LweDimension. LweCiphertext output LweDimension {:?}. \
        FourierLweMultiBitBootstrapKey output LweDimension {:?}.",
        output.lwe_dimension(),
        multi_bit_bsk.output_lwe_dimension(),
    );

    assert_eq!(
        accumulator.glwe_dimension(),
        multi_bit_bsk.glwe_dimension(),
        "Mismatched GlweSize. Accumulator GlweSize {:?}. \
        FourierLweMultiBitBootstrapKey GlweSize {:?}.",
        accumulator.glwe_dimension(),
        multi_bit_bsk.glwe_dimension(),
    );

    assert_eq!(
        accumulator.polynomial_size(),
        multi_bit_bsk.polynomial_size(),
        "Mismatched PolynomialSize. Accumulator PolynomialSize {:?}. \
        FourierLweMultiBitBootstrapKey PolynomialSize {:?}.",
        accumulator.polynomial_size(),
        multi_bit_bsk.polynomial_size(),
    );

    assert_eq!(
        output.ciphertext_modulus(),
        accumulator.ciphertext_modulus(),
        "Mismatched CiphertextModulus between output ({:?}) and accumulator ({:?})",
        input.ciphertext_modulus(),
        accumulator.ciphertext_modulus(),
    );
    assert_eq!(
        streams.gpu_indexes[0],
        multi_bit_bsk.d_vec.gpu_index(0),
        "GPU error: first stream is on GPU {}, first bsk pointer is on GPU {}",
        streams.gpu_indexes[0].get(),
        multi_bit_bsk.d_vec.gpu_index(0).get(),
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

    unsafe {
        programmable_bootstrap_multi_bit(
            streams,
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
            u32::try_from(input.lwe_ciphertext_count().0).unwrap(),
        );
        streams.synchronize();
    }
}
