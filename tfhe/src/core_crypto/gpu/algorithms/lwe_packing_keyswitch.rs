#![deny(clippy::cast_possible_truncation)]
use crate::core_crypto::gpu::glwe_ciphertext_list::CudaGlweCiphertextList;
use crate::core_crypto::gpu::lwe_ciphertext_list::CudaLweCiphertextList;
use crate::core_crypto::gpu::lwe_packing_keyswitch_key::CudaLwePackingKeyswitchKey;
use crate::core_crypto::gpu::{packing_keyswitch_list_128, packing_keyswitch_list_64, CudaStreams};
use crate::core_crypto::prelude::{CastInto, UnsignedTorus};

pub fn cuda_keyswitch_lwe_ciphertext_list_into_glwe_ciphertext_64<Scalar>(
    lwe_pksk: &CudaLwePackingKeyswitchKey<Scalar>,
    input_lwe_ciphertext_list: &CudaLweCiphertextList<Scalar>,
    output_glwe_ciphertext: &mut CudaGlweCiphertextList<Scalar>,
    streams: &CudaStreams,
) where
    // CastInto required for PBS modulus switch which returns a usize
    Scalar: UnsignedTorus + CastInto<usize>,
{
    let input_lwe_dimension = input_lwe_ciphertext_list.lwe_dimension();
    let output_glwe_dimension = output_glwe_ciphertext.glwe_dimension();
    let output_polynomial_size = output_glwe_ciphertext.polynomial_size();

    // Parameter validation
    assert!(
        lwe_pksk.input_key_lwe_dimension() == input_lwe_dimension,
        "Mismatched input LweDimension. \
        LwePackingKeyswitchKey input LweDimension: {:?}, input LweCiphertext LweDimension {:?}.",
        lwe_pksk.input_key_lwe_dimension(),
        input_lwe_dimension
    );
    assert!(
        lwe_pksk.output_glwe_size().to_glwe_dimension() == output_glwe_dimension,
        "Mismatched output GlweDimension. \
        LwePackingKeyswitchKey output GlweDimension: {:?}, \
        output GlweCiphertext GlweDimension {:?}.",
        lwe_pksk.output_glwe_size().to_glwe_dimension(),
        output_glwe_dimension
    );
    assert!(
        lwe_pksk.output_polynomial_size() == output_polynomial_size,
        "Mismatched output PolynomialSize. \
        LwePackingKeyswitchKey output PolynomialSize: {:?}, \
        output GlweCiphertext PolynomialSize {:?}.",
        lwe_pksk.output_polynomial_size(),
        output_polynomial_size
    );
    assert!(
        lwe_pksk.ciphertext_modulus() == input_lwe_ciphertext_list.ciphertext_modulus(),
        "Mismatched CiphertextModulus. \
        LwePackingKeyswitchKey CiphertextModulus: {:?}, input LweCiphertext CiphertextModulus {:?}.",
        lwe_pksk.ciphertext_modulus(),
        input_lwe_ciphertext_list.ciphertext_modulus()
    );
    assert!(
        lwe_pksk.ciphertext_modulus() == output_glwe_ciphertext.ciphertext_modulus(),
        "Mismatched CiphertextModulus. \
        LwePackingKeyswitchKey CiphertextModulus: {:?}, \
        output GlweCiphertext CiphertextModulus {:?}.",
        lwe_pksk.ciphertext_modulus(),
        output_glwe_ciphertext.ciphertext_modulus()
    );
    assert!(
        input_lwe_ciphertext_list
            .ciphertext_modulus()
            .is_compatible_with_native_modulus(),
        "GPU packing keyswitch currently only supports power of 2 moduli"
    );
    assert!(
        input_lwe_ciphertext_list.lwe_ciphertext_count().0 <= output_polynomial_size.0,
        "Input LWE ciphertext count ({}) exceeds output polynomial size ({})",
        input_lwe_ciphertext_list.lwe_ciphertext_count().0,
        output_polynomial_size.0
    );

    // GPU index checks
    assert_eq!(
        streams.gpu_indexes[0],
        input_lwe_ciphertext_list.0.d_vec.gpu_index(0),
        "GPU error: first stream is on GPU {}, first input pointer is on GPU {}",
        streams.gpu_indexes[0].get(),
        input_lwe_ciphertext_list.0.d_vec.gpu_index(0).get(),
    );
    assert_eq!(
        streams.gpu_indexes[0],
        output_glwe_ciphertext.0.d_vec.gpu_index(0),
        "GPU error: first stream is on GPU {}, first output pointer is on GPU {}",
        streams.gpu_indexes[0].get(),
        output_glwe_ciphertext.0.d_vec.gpu_index(0).get(),
    );
    assert_eq!(
        streams.gpu_indexes[0],
        lwe_pksk.d_vec.gpu_index(0),
        "GPU error: first stream is on GPU {}, first pksk pointer is on GPU {}",
        streams.gpu_indexes[0].get(),
        lwe_pksk.d_vec.gpu_index(0).get(),
    );

    unsafe {
        packing_keyswitch_list_64(
            streams,
            &mut output_glwe_ciphertext.0.d_vec,
            &input_lwe_ciphertext_list.0.d_vec,
            input_lwe_dimension,
            output_glwe_dimension,
            output_polynomial_size,
            &lwe_pksk.d_vec,
            lwe_pksk.decomposition_base_log(),
            lwe_pksk.decomposition_level_count(),
            input_lwe_ciphertext_list.lwe_ciphertext_count(),
        );
        streams.synchronize();
    }
}

pub fn cuda_keyswitch_lwe_ciphertext_list_into_glwe_ciphertext_128<Scalar>(
    lwe_pksk: &CudaLwePackingKeyswitchKey<Scalar>,
    input_lwe_ciphertext_list: &CudaLweCiphertextList<Scalar>,
    output_glwe_ciphertext: &mut CudaGlweCiphertextList<Scalar>,
    streams: &CudaStreams,
) where
    // CastInto required for PBS modulus switch which returns a usize
    Scalar: UnsignedTorus + CastInto<usize>,
{
    let input_lwe_dimension = input_lwe_ciphertext_list.lwe_dimension();
    let output_glwe_dimension = output_glwe_ciphertext.glwe_dimension();
    let output_polynomial_size = output_glwe_ciphertext.polynomial_size();

    // Parameter validation
    assert!(
        lwe_pksk.input_key_lwe_dimension() == input_lwe_dimension,
        "Mismatched input LweDimension. \
        LwePackingKeyswitchKey input LweDimension: {:?}, input LweCiphertext LweDimension {:?}.",
        lwe_pksk.input_key_lwe_dimension(),
        input_lwe_dimension
    );
    assert!(
        lwe_pksk.output_glwe_size().to_glwe_dimension() == output_glwe_dimension,
        "Mismatched output GlweDimension. \
        LwePackingKeyswitchKey output GlweDimension: {:?}, \
        output GlweCiphertext GlweDimension {:?}.",
        lwe_pksk.output_glwe_size().to_glwe_dimension(),
        output_glwe_dimension
    );
    assert!(
        lwe_pksk.output_polynomial_size() == output_polynomial_size,
        "Mismatched output PolynomialSize. \
        LwePackingKeyswitchKey output PolynomialSize: {:?}, \
        output GlweCiphertext PolynomialSize {:?}.",
        lwe_pksk.output_polynomial_size(),
        output_polynomial_size
    );
    assert!(
        lwe_pksk.ciphertext_modulus() == input_lwe_ciphertext_list.ciphertext_modulus(),
        "Mismatched CiphertextModulus. \
        LwePackingKeyswitchKey CiphertextModulus: {:?}, input LweCiphertext CiphertextModulus {:?}.",
        lwe_pksk.ciphertext_modulus(),
        input_lwe_ciphertext_list.ciphertext_modulus()
    );
    assert!(
        lwe_pksk.ciphertext_modulus() == output_glwe_ciphertext.ciphertext_modulus(),
        "Mismatched CiphertextModulus. \
        LwePackingKeyswitchKey CiphertextModulus: {:?}, \
        output GlweCiphertext CiphertextModulus {:?}.",
        lwe_pksk.ciphertext_modulus(),
        output_glwe_ciphertext.ciphertext_modulus()
    );
    assert!(
        input_lwe_ciphertext_list
            .ciphertext_modulus()
            .is_compatible_with_native_modulus(),
        "GPU packing keyswitch currently only supports power of 2 moduli"
    );
    assert!(
        input_lwe_ciphertext_list.lwe_ciphertext_count().0 <= output_polynomial_size.0,
        "Input LWE ciphertext count ({}) exceeds output polynomial size ({})",
        input_lwe_ciphertext_list.lwe_ciphertext_count().0,
        output_polynomial_size.0
    );

    // GPU index checks
    assert_eq!(
        streams.gpu_indexes[0],
        input_lwe_ciphertext_list.0.d_vec.gpu_index(0),
        "GPU error: first stream is on GPU {}, first input pointer is on GPU {}",
        streams.gpu_indexes[0].get(),
        input_lwe_ciphertext_list.0.d_vec.gpu_index(0).get(),
    );
    assert_eq!(
        streams.gpu_indexes[0],
        output_glwe_ciphertext.0.d_vec.gpu_index(0),
        "GPU error: first stream is on GPU {}, first output pointer is on GPU {}",
        streams.gpu_indexes[0].get(),
        output_glwe_ciphertext.0.d_vec.gpu_index(0).get(),
    );
    assert_eq!(
        streams.gpu_indexes[0],
        lwe_pksk.d_vec.gpu_index(0),
        "GPU error: first stream is on GPU {}, first pksk pointer is on GPU {}",
        streams.gpu_indexes[0].get(),
        lwe_pksk.d_vec.gpu_index(0).get(),
    );

    unsafe {
        packing_keyswitch_list_128(
            streams,
            &mut output_glwe_ciphertext.0.d_vec,
            &input_lwe_ciphertext_list.0.d_vec,
            input_lwe_dimension,
            output_glwe_dimension,
            output_polynomial_size,
            &lwe_pksk.d_vec,
            lwe_pksk.decomposition_base_log(),
            lwe_pksk.decomposition_level_count(),
            input_lwe_ciphertext_list.lwe_ciphertext_count(),
        );
        streams.synchronize();
    }
}
