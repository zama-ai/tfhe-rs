#![deny(clippy::cast_possible_truncation)]
use crate::core_crypto::gpu::lwe_ciphertext_list::CudaLweCiphertextList;
use crate::core_crypto::gpu::vec::CudaVec;
use crate::core_crypto::gpu::{
    add_lwe_ciphertext_vector_assign_async, add_lwe_ciphertext_vector_async,
    add_lwe_ciphertext_vector_plaintext_vector_assign_async,
    add_lwe_ciphertext_vector_plaintext_vector_async, mult_lwe_ciphertext_vector_cleartext_vector,
    mult_lwe_ciphertext_vector_cleartext_vector_assign_async,
    negate_lwe_ciphertext_vector_assign_async, negate_lwe_ciphertext_vector_async, CudaStreams,
};
use crate::core_crypto::prelude::UnsignedInteger;

pub fn cuda_lwe_ciphertext_add<Scalar>(
    output: &mut CudaLweCiphertextList<Scalar>,
    lhs: &CudaLweCiphertextList<Scalar>,
    rhs: &CudaLweCiphertextList<Scalar>,
    streams: &CudaStreams,
) where
    Scalar: UnsignedInteger,
{
    let num_samples = u32::try_from(output.lwe_ciphertext_count().0).unwrap();

    assert_eq!(
        lhs.lwe_ciphertext_count(),
        rhs.lwe_ciphertext_count(),
        "Mismatched number of ciphertexts between lhs ({:?}) and rhs ({:?})",
        lhs.lwe_ciphertext_count(),
        rhs.lwe_ciphertext_count()
    );

    assert_eq!(
        output.lwe_ciphertext_count(),
        rhs.lwe_ciphertext_count(),
        "Mismatched number of ciphertexts between output ({:?}) and rhs ({:?})",
        output.lwe_ciphertext_count(),
        rhs.lwe_ciphertext_count()
    );

    assert_eq!(
        lhs.ciphertext_modulus(),
        rhs.ciphertext_modulus(),
        "Mismatched moduli between lhs ({:?}) and rhs ({:?}) LweCiphertext",
        lhs.ciphertext_modulus(),
        rhs.ciphertext_modulus()
    );

    assert_eq!(
        output.ciphertext_modulus(),
        rhs.ciphertext_modulus(),
        "Mismatched moduli between output ({:?}) and rhs ({:?}) LweCiphertext",
        output.ciphertext_modulus(),
        rhs.ciphertext_modulus()
    );
    assert_eq!(
        streams.gpu_indexes[0],
        rhs.0.d_vec.gpu_index(0),
        "GPU error: first stream is on GPU {}, first rhs pointer is on GPU {}",
        streams.gpu_indexes[0].get(),
        rhs.0.d_vec.gpu_index(0).get(),
    );
    assert_eq!(
        streams.gpu_indexes[0],
        lhs.0.d_vec.gpu_index(0),
        "GPU error: first stream is on GPU {}, first lhs pointer is on GPU {}",
        streams.gpu_indexes[0].get(),
        lhs.0.d_vec.gpu_index(0).get(),
    );
    assert_eq!(
        streams.gpu_indexes[0],
        output.0.d_vec.gpu_index(0),
        "GPU error: first stream is on GPU {}, first output pointer is on GPU {}",
        streams.gpu_indexes[0].get(),
        output.0.d_vec.gpu_index(0).get(),
    );

    unsafe {
        add_lwe_ciphertext_vector_async(
            streams,
            &mut output.0.d_vec,
            &lhs.0.d_vec,
            &rhs.0.d_vec,
            lhs.lwe_dimension(),
            num_samples,
        );
        streams.synchronize();
    }
}

pub fn cuda_lwe_ciphertext_add_assign<Scalar>(
    lhs: &mut CudaLweCiphertextList<Scalar>,
    rhs: &CudaLweCiphertextList<Scalar>,
    streams: &CudaStreams,
) where
    Scalar: UnsignedInteger,
{
    let num_samples = u32::try_from(lhs.lwe_ciphertext_count().0).unwrap();

    assert_eq!(
        lhs.lwe_ciphertext_count(),
        rhs.lwe_ciphertext_count(),
        "Mismatched number of ciphertexts between lhs ({:?}) and rhs ({:?})",
        lhs.lwe_ciphertext_count(),
        rhs.lwe_ciphertext_count()
    );

    assert_eq!(
        lhs.ciphertext_modulus(),
        rhs.ciphertext_modulus(),
        "Mismatched moduli between lhs ({:?}) and rhs ({:?}) LweCiphertext",
        lhs.ciphertext_modulus(),
        rhs.ciphertext_modulus()
    );
    assert!(
        lhs.ciphertext_modulus().is_compatible_with_native_modulus(),
        "GPU LWE ciphertext add currently only supports power of 2 moduli"
    );
    assert_eq!(
        streams.gpu_indexes[0],
        lhs.0.d_vec.gpu_index(0),
        "GPU error: first stream is on GPU {}, first lhs pointer is on GPU {}",
        streams.gpu_indexes[0].get(),
        lhs.0.d_vec.gpu_index(0).get(),
    );
    assert_eq!(
        streams.gpu_indexes[0],
        rhs.0.d_vec.gpu_index(0),
        "GPU error: first stream is on GPU {}, first rhs pointer is on GPU {}",
        streams.gpu_indexes[0].get(),
        rhs.0.d_vec.gpu_index(0).get(),
    );

    unsafe {
        add_lwe_ciphertext_vector_assign_async(
            streams,
            &mut lhs.0.d_vec,
            &rhs.0.d_vec,
            rhs.lwe_dimension(),
            num_samples,
        );
        streams.synchronize();
    }
}

pub fn cuda_lwe_ciphertext_plaintext_add<Scalar>(
    output: &mut CudaLweCiphertextList<Scalar>,
    lhs: &CudaLweCiphertextList<Scalar>,
    rhs: &CudaVec<Scalar>,
    streams: &CudaStreams,
) where
    Scalar: UnsignedInteger,
{
    let num_samples = u32::try_from(output.lwe_ciphertext_count().0).unwrap();

    assert_eq!(
        output.lwe_ciphertext_count(),
        lhs.lwe_ciphertext_count(),
        "Mismatched number of ciphertexts between output ({:?}) and lhs ({:?})",
        output.lwe_ciphertext_count(),
        lhs.lwe_ciphertext_count()
    );

    assert_eq!(
        output.ciphertext_modulus(),
        lhs.ciphertext_modulus(),
        "Mismatched moduli between output ({:?}) and lhs ({:?}) LweCiphertext",
        output.ciphertext_modulus(),
        lhs.ciphertext_modulus()
    );
    assert_eq!(
        streams.gpu_indexes[0],
        lhs.0.d_vec.gpu_index(0),
        "GPU error: first stream is on GPU {}, first lhs pointer is on GPU {}",
        streams.gpu_indexes[0].get(),
        lhs.0.d_vec.gpu_index(0).get(),
    );
    assert_eq!(
        streams.gpu_indexes[0],
        rhs.gpu_index(0),
        "GPU error: first stream is on GPU {}, first rhs pointer is on GPU {}",
        streams.gpu_indexes[0].get(),
        rhs.gpu_index(0).get(),
    );
    assert_eq!(
        streams.gpu_indexes[0],
        output.0.d_vec.gpu_index(0),
        "GPU error: first stream is on GPU {}, first output pointer is on GPU {}",
        streams.gpu_indexes[0].get(),
        output.0.d_vec.gpu_index(0).get(),
    );

    unsafe {
        add_lwe_ciphertext_vector_plaintext_vector_async(
            streams,
            &mut output.0.d_vec,
            &lhs.0.d_vec,
            rhs,
            lhs.lwe_dimension(),
            num_samples,
        );
        streams.synchronize();
    }
}

pub fn cuda_lwe_ciphertext_plaintext_add_assign<Scalar>(
    lhs: &mut CudaLweCiphertextList<Scalar>,
    rhs: &CudaVec<Scalar>,
    streams: &CudaStreams,
) where
    Scalar: UnsignedInteger,
{
    let num_samples = u32::try_from(lhs.lwe_ciphertext_count().0).unwrap();
    let lwe_dimension = &lhs.lwe_dimension();

    assert_eq!(
        rhs.len(),
        lhs.lwe_ciphertext_count().0,
        "Mismatched number of ciphertexts between output ({:?}) and lhs ({:?})",
        rhs.len(),
        lhs.lwe_ciphertext_count().0
    );

    // GPU index checks
    assert_eq!(
        streams.gpu_indexes[0],
        lhs.0.d_vec.gpu_index(0),
        "GPU error: first stream is on GPU {}, first lhs pointer is on GPU {}",
        streams.gpu_indexes[0].get(),
        lhs.0.d_vec.gpu_index(0).get(),
    );
    assert_eq!(
        streams.gpu_indexes[0],
        rhs.gpu_index(0),
        "GPU error: first stream is on GPU {}, first rhs pointer is on GPU {}",
        streams.gpu_indexes[0].get(),
        rhs.gpu_index(0).get(),
    );

    // Native modulus check
    assert!(
        lhs.ciphertext_modulus().is_compatible_with_native_modulus(),
        "GPU LWE ciphertext plaintext add currently only supports power of 2 moduli"
    );

    unsafe {
        add_lwe_ciphertext_vector_plaintext_vector_assign_async(
            streams,
            &mut lhs.0.d_vec,
            rhs,
            *lwe_dimension,
            num_samples,
        );
        streams.synchronize();
    }
}

pub fn cuda_lwe_ciphertext_negate<Scalar>(
    output: &mut CudaLweCiphertextList<Scalar>,
    input: &CudaLweCiphertextList<Scalar>,
    streams: &CudaStreams,
) where
    Scalar: UnsignedInteger,
{
    assert_eq!(
        input.lwe_ciphertext_count(),
        output.lwe_ciphertext_count(),
        "Mismatched number of ciphertexts between input ({:?}) and output ({:?})",
        input.lwe_ciphertext_count(),
        output.lwe_ciphertext_count()
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
    let num_samples = u32::try_from(output.lwe_ciphertext_count().0).unwrap();
    let lwe_dimension = &output.lwe_dimension();

    unsafe {
        negate_lwe_ciphertext_vector_async(
            streams,
            &mut output.0.d_vec,
            &input.0.d_vec,
            *lwe_dimension,
            num_samples,
        );
        streams.synchronize();
    }
}

pub fn cuda_lwe_ciphertext_negate_assign<Scalar>(
    ct: &mut CudaLweCiphertextList<Scalar>,
    streams: &CudaStreams,
) where
    Scalar: UnsignedInteger,
{
    assert_eq!(
        streams.gpu_indexes[0],
        ct.0.d_vec.gpu_index(0),
        "GPU error: first stream is on GPU {}, first input pointer is on GPU {}",
        streams.gpu_indexes[0].get(),
        ct.0.d_vec.gpu_index(0).get(),
    );
    let num_samples = u32::try_from(ct.lwe_ciphertext_count().0).unwrap();
    let lwe_dimension = &ct.lwe_dimension();

    unsafe {
        negate_lwe_ciphertext_vector_assign_async(
            streams,
            &mut ct.0.d_vec,
            *lwe_dimension,
            num_samples,
        );
        streams.synchronize();
    }
}

pub fn cuda_lwe_ciphertext_cleartext_mul<Scalar>(
    output: &mut CudaLweCiphertextList<Scalar>,
    input: &CudaLweCiphertextList<Scalar>,
    cleartext: &CudaVec<Scalar>,
    streams: &CudaStreams,
) where
    Scalar: UnsignedInteger,
{
    assert_eq!(
        input.lwe_ciphertext_count(),
        output.lwe_ciphertext_count(),
        "Mismatched number of ciphertexts between input ({:?}) and output ({:?})",
        input.lwe_ciphertext_count(),
        output.lwe_ciphertext_count()
    );
    assert_eq!(
        input.lwe_ciphertext_count().0,
        cleartext.len(),
        "Mismatched number of ciphertexts between input ({:?}) and cleartext ({:?})",
        input.lwe_ciphertext_count(),
        cleartext.len()
    );
    assert_eq!(
        output.ciphertext_modulus(),
        input.ciphertext_modulus(),
        "Mismatched moduli between output ({:?}) and input ({:?}) LweCiphertext",
        output.ciphertext_modulus(),
        input.ciphertext_modulus()
    );
    assert!(
        input
            .ciphertext_modulus()
            .is_compatible_with_native_modulus(),
        "GPU LWE ciphertext cleartext mul currently only supports power of 2 moduli"
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
        cleartext.gpu_index(0),
        "GPU error: first stream is on GPU {}, first cleartext pointer is on GPU {}",
        streams.gpu_indexes[0].get(),
        cleartext.gpu_index(0).get(),
    );
    let num_samples = u32::try_from(output.lwe_ciphertext_count().0).unwrap();
    let lwe_dimension = &output.lwe_dimension();

    unsafe {
        mult_lwe_ciphertext_vector_cleartext_vector(
            streams,
            &mut output.0.d_vec,
            &input.0.d_vec,
            cleartext,
            *lwe_dimension,
            num_samples,
        );
        streams.synchronize();
    }
}

pub fn cuda_lwe_ciphertext_cleartext_mul_assign<Scalar>(
    ct: &mut CudaLweCiphertextList<Scalar>,
    cleartext: &CudaVec<Scalar>,
    streams: &CudaStreams,
) where
    Scalar: UnsignedInteger,
{
    assert_eq!(
        streams.gpu_indexes[0],
        ct.0.d_vec.gpu_index(0),
        "GPU error: first stream is on GPU {}, first input pointer is on GPU {}",
        streams.gpu_indexes[0].get(),
        ct.0.d_vec.gpu_index(0).get(),
    );
    assert_eq!(
        streams.gpu_indexes[0],
        cleartext.gpu_index(0),
        "GPU error: first stream is on GPU {}, first cleartext pointer is on GPU {}",
        streams.gpu_indexes[0].get(),
        cleartext.gpu_index(0).get(),
    );
    assert_eq!(
        ct.lwe_ciphertext_count().0,
        cleartext.len(),
        "Mismatched number of ciphertexts between input ({:?}) and cleartext ({:?})",
        ct.lwe_ciphertext_count(),
        cleartext.len()
    );
    let num_samples = u32::try_from(ct.lwe_ciphertext_count().0).unwrap();
    let lwe_dimension = ct.lwe_dimension();

    unsafe {
        mult_lwe_ciphertext_vector_cleartext_vector_assign_async(
            streams,
            &mut ct.0.d_vec,
            cleartext,
            lwe_dimension,
            num_samples,
        );
        streams.synchronize();
    }
}
