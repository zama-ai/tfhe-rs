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

/// # Safety
///
/// - `stream` __must__ be synchronized to guarantee computation has finished, and inputs must not
///   be dropped until stream is synchronised
pub unsafe fn cuda_lwe_ciphertext_add_async<Scalar>(
    output: &mut CudaLweCiphertextList<Scalar>,
    lhs: &CudaLweCiphertextList<Scalar>,
    rhs: &CudaLweCiphertextList<Scalar>,
    streams: &CudaStreams,
) where
    Scalar: UnsignedInteger,
{
    let num_samples = output.lwe_ciphertext_count().0 as u32;

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

    add_lwe_ciphertext_vector_async(
        streams,
        &mut output.0.d_vec,
        &lhs.0.d_vec,
        &rhs.0.d_vec,
        lhs.lwe_dimension(),
        num_samples,
    );
}

/// # Safety
///
/// - `stream` __must__ be synchronized to guarantee computation has finished, and inputs must not
///   be dropped until stream is synchronised
pub unsafe fn cuda_lwe_ciphertext_add_assign_async<Scalar>(
    lhs: &mut CudaLweCiphertextList<Scalar>,
    rhs: &CudaLweCiphertextList<Scalar>,
    streams: &CudaStreams,
) where
    Scalar: UnsignedInteger,
{
    let num_samples = lhs.lwe_ciphertext_count().0 as u32;

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

    add_lwe_ciphertext_vector_assign_async(
        streams,
        &mut lhs.0.d_vec,
        &rhs.0.d_vec,
        rhs.lwe_dimension(),
        num_samples,
    );
}

/// # Safety
///
/// - `stream` __must__ be synchronized to guarantee computation has finished, and inputs must not
///   be dropped until stream is synchronised
pub unsafe fn cuda_lwe_ciphertext_plaintext_add_async<Scalar>(
    output: &mut CudaLweCiphertextList<Scalar>,
    lhs: &CudaLweCiphertextList<Scalar>,
    rhs: &CudaVec<Scalar>,
    stream: &CudaStreams,
) where
    Scalar: UnsignedInteger,
{
    let num_samples = output.lwe_ciphertext_count().0 as u32;

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

    add_lwe_ciphertext_vector_plaintext_vector_async(
        stream,
        &mut output.0.d_vec,
        &lhs.0.d_vec,
        rhs,
        lhs.lwe_dimension(),
        num_samples,
    );
}

/// # Safety
///
/// - `stream` __must__ be synchronized to guarantee computation has finished, and inputs must not
///   be dropped until stream is synchronised
pub unsafe fn cuda_lwe_ciphertext_plaintext_add_assign_async<Scalar>(
    lhs: &mut CudaLweCiphertextList<Scalar>,
    rhs: &CudaVec<Scalar>,
    stream: &CudaStreams,
) where
    Scalar: UnsignedInteger,
{
    let num_samples = lhs.lwe_ciphertext_count().0 as u32;
    let lwe_dimension = &lhs.lwe_dimension();

    add_lwe_ciphertext_vector_plaintext_vector_assign_async(
        stream,
        &mut lhs.0.d_vec,
        rhs,
        *lwe_dimension,
        num_samples,
    );
}

/// # Safety
///
/// - `stream` __must__ be synchronized to guarantee computation has finished, and inputs must not
///   be dropped until stream is synchronised
pub unsafe fn cuda_lwe_ciphertext_negate_async<Scalar>(
    output: &mut CudaLweCiphertextList<Scalar>,
    input: &CudaLweCiphertextList<Scalar>,
    stream: &CudaStreams,
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
    let num_samples = output.lwe_ciphertext_count().0 as u32;
    let lwe_dimension = &output.lwe_dimension();

    negate_lwe_ciphertext_vector_async(
        stream,
        &mut output.0.d_vec,
        &input.0.d_vec,
        *lwe_dimension,
        num_samples,
    );
}

/// # Safety
///
/// - `stream` __must__ be synchronized to guarantee computation has finished, and inputs must not
///   be dropped until stream is synchronised
pub unsafe fn cuda_lwe_ciphertext_negate_assign_async<Scalar>(
    ct: &mut CudaLweCiphertextList<Scalar>,
    stream: &CudaStreams,
) where
    Scalar: UnsignedInteger,
{
    let num_samples = ct.lwe_ciphertext_count().0 as u32;
    let lwe_dimension = &ct.lwe_dimension();

    negate_lwe_ciphertext_vector_assign_async(stream, &mut ct.0.d_vec, *lwe_dimension, num_samples);
}

/// # Safety
///
/// - `stream` __must__ be synchronized to guarantee computation has finished, and inputs must not
///   be dropped until stream is synchronised
pub unsafe fn cuda_lwe_ciphertext_cleartext_mul_async<Scalar>(
    output: &mut CudaLweCiphertextList<Scalar>,
    input: &CudaLweCiphertextList<Scalar>,
    cleartext: &CudaVec<Scalar>,
    stream: &CudaStreams,
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
    let num_samples = output.lwe_ciphertext_count().0 as u32;
    let lwe_dimension = &output.lwe_dimension();

    mult_lwe_ciphertext_vector_cleartext_vector(
        stream,
        &mut output.0.d_vec,
        &input.0.d_vec,
        cleartext,
        *lwe_dimension,
        num_samples,
    );
}

/// # Safety
///
/// - `stream` __must__ be synchronized to guarantee computation has finished, and inputs must not
///   be dropped until stream is synchronised
pub unsafe fn cuda_lwe_ciphertext_cleartext_mul_assign_async<Scalar>(
    ct: &mut CudaLweCiphertextList<Scalar>,
    cleartext: &CudaVec<Scalar>,
    stream: &CudaStreams,
) where
    Scalar: UnsignedInteger,
{
    let num_samples = ct.lwe_ciphertext_count().0 as u32;
    let lwe_dimension = ct.lwe_dimension();

    mult_lwe_ciphertext_vector_cleartext_vector_assign_async(
        stream,
        &mut ct.0.d_vec,
        cleartext,
        lwe_dimension,
        num_samples,
    );
}

pub fn cuda_lwe_ciphertext_add<Scalar>(
    output: &mut CudaLweCiphertextList<Scalar>,
    lhs: &CudaLweCiphertextList<Scalar>,
    rhs: &CudaLweCiphertextList<Scalar>,
    streams: &CudaStreams,
) where
    Scalar: UnsignedInteger,
{
    unsafe {
        cuda_lwe_ciphertext_add_async(output, lhs, rhs, streams);
    }
    streams.synchronize();
}

pub fn cuda_lwe_ciphertext_add_assign<Scalar>(
    lhs: &mut CudaLweCiphertextList<Scalar>,
    rhs: &CudaLweCiphertextList<Scalar>,
    streams: &CudaStreams,
) where
    Scalar: UnsignedInteger,
{
    unsafe {
        cuda_lwe_ciphertext_add_assign_async(lhs, rhs, streams);
    }
    streams.synchronize();
}

pub fn cuda_lwe_ciphertext_plaintext_add<Scalar>(
    output: &mut CudaLweCiphertextList<Scalar>,
    lhs: &CudaLweCiphertextList<Scalar>,
    rhs: &CudaVec<Scalar>,
    stream: &CudaStreams,
) where
    Scalar: UnsignedInteger,
{
    unsafe {
        cuda_lwe_ciphertext_plaintext_add_async(output, lhs, rhs, stream);
    }
    stream.synchronize();
}

pub fn cuda_lwe_ciphertext_plaintext_add_assign<Scalar>(
    lhs: &mut CudaLweCiphertextList<Scalar>,
    rhs: &CudaVec<Scalar>,
    stream: &CudaStreams,
) where
    Scalar: UnsignedInteger,
{
    unsafe {
        cuda_lwe_ciphertext_plaintext_add_assign_async(lhs, rhs, stream);
    }
    stream.synchronize();
}

pub fn cuda_lwe_ciphertext_negate<Scalar>(
    output: &mut CudaLweCiphertextList<Scalar>,
    input: &CudaLweCiphertextList<Scalar>,
    stream: &CudaStreams,
) where
    Scalar: UnsignedInteger,
{
    unsafe {
        cuda_lwe_ciphertext_negate_async(output, input, stream);
    }
    stream.synchronize();
}

pub fn cuda_lwe_ciphertext_negate_assign<Scalar>(
    ct: &mut CudaLweCiphertextList<Scalar>,
    stream: &CudaStreams,
) where
    Scalar: UnsignedInteger,
{
    unsafe {
        cuda_lwe_ciphertext_negate_assign_async(ct, stream);
    }
    stream.synchronize();
}

pub fn cuda_lwe_ciphertext_cleartext_mul<Scalar>(
    output: &mut CudaLweCiphertextList<Scalar>,
    input: &CudaLweCiphertextList<Scalar>,
    cleartext: &CudaVec<Scalar>,
    stream: &CudaStreams,
) where
    Scalar: UnsignedInteger,
{
    unsafe {
        cuda_lwe_ciphertext_cleartext_mul_async(output, input, cleartext, stream);
    }
    stream.synchronize();
}

pub fn cuda_lwe_ciphertext_cleartext_mul_assign<Scalar>(
    ct: &mut CudaLweCiphertextList<Scalar>,
    cleartext: &CudaVec<Scalar>,
    stream: &CudaStreams,
) where
    Scalar: UnsignedInteger,
{
    unsafe {
        cuda_lwe_ciphertext_cleartext_mul_assign_async(ct, cleartext, stream);
    }
    stream.synchronize();
}
