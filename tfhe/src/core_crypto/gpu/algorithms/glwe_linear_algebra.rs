use crate::core_crypto::gpu::vec::CudaVec;
use crate::core_crypto::gpu::{
    CudaStreams,
};
use crate::core_crypto::prelude::UnsignedInteger;
use tfhe_cuda_backend::bindings::cuda_wrapping_polynomial_mul_one_to_many_64;
use tfhe_cuda_backend::bindings::cuda_glwe_wrapping_polynomial_mul_one_to_many_64;
use crate::core_crypto::gpu::glwe_ciphertext_list::CudaGlweCiphertextList;

pub fn cuda_wrapping_polynomial_mul_one_to_many<Scalar>(
    lhs: &CudaVec<Scalar>,
    rhs: &CudaVec<Scalar>,
    out: &mut CudaVec<Scalar>,
    stream: &CudaStreams,
) where
    Scalar: UnsignedInteger,
{
    assert_eq!(rhs.len() % lhs.len(), 0,
               "CUDA polynomial multiplication one to many: the rhs
        must contain multiple polynomials of the same size as the
        lhs");

    assert_eq!(lhs.len().is_power_of_two(), true,
               "CUDA polynomial multiplication one to many: expected
        the polynomial size to be a multiple of two");

    unsafe {
        cuda_wrapping_polynomial_mul_one_to_many_64(
            stream.ptr[0],
            stream.gpu_indexes[0].0,
            out.as_mut_c_ptr(0),
            lhs.as_c_ptr(0),
            rhs.as_c_ptr(0),
            lhs.len() as u32,
            (rhs.len() / lhs.len()) as u32,
        );
    }
    stream.synchronize();
}


pub fn cuda_glwe_wrapping_polynomial_mul_one_to_many<Scalar>(
    lhs: &CudaGlweCiphertextList<Scalar>,
    rhs: &CudaVec<Scalar>,
    out: &mut CudaGlweCiphertextList<Scalar>,
    stream: &CudaStreams,
) where
    Scalar: UnsignedInteger,
{
    assert_eq!(rhs.len() % lhs.polynomial_size().0, 0,
               "CUDA GLWE multiplication with clear, one to many: the rhs
        must contain multiple polynomials of the same size as the
        lhs");

    assert_eq!(lhs.polynomial_size().0.is_power_of_two(), true,
               "CUDA GLWE polynomial multiplication one to many: expected
        the polynomial size to be a multiple of two");

    assert_eq!(lhs.glwe_dimension().0, 1,
               "CUDA GLWE polynomial multiplication one to many: expected
        the GLWE to have glwe dimension of 1");

    assert_eq!(lhs.glwe_ciphertext_count().0, 1,
               "CUDA GLWE polynomial multiplication one to many: expected
        a single GLWE");

    unsafe {
        cuda_glwe_wrapping_polynomial_mul_one_to_many_64(
            stream.ptr[0],
            stream.gpu_indexes[0].0,
            out.0.d_vec.as_mut_c_ptr(0),
            lhs.0.d_vec.as_c_ptr(0),
            rhs.as_c_ptr(0),
            lhs.polynomial_size().0 as u32,
            lhs.glwe_dimension().0 as u32,
            (rhs.len() / lhs.polynomial_size().0) as u32,
        );
    }
    stream.synchronize();

}