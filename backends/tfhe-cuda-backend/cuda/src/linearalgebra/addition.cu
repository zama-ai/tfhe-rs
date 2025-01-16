#include "integer/integer.h"
#include "linearalgebra/addition.cuh"

void cuda_add_lwe_ciphertext_vector_32(
    void *stream, uint32_t gpu_index, CudaRadixCiphertextFFI *lwe_array_out,
    CudaRadixCiphertextFFI const *lwe_array_in_1,
    CudaRadixCiphertextFFI const *lwe_array_in_2) {

  host_addition<uint32_t>(static_cast<cudaStream_t>(stream), gpu_index,
                          lwe_array_out, lwe_array_in_1, lwe_array_in_2);
}

/*
 * Perform the addition of two u64 input LWE ciphertext vectors.
 * - `v_stream` is a void pointer to the Cuda stream to be used in the kernel
 * launch
 * - `gpu_index` is the index of the GPU to be used in the kernel launch
 * - `lwe_array_out` is an array of size
 * `(input_lwe_dimension + 1) * input_lwe_ciphertext_count` that should have
 * been allocated on the GPU before calling this function, and that will hold
 * the result of the computation.
 * - `lwe_array_in_1` is the first LWE ciphertext vector used as input, it
 * should have been allocated and initialized before calling this function. It
 * has the same size as the output array.
 * - `lwe_array_in_2` is the second LWE ciphertext vector used as input, it
 * should have been allocated and initialized before calling this function. It
 * has the same size as the output array.
 * - `input_lwe_dimension` is the number of mask elements in the two input and
 * in the output ciphertext vectors
 * - `input_lwe_ciphertext_count` is the number of ciphertexts contained in each
 * input LWE ciphertext vector, as well as in the output.
 *
 * Each element (mask element or body) of the input LWE ciphertext vector 1 is
 * added to the corresponding element in the input LWE ciphertext 2. The result
 * is stored in the output LWE ciphertext vector. The two input LWE ciphertext
 * vectors are left unchanged. This function is a wrapper to a device function
 * that performs the operation on the GPU.
 */
void cuda_add_lwe_ciphertext_vector_64(
    void *stream, uint32_t gpu_index, CudaRadixCiphertextFFI *lwe_array_out,
    CudaRadixCiphertextFFI const *lwe_array_in_1,
    CudaRadixCiphertextFFI const *lwe_array_in_2) {

  host_addition<uint64_t>(static_cast<cudaStream_t>(stream), gpu_index,
                          lwe_array_out, lwe_array_in_1, lwe_array_in_2);
}

/*
 * Perform the addition of a u32 input LWE ciphertext vector with a u32
 * plaintext vector. See the equivalent operation on u64 data for more details.
 */
void cuda_add_lwe_ciphertext_vector_plaintext_vector_32(
    void *stream, uint32_t gpu_index, void *lwe_array_out,
    void const *lwe_array_in, void const *plaintext_array_in,
    const uint32_t input_lwe_dimension,
    const uint32_t input_lwe_ciphertext_count) {

  host_addition_plaintext<uint32_t>(
      static_cast<cudaStream_t>(stream), gpu_index,
      static_cast<uint32_t *>(lwe_array_out),
      static_cast<const uint32_t *>(lwe_array_in),
      static_cast<const uint32_t *>(plaintext_array_in), input_lwe_dimension,
      input_lwe_ciphertext_count);
}
/*
 * Perform the addition of a u64 input LWE ciphertext vector with a u64 input
 * plaintext vector.
 * - `v_stream` is a void pointer to the Cuda stream to be used in the kernel
 * launch
 * - `gpu_index` is the index of the GPU to be used in the kernel launch
 * - `lwe_array_out` is an array of size
 * `(input_lwe_dimension + 1) * input_lwe_ciphertext_count` that should have
 * been allocated on the GPU before calling this function, and that will hold
 * the result of the computation.
 * - `lwe_array_in` is the LWE ciphertext vector used as input, it should have
 * been allocated and initialized before calling this function. It has the same
 * size as the output array.
 * - `plaintext_array_in` is the plaintext vector used as input, it should have
 * been allocated and initialized before calling this function. It should be of
 * size `input_lwe_ciphertext_count`.
 * - `input_lwe_dimension` is the number of mask elements in the input and
 * output LWE ciphertext vectors
 * - `input_lwe_ciphertext_count` is the number of ciphertexts contained in the
 * input LWE ciphertext vector, as well as in the output. It is also the number
 * of plaintexts in the input plaintext vector.
 *
 * Each plaintext of the input plaintext vector is added to the body of the
 * corresponding LWE ciphertext in the LWE ciphertext vector. The result of the
 * operation is stored in the output LWE ciphertext vector. The two input
 * vectors are unchanged. This function is a wrapper to a device function that
 * performs the operation on the GPU.
 */
void cuda_add_lwe_ciphertext_vector_plaintext_vector_64(
    void *stream, uint32_t gpu_index, void *lwe_array_out,
    void const *lwe_array_in, void const *plaintext_array_in,
    const uint32_t input_lwe_dimension,
    const uint32_t input_lwe_ciphertext_count) {

  host_addition_plaintext<uint64_t>(
      static_cast<cudaStream_t>(stream), gpu_index,
      static_cast<uint64_t *>(lwe_array_out),
      static_cast<const uint64_t *>(lwe_array_in),
      static_cast<const uint64_t *>(plaintext_array_in), input_lwe_dimension,
      input_lwe_ciphertext_count);
}

/*
 * Perform the addition of a u64 input LWE ciphertext vector with a u64 input
 * plaintext scalar.
 * - `stream` is a void pointer to the Cuda stream to be used in the kernel
 * launch
 * - `gpu_index` is the index of the GPU to be used in the kernel launch
 * - `lwe_array_out` is an array of size
 * `(input_lwe_dimension + 1) * input_lwe_ciphertext_count` that should have
 * been allocated on the GPU before calling this function, and that will hold
 * the result of the computation.
 * - `lwe_array_in` is the LWE ciphertext vector used as input, it should have
 * been allocated and initialized before calling this function. It has the same
 * size as the output array.
 * - `plaintext_in` is the plaintext used as input.
 * - `input_lwe_dimension` is the number of mask elements in the input and
 * output LWE ciphertext vectors
 * - `input_lwe_ciphertext_count` is the number of ciphertexts contained in the
 * input LWE ciphertext vector, as well as in the output.
 *
 * The same input plaintext is added to the body of the
 * LWE ciphertexts in the LWE ciphertext vector. The result of the
 * operation is stored in the output LWE ciphertext vector. The two input
 * vectors are unchanged. This function is a wrapper to a device function that
 * performs the operation on the GPU.
 */
void cuda_add_lwe_ciphertext_vector_plaintext_64(
    void *stream, uint32_t gpu_index, void *lwe_array_out,
    void const *lwe_array_in, const uint64_t plaintext_in,
    const uint32_t input_lwe_dimension,
    const uint32_t input_lwe_ciphertext_count) {

  host_addition_plaintext_scalar<uint64_t>(
      static_cast<cudaStream_t>(stream), gpu_index,
      static_cast<uint64_t *>(lwe_array_out),
      static_cast<const uint64_t *>(lwe_array_in), plaintext_in,
      input_lwe_dimension, input_lwe_ciphertext_count);
}
