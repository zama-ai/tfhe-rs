#include "linearalgebra/negation.cuh"

/*
 * Perform the negation of a u32 input LWE ciphertext vector.
 * See the equivalent operation on u64 ciphertexts for more details.
 */
void cuda_negate_lwe_ciphertext_vector_32(
    void *stream, uint32_t gpu_index, void *lwe_array_out,
    void const *lwe_array_in, const uint32_t input_lwe_dimension,
    const uint32_t input_lwe_ciphertext_count) {

  host_negation<uint32_t>(static_cast<cudaStream_t>(stream), gpu_index,
                          static_cast<uint32_t *>(lwe_array_out),
                          static_cast<const uint32_t *>(lwe_array_in),
                          input_lwe_dimension, input_lwe_ciphertext_count);
}

/*
 * Perform the negation of a u64 input LWE ciphertext vector.
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
 * - `input_lwe_dimension` is the number of mask elements in the two input and
 * in the output ciphertext vectors
 * - `input_lwe_ciphertext_count` is the number of ciphertexts contained in each
 * input LWE ciphertext vector, as well as in the output.
 *
 * Each element (mask element or body) of the input LWE ciphertext vector is
 * negated. The result is stored in the output LWE ciphertext vector. The input
 * LWE ciphertext vector is left unchanged. This function is a wrapper to a
 * device function that performs the operation on the GPU.
 */
void cuda_negate_lwe_ciphertext_vector_64(
    void *stream, uint32_t gpu_index, void *lwe_array_out,
    void const *lwe_array_in, const uint32_t input_lwe_dimension,
    const uint32_t input_lwe_ciphertext_count) {

  host_negation<uint64_t>(static_cast<cudaStream_t>(stream), gpu_index,
                          static_cast<uint64_t *>(lwe_array_out),
                          static_cast<const uint64_t *>(lwe_array_in),
                          input_lwe_dimension, input_lwe_ciphertext_count);
}
