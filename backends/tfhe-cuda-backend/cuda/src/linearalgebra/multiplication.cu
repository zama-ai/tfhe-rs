#include "linearalgebra/multiplication.cuh"

/*
 * Perform the multiplication of a u32 input LWE ciphertext vector with a u32
 * cleartext vector. See the equivalent operation on u64 data for more details.
 */
void cuda_mult_lwe_ciphertext_vector_cleartext_vector_32(
    cuda_stream_t *stream, void *lwe_array_out, void *lwe_array_in,
    void *cleartext_array_in, uint32_t input_lwe_dimension,
    uint32_t input_lwe_ciphertext_count) {

  host_cleartext_multiplication(stream, static_cast<uint32_t *>(lwe_array_out),
                                static_cast<uint32_t *>(lwe_array_in),
                                static_cast<uint32_t *>(cleartext_array_in),
                                input_lwe_dimension,
                                input_lwe_ciphertext_count);
}
/*
 * Perform the multiplication of a u64 input LWE ciphertext vector with a u64
 * input cleartext vector.
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
 * - `cleartext_array_in` is the cleartext vector used as input, it should have
 * been allocated and initialized before calling this function. It should be of
 * size `input_lwe_ciphertext_count`.
 * - `input_lwe_dimension` is the number of mask elements in the input and
 * output LWE ciphertext vectors
 * - `input_lwe_ciphertext_count` is the number of ciphertexts contained in the
 * input LWE ciphertext vector, as well as in the output. It is also the number
 * of cleartexts in the input cleartext vector.
 *
 * Each cleartext of the input cleartext vector is multiplied to the mask and
 * body of the corresponding LWE ciphertext in the LWE ciphertext vector. The
 * result of the operation is stored in the output LWE ciphertext vector. The
 * two input vectors are unchanged. This function is a wrapper to a device
 * function that performs the operation on the GPU.
 */
void cuda_mult_lwe_ciphertext_vector_cleartext_vector_64(
    cuda_stream_t *stream, void *lwe_array_out, void *lwe_array_in,
    void *cleartext_array_in, uint32_t input_lwe_dimension,
    uint32_t input_lwe_ciphertext_count) {

  host_cleartext_multiplication(stream, static_cast<uint64_t *>(lwe_array_out),
                                static_cast<uint64_t *>(lwe_array_in),
                                static_cast<uint64_t *>(cleartext_array_in),
                                input_lwe_dimension,
                                input_lwe_ciphertext_count);
}
