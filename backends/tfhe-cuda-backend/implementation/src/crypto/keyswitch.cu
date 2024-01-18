#include "keyswitch.cuh"
#include "keyswitch.h"
#include <cstdint>

/* Perform keyswitch on a batch of 32 bits input LWE ciphertexts.
 * Head out to the equivalent operation on 64 bits for more details.
 */
void cuda_keyswitch_lwe_ciphertext_vector_32(
    cuda_stream_t *stream, void *lwe_array_out, void *lwe_output_indexes,
    void *lwe_array_in, void *lwe_input_indexes, void *ksk,
    uint32_t lwe_dimension_in, uint32_t lwe_dimension_out, uint32_t base_log,
    uint32_t level_count, uint32_t num_samples) {
  cuda_keyswitch_lwe_ciphertext_vector(
      stream, static_cast<uint32_t *>(lwe_array_out),
      static_cast<uint32_t *>(lwe_output_indexes),
      static_cast<uint32_t *>(lwe_array_in),
      static_cast<uint32_t *>(lwe_input_indexes), static_cast<uint32_t *>(ksk),
      lwe_dimension_in, lwe_dimension_out, base_log, level_count, num_samples);
}

/* Perform keyswitch on a batch of 64 bits input LWE ciphertexts.
 *
 * - `v_stream` is a void pointer to the Cuda stream to be used in the kernel
 * launch
 * - `gpu_index` is the index of the GPU to be used in the kernel launch
 *  - lwe_array_out: output batch of num_samples keyswitched ciphertexts c =
 * (a0,..an-1,b) where n is the output LWE dimension (lwe_dimension_out)
 *  - lwe_array_in: input batch of num_samples LWE ciphertexts, containing
 * lwe_dimension_in mask values + 1 body value
 *  - ksk: the keyswitch key to be used in the operation
 *  - base log: the log of the base used in the decomposition (should be the one
 * used to create the ksk)
 *
 * This function calls a wrapper to a device kernel that performs the keyswitch
 * 	- num_samples blocks of threads are launched
 */
void cuda_keyswitch_lwe_ciphertext_vector_64(
    cuda_stream_t *stream, void *lwe_array_out, void *lwe_output_indexes,
    void *lwe_array_in, void *lwe_input_indexes, void *ksk,
    uint32_t lwe_dimension_in, uint32_t lwe_dimension_out, uint32_t base_log,
    uint32_t level_count, uint32_t num_samples) {
  cuda_keyswitch_lwe_ciphertext_vector(
      stream, static_cast<uint64_t *>(lwe_array_out),
      static_cast<uint64_t *>(lwe_output_indexes),
      static_cast<uint64_t *>(lwe_array_in),
      static_cast<uint64_t *>(lwe_input_indexes), static_cast<uint64_t *>(ksk),
      lwe_dimension_in, lwe_dimension_out, base_log, level_count, num_samples);
}
