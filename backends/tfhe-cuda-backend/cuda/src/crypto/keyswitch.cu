#include "keyswitch.cuh"
#include "keyswitch/keyswitch.h"
#include "packing_keyswitch.cuh"

/* Perform keyswitch on a batch of 64 bits input LWE ciphertexts
 * using a 64-b key-switching key. Uses the GEMM approach which
 * achieves good throughput on large batches (128 LWEs on H100)
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
void cuda_keyswitch_gemm_lwe_ciphertext_vector_64_64(
    void *stream, uint32_t gpu_index, void *lwe_array_out,
    void const *lwe_output_indexes, void const *lwe_array_in,
    void const *lwe_input_indexes, void const *ksk, uint32_t lwe_dimension_in,
    uint32_t lwe_dimension_out, uint32_t base_log, uint32_t level_count,
    uint32_t num_samples, const void *ks_tmp_buffer,
    bool uses_trivial_indices) {

  host_gemm_keyswitch_lwe_ciphertext_vector<uint64_t, uint64_t>(
      static_cast<cudaStream_t>(stream), gpu_index,
      static_cast<uint64_t *>(lwe_array_out),
      static_cast<const uint64_t *>(lwe_output_indexes),
      static_cast<const uint64_t *>(lwe_array_in),
      static_cast<const uint64_t *>(lwe_input_indexes),
      static_cast<const uint64_t *>(ksk), lwe_dimension_in, lwe_dimension_out,
      base_log, level_count, num_samples,
      static_cast<const ks_mem<uint64_t> *>(ks_tmp_buffer)->d_buffer,
      uses_trivial_indices);
}

/* Perform keyswitch on a batch of 64 bits input LWE ciphertexts
 * using a 32-b key-switching key, producing 32-bit LWE outputs.
 * Uses the GEMM approach which achieves good throughput on large batches
 */
void cuda_keyswitch_gemm_lwe_ciphertext_vector_64_32(
    void *stream, uint32_t gpu_index, void *lwe_array_out,
    void const *lwe_output_indexes, void const *lwe_array_in,
    void const *lwe_input_indexes, void const *ksk, uint32_t lwe_dimension_in,
    uint32_t lwe_dimension_out, uint32_t base_log, uint32_t level_count,
    uint32_t num_samples, const void *ks_tmp_buffer,
    bool uses_trivial_indices) {

  host_gemm_keyswitch_lwe_ciphertext_vector<uint64_t, uint32_t>(
      static_cast<cudaStream_t>(stream), gpu_index,
      static_cast<uint32_t *>(lwe_array_out),
      static_cast<const uint64_t *>(lwe_output_indexes),
      static_cast<const uint64_t *>(lwe_array_in),
      static_cast<const uint64_t *>(lwe_input_indexes),
      static_cast<const uint32_t *>(ksk), lwe_dimension_in, lwe_dimension_out,
      base_log, level_count, num_samples,
      static_cast<const ks_mem<uint64_t> *>(ks_tmp_buffer)->d_buffer,
      uses_trivial_indices);
}

void cuda_keyswitch_lwe_ciphertext_vector_64_64(
    void *stream, uint32_t gpu_index, void *lwe_array_out,
    void const *lwe_output_indexes, void const *lwe_array_in,
    void const *lwe_input_indexes, void const *ksk, uint32_t lwe_dimension_in,
    uint32_t lwe_dimension_out, uint32_t base_log, uint32_t level_count,
    uint32_t num_samples) {
  host_keyswitch_lwe_ciphertext_vector<uint64_t, uint64_t>(
      static_cast<cudaStream_t>(stream), gpu_index,
      static_cast<uint64_t *>(lwe_array_out),
      static_cast<uint64_t const *>(lwe_output_indexes),
      static_cast<uint64_t const *>(lwe_array_in),
      static_cast<uint64_t const *>(lwe_input_indexes),
      static_cast<uint64_t const *>(ksk), lwe_dimension_in, lwe_dimension_out,
      base_log, level_count, num_samples);
}

void cuda_keyswitch_lwe_ciphertext_vector_64_32(
    void *stream, uint32_t gpu_index, void *lwe_array_out,
    void const *lwe_output_indexes, void const *lwe_array_in,
    void const *lwe_input_indexes, void const *ksk, uint32_t lwe_dimension_in,
    uint32_t lwe_dimension_out, uint32_t base_log, uint32_t level_count,
    uint32_t num_samples) {
  host_keyswitch_lwe_ciphertext_vector<uint64_t, uint32_t>(
      static_cast<cudaStream_t>(stream), gpu_index,
      static_cast<uint32_t *>(lwe_array_out),
      static_cast<const uint64_t *>(lwe_output_indexes),
      static_cast<const uint64_t *>(lwe_array_in),
      static_cast<const uint64_t *>(lwe_input_indexes),
      static_cast<const uint32_t *>(ksk), lwe_dimension_in, lwe_dimension_out,
      base_log, level_count, num_samples);
}

uint64_t scratch_packing_keyswitch_lwe_list_to_glwe_64(
    void *stream, uint32_t gpu_index, int8_t **fp_ks_buffer,
    uint32_t lwe_dimension, uint32_t glwe_dimension, uint32_t polynomial_size,
    uint32_t num_lwes, bool allocate_gpu_memory) {
  return scratch_packing_keyswitch_lwe_list_to_glwe<uint64_t>(
      static_cast<cudaStream_t>(stream), gpu_index, fp_ks_buffer, lwe_dimension,
      glwe_dimension, polynomial_size, num_lwes, allocate_gpu_memory);
}

uint64_t scratch_cuda_keyswitch_gemm_64(void *stream, uint32_t gpu_index,
                                        void **ks_tmp_buffer,
                                        uint32_t lwe_dimension_in,
                                        uint32_t lwe_dimension_out,
                                        uint32_t num_lwes,
                                        bool allocate_gpu_memory) {
  return scratch_cuda_keyswitch<uint64_t>(
      static_cast<cudaStream_t>(stream), gpu_index,
      (ks_mem<uint64_t> **)ks_tmp_buffer, lwe_dimension_in, lwe_dimension_out,
      num_lwes, allocate_gpu_memory);
}

void cleanup_cuda_keyswitch_gemm_64(void *stream, uint32_t gpu_index,
                                    void **ks_tmp_buffer,
                                    bool allocate_gpu_memory) {
  cleanup_cuda_keyswitch<uint64_t>(static_cast<cudaStream_t>(stream), gpu_index,
                                   (ks_mem<uint64_t> *)*ks_tmp_buffer,
                                   allocate_gpu_memory);
  *ks_tmp_buffer = nullptr;
}

/* Perform functional packing keyswitch on a batch of 64 bits input LWE
 * ciphertexts.
 */

void cuda_packing_keyswitch_lwe_list_to_glwe_64(
    void *stream, uint32_t gpu_index, void *glwe_array_out,
    void const *lwe_array_in, void const *fp_ksk_array, int8_t *fp_ks_buffer,
    uint32_t input_lwe_dimension, uint32_t output_glwe_dimension,
    uint32_t output_polynomial_size, uint32_t base_log, uint32_t level_count,
    uint32_t num_lwes) {

  host_packing_keyswitch_lwe_list_to_glwe<uint64_t>(
      static_cast<cudaStream_t>(stream), gpu_index,
      static_cast<uint64_t *>(glwe_array_out),
      static_cast<const uint64_t *>(lwe_array_in),
      static_cast<const uint64_t *>(fp_ksk_array), fp_ks_buffer,
      input_lwe_dimension, output_glwe_dimension, output_polynomial_size,
      base_log, level_count, num_lwes);
}

void cleanup_packing_keyswitch_lwe_list_to_glwe(void *stream,
                                                uint32_t gpu_index,
                                                int8_t **fp_ks_buffer,
                                                bool gpu_memory_allocated) {
  cuda_drop_with_size_tracking_async(*fp_ks_buffer,
                                     static_cast<cudaStream_t>(stream),
                                     gpu_index, gpu_memory_allocated);
  *fp_ks_buffer = nullptr;
}

void scratch_packing_keyswitch_lwe_list_to_glwe_128(
    void *stream, uint32_t gpu_index, int8_t **fp_ks_buffer,
    uint32_t lwe_dimension, uint32_t glwe_dimension, uint32_t polynomial_size,
    uint32_t num_lwes, bool allocate_gpu_memory) {
  scratch_packing_keyswitch_lwe_list_to_glwe<__uint128_t>(
      static_cast<cudaStream_t>(stream), gpu_index, fp_ks_buffer, lwe_dimension,
      glwe_dimension, polynomial_size, num_lwes, allocate_gpu_memory);
}

/* Perform functional packing keyswitch on a batch of 64 bits input LWE
 * ciphertexts.
 */

void cuda_packing_keyswitch_lwe_list_to_glwe_128(
    void *stream, uint32_t gpu_index, void *glwe_array_out,
    void const *lwe_array_in, void const *fp_ksk_array, int8_t *fp_ks_buffer,
    uint32_t input_lwe_dimension, uint32_t output_glwe_dimension,
    uint32_t output_polynomial_size, uint32_t base_log, uint32_t level_count,
    uint32_t num_lwes) {
  host_packing_keyswitch_lwe_list_to_glwe<__uint128_t>(
      static_cast<cudaStream_t>(stream), gpu_index,
      static_cast<__uint128_t *>(glwe_array_out),
      static_cast<const __uint128_t *>(lwe_array_in),
      static_cast<const __uint128_t *>(fp_ksk_array), fp_ks_buffer,
      input_lwe_dimension, output_glwe_dimension, output_polynomial_size,
      base_log, level_count, num_lwes);
}

void cuda_closest_representable_64_async(void *stream, uint32_t gpu_index,
                                         void const *input, void *output,
                                         uint32_t base_log,
                                         uint32_t level_count) {
  host_cuda_closest_representable(static_cast<cudaStream_t>(stream), gpu_index,
                                  static_cast<const uint64_t *>(input),
                                  static_cast<uint64_t *>(output), base_log,
                                  level_count);
}
