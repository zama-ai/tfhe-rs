#include "keyswitch.cuh"
#include "keyswitch.h"
#include "fast_packing_keyswitch.cuh"
#include <cstdint>
#include <stdio.h>

/* Perform keyswitch on a batch of 32 bits input LWE ciphertexts.
 * Head out to the equivalent operation on 64 bits for more details.
 */
void cuda_keyswitch_lwe_ciphertext_vector_32(
    void *stream, uint32_t gpu_index, void *lwe_array_out,
    void *lwe_output_indexes, void *lwe_array_in, void *lwe_input_indexes,
    void *ksk, uint32_t lwe_dimension_in, uint32_t lwe_dimension_out,
    uint32_t base_log, uint32_t level_count, uint32_t num_samples) {
  host_keyswitch_lwe_ciphertext_vector<uint32_t>(
      static_cast<cudaStream_t>(stream), gpu_index,
      static_cast<uint32_t *>(lwe_array_out),
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
    void *stream, uint32_t gpu_index, void *lwe_array_out,
    void const *lwe_output_indexes, void const *lwe_array_in,
    void const *lwe_input_indexes, void const *ksk, uint32_t lwe_dimension_in,
    uint32_t lwe_dimension_out, uint32_t base_log, uint32_t level_count,
    uint32_t num_samples) {
  host_keyswitch_lwe_ciphertext_vector<uint64_t>(
      static_cast<cudaStream_t>(stream), gpu_index,
      static_cast<uint64_t *>(lwe_array_out),
      static_cast<const uint64_t *>(lwe_output_indexes),
      static_cast<const uint64_t *>(lwe_array_in),
      static_cast<const uint64_t *>(lwe_input_indexes),
      static_cast<const uint64_t *>(ksk), lwe_dimension_in, lwe_dimension_out,
      base_log, level_count, num_samples);
}

void scratch_packing_keyswitch_lwe_list_to_glwe_64(
    void *stream, uint32_t gpu_index, int8_t **fp_ks_buffer,
    uint32_t glwe_dimension, uint32_t polynomial_size, uint32_t num_lwes,
    bool allocate_gpu_memory) {
  scratch_packing_keyswitch_lwe_list_to_glwe<uint64_t>(
      static_cast<cudaStream_t>(stream), gpu_index, fp_ks_buffer,
      glwe_dimension, polynomial_size, num_lwes, allocate_gpu_memory);
}

void dump_2d_64(const char* fname, uint64_t const* gpu_buf, int lines, int cols, int stride, cudaStream_t stream) {
    FILE* fp_lwe = fopen(fname, "wt");
    uint64_t* buf_host = (uint64_t* )malloc(lines * stride * sizeof(uint64_t));

    printf("Dump %d %d %d to %s\n", lines, cols, stride, fname);
    cudaMemcpy(buf_host, gpu_buf, lines * stride * sizeof(uint64_t), cudaMemcpyDeviceToHost);
    cudaStreamSynchronize(stream);

    for (int i = 0; i < lines; ++i) {
      for (int j = 0; j < cols; ++j) { // 
        uint64_t val = buf_host[i*stride + j];
        fprintf(fp_lwe, "%llu,", val);
      }
      fprintf(fp_lwe, "\n");
    }
    fclose(fp_lwe);
    free(buf_host);
}

/* Perform functional packing keyswitch on a batch of 64 bits input LWE
 * ciphertexts.
 */

//#define KS_VAL_DBG 

void cuda_packing_keyswitch_lwe_list_to_glwe_64(
    void *stream, uint32_t gpu_index, void *glwe_array_out,
    void const *lwe_array_in, void const *fp_ksk_array, int8_t *fp_ks_buffer,
    uint32_t input_lwe_dimension, uint32_t output_glwe_dimension,
    uint32_t output_polynomial_size, uint32_t base_log, uint32_t level_count,
    uint32_t num_lwes) {

  if (can_use_pks_fast_path(
    input_lwe_dimension, num_lwes, output_polynomial_size, level_count, output_glwe_dimension
  )) {
#ifdef KS_VAL_DBG     
    cudaStream_t s = static_cast<cudaStream_t>(stream);

    dump_2d_64("/home/stoiana/lwe_mask.csv", 
      static_cast<const uint64_t *>(lwe_array_in), 
      num_lwes, 
      input_lwe_dimension, 
      input_lwe_dimension + 1, 
      s);
#endif

    host_fast_packing_keyswitch_lwe_list_to_glwe<uint64_t, ulonglong4>(
        static_cast<cudaStream_t>(stream), gpu_index,
        static_cast<uint64_t *>(glwe_array_out),
        static_cast<const uint64_t *>(lwe_array_in),
        static_cast<const uint64_t *>(fp_ksk_array), fp_ks_buffer,
        input_lwe_dimension, output_glwe_dimension, output_polynomial_size,
        base_log, level_count, num_lwes);

#ifdef KS_VAL_DBG     
    dump_2d_64("/home/stoiana/decomp_lwe_mask.csv", 
      (const uint64_t *)fp_ks_buffer, 
      num_lwes, 
      input_lwe_dimension, 
      input_lwe_dimension, 
      s);

    auto size_ks_glwe = output_polynomial_size * (output_glwe_dimension+1);
    auto fp_ks_buffer_part2 = (uint64_t*)fp_ks_buffer + num_lwes * size_ks_glwe;
    dump_2d_64("/home/stoiana/gemm.csv", 
      static_cast<const uint64_t *>(fp_ks_buffer_part2), 
      num_lwes, 
      size_ks_glwe, 
      size_ks_glwe, 
      s);

    dump_2d_64("/home/stoiana/ksk.csv", 
      static_cast<const uint64_t *>(fp_ksk_array), 
      input_lwe_dimension, 
      size_ks_glwe, 
      size_ks_glwe, 
      s);

    dump_2d_64("/home/stoiana/rotated_gpu.csv", 
      (const uint64_t *)fp_ks_buffer, 
      num_lwes, 
      size_ks_glwe, 
      size_ks_glwe, 
      s);

    dump_2d_64("/home/stoiana/glwe.csv", 
      static_cast<const uint64_t *>(glwe_array_out), 
      1, 
      size_ks_glwe, 
      size_ks_glwe, 
      s);
#endif

  } else
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
                                                int8_t **fp_ks_buffer) {
  cuda_drop_async(*fp_ks_buffer, static_cast<cudaStream_t>(stream), gpu_index);
}
