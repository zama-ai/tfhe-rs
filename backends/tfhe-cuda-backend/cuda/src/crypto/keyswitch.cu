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
/* Perform functional packing keyswitch on a batch of 64 bits input LWE
 * ciphertexts.
 */
void cuda_packing_keyswitch_lwe_list_to_glwe_64(
    void *stream, uint32_t gpu_index, void *glwe_array_out,
    void const *lwe_array_in, void const *fp_ksk_array, int8_t *fp_ks_buffer,
    uint32_t input_lwe_dimension, uint32_t output_glwe_dimension,
    uint32_t output_polynomial_size, uint32_t base_log, uint32_t level_count,
    uint32_t num_lwes) {

  if (can_use_pks_fast_path(
    input_lwe_dimension, num_lwes, output_polynomial_size, level_count, output_glwe_dimension
  )) {

    host_fast_packing_keyswitch_lwe_list_to_glwe<uint64_t, ulonglong4>(
        static_cast<cudaStream_t>(stream), gpu_index,
        static_cast<uint64_t *>(glwe_array_out),
        static_cast<const uint64_t *>(lwe_array_in),
        static_cast<const uint64_t *>(fp_ksk_array), fp_ks_buffer,
        input_lwe_dimension, output_glwe_dimension, output_polynomial_size,
        base_log, level_count, num_lwes);
/*
    FILE* fp_lwe = fopen("/home/stoiana/lwe.csv", "wt");
    uint64_t* lwe_host = (uint64_t* )malloc((num_lwes * (input_lwe_dimension + 1)) * sizeof(uint64_t));
    cudaMemcpy(lwe_host, lwe_array_in, (num_lwes * (input_lwe_dimension + 1)) * sizeof(uint64_t), cudaMemcpyDeviceToHost);
    cudaStreamSynchronize(static_cast<cudaStream_t>(stream));
    for (int i = 0; i < num_lwes; ++i) {
      for (int j = 0; j < input_lwe_dimension; ++j) { // 
        uint64_t val = lwe_host[i*(input_lwe_dimension+1) + j];
        fprintf(fp_lwe, "%llu,", val);
      }
      fprintf(fp_lwe, "\n");
    }
    fclose(fp_lwe);
    free(lwe_host);

    FILE* fp_ksk = fopen("/home/stoiana/ksk.csv", "wt");
    uint64_t* ksk_host = (uint64_t* )malloc(input_lwe_dimension * output_polynomial_size * (output_glwe_dimension + 1) * sizeof(uint64_t));
    cudaMemcpy(ksk_host, lwe_array_in, 
      input_lwe_dimension * output_polynomial_size * (output_glwe_dimension + 1) * sizeof(uint64_t), 
      cudaMemcpyDeviceToHost
    );
    cudaStreamSynchronize(static_cast<cudaStream_t>(stream));
    for (int i = 0; i < input_lwe_dimension; ++i) {
      for (int j = 0; j < output_polynomial_size * (output_glwe_dimension + 1); ++j) {
        fprintf(fp_ksk, "%llu,", ksk_host[i*output_polynomial_size * (output_glwe_dimension + 1) + j]);
      }
      fprintf(fp_ksk, "\n");
    }
    fclose(fp_ksk);
    free(ksk_host);

    FILE* fp_glwes = fopen("/home/stoiana/glwe.csv", "wt");
    uint64_t* glwes_host = (uint64_t* )malloc(num_lwes * output_polynomial_size * (output_glwe_dimension + 1) * sizeof(uint64_t));
    cudaMemcpy(glwes_host, fp_ks_buffer, 
      num_lwes * output_polynomial_size * (output_glwe_dimension + 1) * sizeof(uint64_t), 
      cudaMemcpyDeviceToHost
    );
    cudaStreamSynchronize(static_cast<cudaStream_t>(stream));

    for (int i = 0; i < num_lwes; ++i) {
      for (int j = 0; j < output_polynomial_size * (output_glwe_dimension + 1); ++j) {
        fprintf(fp_glwes, "%llu, ", glwes_host[i*output_polynomial_size * (output_glwe_dimension + 1) + j]);
      }
      fprintf(fp_glwes, "\n");
    }
    fclose(fp_glwes);
    free(glwes_host);
    */
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
