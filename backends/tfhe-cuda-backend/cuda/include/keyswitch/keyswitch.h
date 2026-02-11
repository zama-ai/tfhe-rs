#ifndef CNCRT_KS_H_
#define CNCRT_KS_H_

#include <stdint.h>

extern "C" {

void cuda_keyswitch_lwe_ciphertext_vector_64_64_async(
    void *stream, uint32_t gpu_index, void *lwe_array_out,
    void const *lwe_output_indexes, void const *lwe_array_in,
    void const *lwe_input_indexes, void const *ksk, uint32_t lwe_dimension_in,
    uint32_t lwe_dimension_out, uint32_t base_log, uint32_t level_count,
    uint32_t num_samples);

void cuda_keyswitch_lwe_ciphertext_vector_64_32_async(
    void *stream, uint32_t gpu_index, void *lwe_array_out,
    void const *lwe_output_indexes, void const *lwe_array_in,
    void const *lwe_input_indexes, void const *ksk, uint32_t lwe_dimension_in,
    uint32_t lwe_dimension_out, uint32_t base_log, uint32_t level_count,
    uint32_t num_samples);

uint64_t scratch_cuda_packing_keyswitch_lwe_list_to_glwe_64_async(
    void *stream, uint32_t gpu_index, int8_t **fp_ks_buffer,
    uint32_t lwe_dimension, uint32_t glwe_dimension, uint32_t polynomial_size,
    uint32_t num_lwes, bool allocate_gpu_memory);

void cuda_keyswitch_gemm_64_64_async(
    void *stream, uint32_t gpu_index, void *lwe_array_out,
    void const *lwe_output_indexes, void const *lwe_array_in,
    void const *lwe_input_indexes, void const *ksk, uint32_t lwe_dimension_in,
    uint32_t lwe_dimension_out, uint32_t base_log, uint32_t level_count,
    uint32_t num_samples, const void *ks_tmp_buffer, bool uses_trivial_indexes);

void cuda_keyswitch_gemm_64_32_async(
    void *stream, uint32_t gpu_index, void *lwe_array_out,
    void const *lwe_output_indexes, void const *lwe_array_in,
    void const *lwe_input_indexes, void const *ksk, uint32_t lwe_dimension_in,
    uint32_t lwe_dimension_out, uint32_t base_log, uint32_t level_count,
    uint32_t num_samples, const void *ks_tmp_buffer, bool uses_trivial_indexes);

uint64_t scratch_cuda_keyswitch_gemm_64_64_async(
    void *stream, uint32_t gpu_index, void **ks_tmp_memory,
    uint32_t lwe_dimension_in, uint32_t lwe_dimension_out, uint32_t num_lwes,
    bool allocate_gpu_memory);

uint64_t scratch_cuda_keyswitch_gemm_64_32_async(
    void *stream, uint32_t gpu_index, void **ks_tmp_memory,
    uint32_t lwe_dimension_in, uint32_t lwe_dimension_out, uint32_t num_lwes,
    bool allocate_gpu_memory);

void cleanup_cuda_keyswitch_gemm_64_64(void *stream, uint32_t gpu_index,
                                       void **ks_tmp_memory,
                                       bool allocate_gpu_memory);

void cleanup_cuda_keyswitch_gemm_64_32(void *stream, uint32_t gpu_index,
                                       void **ks_tmp_memory,
                                       bool allocate_gpu_memory);

void cuda_packing_keyswitch_lwe_list_to_glwe_64_async(
    void *stream, uint32_t gpu_index, void *glwe_array_out,
    void const *lwe_array_in, void const *fp_ksk_array, int8_t *fp_ks_buffer,
    uint32_t input_lwe_dimension, uint32_t output_glwe_dimension,
    uint32_t output_polynomial_size, uint32_t base_log, uint32_t level_count,
    uint32_t num_lwes);

void scratch_cuda_packing_keyswitch_lwe_list_to_glwe_128_async(
    void *stream, uint32_t gpu_index, int8_t **fp_ks_buffer,
    uint32_t lwe_dimension, uint32_t glwe_dimension, uint32_t polynomial_size,
    uint32_t num_lwes, bool allocate_gpu_memory);

void cuda_packing_keyswitch_lwe_list_to_glwe_128_async(
    void *stream, uint32_t gpu_index, void *glwe_array_out,
    void const *lwe_array_in, void const *fp_ksk_array, int8_t *fp_ks_buffer,
    uint32_t input_lwe_dimension, uint32_t output_glwe_dimension,
    uint32_t output_polynomial_size, uint32_t base_log, uint32_t level_count,
    uint32_t num_lwes);

void cleanup_cuda_packing_keyswitch_lwe_list_to_glwe_64(
    void *stream, uint32_t gpu_index, int8_t **fp_ks_buffer,
    bool gpu_memory_allocated);

void cleanup_cuda_packing_keyswitch_lwe_list_to_glwe_128(
    void *stream, uint32_t gpu_index, int8_t **fp_ks_buffer,
    bool gpu_memory_allocated);

void cuda_closest_representable_64_async(void *stream, uint32_t gpu_index,
                                         void const *input, void *output,
                                         uint32_t base_log,
                                         uint32_t level_count);
}

#endif // CNCRT_KS_H_
