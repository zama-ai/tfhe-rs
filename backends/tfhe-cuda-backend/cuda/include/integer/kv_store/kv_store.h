#ifndef CUDA_INTEGER_KV_STORE_H
#define CUDA_INTEGER_KV_STORE_H

#include "../../pbs/pbs_enums.h"
#include "../integer.h"

extern "C" {
uint64_t scratch_cuda_kv_store_get_64_async(
    CudaStreamsFFI streams, int8_t **mem_ptr, uint32_t glwe_dimension,
    uint32_t polynomial_size, uint32_t big_lwe_dimension,
    uint32_t small_lwe_dimension, uint32_t ks_level, uint32_t ks_base_log,
    uint32_t pbs_level, uint32_t pbs_base_log, uint32_t grouping_factor,
    uint32_t num_entries, uint32_t num_key_blocks, uint32_t num_value_blocks,
    uint32_t message_modulus, uint32_t carry_modulus, PBS_TYPE pbs_type,
    bool allocate_gpu_memory, PBS_MS_REDUCTION_T noise_reduction_type);

void cuda_kv_store_get_64_async(
    CudaStreamsFFI streams, CudaRadixCiphertextFFI *lwe_array_out_result,
    CudaRadixCiphertextFFI *lwe_array_out_boolean,
    CudaRadixCiphertextFFI *lwe_array_out_selectors,
    CudaRadixCiphertextFFI const *lwe_array_in_encrypted_key,
    CudaRadixCiphertextFFI const *lwe_array_in_values,
    const uint64_t *h_decomposed_clear_keys, int8_t *mem, void *const *bsks,
    void *const *ksks);

void cleanup_cuda_kv_store_get_64(CudaStreamsFFI streams,
                                  int8_t **mem_ptr_void);

uint64_t scratch_cuda_kv_store_update_64_async(
    CudaStreamsFFI streams, int8_t **mem_ptr, uint32_t glwe_dimension,
    uint32_t polynomial_size, uint32_t big_lwe_dimension,
    uint32_t small_lwe_dimension, uint32_t ks_level, uint32_t ks_base_log,
    uint32_t pbs_level, uint32_t pbs_base_log, uint32_t grouping_factor,
    uint32_t num_entries, uint32_t num_key_blocks, uint32_t num_value_blocks,
    uint32_t message_modulus, uint32_t carry_modulus, PBS_TYPE pbs_type,
    bool allocate_gpu_memory, PBS_MS_REDUCTION_T noise_reduction_type);

void cuda_kv_store_update_64_async(
    CudaStreamsFFI streams, CudaRadixCiphertextFFI *lwe_check_out_block,
    CudaRadixCiphertextFFI *lwe_array_out_values,
    CudaRadixCiphertextFFI const *lwe_array_in_encrypted_key,
    CudaRadixCiphertextFFI const *lwe_array_in_values,
    CudaRadixCiphertextFFI const *lwe_in_new_value,
    const uint64_t *h_decomposed_clear_keys, int8_t *mem_ptr, void *const *bsks,
    void *const *ksks);

void cleanup_cuda_kv_store_update_64(CudaStreamsFFI streams,
                                     int8_t **mem_ptr_void);

uint64_t scratch_cuda_kv_store_map_64_async(
    CudaStreamsFFI streams, int8_t **mem_ptr, uint32_t glwe_dimension,
    uint32_t polynomial_size, uint32_t big_lwe_dimension,
    uint32_t small_lwe_dimension, uint32_t ks_level, uint32_t ks_base_log,
    uint32_t pbs_level, uint32_t pbs_base_log, uint32_t grouping_factor,
    uint32_t num_entries, uint32_t num_value_blocks, uint32_t message_modulus,
    uint32_t carry_modulus, PBS_TYPE pbs_type, bool allocate_gpu_memory,
    PBS_MS_REDUCTION_T noise_reduction_type);

void cuda_kv_store_map_64_async(
    CudaStreamsFFI streams, CudaRadixCiphertextFFI *lwe_check_out_block,
    CudaRadixCiphertextFFI *lwe_array_out_values,
    CudaRadixCiphertextFFI const *lwe_array_in_values,
    CudaRadixCiphertextFFI const *lwe_in_new_value,
    CudaRadixCiphertextFFI const *lwe_array_in_selectors, int8_t *mem_ptr,
    void *const *bsks, void *const *ksks);

void cleanup_cuda_kv_store_map_64(CudaStreamsFFI streams,
                                  int8_t **mem_ptr_void);
}

#endif // CUDA_INTEGER_KV_STORE_H
