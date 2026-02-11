#pragma once

#include "integer.h"

extern "C" {
uint64_t scratch_cuda_rerand_64_async(
    CudaStreamsFFI streams, int8_t **mem_ptr, uint32_t big_lwe_dimension,
    uint32_t small_lwe_dimension, uint32_t ks_level, uint32_t ks_base_log,
    uint32_t lwe_ciphertext_count, uint32_t message_modulus,
    uint32_t carry_modulus, bool allocate_gpu_memory);

void cuda_rerand_64_async(
    CudaStreamsFFI streams, void *lwe_array,
    const void *lwe_flattened_encryptions_of_zero_compact_array_in,
    int8_t *mem_ptr, void *const *ksk);

void cleanup_cuda_rerand_64(CudaStreamsFFI streams, int8_t **mem_ptr_void);
}
