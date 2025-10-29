#pragma once
#include "../integer/integer.h"
extern "C" {
uint64_t scratch_cuda_erc20_64(
    CudaStreamsFFI streams, int8_t **mem_ptr, uint32_t glwe_dimension,
    uint32_t polynomial_size, uint32_t big_lwe_dimension,
    uint32_t small_lwe_dimension, uint32_t ks_level, uint32_t ks_base_log,
    uint32_t pbs_level, uint32_t pbs_base_log, uint32_t grouping_factor,
    uint32_t lwe_ciphertext_count, uint32_t message_modulus,
    uint32_t carry_modulus, PBS_TYPE pbs_type, bool allocate_gpu_memory,
    PBS_MS_REDUCTION_T noise_reduction_type);

void cuda_erc20_assign_64(CudaStreamsFFI streams,
                          CudaRadixCiphertextFFI *from_amount,
                          CudaRadixCiphertextFFI *to_amount,
                          CudaRadixCiphertextFFI const *amount, int8_t *mem_ptr,
                          void *const *bsks, void *const *ksks);

void cleanup_cuda_erc20(CudaStreamsFFI streams, int8_t **mem_ptr_void);
}
