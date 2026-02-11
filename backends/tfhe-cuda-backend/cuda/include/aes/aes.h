#ifndef AES_H
#define AES_H
#include "../integer/integer.h"

extern "C" {
uint64_t scratch_cuda_integer_aes_ctr_encrypt_64_async(
    CudaStreamsFFI streams, int8_t **mem_ptr, uint32_t glwe_dimension,
    uint32_t polynomial_size, uint32_t lwe_dimension, uint32_t ks_level,
    uint32_t ks_base_log, uint32_t pbs_level, uint32_t pbs_base_log,
    uint32_t grouping_factor, uint32_t message_modulus, uint32_t carry_modulus,
    PBS_TYPE pbs_type, bool allocate_gpu_memory,
    PBS_MS_REDUCTION_T noise_reduction_type, uint32_t num_aes_inputs,
    uint32_t sbox_parallelism);

uint64_t scratch_cuda_integer_aes_ctr_256_encrypt_64_async(
    CudaStreamsFFI streams, int8_t **mem_ptr, uint32_t glwe_dimension,
    uint32_t polynomial_size, uint32_t lwe_dimension, uint32_t ks_level,
    uint32_t ks_base_log, uint32_t pbs_level, uint32_t pbs_base_log,
    uint32_t grouping_factor, uint32_t message_modulus, uint32_t carry_modulus,
    PBS_TYPE pbs_type, bool allocate_gpu_memory,
    PBS_MS_REDUCTION_T noise_reduction_type, uint32_t num_aes_inputs,
    uint32_t sbox_parallelism);

void cuda_integer_aes_ctr_encrypt_64_async(
    CudaStreamsFFI streams, CudaRadixCiphertextFFI *output,
    CudaRadixCiphertextFFI const *iv, CudaRadixCiphertextFFI const *round_keys,
    const uint64_t *counter_bits_le_all_blocks, uint32_t num_aes_inputs,
    int8_t *mem_ptr, void *const *bsks, void *const *ksks);

void cleanup_cuda_integer_aes_ctr_encrypt_64(CudaStreamsFFI streams,
                                             int8_t **mem_ptr_void);

void cleanup_cuda_integer_aes_ctr_256_encrypt_64(CudaStreamsFFI streams,
                                                 int8_t **mem_ptr_void);

uint64_t scratch_cuda_integer_key_expansion_64_async(
    CudaStreamsFFI streams, int8_t **mem_ptr, uint32_t glwe_dimension,
    uint32_t polynomial_size, uint32_t lwe_dimension, uint32_t ks_level,
    uint32_t ks_base_log, uint32_t pbs_level, uint32_t pbs_base_log,
    uint32_t grouping_factor, uint32_t message_modulus, uint32_t carry_modulus,
    PBS_TYPE pbs_type, bool allocate_gpu_memory,
    PBS_MS_REDUCTION_T noise_reduction_type);

void cuda_integer_key_expansion_64_async(CudaStreamsFFI streams,
                                         CudaRadixCiphertextFFI *expanded_keys,
                                         CudaRadixCiphertextFFI const *key,
                                         int8_t *mem_ptr, void *const *bsks,
                                         void *const *ksks);

void cleanup_cuda_integer_key_expansion_64(CudaStreamsFFI streams,
                                           int8_t **mem_ptr_void);

void cuda_integer_aes_ctr_256_encrypt_64_async(
    CudaStreamsFFI streams, CudaRadixCiphertextFFI *output,
    CudaRadixCiphertextFFI const *iv, CudaRadixCiphertextFFI const *round_keys,
    const uint64_t *counter_bits_le_all_blocks, uint32_t num_aes_inputs,
    int8_t *mem_ptr, void *const *bsks, void *const *ksks);

uint64_t scratch_cuda_integer_key_expansion_256_64_async(
    CudaStreamsFFI streams, int8_t **mem_ptr, uint32_t glwe_dimension,
    uint32_t polynomial_size, uint32_t lwe_dimension, uint32_t ks_level,
    uint32_t ks_base_log, uint32_t pbs_level, uint32_t pbs_base_log,
    uint32_t grouping_factor, uint32_t message_modulus, uint32_t carry_modulus,
    PBS_TYPE pbs_type, bool allocate_gpu_memory,
    PBS_MS_REDUCTION_T noise_reduction_type);

void cuda_integer_key_expansion_256_64_async(
    CudaStreamsFFI streams, CudaRadixCiphertextFFI *expanded_keys,
    CudaRadixCiphertextFFI const *key, int8_t *mem_ptr, void *const *bsks,
    void *const *ksks);

void cleanup_cuda_integer_key_expansion_256_64(CudaStreamsFFI streams,
                                               int8_t **mem_ptr_void);
}

#endif
