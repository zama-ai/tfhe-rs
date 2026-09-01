#ifndef TRIVIUM_H
#define TRIVIUM_H

#include "../integer/integer.h"

extern "C" {
uint64_t scratch_cuda_trivium_init_async(
    CudaStreamsFFI streams, int8_t **mem_ptr,
    CudaLweBootstrapKeyParamsFFI bsk_params,
    CudaLweKeyswitchKeyParamsFFI ksk_params, uint32_t message_modulus,
    uint32_t carry_modulus, bool allocate_gpu_memory,
    PBS_MS_REDUCTION_T noise_reduction_type, uint32_t num_inputs);

void cuda_trivium_init_async(
    CudaStreamsFFI streams, CudaRadixCiphertextFFI const *a_reg,
    CudaRadixCiphertextFFI const *b_reg, CudaRadixCiphertextFFI const *c_reg,
    const CudaRadixCiphertextFFI *key, const CudaRadixCiphertextFFI *iv,
    uint32_t num_inputs, int8_t *mem_ptr, void *const *bsks, void *const *ksks);

void cleanup_cuda_trivium_init(CudaStreamsFFI streams, int8_t **mem_ptr_void);

uint64_t scratch_cuda_trivium_step_async(
    CudaStreamsFFI streams, int8_t **mem_ptr,
    CudaLweBootstrapKeyParamsFFI bsk_params,
    CudaLweKeyswitchKeyParamsFFI ksk_params, uint32_t message_modulus,
    uint32_t carry_modulus, bool allocate_gpu_memory,
    PBS_MS_REDUCTION_T noise_reduction_type, uint32_t num_inputs);

void cuda_trivium_step_async(
    CudaStreamsFFI streams, CudaRadixCiphertextFFI const *keystream_output,
    CudaRadixCiphertextFFI const *a_reg, CudaRadixCiphertextFFI const *b_reg,
    CudaRadixCiphertextFFI const *c_reg, uint32_t num_inputs,
    uint32_t num_steps, int8_t *mem_ptr, void *const *bsks, void *const *ksks);

void cleanup_cuda_trivium_step(CudaStreamsFFI streams, int8_t **mem_ptr_void);
}

#endif
