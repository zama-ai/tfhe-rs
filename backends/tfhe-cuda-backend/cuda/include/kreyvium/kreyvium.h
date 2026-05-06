#ifndef KREYVIUM_H
#define KREYVIUM_H

#include "../integer/integer.h"

extern "C" {
uint64_t scratch_cuda_kreyvium_init_async(
    CudaStreamsFFI streams, int8_t **mem_ptr,
    CudaLweBootstrapKeyParamsFFI bsk_params,
    CudaLweKeyswitchKeyParamsFFI ksk_params, uint32_t message_modulus,
    uint32_t carry_modulus, bool allocate_gpu_memory,
    PBS_MS_REDUCTION_T noise_reduction_type, uint32_t num_inputs);

void cleanup_cuda_kreyvium_init(CudaStreamsFFI streams, int8_t **mem_ptr_void);

uint64_t scratch_cuda_kreyvium_step_async(
    CudaStreamsFFI streams, int8_t **mem_ptr,
    CudaLweBootstrapKeyParamsFFI bsk_params,
    CudaLweKeyswitchKeyParamsFFI ksk_params, uint32_t message_modulus,
    uint32_t carry_modulus, bool allocate_gpu_memory,
    PBS_MS_REDUCTION_T noise_reduction_type, uint32_t num_inputs);
void cleanup_cuda_kreyvium_step(CudaStreamsFFI streams, int8_t **mem_ptr_void);

void cuda_kreyvium_init_async(
    CudaStreamsFFI streams, CudaRadixCiphertextFFI *a_reg,
    CudaRadixCiphertextFFI *b_reg, CudaRadixCiphertextFFI *c_reg,
    CudaRadixCiphertextFFI *k_reg, CudaRadixCiphertextFFI *iv_reg,
    uint32_t *k_offset, uint32_t *iv_offset, const CudaRadixCiphertextFFI *key,
    const CudaRadixCiphertextFFI *iv_in, uint32_t num_inputs, int8_t *mem_ptr,
    void *const *bsks, void *const *ksks);
void cuda_kreyvium_step_async(
    CudaStreamsFFI streams, CudaRadixCiphertextFFI *keystream_output,
    CudaRadixCiphertextFFI *a_reg, CudaRadixCiphertextFFI *b_reg,
    CudaRadixCiphertextFFI *c_reg, CudaRadixCiphertextFFI *k_reg,
    CudaRadixCiphertextFFI *iv_reg, uint32_t *k_offset, uint32_t *iv_offset,
    uint32_t num_inputs, uint32_t num_steps, int8_t *mem_ptr, void *const *bsks,
    void *const *ksks);
}

#endif
