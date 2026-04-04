#ifndef KREYVIUM_H
#define KREYVIUM_H

#include "../integer/integer.h"

extern "C" {
uint64_t scratch_cuda_kreyvium_generate_keystream_64_async(
    CudaStreamsFFI streams, int8_t **mem_ptr,
    CudaLweBootstrapKeyParamsFFI bsk_params, uint32_t ks_level,
    uint32_t ks_base_log, uint32_t message_modulus, uint32_t carry_modulus,
    bool allocate_gpu_memory, PBS_MS_REDUCTION_T noise_reduction_type,
    uint32_t num_inputs);

void cuda_kreyvium_generate_keystream_64_async(
    CudaStreamsFFI streams, CudaRadixCiphertextFFI *keystream_output,
    const CudaRadixCiphertextFFI *key, const CudaRadixCiphertextFFI *iv,
    uint32_t num_inputs, uint32_t num_steps, int8_t *mem_ptr, void *const *bsks,
    void *const *ksks);

void cleanup_cuda_kreyvium_generate_keystream_64(CudaStreamsFFI streams,
                                                 int8_t **mem_ptr_void);
}

#endif
