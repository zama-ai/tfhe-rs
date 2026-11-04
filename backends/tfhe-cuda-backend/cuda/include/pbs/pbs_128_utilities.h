#ifndef CUDA_BOOTSTRAP_128_H
#define CUDA_BOOTSTRAP_128_H

#include "bootstrap_key_params.h"
#include "pbs_enums.h"
#include <stdint.h>

uint64_t scratch_cuda_programmable_bootstrap_128_vector_64(
    void *stream, uint32_t gpu_index, int8_t **pbs_buffer,
    const CudaLweBootstrapKeyParamsFFI &bsk_params,
    uint32_t input_lwe_ciphertext_count, bool allocate_gpu_memory);

#endif // CUDA_BOOTSTRAP_128_H
