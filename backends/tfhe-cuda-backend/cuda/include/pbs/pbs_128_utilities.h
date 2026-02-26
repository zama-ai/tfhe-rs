#ifndef CUDA_BOOTSTRAP_128_H
#define CUDA_BOOTSTRAP_128_H

#include "pbs_enums.h"
#include <stdint.h>

uint64_t scratch_cuda_programmable_bootstrap_128_vector_64(
    void *stream, uint32_t gpu_index, int8_t **pbs_buffer,
    uint32_t lwe_dimension, uint32_t glwe_dimension, uint32_t polynomial_size,
    uint32_t level_count, uint32_t base_log,
    uint32_t input_lwe_ciphertext_count, bool allocate_gpu_memory,
    PBS_MS_REDUCTION_T noise_reduction_type);

#endif // CUDA_BOOTSTRAP_128_H
