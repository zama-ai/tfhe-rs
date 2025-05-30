#ifndef CUDA_BOOTSTRAP_128_H
#define CUDA_BOOTSTRAP_128_H

#include "pbs_enums.h"
#include <stdint.h>

uint64_t scratch_cuda_programmable_bootstrap_128_vector_64(
    void *stream, uint32_t gpu_index, int8_t **pbs_buffer,
    uint32_t lwe_dimension, uint32_t glwe_dimension, uint32_t polynomial_size,
    uint32_t level_count, uint32_t input_lwe_ciphertext_count,
    bool allocate_gpu_memory, bool allocate_ms_array);

void cuda_programmable_bootstrap_lwe_ciphertext_vector_128_input_64(
    void *streams, uint32_t gpu_index, void *lwe_array_out,
    void const *lut_vector, void const *lwe_array_in,
    void const *bootstrapping_key,
    CudaModulusSwitchNoiseReductionKeyFFI const *ms_noise_reduction_key,
    void const *ms_noise_reduction_ptr, int8_t *mem_ptr, uint32_t lwe_dimension,
    uint32_t glwe_dimension, uint32_t polynomial_size, uint32_t base_log,
    uint32_t level_count, uint32_t num_samples);

#endif // CUDA_BOOTSTRAP_128_H
