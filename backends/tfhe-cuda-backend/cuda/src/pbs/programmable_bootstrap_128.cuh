#ifndef CUDA_PROGRAMMABLE_BOOTSTRAP_128_CUH
#define CUDA_PROGRAMMABLE_BOOTSTRAP_128_CUH
#include "pbs/pbs_128_utilities.h"

static void
execute_scratch_pbs_128(void *stream, uint32_t gpu_index, int8_t **pbs_buffer,
                        uint32_t lwe_dimension, uint32_t glwe_dimension,
                        uint32_t polynomial_size, uint32_t level_count,
                        uint32_t input_lwe_ciphertext_count,
                        bool allocate_gpu_memory, bool allocate_ms_array,
                        uint64_t *size_tracker_on_gpu) {
  // The squash noise function receives as input 64-bit integers
  *size_tracker_on_gpu = scratch_cuda_programmable_bootstrap_128_vector_64(
      stream, gpu_index, pbs_buffer, lwe_dimension, glwe_dimension,
      polynomial_size, level_count, input_lwe_ciphertext_count,
      allocate_gpu_memory, allocate_ms_array);
}
template <typename Torus>
static void execute_pbs_128_async(
    cudaStream_t const *streams, uint32_t const *gpu_index,
    uint32_t active_gpu_count,
    const LweArrayVariant<__uint128_t> &lwe_array_out,
    const std::vector<Torus *> lut_vector,
    const LweArrayVariant<uint64_t> &lwe_array_in,
    void *const *bootstrapping_keys,
    CudaModulusSwitchNoiseReductionKeyFFI const *ms_noise_reduction_key,
    std::vector<int8_t *> pbs_buffer, uint32_t lwe_dimension,
    uint32_t glwe_dimension, uint32_t polynomial_size, uint32_t base_log,
    uint32_t level_count, uint32_t num_samples) {

  for (uint32_t i = 0; i < active_gpu_count; i++) {
    int num_inputs_on_gpu =
        get_num_inputs_on_gpu(num_samples, i, active_gpu_count);

    Torus *current_lwe_array_out = GET_VARIANT_ELEMENT(lwe_array_out, i);
    uint64_t *current_lwe_array_in = GET_VARIANT_ELEMENT_64BIT(lwe_array_in, i);
    void *zeros = nullptr;
    if (ms_noise_reduction_key != nullptr)
      zeros = ms_noise_reduction_key->ptr[i];

    cuda_programmable_bootstrap_lwe_ciphertext_vector_128_input_64(
        streams[i], gpu_index[i], current_lwe_array_out, lut_vector[i],
        current_lwe_array_in,
        // streams[i], gpu_index[i], lwe_array_out, lut_vector, lwe_array_in,
        bootstrapping_keys[i], ms_noise_reduction_key, zeros, pbs_buffer[i],
        lwe_dimension, glwe_dimension, polynomial_size, base_log, level_count,
        num_inputs_on_gpu);
  }
}
#endif