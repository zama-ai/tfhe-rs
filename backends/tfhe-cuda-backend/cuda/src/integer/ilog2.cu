#include "ilog2.cuh"

uint64_t scratch_cuda_prepare_count_of_consecutive_bits_buffer_kb_64(
    void *const *streams, uint32_t const *gpu_indexes, const uint32_t gpu_count,
    int8_t **mem_ptr, const uint32_t num_radix_blocks, const Direction dir,
    const BitValue bit_value, const bool allocate_gpu_memory,
    const uint32_t glwe_dimension, const uint32_t polynomial_size,
    const uint32_t lwe_dimension, const uint32_t ks_level,
    const uint32_t ks_base_log, const uint32_t pbs_level,
    const uint32_t pbs_base_log, const uint32_t grouping_factor,
    const uint32_t message_modulus, const uint32_t carry_modulus,
    const PBS_TYPE pbs_type, const bool allocate_ms_array) {

  int_radix_params params(pbs_type, glwe_dimension, polynomial_size,
                          glwe_dimension * polynomial_size, lwe_dimension,
                          ks_level, ks_base_log, pbs_level, pbs_base_log,
                          grouping_factor, message_modulus, carry_modulus,
                          allocate_ms_array);

  return scratch_cuda_prepare_count_of_consecutive_bits_buffer_kb<uint64_t>(
      (cudaStream_t *)streams, gpu_indexes, gpu_count,
      (int_prepare_count_of_consecutive_bits_buffer<uint64_t> **)mem_ptr,
      num_radix_blocks, params, dir, bit_value, allocate_gpu_memory);
}

void cuda_prepare_count_of_consecutive_bits_buffer_kb_64(
    void *const *streams, uint32_t const *gpu_indexes, const uint32_t gpu_count,
    CudaRadixCiphertextFFI *output, CudaRadixCiphertextFFI const *input,
    int8_t *mem_ptr, void *const *bsks, void *const *ksks,
    CudaModulusSwitchNoiseReductionKeyFFI const *ms_noise_reduction_key) {

  host_cuda_prepare_count_of_consecutive_bits_buffer_kb<uint64_t>(
      (cudaStream_t *)streams, gpu_indexes, gpu_count, output, input,
      (int_prepare_count_of_consecutive_bits_buffer<uint64_t> *)mem_ptr, bsks,
      (uint64_t **)ksks, ms_noise_reduction_key);
}

void cleanup_cuda_prepare_count_of_consecutive_bits_buffer_kb_64(
    void *const *streams, uint32_t const *gpu_indexes, uint32_t gpu_count,
    int8_t **mem_ptr) {

  auto *buf =
      (int_prepare_count_of_consecutive_bits_buffer<uint64_t> *)(*mem_ptr);

  buf->release((cudaStream_t *)(streams), gpu_indexes, gpu_count);
}
