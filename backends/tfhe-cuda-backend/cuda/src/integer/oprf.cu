#include "integer/oprf.cuh"

uint64_t scratch_cuda_integer_grouped_oprf_64(
    void *const *streams, uint32_t const *gpu_indexes, uint32_t gpu_count,
    int8_t **mem_ptr, uint32_t glwe_dimension, uint32_t polynomial_size,
    uint32_t lwe_dimension, uint32_t ks_level, uint32_t ks_base_log,
    uint32_t pbs_level, uint32_t pbs_base_log, uint32_t grouping_factor,
    uint32_t num_blocks_to_process, uint32_t num_blocks,
    uint32_t message_modulus, uint32_t carry_modulus, PBS_TYPE pbs_type,
    bool allocate_gpu_memory, uint32_t message_bits_per_block,
    uint32_t total_random_bits, bool allocate_ms_array) {

  int_radix_params params(pbs_type, glwe_dimension, polynomial_size,
                          glwe_dimension * polynomial_size, lwe_dimension,
                          ks_level, ks_base_log, pbs_level, pbs_base_log,
                          grouping_factor, message_modulus, carry_modulus,
                          allocate_ms_array);

  return scratch_cuda_integer_grouped_oprf<uint64_t>(
      (cudaStream_t *)streams, gpu_indexes, gpu_count,
      (int_grouped_oprf_memory<uint64_t> **)mem_ptr, params,
      num_blocks_to_process, num_blocks, message_bits_per_block,
      total_random_bits, allocate_gpu_memory);
}

void cuda_integer_grouped_oprf_async_64(
    void *const *streams, uint32_t const *gpu_indexes, uint32_t gpu_count,
    CudaRadixCiphertextFFI *radix_lwe_out, const void *seeded_lwe_input,
    uint32_t num_blocks_to_process, int8_t *mem, void *const *bsks,
    CudaModulusSwitchNoiseReductionKeyFFI const *ms_noise_reduction_key) {

  host_integer_grouped_oprf<uint64_t>(
      (cudaStream_t *)streams, gpu_indexes, gpu_count, radix_lwe_out,
      (const uint64_t *)seeded_lwe_input, num_blocks_to_process,
      (int_grouped_oprf_memory<uint64_t> *)mem, bsks, ms_noise_reduction_key);
}

void cleanup_cuda_integer_grouped_oprf_64(void *const *streams,
                                          uint32_t const *gpu_indexes,
                                          uint32_t gpu_count,
                                          int8_t **mem_ptr_void) {

  int_grouped_oprf_memory<uint64_t> *mem_ptr =
      (int_grouped_oprf_memory<uint64_t> *)(*mem_ptr_void);

  mem_ptr->release((cudaStream_t *)streams, gpu_indexes, gpu_count);

  delete mem_ptr;
  *mem_ptr_void = nullptr;
}
