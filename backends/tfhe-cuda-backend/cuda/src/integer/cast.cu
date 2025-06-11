#include "cast.cuh"

void extend_radix_with_trivial_zero_blocks_msb_64(
    CudaRadixCiphertextFFI *output, CudaRadixCiphertextFFI const *input,
    void *const *streams, uint32_t const *gpu_indexes) {
  host_extend_radix_with_trivial_zero_blocks_msb<uint64_t>(
      output, input, (cudaStream_t *)streams, gpu_indexes);
}

void trim_radix_blocks_lsb_64(CudaRadixCiphertextFFI *output,
                              CudaRadixCiphertextFFI const *input,
                              void *const *streams,
                              uint32_t const *gpu_indexes) {

  host_trim_radix_blocks_lsb<uint64_t>(output, input, (cudaStream_t *)streams,
                                       gpu_indexes);
}

uint64_t scratch_cuda_extend_radix_with_sign_msb_64(
    void *const *streams, uint32_t const *gpu_indexes, uint32_t gpu_count,
    int8_t **mem_ptr, uint32_t glwe_dimension, uint32_t polynomial_size,
    uint32_t lwe_dimension, uint32_t ks_level, uint32_t ks_base_log,
    uint32_t pbs_level, uint32_t pbs_base_log, uint32_t grouping_factor,
    uint32_t num_blocks, uint32_t num_additional_blocks,
    uint32_t message_modulus, uint32_t carry_modulus, PBS_TYPE pbs_type,
    bool allocate_gpu_memory, bool allocate_ms_array) {

  int_radix_params params(pbs_type, glwe_dimension, polynomial_size,
                          glwe_dimension * polynomial_size, lwe_dimension,
                          ks_level, ks_base_log, pbs_level, pbs_base_log,
                          grouping_factor, message_modulus, carry_modulus,
                          allocate_ms_array);

  return scratch_extend_radix_with_sign_msb<uint64_t>(
      (cudaStream_t *)streams, gpu_indexes, gpu_count,
      (int_extend_radix_with_sign_msb<uint64_t> **)mem_ptr, params, num_blocks,
      num_additional_blocks, allocate_gpu_memory);
}

void cuda_extend_radix_with_sign_msb_64(
    void *const *streams, uint32_t const *gpu_indexes, uint32_t gpu_count,
    CudaRadixCiphertextFFI *output, CudaRadixCiphertextFFI const *input,
    int8_t *mem_ptr, uint32_t num_additional_blocks, void *const *bsks,
    void *const *ksks,
    CudaModulusSwitchNoiseReductionKeyFFI const *ms_noise_reduction_key) {

  host_extend_radix_with_sign_msb<uint64_t>(
      (cudaStream_t *)streams, gpu_indexes, gpu_count, output, input,
      (int_extend_radix_with_sign_msb<uint64_t> *)mem_ptr,
      num_additional_blocks, bsks, (uint64_t **)ksks, ms_noise_reduction_key);
}

void cleanup_cuda_extend_radix_with_sign_msb_64(void *const *streams,
                                                uint32_t const *gpu_indexes,
                                                uint32_t gpu_count,
                                                int8_t **mem_ptr_void) {

  int_extend_radix_with_sign_msb<uint64_t> *mem_ptr =
      (int_extend_radix_with_sign_msb<uint64_t> *)(*mem_ptr_void);

  mem_ptr->release((cudaStream_t *)(streams), gpu_indexes, gpu_count);
}
