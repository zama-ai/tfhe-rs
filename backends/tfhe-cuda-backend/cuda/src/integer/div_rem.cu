#include "integer/div_rem.cuh"

uint64_t scratch_cuda_integer_div_rem_radix_ciphertext_kb_64(
    void *const *streams, uint32_t const *gpu_indexes, uint32_t gpu_count,
    bool is_signed, int8_t **mem_ptr, uint32_t glwe_dimension,
    uint32_t polynomial_size, uint32_t big_lwe_dimension,
    uint32_t small_lwe_dimension, uint32_t ks_level, uint32_t ks_base_log,
    uint32_t pbs_level, uint32_t pbs_base_log, uint32_t grouping_factor,
    uint32_t num_blocks, uint32_t message_modulus, uint32_t carry_modulus,
    PBS_TYPE pbs_type, bool allocate_gpu_memory, bool allocate_ms_array) {
  PUSH_RANGE("scratch div")
  int_radix_params params(pbs_type, glwe_dimension, polynomial_size,
                          big_lwe_dimension, small_lwe_dimension, ks_level,
                          ks_base_log, pbs_level, pbs_base_log, grouping_factor,
                          message_modulus, carry_modulus, allocate_ms_array);

  return scratch_cuda_integer_div_rem_kb<uint64_t>(
      (cudaStream_t *)(streams), gpu_indexes, gpu_count, is_signed,
      (int_div_rem_memory<uint64_t> **)mem_ptr, num_blocks, params,
      allocate_gpu_memory);
  POP_RANGE()
}

void cuda_integer_div_rem_radix_ciphertext_kb_64(
    void *const *streams, uint32_t const *gpu_indexes, uint32_t gpu_count,
    CudaRadixCiphertextFFI *quotient, CudaRadixCiphertextFFI *remainder,
    CudaRadixCiphertextFFI const *numerator,
    CudaRadixCiphertextFFI const *divisor, bool is_signed, int8_t *mem_ptr,
    void *const *bsks, void *const *ksks,
    CudaModulusSwitchNoiseReductionKeyFFI const *ms_noise_reduction_key) {
  PUSH_RANGE("div")
  auto mem = (int_div_rem_memory<uint64_t> *)mem_ptr;

  host_integer_div_rem_kb<uint64_t>(
      (cudaStream_t *)(streams), gpu_indexes, gpu_count, quotient, remainder,
      numerator, divisor, is_signed, bsks, (uint64_t **)(ksks),
      ms_noise_reduction_key, mem);
  POP_RANGE()
}

void cleanup_cuda_integer_div_rem(void *const *streams,
                                  uint32_t const *gpu_indexes,
                                  uint32_t gpu_count, int8_t **mem_ptr_void) {
  PUSH_RANGE("cleanup div")
  int_div_rem_memory<uint64_t> *mem_ptr =
      (int_div_rem_memory<uint64_t> *)(*mem_ptr_void);

  mem_ptr->release((cudaStream_t *)(streams), gpu_indexes, gpu_count);
  delete mem_ptr;
  *mem_ptr_void = nullptr;
  POP_RANGE()
}
