#include "integer/bitwise_ops.cuh"

uint64_t scratch_cuda_integer_radix_bitop_kb_64(
    void *const *streams, uint32_t const *gpu_indexes, uint32_t gpu_count,
    int8_t **mem_ptr, uint32_t glwe_dimension, uint32_t polynomial_size,
    uint32_t big_lwe_dimension, uint32_t small_lwe_dimension, uint32_t ks_level,
    uint32_t ks_base_log, uint32_t pbs_level, uint32_t pbs_base_log,
    uint32_t grouping_factor, uint32_t lwe_ciphertext_count,
    uint32_t message_modulus, uint32_t carry_modulus, PBS_TYPE pbs_type,
    BITOP_TYPE op_type, bool allocate_gpu_memory, bool allocate_ms_array) {

  int_radix_params params(pbs_type, glwe_dimension, polynomial_size,
                          big_lwe_dimension, small_lwe_dimension, ks_level,
                          ks_base_log, pbs_level, pbs_base_log, grouping_factor,
                          message_modulus, carry_modulus, allocate_ms_array);

  return scratch_cuda_integer_radix_bitop_kb<uint64_t>(
      (cudaStream_t *)(streams), gpu_indexes, gpu_count,
      (int_bitop_buffer<uint64_t> **)mem_ptr, lwe_ciphertext_count, params,
      op_type, allocate_gpu_memory);
}

void cuda_bitop_integer_radix_ciphertext_kb_64(
    void *const *streams, uint32_t const *gpu_indexes, uint32_t gpu_count,
    CudaRadixCiphertextFFI *lwe_array_out,
    CudaRadixCiphertextFFI const *lwe_array_1,
    CudaRadixCiphertextFFI const *lwe_array_2, int8_t *mem_ptr,
    void *const *bsks, void *const *ksks,
    CudaModulusSwitchNoiseReductionKeyFFI const *ms_noise_reduction_key) {

  host_integer_radix_bitop_kb<uint64_t>(
      (cudaStream_t *)(streams), gpu_indexes, gpu_count, lwe_array_out,
      lwe_array_1, lwe_array_2, (int_bitop_buffer<uint64_t> *)mem_ptr, bsks,
      (uint64_t **)(ksks), ms_noise_reduction_key);
}

void cleanup_cuda_integer_bitop(void *const *streams,
                                uint32_t const *gpu_indexes, uint32_t gpu_count,
                                int8_t **mem_ptr_void) {

  int_bitop_buffer<uint64_t> *mem_ptr =
      (int_bitop_buffer<uint64_t> *)(*mem_ptr_void);
  mem_ptr->release((cudaStream_t *)(streams), gpu_indexes, gpu_count);
}

void update_degrees_after_bitand(uint64_t *output_degrees,
                                 uint64_t *lwe_array_1_degrees,
                                 uint64_t *lwe_array_2_degrees,
                                 uint32_t num_radix_blocks) {
  for (uint i = 0; i < num_radix_blocks; i++) {
    output_degrees[i] =
        std::min(lwe_array_1_degrees[i], lwe_array_2_degrees[i]);
  }
}

void update_degrees_after_bitor(uint64_t *output_degrees,
                                uint64_t *lwe_array_1_degrees,
                                uint64_t *lwe_array_2_degrees,
                                uint32_t num_radix_blocks) {
  for (uint i = 0; i < num_radix_blocks; i++) {
    auto max = std::max(lwe_array_1_degrees[i], lwe_array_2_degrees[i]);
    auto min = std::min(lwe_array_1_degrees[i], lwe_array_2_degrees[i]);
    auto result = max;

    for (uint j = 0; j < min + 1; j++) {
      if ((max | j) > result) {
        result = max | j;
      }
    }
    output_degrees[i] = result;
  }
}

void update_degrees_after_bitxor(uint64_t *output_degrees,
                                 uint64_t *lwe_array_1_degrees,
                                 uint64_t *lwe_array_2_degrees,
                                 uint32_t num_radix_blocks) {
  for (uint i = 0; i < num_radix_blocks; i++) {
    auto max = std::max(lwe_array_1_degrees[i], lwe_array_2_degrees[i]);
    auto min = std::min(lwe_array_1_degrees[i], lwe_array_2_degrees[i]);
    auto result = max;

    // Try every possibility to find the worst case
    for (uint j = 0; j < min + 1; j++) {
      if ((max ^ j) > result) {
        result = max ^ j;
      }
    }
    output_degrees[i] = result;
  }
}
