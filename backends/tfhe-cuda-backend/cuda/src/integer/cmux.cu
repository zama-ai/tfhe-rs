#include "integer/cmux.cuh"

void scratch_cuda_integer_radix_cmux_kb_64(
    void *const *streams, uint32_t const *gpu_indexes, uint32_t gpu_count,
    int8_t **mem_ptr, uint32_t glwe_dimension, uint32_t polynomial_size,
    uint32_t big_lwe_dimension, uint32_t small_lwe_dimension, uint32_t ks_level,
    uint32_t ks_base_log, uint32_t pbs_level, uint32_t pbs_base_log,
    uint32_t grouping_factor, uint32_t lwe_ciphertext_count,
    uint32_t message_modulus, uint32_t carry_modulus, PBS_TYPE pbs_type,
    bool allocate_gpu_memory) {

  int_radix_params params(pbs_type, glwe_dimension, polynomial_size,
                          big_lwe_dimension, small_lwe_dimension, ks_level,
                          ks_base_log, pbs_level, pbs_base_log, grouping_factor,
                          message_modulus, carry_modulus);

  std::function<uint64_t(uint64_t)> predicate_lut_f =
      [](uint64_t x) -> uint64_t { return x == 1; };

  scratch_cuda_integer_radix_cmux_kb<uint64_t>(
      (cudaStream_t *)(streams), gpu_indexes, gpu_count,
      (int_cmux_buffer<uint64_t> **)mem_ptr, predicate_lut_f,
      lwe_ciphertext_count, params, allocate_gpu_memory);
}

void cuda_cmux_integer_radix_ciphertext_kb_64(
    void *const *streams, uint32_t const *gpu_indexes, uint32_t gpu_count,
    void *lwe_array_out, void const *lwe_condition, void const *lwe_array_true,
    void const *lwe_array_false, int8_t *mem_ptr, void *const *bsks,
    void *const *ksks, uint32_t lwe_ciphertext_count) {

  host_integer_radix_cmux_kb<uint64_t>(
      (cudaStream_t *)(streams), gpu_indexes, gpu_count,
      static_cast<uint64_t *>(lwe_array_out),
      static_cast<const uint64_t *>(lwe_condition),
      static_cast<const uint64_t *>(lwe_array_true),
      static_cast<const uint64_t *>(lwe_array_false),
      (int_cmux_buffer<uint64_t> *)mem_ptr, bsks, (uint64_t **)(ksks),

      lwe_ciphertext_count);
}

void cleanup_cuda_integer_radix_cmux(void *const *streams,
                                     uint32_t const *gpu_indexes,
                                     uint32_t gpu_count,
                                     int8_t **mem_ptr_void) {

  int_cmux_buffer<uint64_t> *mem_ptr =
      (int_cmux_buffer<uint64_t> *)(*mem_ptr_void);
  mem_ptr->release((cudaStream_t *)(streams), gpu_indexes, gpu_count);
}
