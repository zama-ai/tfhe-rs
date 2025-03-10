#include "zk.cuh"

void scratch_cuda_expand_without_verification_64(
    void *const *streams, uint32_t const *gpu_indexes, uint32_t gpu_count,
    int8_t **mem_ptr, uint32_t glwe_dimension, uint32_t polynomial_size,
    uint32_t big_lwe_dimension, uint32_t small_lwe_dimension, uint32_t ks_level,
    uint32_t ks_base_log, uint32_t pbs_level, uint32_t pbs_base_log,
    uint32_t grouping_factor, uint32_t lwe_ciphertext_count,
    uint32_t message_modulus, uint32_t carry_modulus, PBS_TYPE pbs_type,
    KS_TYPE ks_type, bool allocate_gpu_memory) {

  // TODO: It's weird to use a int_ thing here. Maybe we should rename
  // int_radix_params to just "tfhe_params"
  int_radix_params params(pbs_type, ks_type, glwe_dimension, polynomial_size,
                          big_lwe_dimension, small_lwe_dimension, ks_level,
                          ks_base_log, pbs_level, pbs_base_log, grouping_factor,
                          message_modulus, carry_modulus);

  scratch_cuda_expand_without_verification<uint64_t>(
      (cudaStream_t *)streams, gpu_indexes, gpu_count,
      (zk_expand<uint64_t> **)mem_ptr, lwe_ciphertext_count, params,
      allocate_gpu_memory);
}

void cuda_expand_without_verification_64(
    void *const *streams, uint32_t const *gpu_indexes, uint32_t gpu_count,
    void *lwe_array_out, const void *lwe_compact_array_in, int8_t *mem_ptr,
    void *const *bsks, void *const *ksks) {

  host_expand_without_verification<uint64_t>(
      (cudaStream_t *)(streams), gpu_indexes, gpu_count,
      static_cast<uint64_t *>(lwe_array_out),
      static_cast<const uint64_t *>(lwe_compact_array_in),
      static_cast<const bool *>(NULL), (zk_expand<uint64_t> *)mem_ptr, bsks,
      (uint64_t **)(ksks));
}

void cleanup_expand_without_verification_64(void *const *streams,
                                            uint32_t const *gpu_indexes,
                                            uint32_t gpu_count,
                                            int8_t **mem_ptr_void) {

  zk_expand<uint64_t> *mem_ptr = (zk_expand<uint64_t> *)(*mem_ptr_void);
  mem_ptr->release((cudaStream_t *)(streams), gpu_indexes, gpu_count);
}
