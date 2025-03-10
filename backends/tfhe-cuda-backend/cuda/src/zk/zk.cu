#include "zk.cuh"

void scratch_cuda_expand_without_verification_64(
    void *const *streams, uint32_t const *gpu_indexes, uint32_t gpu_count,
    int8_t **mem_ptr, uint32_t glwe_dimension, uint32_t polynomial_size,
    uint32_t big_lwe_dimension, uint32_t small_lwe_dimension, uint32_t ks_level,
    uint32_t ks_base_log, uint32_t pbs_level, uint32_t pbs_base_log,
    uint32_t grouping_factor, const uint32_t *num_lwes_per_compact_list,
    const bool *is_boolean_array, uint32_t num_compact_lists,
    uint32_t message_modulus, uint32_t carry_modulus, PBS_TYPE pbs_type,
    bool allocate_gpu_memory, bool allocate_ms_array) {

  // TODO: It's weird to use a int_ thing here. Maybe we should rename
  // int_radix_params to just "tfhe_params"
  int_radix_params params(pbs_type, glwe_dimension, polynomial_size,
                          big_lwe_dimension, small_lwe_dimension, ks_level,
                          ks_base_log, pbs_level, pbs_base_log, grouping_factor,
                          message_modulus, carry_modulus, allocate_ms_array);

  scratch_cuda_expand_without_verification<uint64_t>(
      (cudaStream_t *)streams, gpu_indexes, gpu_count,
      reinterpret_cast<zk_expand_mem<uint64_t> **>(mem_ptr),
      num_lwes_per_compact_list, is_boolean_array, num_compact_lists, params,
      allocate_gpu_memory);
}

void cuda_expand_without_verification_64(
    void *const *streams, uint32_t const *gpu_indexes, uint32_t gpu_count,
    void *lwe_array_out, const void *lwe_compact_array_in, int8_t *mem_ptr,
    KS_TYPE ks_type, void *const *bsks, void *const *ksks,
    CudaModulusSwitchNoiseReductionKeyFFI const *ms_noise_reduction_key) {

  host_expand_without_verification<uint64_t>(
      (cudaStream_t *)(streams), gpu_indexes, gpu_count,
      static_cast<uint64_t *>(lwe_array_out),
      static_cast<const uint64_t *>(lwe_compact_array_in),
      reinterpret_cast<zk_expand_mem<uint64_t> *>(mem_ptr), ks_type, bsks,
      (uint64_t **)(ksks), ms_noise_reduction_key);
}

void cleanup_expand_without_verification_64(void *const *streams,
                                            uint32_t const *gpu_indexes,
                                            uint32_t gpu_count,
                                            int8_t **mem_ptr_void) {

  zk_expand_mem<uint64_t> *mem_ptr =
      reinterpret_cast<zk_expand_mem<uint64_t> *>(*mem_ptr_void);
  mem_ptr->release((cudaStream_t *)(streams), gpu_indexes, gpu_count);
}
