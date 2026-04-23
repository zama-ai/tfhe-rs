#include "integer/shuffle.cuh"

uint64_t scratch_cuda_integer_bitonic_sort_64_async(
    CudaStreamsFFI streams, int8_t **mem_ptr, uint32_t glwe_dimension,
    uint32_t polynomial_size, uint32_t big_lwe_dimension,
    uint32_t small_lwe_dimension, uint32_t ks_level, uint32_t ks_base_log,
    uint32_t pbs_level, uint32_t pbs_base_log, uint32_t grouping_factor,
    uint32_t num_radix_blocks, uint32_t num_values, uint32_t message_modulus,
    uint32_t carry_modulus, PBS_TYPE pbs_type, bool is_signed,
    bool allocate_gpu_memory, PBS_MS_REDUCTION_T noise_reduction_type) {

  PUSH_RANGE("scratch bitonic sort")
  int_radix_params params(pbs_type, glwe_dimension, polynomial_size,
                          big_lwe_dimension, small_lwe_dimension, ks_level,
                          ks_base_log, pbs_level, pbs_base_log, grouping_factor,
                          message_modulus, carry_modulus, noise_reduction_type);

  uint64_t ret = scratch_cuda_integer_bitonic_sort<uint64_t>(
      CudaStreams(streams), (int_bitonic_sort_buffer<uint64_t> **)mem_ptr,
      num_radix_blocks, num_values, params, is_signed, allocate_gpu_memory);
  POP_RANGE()
  return ret;
}

void cuda_integer_bitonic_sort_64_async(CudaStreamsFFI streams,
                                        CudaRadixCiphertextFFI **values,
                                        uint32_t num_values, int8_t *mem_ptr,
                                        void *const *bsks, void *const *ksks,
                                        int32_t direction) {

  PUSH_RANGE("bitonic sort")
  host_bitonic_sort<uint64_t>(CudaStreams(streams), values, num_values,
                              (int_bitonic_sort_buffer<uint64_t> *)mem_ptr,
                              bsks, (uint64_t **)(ksks), direction);
  POP_RANGE()
}

void cleanup_cuda_integer_bitonic_sort_64(CudaStreamsFFI streams,
                                          int8_t **mem_ptr_void) {

  PUSH_RANGE("cleanup bitonic sort")
  int_bitonic_sort_buffer<uint64_t> *mem_ptr =
      (int_bitonic_sort_buffer<uint64_t> *)(*mem_ptr_void);
  mem_ptr->release(CudaStreams(streams));
  delete mem_ptr;
  *mem_ptr_void = nullptr;
  POP_RANGE()
}
