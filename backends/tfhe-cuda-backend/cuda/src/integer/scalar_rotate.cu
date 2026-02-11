#include "scalar_rotate.cuh"

uint64_t scratch_cuda_scalar_rotate_64_inplace_async(
    CudaStreamsFFI streams, int8_t **mem_ptr, uint32_t glwe_dimension,
    uint32_t polynomial_size, uint32_t big_lwe_dimension,
    uint32_t small_lwe_dimension, uint32_t ks_level, uint32_t ks_base_log,
    uint32_t pbs_level, uint32_t pbs_base_log, uint32_t grouping_factor,
    uint32_t num_blocks, uint32_t message_modulus, uint32_t carry_modulus,
    PBS_TYPE pbs_type, SHIFT_OR_ROTATE_TYPE shift_type,
    bool allocate_gpu_memory, PBS_MS_REDUCTION_T noise_reduction_type) {

  int_radix_params params(pbs_type, glwe_dimension, polynomial_size,
                          big_lwe_dimension, small_lwe_dimension, ks_level,
                          ks_base_log, pbs_level, pbs_base_log, grouping_factor,
                          message_modulus, carry_modulus, noise_reduction_type);

  return scratch_cuda_scalar_rotate<uint64_t>(
      CudaStreams(streams),
      (int_logical_scalar_shift_buffer<uint64_t> **)mem_ptr, num_blocks, params,
      shift_type, allocate_gpu_memory);
}

void cuda_scalar_rotate_64_inplace_async(CudaStreamsFFI streams,
                                         CudaRadixCiphertextFFI *lwe_array,
                                         uint32_t n, int8_t *mem_ptr,
                                         void *const *bsks, void *const *ksks) {

  host_scalar_rotate_inplace<uint64_t>(
      CudaStreams(streams), lwe_array, n,
      (int_logical_scalar_shift_buffer<uint64_t> *)mem_ptr, bsks,
      (uint64_t **)(ksks));
}

void cleanup_cuda_scalar_rotate_64_inplace(CudaStreamsFFI streams,
                                           int8_t **mem_ptr_void) {

  int_logical_scalar_shift_buffer<uint64_t> *mem_ptr =
      (int_logical_scalar_shift_buffer<uint64_t> *)(*mem_ptr_void);

  mem_ptr->release(CudaStreams(streams));
  delete mem_ptr;
  *mem_ptr_void = nullptr;
}
