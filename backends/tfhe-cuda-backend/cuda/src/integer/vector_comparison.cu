#include "integer/vector_comparison.cuh"

uint64_t scratch_cuda_unchecked_all_eq_slices_64_async(
    CudaStreamsFFI streams, int8_t **mem_ptr, uint32_t glwe_dimension,
    uint32_t polynomial_size, uint32_t big_lwe_dimension,
    uint32_t small_lwe_dimension, uint32_t ks_level, uint32_t ks_base_log,
    uint32_t pbs_level, uint32_t pbs_base_log, uint32_t grouping_factor,
    uint32_t num_inputs, uint32_t num_blocks, uint32_t message_modulus,
    uint32_t carry_modulus, PBS_TYPE pbs_type, bool allocate_gpu_memory,
    PBS_MS_REDUCTION_T noise_reduction_type) {

  int_radix_params params(pbs_type, glwe_dimension, polynomial_size,
                          big_lwe_dimension, small_lwe_dimension, ks_level,
                          ks_base_log, pbs_level, pbs_base_log, grouping_factor,
                          message_modulus, carry_modulus, noise_reduction_type);

  return scratch_cuda_unchecked_all_eq_slices<uint64_t>(
      CudaStreams(streams),
      (int_unchecked_all_eq_slices_buffer<uint64_t> **)mem_ptr, params,
      num_inputs, num_blocks, allocate_gpu_memory);
}

void cuda_unchecked_all_eq_slices_64_async(
    CudaStreamsFFI streams, CudaRadixCiphertextFFI *match_ct,
    CudaRadixCiphertextFFI const *lhs, CudaRadixCiphertextFFI const *rhs,
    uint32_t num_inputs, uint32_t num_blocks, int8_t *mem, void *const *bsks,
    void *const *ksks) {

  host_unchecked_all_eq_slices<uint64_t>(
      CudaStreams(streams), match_ct, lhs, rhs, num_inputs, num_blocks,
      (int_unchecked_all_eq_slices_buffer<uint64_t> *)mem, bsks,
      (uint64_t *const *)ksks);
}

void cleanup_cuda_unchecked_all_eq_slices_64(CudaStreamsFFI streams,
                                             int8_t **mem_ptr_void) {
  int_unchecked_all_eq_slices_buffer<uint64_t> *mem_ptr =
      (int_unchecked_all_eq_slices_buffer<uint64_t> *)(*mem_ptr_void);

  mem_ptr->release(CudaStreams(streams));

  delete mem_ptr;
  *mem_ptr_void = nullptr;
}

uint64_t scratch_cuda_unchecked_contains_sub_slice_64_async(
    CudaStreamsFFI streams, int8_t **mem_ptr, uint32_t glwe_dimension,
    uint32_t polynomial_size, uint32_t big_lwe_dimension,
    uint32_t small_lwe_dimension, uint32_t ks_level, uint32_t ks_base_log,
    uint32_t pbs_level, uint32_t pbs_base_log, uint32_t grouping_factor,
    uint32_t num_lhs, uint32_t num_rhs, uint32_t num_blocks,
    uint32_t message_modulus, uint32_t carry_modulus, PBS_TYPE pbs_type,
    bool allocate_gpu_memory, PBS_MS_REDUCTION_T noise_reduction_type) {

  int_radix_params params(pbs_type, glwe_dimension, polynomial_size,
                          big_lwe_dimension, small_lwe_dimension, ks_level,
                          ks_base_log, pbs_level, pbs_base_log, grouping_factor,
                          message_modulus, carry_modulus, noise_reduction_type);

  return scratch_cuda_unchecked_contains_sub_slice<uint64_t>(
      CudaStreams(streams),
      (int_unchecked_contains_sub_slice_buffer<uint64_t> **)mem_ptr, params,
      num_lhs, num_rhs, num_blocks, allocate_gpu_memory);
}

void cuda_unchecked_contains_sub_slice_64_async(
    CudaStreamsFFI streams, CudaRadixCiphertextFFI *match_ct,
    CudaRadixCiphertextFFI const *lhs, CudaRadixCiphertextFFI const *rhs,
    uint32_t num_rhs, uint32_t num_blocks, int8_t *mem, void *const *bsks,
    void *const *ksks) {

  host_unchecked_contains_sub_slice<uint64_t>(
      CudaStreams(streams), match_ct, lhs, rhs, num_rhs, num_blocks,
      (int_unchecked_contains_sub_slice_buffer<uint64_t> *)mem, bsks,
      (uint64_t *const *)ksks);
}

void cleanup_cuda_unchecked_contains_sub_slice_64(CudaStreamsFFI streams,
                                                  int8_t **mem_ptr_void) {
  int_unchecked_contains_sub_slice_buffer<uint64_t> *mem_ptr =
      (int_unchecked_contains_sub_slice_buffer<uint64_t> *)(*mem_ptr_void);

  mem_ptr->release(CudaStreams(streams));

  delete mem_ptr;
  *mem_ptr_void = nullptr;
}
