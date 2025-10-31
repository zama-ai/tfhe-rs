#include "integer/vector_find.cuh"

uint64_t scratch_cuda_compute_equality_selectors_64(
    CudaStreamsFFI streams, int8_t **mem_ptr, uint32_t glwe_dimension,
    uint32_t polynomial_size, uint32_t big_lwe_dimension,
    uint32_t small_lwe_dimension, uint32_t ks_level, uint32_t ks_base_log,
    uint32_t pbs_level, uint32_t pbs_base_log, uint32_t grouping_factor,
    uint32_t num_possible_values, uint32_t num_blocks, uint32_t message_modulus,
    uint32_t carry_modulus, PBS_TYPE pbs_type, bool allocate_gpu_memory,
    PBS_MS_REDUCTION_T noise_reduction_type) {

  int_radix_params params(pbs_type, glwe_dimension, polynomial_size,
                          big_lwe_dimension, small_lwe_dimension, ks_level,
                          ks_base_log, pbs_level, pbs_base_log, grouping_factor,
                          message_modulus, carry_modulus, noise_reduction_type);

  return scratch_cuda_compute_equality_selectors<uint64_t>(
      CudaStreams(streams), (int_equality_selectors_buffer<uint64_t> **)mem_ptr,
      params, num_possible_values, num_blocks, allocate_gpu_memory);
}

void cuda_compute_equality_selectors_64(
    CudaStreamsFFI streams, CudaRadixCiphertextFFI *lwe_array_out_list,
    CudaRadixCiphertextFFI const *lwe_array_in, uint32_t num_blocks,
    const uint64_t *h_decomposed_cleartexts, int8_t *mem, void *const *bsks,
    void *const *ksks) {

  host_compute_equality_selectors<uint64_t>(
      CudaStreams(streams), lwe_array_out_list, lwe_array_in, num_blocks,
      h_decomposed_cleartexts, (int_equality_selectors_buffer<uint64_t> *)mem,
      bsks, (uint64_t *const *)ksks);
}

void cleanup_cuda_compute_equality_selectors_64(CudaStreamsFFI streams,
                                                int8_t **mem_ptr_void) {
  int_equality_selectors_buffer<uint64_t> *mem_ptr =
      (int_equality_selectors_buffer<uint64_t> *)(*mem_ptr_void);

  mem_ptr->release(CudaStreams(streams));

  delete mem_ptr;
  *mem_ptr_void = nullptr;
}

uint64_t scratch_cuda_create_possible_results_64(
    CudaStreamsFFI streams, int8_t **mem_ptr, uint32_t glwe_dimension,
    uint32_t polynomial_size, uint32_t big_lwe_dimension,
    uint32_t small_lwe_dimension, uint32_t ks_level, uint32_t ks_base_log,
    uint32_t pbs_level, uint32_t pbs_base_log, uint32_t grouping_factor,
    uint32_t num_possible_values, uint32_t num_blocks, uint32_t message_modulus,
    uint32_t carry_modulus, PBS_TYPE pbs_type, bool allocate_gpu_memory,
    PBS_MS_REDUCTION_T noise_reduction_type) {

  int_radix_params params(pbs_type, glwe_dimension, polynomial_size,
                          big_lwe_dimension, small_lwe_dimension, ks_level,
                          ks_base_log, pbs_level, pbs_base_log, grouping_factor,
                          message_modulus, carry_modulus, noise_reduction_type);

  return scratch_cuda_create_possible_results<uint64_t>(
      CudaStreams(streams), (int_possible_results_buffer<uint64_t> **)mem_ptr,
      params, num_blocks, num_possible_values, allocate_gpu_memory);
}

void cuda_create_possible_results_64(
    CudaStreamsFFI streams, CudaRadixCiphertextFFI *lwe_array_out_list,
    CudaRadixCiphertextFFI const *lwe_array_in_list,
    uint32_t num_possible_values, const uint64_t *h_decomposed_cleartexts,
    uint32_t num_blocks, int8_t *mem, void *const *bsks, void *const *ksks) {

  host_create_possible_results<uint64_t>(
      CudaStreams(streams), lwe_array_out_list, lwe_array_in_list,
      num_possible_values, h_decomposed_cleartexts, num_blocks,
      (int_possible_results_buffer<uint64_t> *)mem, bsks,
      (uint64_t *const *)ksks);
}

void cleanup_cuda_create_possible_results_64(CudaStreamsFFI streams,
                                             int8_t **mem_ptr_void) {
  int_possible_results_buffer<uint64_t> *mem_ptr =
      (int_possible_results_buffer<uint64_t> *)(*mem_ptr_void);

  mem_ptr->release(CudaStreams(streams));

  delete mem_ptr;
  *mem_ptr_void = nullptr;
}

uint64_t scratch_cuda_aggregate_one_hot_vector_64(
    CudaStreamsFFI streams, int8_t **mem_ptr, uint32_t glwe_dimension,
    uint32_t polynomial_size, uint32_t big_lwe_dimension,
    uint32_t small_lwe_dimension, uint32_t ks_level, uint32_t ks_base_log,
    uint32_t pbs_level, uint32_t pbs_base_log, uint32_t grouping_factor,
    uint32_t num_blocks, uint32_t num_matches, uint32_t message_modulus,
    uint32_t carry_modulus, PBS_TYPE pbs_type, bool allocate_gpu_memory,
    PBS_MS_REDUCTION_T noise_reduction_type) {

  int_radix_params params(pbs_type, glwe_dimension, polynomial_size,
                          big_lwe_dimension, small_lwe_dimension, ks_level,
                          ks_base_log, pbs_level, pbs_base_log, grouping_factor,
                          message_modulus, carry_modulus, noise_reduction_type);

  return scratch_cuda_aggregate_one_hot_vector<uint64_t>(
      CudaStreams(streams), (int_aggregate_one_hot_buffer<uint64_t> **)mem_ptr,
      params, num_blocks, num_matches, allocate_gpu_memory);
}

void cuda_aggregate_one_hot_vector_64(
    CudaStreamsFFI streams, CudaRadixCiphertextFFI *lwe_array_out,
    CudaRadixCiphertextFFI const *lwe_array_in_list,
    uint32_t num_input_ciphertexts, uint32_t num_blocks, int8_t *mem,
    void *const *bsks, void *const *ksks) {

  host_aggregate_one_hot_vector<uint64_t>(
      CudaStreams(streams), lwe_array_out, lwe_array_in_list,
      num_input_ciphertexts, num_blocks,
      (int_aggregate_one_hot_buffer<uint64_t> *)mem, bsks,
      (uint64_t *const *)ksks);
}

void cleanup_cuda_aggregate_one_hot_vector_64(CudaStreamsFFI streams,
                                              int8_t **mem_ptr_void) {
  int_aggregate_one_hot_buffer<uint64_t> *mem_ptr =
      (int_aggregate_one_hot_buffer<uint64_t> *)(*mem_ptr_void);

  mem_ptr->release(CudaStreams(streams));

  delete mem_ptr;
  *mem_ptr_void = nullptr;
}

uint64_t scratch_cuda_unchecked_match_value_64(
    CudaStreamsFFI streams, int8_t **mem_ptr, uint32_t glwe_dimension,
    uint32_t polynomial_size, uint32_t big_lwe_dimension,
    uint32_t small_lwe_dimension, uint32_t ks_level, uint32_t ks_base_log,
    uint32_t pbs_level, uint32_t pbs_base_log, uint32_t grouping_factor,
    uint32_t num_matches, uint32_t num_input_blocks,
    uint32_t num_output_packed_blocks, uint32_t max_output_is_zero,
    uint32_t message_modulus, uint32_t carry_modulus, PBS_TYPE pbs_type,
    bool allocate_gpu_memory, PBS_MS_REDUCTION_T noise_reduction_type) {

  int_radix_params params(pbs_type, glwe_dimension, polynomial_size,
                          big_lwe_dimension, small_lwe_dimension, ks_level,
                          ks_base_log, pbs_level, pbs_base_log, grouping_factor,
                          message_modulus, carry_modulus, noise_reduction_type);

  return scratch_cuda_unchecked_match_value<uint64_t>(
      CudaStreams(streams), (int_unchecked_match_buffer<uint64_t> **)mem_ptr,
      params, num_matches, num_input_blocks, num_output_packed_blocks,
      max_output_is_zero, allocate_gpu_memory);
}

void cuda_unchecked_match_value_64(
    CudaStreamsFFI streams, CudaRadixCiphertextFFI *lwe_array_out_result,
    CudaRadixCiphertextFFI *lwe_array_out_boolean,
    CudaRadixCiphertextFFI const *lwe_array_in_ct,
    const uint64_t *h_match_inputs, const uint64_t *h_match_outputs,
    int8_t *mem, void *const *bsks, void *const *ksks) {

  host_unchecked_match_value<uint64_t>(
      CudaStreams(streams), lwe_array_out_result, lwe_array_out_boolean,
      lwe_array_in_ct, h_match_inputs, h_match_outputs,
      (int_unchecked_match_buffer<uint64_t> *)mem, bsks,
      (uint64_t *const *)ksks);
}

void cleanup_cuda_unchecked_match_value_64(CudaStreamsFFI streams,
                                           int8_t **mem_ptr_void) {
  int_unchecked_match_buffer<uint64_t> *mem_ptr =
      (int_unchecked_match_buffer<uint64_t> *)(*mem_ptr_void);

  mem_ptr->release(CudaStreams(streams));

  delete mem_ptr;
  *mem_ptr_void = nullptr;
}
