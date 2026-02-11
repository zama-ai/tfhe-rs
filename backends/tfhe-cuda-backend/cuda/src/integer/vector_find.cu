#include "integer/vector_find.cuh"

uint64_t scratch_cuda_unchecked_match_value_64_async(
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

void cuda_unchecked_match_value_64_async(
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

uint64_t scratch_cuda_unchecked_match_value_or_64_async(
    CudaStreamsFFI streams, int8_t **mem_ptr, uint32_t glwe_dimension,
    uint32_t polynomial_size, uint32_t big_lwe_dimension,
    uint32_t small_lwe_dimension, uint32_t ks_level, uint32_t ks_base_log,
    uint32_t pbs_level, uint32_t pbs_base_log, uint32_t grouping_factor,
    uint32_t num_matches, uint32_t num_input_blocks,
    uint32_t num_match_packed_blocks, uint32_t num_final_blocks,
    uint32_t max_output_is_zero, uint32_t message_modulus,
    uint32_t carry_modulus, PBS_TYPE pbs_type, bool allocate_gpu_memory,
    PBS_MS_REDUCTION_T noise_reduction_type) {

  int_radix_params params(pbs_type, glwe_dimension, polynomial_size,
                          big_lwe_dimension, small_lwe_dimension, ks_level,
                          ks_base_log, pbs_level, pbs_base_log, grouping_factor,
                          message_modulus, carry_modulus, noise_reduction_type);

  return scratch_cuda_unchecked_match_value_or<uint64_t>(
      CudaStreams(streams),
      (int_unchecked_match_value_or_buffer<uint64_t> **)mem_ptr, params,
      num_matches, num_input_blocks, num_match_packed_blocks, num_final_blocks,
      max_output_is_zero, allocate_gpu_memory);
}

void cuda_unchecked_match_value_or_64_async(
    CudaStreamsFFI streams, CudaRadixCiphertextFFI *lwe_array_out,
    CudaRadixCiphertextFFI const *lwe_array_in_ct,
    const uint64_t *h_match_inputs, const uint64_t *h_match_outputs,
    const uint64_t *h_or_value, int8_t *mem, void *const *bsks,
    void *const *ksks) {

  host_unchecked_match_value_or<uint64_t>(
      CudaStreams(streams), lwe_array_out, lwe_array_in_ct, h_match_inputs,
      h_match_outputs, h_or_value,
      (int_unchecked_match_value_or_buffer<uint64_t> *)mem, bsks,
      (uint64_t *const *)ksks);
}

void cleanup_cuda_unchecked_match_value_or_64(CudaStreamsFFI streams,
                                              int8_t **mem_ptr_void) {
  int_unchecked_match_value_or_buffer<uint64_t> *mem_ptr =
      (int_unchecked_match_value_or_buffer<uint64_t> *)(*mem_ptr_void);

  mem_ptr->release(CudaStreams(streams));

  delete mem_ptr;
  *mem_ptr_void = nullptr;
}

uint64_t scratch_cuda_unchecked_contains_64_async(
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

  return scratch_cuda_unchecked_contains<uint64_t>(
      CudaStreams(streams), (int_unchecked_contains_buffer<uint64_t> **)mem_ptr,
      params, num_inputs, num_blocks, allocate_gpu_memory);
}

void cuda_unchecked_contains_64_async(CudaStreamsFFI streams,
                                      CudaRadixCiphertextFFI *output,
                                      CudaRadixCiphertextFFI const *inputs,
                                      CudaRadixCiphertextFFI const *value,
                                      uint32_t num_inputs, uint32_t num_blocks,
                                      int8_t *mem, void *const *bsks,
                                      void *const *ksks) {

  host_unchecked_contains<uint64_t>(
      CudaStreams(streams), output, inputs, value, num_inputs, num_blocks,
      (int_unchecked_contains_buffer<uint64_t> *)mem, bsks,
      (uint64_t *const *)ksks);
}

void cleanup_cuda_unchecked_contains_64(CudaStreamsFFI streams,
                                        int8_t **mem_ptr_void) {
  int_unchecked_contains_buffer<uint64_t> *mem_ptr =
      (int_unchecked_contains_buffer<uint64_t> *)(*mem_ptr_void);

  mem_ptr->release(CudaStreams(streams));

  delete mem_ptr;
  *mem_ptr_void = nullptr;
}

uint64_t scratch_cuda_unchecked_contains_clear_64_async(
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

  return scratch_cuda_unchecked_contains_clear<uint64_t>(
      CudaStreams(streams),
      (int_unchecked_contains_clear_buffer<uint64_t> **)mem_ptr, params,
      num_inputs, num_blocks, allocate_gpu_memory);
}

void cuda_unchecked_contains_clear_64_async(
    CudaStreamsFFI streams, CudaRadixCiphertextFFI *output,
    CudaRadixCiphertextFFI const *inputs, const uint64_t *h_clear_val,
    uint32_t num_inputs, uint32_t num_blocks, int8_t *mem, void *const *bsks,
    void *const *ksks) {

  host_unchecked_contains_clear<uint64_t>(
      CudaStreams(streams), output, inputs, h_clear_val, num_inputs, num_blocks,
      (int_unchecked_contains_clear_buffer<uint64_t> *)mem, bsks,
      (uint64_t *const *)ksks);
}

void cleanup_cuda_unchecked_contains_clear_64(CudaStreamsFFI streams,
                                              int8_t **mem_ptr_void) {
  int_unchecked_contains_clear_buffer<uint64_t> *mem_ptr =
      (int_unchecked_contains_clear_buffer<uint64_t> *)(*mem_ptr_void);

  mem_ptr->release(CudaStreams(streams));

  delete mem_ptr;
  *mem_ptr_void = nullptr;
}

uint64_t scratch_cuda_unchecked_is_in_clears_64_async(
    CudaStreamsFFI streams, int8_t **mem_ptr, uint32_t glwe_dimension,
    uint32_t polynomial_size, uint32_t big_lwe_dimension,
    uint32_t small_lwe_dimension, uint32_t ks_level, uint32_t ks_base_log,
    uint32_t pbs_level, uint32_t pbs_base_log, uint32_t grouping_factor,
    uint32_t num_clears, uint32_t num_blocks, uint32_t message_modulus,
    uint32_t carry_modulus, PBS_TYPE pbs_type, bool allocate_gpu_memory,
    PBS_MS_REDUCTION_T noise_reduction_type) {

  int_radix_params params(pbs_type, glwe_dimension, polynomial_size,
                          big_lwe_dimension, small_lwe_dimension, ks_level,
                          ks_base_log, pbs_level, pbs_base_log, grouping_factor,
                          message_modulus, carry_modulus, noise_reduction_type);

  return scratch_cuda_unchecked_is_in_clears<uint64_t>(
      CudaStreams(streams),
      (int_unchecked_is_in_clears_buffer<uint64_t> **)mem_ptr, params,
      num_clears, num_blocks, allocate_gpu_memory);
}

void cuda_unchecked_is_in_clears_64_async(
    CudaStreamsFFI streams, CudaRadixCiphertextFFI *output,
    CudaRadixCiphertextFFI const *input, const uint64_t *h_cleartexts,
    uint32_t num_clears, uint32_t num_blocks, int8_t *mem, void *const *bsks,
    void *const *ksks) {

  host_unchecked_is_in_clears<uint64_t>(
      CudaStreams(streams), output, input, h_cleartexts, num_clears, num_blocks,
      (int_unchecked_is_in_clears_buffer<uint64_t> *)mem, bsks,
      (uint64_t *const *)ksks);
}

void cleanup_cuda_unchecked_is_in_clears_64(CudaStreamsFFI streams,
                                            int8_t **mem_ptr_void) {
  int_unchecked_is_in_clears_buffer<uint64_t> *mem_ptr =
      (int_unchecked_is_in_clears_buffer<uint64_t> *)(*mem_ptr_void);

  mem_ptr->release(CudaStreams(streams));

  delete mem_ptr;
  *mem_ptr_void = nullptr;
}

uint64_t scratch_cuda_unchecked_index_in_clears_64_async(
    CudaStreamsFFI streams, int8_t **mem_ptr, uint32_t glwe_dimension,
    uint32_t polynomial_size, uint32_t big_lwe_dimension,
    uint32_t small_lwe_dimension, uint32_t ks_level, uint32_t ks_base_log,
    uint32_t pbs_level, uint32_t pbs_base_log, uint32_t grouping_factor,
    uint32_t num_clears, uint32_t num_blocks, uint32_t num_blocks_index,
    uint32_t message_modulus, uint32_t carry_modulus, PBS_TYPE pbs_type,
    bool allocate_gpu_memory, PBS_MS_REDUCTION_T noise_reduction_type) {

  int_radix_params params(pbs_type, glwe_dimension, polynomial_size,
                          big_lwe_dimension, small_lwe_dimension, ks_level,
                          ks_base_log, pbs_level, pbs_base_log, grouping_factor,
                          message_modulus, carry_modulus, noise_reduction_type);

  return scratch_cuda_unchecked_index_in_clears<uint64_t>(
      CudaStreams(streams),
      (int_unchecked_index_in_clears_buffer<uint64_t> **)mem_ptr, params,
      num_clears, num_blocks, num_blocks_index, allocate_gpu_memory);
}

void cuda_unchecked_index_in_clears_64_async(
    CudaStreamsFFI streams, CudaRadixCiphertextFFI *index_ct,
    CudaRadixCiphertextFFI *match_ct, CudaRadixCiphertextFFI const *input,
    const uint64_t *h_cleartexts, uint32_t num_clears, uint32_t num_blocks,
    uint32_t num_blocks_index, int8_t *mem, void *const *bsks,
    void *const *ksks) {

  host_unchecked_index_in_clears<uint64_t>(
      CudaStreams(streams), index_ct, match_ct, input, h_cleartexts, num_clears,
      num_blocks, num_blocks_index,
      (int_unchecked_index_in_clears_buffer<uint64_t> *)mem, bsks,
      (uint64_t *const *)ksks);
}

void cleanup_cuda_unchecked_index_in_clears_64(CudaStreamsFFI streams,
                                               int8_t **mem_ptr_void) {
  int_unchecked_index_in_clears_buffer<uint64_t> *mem_ptr =
      (int_unchecked_index_in_clears_buffer<uint64_t> *)(*mem_ptr_void);

  mem_ptr->release(CudaStreams(streams));

  delete mem_ptr;
  *mem_ptr_void = nullptr;
}

uint64_t scratch_cuda_unchecked_first_index_in_clears_64_async(
    CudaStreamsFFI streams, int8_t **mem_ptr, uint32_t glwe_dimension,
    uint32_t polynomial_size, uint32_t big_lwe_dimension,
    uint32_t small_lwe_dimension, uint32_t ks_level, uint32_t ks_base_log,
    uint32_t pbs_level, uint32_t pbs_base_log, uint32_t grouping_factor,
    uint32_t num_unique, uint32_t num_blocks, uint32_t num_blocks_index,
    uint32_t message_modulus, uint32_t carry_modulus, PBS_TYPE pbs_type,
    bool allocate_gpu_memory, PBS_MS_REDUCTION_T noise_reduction_type) {

  int_radix_params params(pbs_type, glwe_dimension, polynomial_size,
                          big_lwe_dimension, small_lwe_dimension, ks_level,
                          ks_base_log, pbs_level, pbs_base_log, grouping_factor,
                          message_modulus, carry_modulus, noise_reduction_type);

  return scratch_cuda_unchecked_first_index_in_clears<uint64_t>(
      CudaStreams(streams),
      (int_unchecked_first_index_in_clears_buffer<uint64_t> **)mem_ptr, params,
      num_unique, num_blocks, num_blocks_index, allocate_gpu_memory);
}

void cuda_unchecked_first_index_in_clears_64_async(
    CudaStreamsFFI streams, CudaRadixCiphertextFFI *index_ct,
    CudaRadixCiphertextFFI *match_ct, CudaRadixCiphertextFFI const *input,
    const uint64_t *h_unique_values, const uint64_t *h_unique_indices,
    uint32_t num_unique, uint32_t num_blocks, uint32_t num_blocks_index,
    int8_t *mem, void *const *bsks, void *const *ksks) {

  host_unchecked_first_index_in_clears<uint64_t>(
      CudaStreams(streams), index_ct, match_ct, input, h_unique_values,
      h_unique_indices, num_unique, num_blocks, num_blocks_index,
      (int_unchecked_first_index_in_clears_buffer<uint64_t> *)mem, bsks,
      (uint64_t *const *)ksks);
}

void cleanup_cuda_unchecked_first_index_in_clears_64(CudaStreamsFFI streams,
                                                     int8_t **mem_ptr_void) {
  int_unchecked_first_index_in_clears_buffer<uint64_t> *mem_ptr =
      (int_unchecked_first_index_in_clears_buffer<uint64_t> *)(*mem_ptr_void);

  mem_ptr->release(CudaStreams(streams));

  delete mem_ptr;
  *mem_ptr_void = nullptr;
}

uint64_t scratch_cuda_unchecked_first_index_of_clear_64_async(
    CudaStreamsFFI streams, int8_t **mem_ptr, uint32_t glwe_dimension,
    uint32_t polynomial_size, uint32_t big_lwe_dimension,
    uint32_t small_lwe_dimension, uint32_t ks_level, uint32_t ks_base_log,
    uint32_t pbs_level, uint32_t pbs_base_log, uint32_t grouping_factor,
    uint32_t num_inputs, uint32_t num_blocks, uint32_t num_blocks_index,
    uint32_t message_modulus, uint32_t carry_modulus, PBS_TYPE pbs_type,
    bool allocate_gpu_memory, PBS_MS_REDUCTION_T noise_reduction_type) {

  int_radix_params params(pbs_type, glwe_dimension, polynomial_size,
                          big_lwe_dimension, small_lwe_dimension, ks_level,
                          ks_base_log, pbs_level, pbs_base_log, grouping_factor,
                          message_modulus, carry_modulus, noise_reduction_type);

  return scratch_cuda_unchecked_first_index_of_clear<uint64_t>(
      CudaStreams(streams),
      (int_unchecked_first_index_of_clear_buffer<uint64_t> **)mem_ptr, params,
      num_inputs, num_blocks, num_blocks_index, allocate_gpu_memory);
}

void cuda_unchecked_first_index_of_clear_64_async(
    CudaStreamsFFI streams, CudaRadixCiphertextFFI *index_ct,
    CudaRadixCiphertextFFI *match_ct, CudaRadixCiphertextFFI const *inputs,
    const uint64_t *h_clear_val, uint32_t num_inputs, uint32_t num_blocks,
    uint32_t num_blocks_index, int8_t *mem, void *const *bsks,
    void *const *ksks) {

  host_unchecked_first_index_of_clear<uint64_t>(
      CudaStreams(streams), index_ct, match_ct, inputs, h_clear_val, num_inputs,
      num_blocks, num_blocks_index,
      (int_unchecked_first_index_of_clear_buffer<uint64_t> *)mem, bsks,
      (uint64_t *const *)ksks);
}

void cleanup_cuda_unchecked_first_index_of_clear_64(CudaStreamsFFI streams,
                                                    int8_t **mem_ptr_void) {
  int_unchecked_first_index_of_clear_buffer<uint64_t> *mem_ptr =
      (int_unchecked_first_index_of_clear_buffer<uint64_t> *)(*mem_ptr_void);

  mem_ptr->release(CudaStreams(streams));

  delete mem_ptr;
  *mem_ptr_void = nullptr;
}

uint64_t scratch_cuda_unchecked_first_index_of_64_async(
    CudaStreamsFFI streams, int8_t **mem_ptr, uint32_t glwe_dimension,
    uint32_t polynomial_size, uint32_t big_lwe_dimension,
    uint32_t small_lwe_dimension, uint32_t ks_level, uint32_t ks_base_log,
    uint32_t pbs_level, uint32_t pbs_base_log, uint32_t grouping_factor,
    uint32_t num_inputs, uint32_t num_blocks, uint32_t num_blocks_index,
    uint32_t message_modulus, uint32_t carry_modulus, PBS_TYPE pbs_type,
    bool allocate_gpu_memory, PBS_MS_REDUCTION_T noise_reduction_type) {

  int_radix_params params(pbs_type, glwe_dimension, polynomial_size,
                          big_lwe_dimension, small_lwe_dimension, ks_level,
                          ks_base_log, pbs_level, pbs_base_log, grouping_factor,
                          message_modulus, carry_modulus, noise_reduction_type);

  return scratch_cuda_unchecked_first_index_of<uint64_t>(
      CudaStreams(streams),
      (int_unchecked_first_index_of_buffer<uint64_t> **)mem_ptr, params,
      num_inputs, num_blocks, num_blocks_index, allocate_gpu_memory);
}

void cuda_unchecked_first_index_of_64_async(
    CudaStreamsFFI streams, CudaRadixCiphertextFFI *index_ct,
    CudaRadixCiphertextFFI *match_ct, CudaRadixCiphertextFFI const *inputs,
    CudaRadixCiphertextFFI const *value, uint32_t num_inputs,
    uint32_t num_blocks, uint32_t num_blocks_index, int8_t *mem,
    void *const *bsks, void *const *ksks) {

  host_unchecked_first_index_of<uint64_t>(
      CudaStreams(streams), index_ct, match_ct, inputs, value, num_inputs,
      num_blocks, num_blocks_index,
      (int_unchecked_first_index_of_buffer<uint64_t> *)mem, bsks,
      (uint64_t *const *)ksks);
}

void cleanup_cuda_unchecked_first_index_of_64(CudaStreamsFFI streams,
                                              int8_t **mem_ptr_void) {
  int_unchecked_first_index_of_buffer<uint64_t> *mem_ptr =
      (int_unchecked_first_index_of_buffer<uint64_t> *)(*mem_ptr_void);

  mem_ptr->release(CudaStreams(streams));

  delete mem_ptr;
  *mem_ptr_void = nullptr;
}

uint64_t scratch_cuda_unchecked_index_of_64_async(
    CudaStreamsFFI streams, int8_t **mem_ptr, uint32_t glwe_dimension,
    uint32_t polynomial_size, uint32_t big_lwe_dimension,
    uint32_t small_lwe_dimension, uint32_t ks_level, uint32_t ks_base_log,
    uint32_t pbs_level, uint32_t pbs_base_log, uint32_t grouping_factor,
    uint32_t num_inputs, uint32_t num_blocks, uint32_t num_blocks_index,
    uint32_t message_modulus, uint32_t carry_modulus, PBS_TYPE pbs_type,
    bool allocate_gpu_memory, PBS_MS_REDUCTION_T noise_reduction_type) {

  int_radix_params params(pbs_type, glwe_dimension, polynomial_size,
                          big_lwe_dimension, small_lwe_dimension, ks_level,
                          ks_base_log, pbs_level, pbs_base_log, grouping_factor,
                          message_modulus, carry_modulus, noise_reduction_type);

  return scratch_cuda_unchecked_index_of<uint64_t>(
      CudaStreams(streams), (int_unchecked_index_of_buffer<uint64_t> **)mem_ptr,
      params, num_inputs, num_blocks, num_blocks_index, allocate_gpu_memory);
}

void cuda_unchecked_index_of_64_async(CudaStreamsFFI streams,
                                      CudaRadixCiphertextFFI *index_ct,
                                      CudaRadixCiphertextFFI *match_ct,
                                      CudaRadixCiphertextFFI const *inputs,
                                      CudaRadixCiphertextFFI const *value,
                                      uint32_t num_inputs, uint32_t num_blocks,
                                      uint32_t num_blocks_index, int8_t *mem,
                                      void *const *bsks, void *const *ksks) {

  host_unchecked_index_of<uint64_t>(
      CudaStreams(streams), index_ct, match_ct, inputs, value, num_inputs,
      num_blocks, num_blocks_index,
      (int_unchecked_index_of_buffer<uint64_t> *)mem, bsks,
      (uint64_t *const *)ksks);
}

void cleanup_cuda_unchecked_index_of_64(CudaStreamsFFI streams,
                                        int8_t **mem_ptr_void) {
  int_unchecked_index_of_buffer<uint64_t> *mem_ptr =
      (int_unchecked_index_of_buffer<uint64_t> *)(*mem_ptr_void);

  mem_ptr->release(CudaStreams(streams));

  delete mem_ptr;
  *mem_ptr_void = nullptr;
}

uint64_t scratch_cuda_unchecked_index_of_clear_64_async(
    CudaStreamsFFI streams, int8_t **mem_ptr, uint32_t glwe_dimension,
    uint32_t polynomial_size, uint32_t big_lwe_dimension,
    uint32_t small_lwe_dimension, uint32_t ks_level, uint32_t ks_base_log,
    uint32_t pbs_level, uint32_t pbs_base_log, uint32_t grouping_factor,
    uint32_t num_inputs, uint32_t num_blocks, uint32_t num_blocks_index,
    uint32_t message_modulus, uint32_t carry_modulus, PBS_TYPE pbs_type,
    bool allocate_gpu_memory, PBS_MS_REDUCTION_T noise_reduction_type) {

  int_radix_params params(pbs_type, glwe_dimension, polynomial_size,
                          big_lwe_dimension, small_lwe_dimension, ks_level,
                          ks_base_log, pbs_level, pbs_base_log, grouping_factor,
                          message_modulus, carry_modulus, noise_reduction_type);

  return scratch_cuda_unchecked_index_of_clear<uint64_t>(
      CudaStreams(streams),
      (int_unchecked_index_of_clear_buffer<uint64_t> **)mem_ptr, params,
      num_inputs, num_blocks, num_blocks_index, allocate_gpu_memory);
}

void cuda_unchecked_index_of_clear_64_async(
    CudaStreamsFFI streams, CudaRadixCiphertextFFI *index_ct,
    CudaRadixCiphertextFFI *match_ct, CudaRadixCiphertextFFI const *inputs,
    const void *d_scalar_blocks, bool is_scalar_obviously_bigger,
    uint32_t num_inputs, uint32_t num_blocks, uint32_t num_scalar_blocks,
    uint32_t num_blocks_index, int8_t *mem, void *const *bsks,
    void *const *ksks) {

  host_unchecked_index_of_clear<uint64_t>(
      CudaStreams(streams), index_ct, match_ct, inputs,
      (const uint64_t *)d_scalar_blocks, is_scalar_obviously_bigger, num_inputs,
      num_blocks, num_scalar_blocks, num_blocks_index,
      (int_unchecked_index_of_clear_buffer<uint64_t> *)mem, bsks,
      (uint64_t *const *)ksks);
}

void cleanup_cuda_unchecked_index_of_clear_64(CudaStreamsFFI streams,
                                              int8_t **mem_ptr_void) {
  int_unchecked_index_of_clear_buffer<uint64_t> *mem_ptr =
      (int_unchecked_index_of_clear_buffer<uint64_t> *)(*mem_ptr_void);

  mem_ptr->release(CudaStreams(streams));

  delete mem_ptr;
  *mem_ptr_void = nullptr;
}
