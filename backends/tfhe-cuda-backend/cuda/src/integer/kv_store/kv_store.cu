#include "integer/kv_store/kv_store.cuh"

uint64_t scratch_cuda_kv_store_get_64_async(
    CudaStreamsFFI streams, int8_t **mem_ptr, uint32_t glwe_dimension,
    uint32_t polynomial_size, uint32_t big_lwe_dimension,
    uint32_t small_lwe_dimension, uint32_t ks_level, uint32_t ks_base_log,
    uint32_t pbs_level, uint32_t pbs_base_log, uint32_t grouping_factor,
    uint32_t num_entries, uint32_t num_key_blocks, uint32_t num_value_blocks,
    uint32_t message_modulus, uint32_t carry_modulus, PBS_TYPE pbs_type,
    bool allocate_gpu_memory, PBS_MS_REDUCTION_T noise_reduction_type) {

  int_radix_params params(pbs_type, glwe_dimension, polynomial_size,
                          big_lwe_dimension, small_lwe_dimension, ks_level,
                          ks_base_log, pbs_level, pbs_base_log, grouping_factor,
                          message_modulus, carry_modulus, noise_reduction_type);

  return scratch_cuda_kv_store_get<uint64_t>(
      CudaStreams(streams), (int_kv_store_get_buffer<uint64_t> **)mem_ptr,
      params, num_entries, num_key_blocks, num_value_blocks,
      allocate_gpu_memory);
}

// h_decomposed_clear_keys: clear keys pre-decomposed into radix blocks on the
// host, matching the per-block representation of the encrypted key so that
// equality comparisons can operate block-by-block.
void cuda_kv_store_get_64_async(
    CudaStreamsFFI streams, CudaRadixCiphertextFFI *lwe_array_out_result,
    CudaRadixCiphertextFFI *lwe_array_out_boolean,
    CudaRadixCiphertextFFI *lwe_array_out_selectors,
    CudaRadixCiphertextFFI const *lwe_array_in_encrypted_key,
    CudaRadixCiphertextFFI const *lwe_array_in_values,
    const uint64_t *h_decomposed_clear_keys, int8_t *mem, void *const *bsks,
    void *const *ksks) {
  PANIC_IF_FALSE(lwe_array_out_result != lwe_array_in_encrypted_key,
                 "Output result and encrypted key pointers must be different "
                 "for out-of-place operations");
  PANIC_IF_FALSE(lwe_array_out_boolean != lwe_array_in_encrypted_key,
                 "Output boolean and encrypted key pointers must be different "
                 "for out-of-place operations");
  PANIC_IF_FALSE(lwe_array_out_result != lwe_array_out_boolean,
                 "Result and boolean output pointers must be different for "
                 "out-of-place operations");

  host_kv_store_get<uint64_t>(
      CudaStreams(streams), lwe_array_out_result, lwe_array_out_boolean,
      lwe_array_out_selectors, lwe_array_in_encrypted_key, lwe_array_in_values,
      h_decomposed_clear_keys, (int_kv_store_get_buffer<uint64_t> *)mem, bsks,
      (uint64_t *const *)ksks);
}

void cleanup_cuda_kv_store_get_64(CudaStreamsFFI streams,
                                  int8_t **mem_ptr_void) {
  int_kv_store_get_buffer<uint64_t> *mem_ptr =
      (int_kv_store_get_buffer<uint64_t> *)(*mem_ptr_void);

  mem_ptr->release(CudaStreams(streams));

  delete mem_ptr;
  *mem_ptr_void = nullptr;
}

uint64_t scratch_cuda_kv_store_update_64_async(
    CudaStreamsFFI streams, int8_t **mem_ptr, uint32_t glwe_dimension,
    uint32_t polynomial_size, uint32_t big_lwe_dimension,
    uint32_t small_lwe_dimension, uint32_t ks_level, uint32_t ks_base_log,
    uint32_t pbs_level, uint32_t pbs_base_log, uint32_t grouping_factor,
    uint32_t num_entries, uint32_t num_key_blocks, uint32_t num_value_blocks,
    uint32_t message_modulus, uint32_t carry_modulus, PBS_TYPE pbs_type,
    bool allocate_gpu_memory, PBS_MS_REDUCTION_T noise_reduction_type) {

  PUSH_RANGE("scratch kv_store_update")

  int_radix_params params(pbs_type, glwe_dimension, polynomial_size,
                          big_lwe_dimension, small_lwe_dimension, ks_level,
                          ks_base_log, pbs_level, pbs_base_log, grouping_factor,
                          message_modulus, carry_modulus, noise_reduction_type);

  auto size = scratch_cuda_kv_store_update<uint64_t>(
      CudaStreams(streams), (int_kv_store_update_buffer<uint64_t> **)mem_ptr,
      params, num_entries, num_key_blocks, num_value_blocks,
      allocate_gpu_memory);

  POP_RANGE()
  return size;
}

void cuda_kv_store_update_64_async(
    CudaStreamsFFI streams, CudaRadixCiphertextFFI *lwe_check_out_block,
    CudaRadixCiphertextFFI *lwe_array_out_values,
    CudaRadixCiphertextFFI const *lwe_array_in_encrypted_key,
    CudaRadixCiphertextFFI const *lwe_array_in_values,
    CudaRadixCiphertextFFI const *lwe_in_new_value,
    const uint64_t *h_decomposed_clear_keys, int8_t *mem_ptr, void *const *bsks,
    void *const *ksks) {

  PUSH_RANGE("kv_store_update")

  PANIC_IF_FALSE(lwe_array_out_values != lwe_array_in_values,
                 "Output and input values pointers must be different for "
                 "out-of-place operations");
  PANIC_IF_FALSE(lwe_check_out_block != lwe_in_new_value,
                 "Output and new value pointers must be different for "
                 "out-of-place operations");

  host_kv_store_update<uint64_t>(
      CudaStreams(streams), lwe_check_out_block, lwe_array_out_values,
      lwe_array_in_encrypted_key, lwe_array_in_values, lwe_in_new_value,
      h_decomposed_clear_keys, (int_kv_store_update_buffer<uint64_t> *)mem_ptr,
      bsks, (uint64_t *const *)ksks);

  POP_RANGE()
}

void cleanup_cuda_kv_store_update_64(CudaStreamsFFI streams,
                                     int8_t **mem_ptr_void) {
  PUSH_RANGE("cleanup kv_store_update")

  int_kv_store_update_buffer<uint64_t> *mem_ptr =
      (int_kv_store_update_buffer<uint64_t> *)(*mem_ptr_void);

  mem_ptr->release(CudaStreams(streams));

  delete mem_ptr;
  *mem_ptr_void = nullptr;

  POP_RANGE()
}

uint64_t scratch_cuda_kv_store_map_64_async(
    CudaStreamsFFI streams, int8_t **mem_ptr, uint32_t glwe_dimension,
    uint32_t polynomial_size, uint32_t big_lwe_dimension,
    uint32_t small_lwe_dimension, uint32_t ks_level, uint32_t ks_base_log,
    uint32_t pbs_level, uint32_t pbs_base_log, uint32_t grouping_factor,
    uint32_t num_entries, uint32_t num_value_blocks, uint32_t message_modulus,
    uint32_t carry_modulus, PBS_TYPE pbs_type, bool allocate_gpu_memory,
    PBS_MS_REDUCTION_T noise_reduction_type) {

  PUSH_RANGE("scratch kv_store_map")

  int_radix_params params(pbs_type, glwe_dimension, polynomial_size,
                          big_lwe_dimension, small_lwe_dimension, ks_level,
                          ks_base_log, pbs_level, pbs_base_log, grouping_factor,
                          message_modulus, carry_modulus, noise_reduction_type);

  auto size = scratch_cuda_kv_store_map<uint64_t>(
      CudaStreams(streams), (int_kv_store_map_buffer<uint64_t> **)mem_ptr,
      params, num_entries, num_value_blocks, allocate_gpu_memory);

  POP_RANGE()
  return size;
}

void cuda_kv_store_map_64_async(
    CudaStreamsFFI streams, CudaRadixCiphertextFFI *lwe_check_out_block,
    CudaRadixCiphertextFFI *lwe_array_out_values,
    CudaRadixCiphertextFFI const *lwe_array_in_values,
    CudaRadixCiphertextFFI const *lwe_in_new_value,
    CudaRadixCiphertextFFI const *lwe_array_in_selectors, int8_t *mem_ptr,
    void *const *bsks, void *const *ksks) {

  PUSH_RANGE("kv_store_map")

  PANIC_IF_FALSE(lwe_array_out_values != lwe_array_in_values,
                 "Output and input values pointers must be different for "
                 "out-of-place operations");

  PANIC_IF_FALSE(lwe_check_out_block != lwe_in_new_value,
                 "Output and new value pointers must be different for "
                 "out-of-place operations");

  PANIC_IF_FALSE(lwe_check_out_block != lwe_array_in_selectors,
                 "Check output and selectors pointers must be different for "
                 "out-of-place operations");

  host_kv_store_map<uint64_t>(CudaStreams(streams), lwe_check_out_block,
                              lwe_array_out_values, lwe_array_in_values,
                              lwe_in_new_value, lwe_array_in_selectors,
                              (int_kv_store_map_buffer<uint64_t> *)mem_ptr,
                              bsks, (uint64_t *const *)ksks);

  POP_RANGE()
}

void cleanup_cuda_kv_store_map_64(CudaStreamsFFI streams,
                                  int8_t **mem_ptr_void) {
  PUSH_RANGE("cleanup kv_store_map")

  int_kv_store_map_buffer<uint64_t> *mem_ptr =
      (int_kv_store_map_buffer<uint64_t> *)(*mem_ptr_void);

  mem_ptr->release(CudaStreams(streams));

  delete mem_ptr;
  *mem_ptr_void = nullptr;

  POP_RANGE()
}
