#include "integer/kv_store/kv_store.cuh"

uint64_t scratch_cuda_kv_store_get_64_async(
    CudaStreamsFFI streams, int8_t **mem_ptr,
    CudaLweBootstrapKeyParamsFFI bsk_params,
    CudaLweKeyswitchKeyParamsFFI ksk_params, uint32_t num_entries,
    uint32_t num_key_blocks, uint32_t num_value_blocks,
    uint32_t message_modulus, uint32_t carry_modulus, bool allocate_gpu_memory,
    PBS_MS_REDUCTION_T noise_reduction_type) {

  PUSH_RANGE("scratch kv_store_get")

  int_radix_params params(bsk_params, ksk_params, message_modulus,
                          carry_modulus, noise_reduction_type);

  auto size = scratch_cuda_kv_store_get<uint64_t>(
      CudaStreams(streams), (int_kv_store_get_buffer<uint64_t> **)mem_ptr,
      params, num_entries, num_key_blocks, num_value_blocks,
      allocate_gpu_memory);

  POP_RANGE()
  return size;
}

void cuda_kv_store_get_64_async(
    CudaStreamsFFI streams, CudaRadixCiphertextFFI *lwe_array_out_result_ffi,
    CudaRadixCiphertextFFI *lwe_array_out_boolean_ffi,
    CudaRadixCiphertextFFI *lwe_array_out_selectors_ffi,
    CudaRadixCiphertextFFI const *lwe_array_in_encrypted_key_ffi,
    CudaRadixCiphertextFFI const *lwe_array_in_values_ffi,
    const uint64_t *h_decomposed_clear_keys, int8_t *mem, void *const *bsks,
    void *const *ksks) {
  CudaRadixCiphertext lwe_array_out_result_local(*lwe_array_out_result_ffi);
  CudaRadixCiphertext *lwe_array_out_result = &lwe_array_out_result_local;
  CudaRadixCiphertext lwe_array_out_boolean_local(*lwe_array_out_boolean_ffi);
  CudaRadixCiphertext *lwe_array_out_boolean = &lwe_array_out_boolean_local;
  CudaRadixCiphertext lwe_array_out_selectors_local(
      *lwe_array_out_selectors_ffi);
  CudaRadixCiphertext *lwe_array_out_selectors = &lwe_array_out_selectors_local;
  const CudaRadixCiphertext lwe_array_in_encrypted_key_local(
      *lwe_array_in_encrypted_key_ffi);
  const CudaRadixCiphertext *lwe_array_in_encrypted_key =
      &lwe_array_in_encrypted_key_local;
  const CudaRadixCiphertext lwe_array_in_values_local(*lwe_array_in_values_ffi);
  const CudaRadixCiphertext *lwe_array_in_values = &lwe_array_in_values_local;

  PUSH_RANGE("kv_store_get")

  PANIC_IF_FALSE(lwe_array_out_result_ffi != lwe_array_in_encrypted_key_ffi,
                 "Output result and encrypted key pointers must be different "
                 "for out-of-place operations");
  PANIC_IF_FALSE(lwe_array_out_boolean_ffi != lwe_array_in_encrypted_key_ffi,
                 "Output boolean and encrypted key pointers must be different "
                 "for out-of-place operations");
  PANIC_IF_FALSE(lwe_array_out_result_ffi != lwe_array_out_boolean_ffi,
                 "Result and boolean output pointers must be different for "
                 "out-of-place operations");

  host_kv_store_get<uint64_t>(
      CudaStreams(streams), lwe_array_out_result, lwe_array_out_boolean,
      lwe_array_out_selectors, lwe_array_in_encrypted_key, lwe_array_in_values,
      h_decomposed_clear_keys, (int_kv_store_get_buffer<uint64_t> *)mem, bsks,
      (uint64_t *const *)ksks);

  POP_RANGE()
}

void cleanup_cuda_kv_store_get_64(CudaStreamsFFI streams,
                                  int8_t **mem_ptr_void) {
  PUSH_RANGE("cleanup kv_store_get")

  int_kv_store_get_buffer<uint64_t> *mem_ptr =
      (int_kv_store_get_buffer<uint64_t> *)(*mem_ptr_void);

  mem_ptr->release(CudaStreams(streams));

  delete mem_ptr;
  *mem_ptr_void = nullptr;

  POP_RANGE()
}

uint64_t scratch_cuda_kv_store_update_64_async(
    CudaStreamsFFI streams, int8_t **mem_ptr,
    CudaLweBootstrapKeyParamsFFI bsk_params,
    CudaLweKeyswitchKeyParamsFFI ksk_params, uint32_t num_entries,
    uint32_t num_key_blocks, uint32_t num_value_blocks,
    uint32_t message_modulus, uint32_t carry_modulus, bool allocate_gpu_memory,
    PBS_MS_REDUCTION_T noise_reduction_type) {

  PUSH_RANGE("scratch kv_store_update")

  int_radix_params params(bsk_params, ksk_params, message_modulus,
                          carry_modulus, noise_reduction_type);

  auto size = scratch_cuda_kv_store_update<uint64_t>(
      CudaStreams(streams), (int_kv_store_update_buffer<uint64_t> **)mem_ptr,
      params, num_entries, num_key_blocks, num_value_blocks,
      allocate_gpu_memory);

  POP_RANGE()
  return size;
}

void cuda_kv_store_update_64_async(
    CudaStreamsFFI streams, CudaRadixCiphertextFFI *lwe_check_out_block_ffi,
    CudaRadixCiphertextFFI *lwe_array_out_values_ffi,
    CudaRadixCiphertextFFI const *lwe_array_in_encrypted_key_ffi,
    CudaRadixCiphertextFFI const *lwe_array_in_values_ffi,
    CudaRadixCiphertextFFI const *lwe_in_new_value_ffi,
    const uint64_t *h_decomposed_clear_keys, int8_t *mem_ptr, void *const *bsks,
    void *const *ksks) {
  CudaRadixCiphertext lwe_check_out_block_local(*lwe_check_out_block_ffi);
  CudaRadixCiphertext *lwe_check_out_block = &lwe_check_out_block_local;
  CudaRadixCiphertext lwe_array_out_values_local(*lwe_array_out_values_ffi);
  CudaRadixCiphertext *lwe_array_out_values = &lwe_array_out_values_local;
  const CudaRadixCiphertext lwe_array_in_encrypted_key_local(
      *lwe_array_in_encrypted_key_ffi);
  const CudaRadixCiphertext *lwe_array_in_encrypted_key =
      &lwe_array_in_encrypted_key_local;
  const CudaRadixCiphertext lwe_array_in_values_local(*lwe_array_in_values_ffi);
  const CudaRadixCiphertext *lwe_array_in_values = &lwe_array_in_values_local;
  const CudaRadixCiphertext lwe_in_new_value_local(*lwe_in_new_value_ffi);
  const CudaRadixCiphertext *lwe_in_new_value = &lwe_in_new_value_local;

  PUSH_RANGE("kv_store_update")

  PANIC_IF_FALSE(lwe_array_out_values_ffi != lwe_array_in_values_ffi,
                 "Output and input values pointers must be different for "
                 "out-of-place operations");
  PANIC_IF_FALSE(lwe_check_out_block_ffi != lwe_in_new_value_ffi,
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
    CudaStreamsFFI streams, int8_t **mem_ptr,
    CudaLweBootstrapKeyParamsFFI bsk_params,
    CudaLweKeyswitchKeyParamsFFI ksk_params, uint32_t num_entries,
    uint32_t num_value_blocks, uint32_t message_modulus, uint32_t carry_modulus,
    bool allocate_gpu_memory, PBS_MS_REDUCTION_T noise_reduction_type) {

  PUSH_RANGE("scratch kv_store_map")

  int_radix_params params(bsk_params, ksk_params, message_modulus,
                          carry_modulus, noise_reduction_type);

  auto size = scratch_cuda_kv_store_map<uint64_t>(
      CudaStreams(streams), (int_kv_store_map_buffer<uint64_t> **)mem_ptr,
      params, num_entries, num_value_blocks, allocate_gpu_memory);

  POP_RANGE()
  return size;
}

void cuda_kv_store_map_64_async(
    CudaStreamsFFI streams, CudaRadixCiphertextFFI *lwe_check_out_block_ffi,
    CudaRadixCiphertextFFI *lwe_array_out_values_ffi,
    CudaRadixCiphertextFFI const *lwe_array_in_values_ffi,
    CudaRadixCiphertextFFI const *lwe_in_new_value_ffi,
    CudaRadixCiphertextFFI const *lwe_array_in_selectors_ffi, int8_t *mem_ptr,
    void *const *bsks, void *const *ksks) {
  CudaRadixCiphertext lwe_check_out_block_local(*lwe_check_out_block_ffi);
  CudaRadixCiphertext *lwe_check_out_block = &lwe_check_out_block_local;
  CudaRadixCiphertext lwe_array_out_values_local(*lwe_array_out_values_ffi);
  CudaRadixCiphertext *lwe_array_out_values = &lwe_array_out_values_local;
  const CudaRadixCiphertext lwe_array_in_values_local(*lwe_array_in_values_ffi);
  const CudaRadixCiphertext *lwe_array_in_values = &lwe_array_in_values_local;
  const CudaRadixCiphertext lwe_in_new_value_local(*lwe_in_new_value_ffi);
  const CudaRadixCiphertext *lwe_in_new_value = &lwe_in_new_value_local;
  const CudaRadixCiphertext lwe_array_in_selectors_local(
      *lwe_array_in_selectors_ffi);
  const CudaRadixCiphertext *lwe_array_in_selectors =
      &lwe_array_in_selectors_local;

  PUSH_RANGE("kv_store_map")

  PANIC_IF_FALSE(lwe_array_out_values_ffi != lwe_array_in_values_ffi,
                 "Output and input values pointers must be different for "
                 "out-of-place operations");

  PANIC_IF_FALSE(lwe_check_out_block_ffi != lwe_in_new_value_ffi,
                 "Output and new value pointers must be different for "
                 "out-of-place operations");

  PANIC_IF_FALSE(lwe_check_out_block_ffi != lwe_array_in_selectors_ffi,
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

uint64_t scratch_cuda_kv_store_contains_key_64_async(
    CudaStreamsFFI streams, int8_t **mem_ptr,
    CudaLweBootstrapKeyParamsFFI bsk_params,
    CudaLweKeyswitchKeyParamsFFI ksk_params, uint32_t num_entries,
    uint32_t num_key_blocks, uint32_t message_modulus, uint32_t carry_modulus,
    bool allocate_gpu_memory, PBS_MS_REDUCTION_T noise_reduction_type) {

  PUSH_RANGE("scratch kv_store_contains_key")

  int_radix_params params(bsk_params, ksk_params, message_modulus,
                          carry_modulus, noise_reduction_type);

  auto size = scratch_cuda_kv_store_contains_key<uint64_t>(
      CudaStreams(streams),
      (int_kv_store_contains_key_buffer<uint64_t> **)mem_ptr, params,
      num_entries, num_key_blocks, allocate_gpu_memory);

  POP_RANGE()
  return size;
}

void cuda_kv_store_contains_key_64_async(
    CudaStreamsFFI streams, CudaRadixCiphertextFFI *lwe_array_out_boolean_ffi,
    CudaRadixCiphertextFFI const *lwe_array_in_encrypted_key_ffi,
    const uint64_t *h_decomposed_clear_keys, int8_t *mem_ptr, void *const *bsks,
    void *const *ksks) {
  CudaRadixCiphertext lwe_array_out_boolean_local(*lwe_array_out_boolean_ffi);
  CudaRadixCiphertext *lwe_array_out_boolean = &lwe_array_out_boolean_local;
  const CudaRadixCiphertext lwe_array_in_encrypted_key_local(
      *lwe_array_in_encrypted_key_ffi);
  const CudaRadixCiphertext *lwe_array_in_encrypted_key =
      &lwe_array_in_encrypted_key_local;

  PUSH_RANGE("kv_store_contains_key")

  PANIC_IF_FALSE(lwe_array_out_boolean_ffi != lwe_array_in_encrypted_key_ffi,
                 "Output boolean and encrypted key pointers must be different "
                 "for out-of-place operations");

  host_kv_store_contains_key<uint64_t>(
      CudaStreams(streams), lwe_array_out_boolean, lwe_array_in_encrypted_key,
      h_decomposed_clear_keys,
      (int_kv_store_contains_key_buffer<uint64_t> *)mem_ptr, bsks,
      (uint64_t *const *)ksks);

  POP_RANGE()
}

void cleanup_cuda_kv_store_contains_key_64(CudaStreamsFFI streams,
                                           int8_t **mem_ptr_void) {
  PUSH_RANGE("cleanup kv_store_contains_key")

  int_kv_store_contains_key_buffer<uint64_t> *mem_ptr =
      (int_kv_store_contains_key_buffer<uint64_t> *)(*mem_ptr_void);

  mem_ptr->release(CudaStreams(streams));

  delete mem_ptr;
  *mem_ptr_void = nullptr;

  POP_RANGE()
}
