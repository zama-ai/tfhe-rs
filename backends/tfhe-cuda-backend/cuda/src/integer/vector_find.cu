#include "integer/vector_find.cuh"
#include <vector>

// True iff p aliases some element of vec. Rejects in-place-on-output aliasing
// at the boundary against any element of a ciphertext-array input, not just
// the first.
static inline bool ffi_alias_in_vec(CudaRadixCiphertextFFI const *p,
                                    VecCudaRadixCiphertextFFI const *vec) {
  return p >= vec->ptr && p < vec->ptr + vec->num_ciphertexts;
}

uint64_t scratch_cuda_unchecked_match_value_64_async(
    CudaStreamsFFI streams, int8_t **mem_ptr,
    CudaLweBootstrapKeyParamsFFI bsk_params,
    CudaLweKeyswitchKeyParamsFFI ksk_params, uint32_t num_matches,
    uint32_t num_input_blocks, uint32_t num_output_packed_blocks,
    uint32_t max_output_is_zero, uint32_t message_modulus,
    uint32_t carry_modulus, bool allocate_gpu_memory,
    PBS_MS_REDUCTION_T noise_reduction_type) {
  int_radix_params params(bsk_params, ksk_params, message_modulus,
                          carry_modulus, noise_reduction_type);

  return scratch_cuda_unchecked_match_value<uint64_t>(
      CudaStreams(streams), (int_unchecked_match_buffer<uint64_t> **)mem_ptr,
      params, num_matches, num_input_blocks, num_output_packed_blocks,
      max_output_is_zero, allocate_gpu_memory);
}

void cuda_unchecked_match_value_64_async(
    CudaStreamsFFI streams, CudaRadixCiphertextFFI *lwe_array_out_result_ffi,
    CudaRadixCiphertextFFI *lwe_array_out_boolean_ffi,
    CudaRadixCiphertextFFI const *lwe_array_in_ct_ffi,
    const uint64_t *h_match_inputs, const uint64_t *h_match_outputs,
    int8_t *mem, void *const *bsks, void *const *ksks) {
  CudaRadixCiphertext lwe_array_out_result_local(*lwe_array_out_result_ffi);
  CudaRadixCiphertext *lwe_array_out_result = &lwe_array_out_result_local;
  CudaRadixCiphertext lwe_array_out_boolean_local(*lwe_array_out_boolean_ffi);
  CudaRadixCiphertext *lwe_array_out_boolean = &lwe_array_out_boolean_local;
  const CudaRadixCiphertext lwe_array_in_ct_local(*lwe_array_in_ct_ffi);
  const CudaRadixCiphertext *lwe_array_in_ct = &lwe_array_in_ct_local;

  PANIC_IF_FALSE(lwe_array_out_result_ffi != lwe_array_in_ct_ffi,
                 "Output result and input pointers must be different for "
                 "out-of-place operations");
  PANIC_IF_FALSE(lwe_array_out_boolean_ffi != lwe_array_in_ct_ffi,
                 "Output boolean and input pointers must be different for "
                 "out-of-place operations");
  PANIC_IF_FALSE(lwe_array_out_result_ffi != lwe_array_out_boolean_ffi,
                 "Result and boolean output pointers must be different for "
                 "out-of-place operations");

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
    CudaStreamsFFI streams, int8_t **mem_ptr,
    CudaLweBootstrapKeyParamsFFI bsk_params,
    CudaLweKeyswitchKeyParamsFFI ksk_params, uint32_t num_matches,
    uint32_t num_input_blocks, uint32_t num_match_packed_blocks,
    uint32_t num_final_blocks, uint32_t max_output_is_zero,
    uint32_t message_modulus, uint32_t carry_modulus, bool allocate_gpu_memory,
    PBS_MS_REDUCTION_T noise_reduction_type) {
  int_radix_params params(bsk_params, ksk_params, message_modulus,
                          carry_modulus, noise_reduction_type);

  return scratch_cuda_unchecked_match_value_or<uint64_t>(
      CudaStreams(streams),
      (int_unchecked_match_value_or_buffer<uint64_t> **)mem_ptr, params,
      num_matches, num_input_blocks, num_match_packed_blocks, num_final_blocks,
      max_output_is_zero, allocate_gpu_memory);
}

void cuda_unchecked_match_value_or_64_async(
    CudaStreamsFFI streams, CudaRadixCiphertextFFI *lwe_array_out_ffi,
    CudaRadixCiphertextFFI const *lwe_array_in_ct_ffi,
    const uint64_t *h_match_inputs, const uint64_t *h_match_outputs,
    const uint64_t *h_or_value, int8_t *mem, void *const *bsks,
    void *const *ksks) {
  CudaRadixCiphertext lwe_array_out_local(*lwe_array_out_ffi);
  CudaRadixCiphertext *lwe_array_out = &lwe_array_out_local;
  const CudaRadixCiphertext lwe_array_in_ct_local(*lwe_array_in_ct_ffi);
  const CudaRadixCiphertext *lwe_array_in_ct = &lwe_array_in_ct_local;

  PANIC_IF_FALSE(lwe_array_out_ffi != lwe_array_in_ct_ffi,
                 "Output and input pointers must be different for out-of-place "
                 "operations");

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
    CudaStreamsFFI streams, int8_t **mem_ptr,
    CudaLweBootstrapKeyParamsFFI bsk_params,
    CudaLweKeyswitchKeyParamsFFI ksk_params, uint32_t num_inputs,
    uint32_t num_blocks, uint32_t message_modulus, uint32_t carry_modulus,
    bool allocate_gpu_memory, PBS_MS_REDUCTION_T noise_reduction_type) {
  int_radix_params params(bsk_params, ksk_params, message_modulus,
                          carry_modulus, noise_reduction_type);

  return scratch_cuda_unchecked_contains<uint64_t>(
      CudaStreams(streams), (int_unchecked_contains_buffer<uint64_t> **)mem_ptr,
      params, num_inputs, num_blocks, allocate_gpu_memory);
}

void cuda_unchecked_contains_64_async(
    CudaStreamsFFI streams, CudaRadixCiphertextFFI *output_ffi,
    VecCudaRadixCiphertextFFI const *inputs_ffi,
    CudaRadixCiphertextFFI const *value_ffi, uint32_t num_blocks, int8_t *mem,
    void *const *bsks, void *const *ksks) {
  CudaRadixCiphertext output_local(*output_ffi);
  CudaRadixCiphertext *output = &output_local;
  std::vector<CudaRadixCiphertext> inputs_storage;
  inputs_storage.reserve(inputs_ffi->num_ciphertexts);
  for (uint32_t i = 0; i < inputs_ffi->num_ciphertexts; i++) {
    inputs_storage.emplace_back(inputs_ffi->ptr[i]);
  }
  const CudaRadixCiphertext *inputs = inputs_storage.data();
  const CudaRadixCiphertext value_local(*value_ffi);
  const CudaRadixCiphertext *value = &value_local;

  PANIC_IF_FALSE(!ffi_alias_in_vec(output_ffi, inputs_ffi),
                 "Output must not alias any element of the inputs array");
  PANIC_IF_FALSE(output_ffi != value_ffi,
                 "Output and value pointers must be different for "
                 "out-of-place operations");

  host_unchecked_contains<uint64_t>(
      CudaStreams(streams), output, inputs, value, inputs_ffi->num_ciphertexts,
      num_blocks, (int_unchecked_contains_buffer<uint64_t> *)mem, bsks,
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
    CudaStreamsFFI streams, int8_t **mem_ptr,
    CudaLweBootstrapKeyParamsFFI bsk_params,
    CudaLweKeyswitchKeyParamsFFI ksk_params, uint32_t num_inputs,
    uint32_t num_blocks, uint32_t message_modulus, uint32_t carry_modulus,
    bool allocate_gpu_memory, PBS_MS_REDUCTION_T noise_reduction_type) {
  int_radix_params params(bsk_params, ksk_params, message_modulus,
                          carry_modulus, noise_reduction_type);

  return scratch_cuda_unchecked_contains_clear<uint64_t>(
      CudaStreams(streams),
      (int_unchecked_contains_clear_buffer<uint64_t> **)mem_ptr, params,
      num_inputs, num_blocks, allocate_gpu_memory);
}

void cuda_unchecked_contains_clear_64_async(
    CudaStreamsFFI streams, CudaRadixCiphertextFFI *output_ffi,
    VecCudaRadixCiphertextFFI const *inputs_ffi, const uint64_t *h_clear_val,
    uint32_t num_blocks, int8_t *mem, void *const *bsks, void *const *ksks) {
  CudaRadixCiphertext output_local(*output_ffi);
  CudaRadixCiphertext *output = &output_local;
  std::vector<CudaRadixCiphertext> inputs_storage;
  inputs_storage.reserve(inputs_ffi->num_ciphertexts);
  for (uint32_t i = 0; i < inputs_ffi->num_ciphertexts; i++) {
    inputs_storage.emplace_back(inputs_ffi->ptr[i]);
  }
  const CudaRadixCiphertext *inputs = inputs_storage.data();

  PANIC_IF_FALSE(!ffi_alias_in_vec(output_ffi, inputs_ffi),
                 "Output must not alias any element of the inputs array");

  host_unchecked_contains_clear<uint64_t>(
      CudaStreams(streams), output, inputs, h_clear_val,
      inputs_ffi->num_ciphertexts, num_blocks,
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
    CudaStreamsFFI streams, int8_t **mem_ptr,
    CudaLweBootstrapKeyParamsFFI bsk_params,
    CudaLweKeyswitchKeyParamsFFI ksk_params, uint32_t num_clears,
    uint32_t num_blocks, uint32_t message_modulus, uint32_t carry_modulus,
    bool allocate_gpu_memory, PBS_MS_REDUCTION_T noise_reduction_type) {
  int_radix_params params(bsk_params, ksk_params, message_modulus,
                          carry_modulus, noise_reduction_type);

  return scratch_cuda_unchecked_is_in_clears<uint64_t>(
      CudaStreams(streams),
      (int_unchecked_is_in_clears_buffer<uint64_t> **)mem_ptr, params,
      num_clears, num_blocks, allocate_gpu_memory);
}

void cuda_unchecked_is_in_clears_64_async(
    CudaStreamsFFI streams, CudaRadixCiphertextFFI *output_ffi,
    CudaRadixCiphertextFFI const *input_ffi, const uint64_t *h_cleartexts,
    uint32_t num_clears, uint32_t num_blocks, int8_t *mem, void *const *bsks,
    void *const *ksks) {
  CudaRadixCiphertext output_local(*output_ffi);
  CudaRadixCiphertext *output = &output_local;
  const CudaRadixCiphertext input_local(*input_ffi);
  const CudaRadixCiphertext *input = &input_local;

  PANIC_IF_FALSE(output_ffi != input_ffi,
                 "Output and input pointers must be different "
                 "for out-of-place operations");

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
    CudaStreamsFFI streams, int8_t **mem_ptr,
    CudaLweBootstrapKeyParamsFFI bsk_params,
    CudaLweKeyswitchKeyParamsFFI ksk_params, uint32_t num_clears,
    uint32_t num_blocks, uint32_t num_blocks_index, uint32_t message_modulus,
    uint32_t carry_modulus, bool allocate_gpu_memory,
    PBS_MS_REDUCTION_T noise_reduction_type) {
  int_radix_params params(bsk_params, ksk_params, message_modulus,
                          carry_modulus, noise_reduction_type);

  return scratch_cuda_unchecked_index_in_clears<uint64_t>(
      CudaStreams(streams),
      (int_unchecked_index_in_clears_buffer<uint64_t> **)mem_ptr, params,
      num_clears, num_blocks, num_blocks_index, allocate_gpu_memory);
}

void cuda_unchecked_index_in_clears_64_async(
    CudaStreamsFFI streams, CudaRadixCiphertextFFI *index_ct_ffi,
    CudaRadixCiphertextFFI *match_ct_ffi,
    CudaRadixCiphertextFFI const *input_ffi, const uint64_t *h_cleartexts,
    uint32_t num_clears, uint32_t num_blocks, uint32_t num_blocks_index,
    int8_t *mem, void *const *bsks, void *const *ksks) {
  CudaRadixCiphertext index_ct_local(*index_ct_ffi);
  CudaRadixCiphertext *index_ct = &index_ct_local;
  CudaRadixCiphertext match_ct_local(*match_ct_ffi);
  CudaRadixCiphertext *match_ct = &match_ct_local;
  const CudaRadixCiphertext input_local(*input_ffi);
  const CudaRadixCiphertext *input = &input_local;

  PANIC_IF_FALSE(index_ct_ffi != input_ffi,
                 "Output and input pointers must be "
                 "different for out-of-place operations");
  PANIC_IF_FALSE(match_ct_ffi != input_ffi,
                 "Output and input pointers must be "
                 "different for out-of-place operations");
  PANIC_IF_FALSE(index_ct_ffi != match_ct_ffi,
                 "Index and match output pointers must be different for "
                 "out-of-place operations");

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
    CudaStreamsFFI streams, int8_t **mem_ptr,
    CudaLweBootstrapKeyParamsFFI bsk_params,
    CudaLweKeyswitchKeyParamsFFI ksk_params, uint32_t num_unique,
    uint32_t num_blocks, uint32_t num_blocks_index, uint32_t message_modulus,
    uint32_t carry_modulus, bool allocate_gpu_memory,
    PBS_MS_REDUCTION_T noise_reduction_type) {
  int_radix_params params(bsk_params, ksk_params, message_modulus,
                          carry_modulus, noise_reduction_type);

  return scratch_cuda_unchecked_first_index_in_clears<uint64_t>(
      CudaStreams(streams),
      (int_unchecked_first_index_in_clears_buffer<uint64_t> **)mem_ptr, params,
      num_unique, num_blocks, num_blocks_index, allocate_gpu_memory);
}

void cuda_unchecked_first_index_in_clears_64_async(
    CudaStreamsFFI streams, CudaRadixCiphertextFFI *index_ct_ffi,
    CudaRadixCiphertextFFI *match_ct_ffi,
    CudaRadixCiphertextFFI const *input_ffi, const uint64_t *h_unique_values,
    const uint64_t *h_unique_indices, uint32_t num_unique, uint32_t num_blocks,
    uint32_t num_blocks_index, int8_t *mem, void *const *bsks,
    void *const *ksks) {
  CudaRadixCiphertext index_ct_local(*index_ct_ffi);
  CudaRadixCiphertext *index_ct = &index_ct_local;
  CudaRadixCiphertext match_ct_local(*match_ct_ffi);
  CudaRadixCiphertext *match_ct = &match_ct_local;
  const CudaRadixCiphertext input_local(*input_ffi);
  const CudaRadixCiphertext *input = &input_local;

  PANIC_IF_FALSE(index_ct_ffi != input_ffi,
                 "Output and input pointers must be "
                 "different for out-of-place operations");
  PANIC_IF_FALSE(match_ct_ffi != input_ffi,
                 "Output and input pointers must be "
                 "different for out-of-place operations");
  PANIC_IF_FALSE(index_ct_ffi != match_ct_ffi,
                 "Index and match output pointers must be different for "
                 "out-of-place operations");

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
    CudaStreamsFFI streams, int8_t **mem_ptr,
    CudaLweBootstrapKeyParamsFFI bsk_params,
    CudaLweKeyswitchKeyParamsFFI ksk_params, uint32_t num_inputs,
    uint32_t num_blocks, uint32_t num_blocks_index, uint32_t message_modulus,
    uint32_t carry_modulus, bool allocate_gpu_memory,
    PBS_MS_REDUCTION_T noise_reduction_type) {
  int_radix_params params(bsk_params, ksk_params, message_modulus,
                          carry_modulus, noise_reduction_type);

  return scratch_cuda_unchecked_first_index_of_clear<uint64_t>(
      CudaStreams(streams),
      (int_unchecked_first_index_of_clear_buffer<uint64_t> **)mem_ptr, params,
      num_inputs, num_blocks, num_blocks_index, allocate_gpu_memory);
}

void cuda_unchecked_first_index_of_clear_64_async(
    CudaStreamsFFI streams, CudaRadixCiphertextFFI *index_ct_ffi,
    CudaRadixCiphertextFFI *match_ct_ffi,
    VecCudaRadixCiphertextFFI const *inputs_ffi, const uint64_t *h_clear_val,
    uint32_t num_blocks, uint32_t num_blocks_index, int8_t *mem,
    void *const *bsks, void *const *ksks) {
  CudaRadixCiphertext index_ct_local(*index_ct_ffi);
  CudaRadixCiphertext *index_ct = &index_ct_local;
  CudaRadixCiphertext match_ct_local(*match_ct_ffi);
  CudaRadixCiphertext *match_ct = &match_ct_local;
  std::vector<CudaRadixCiphertext> inputs_storage;
  inputs_storage.reserve(inputs_ffi->num_ciphertexts);
  for (uint32_t i = 0; i < inputs_ffi->num_ciphertexts; i++) {
    inputs_storage.emplace_back(inputs_ffi->ptr[i]);
  }
  const CudaRadixCiphertext *inputs = inputs_storage.data();

  PANIC_IF_FALSE(!ffi_alias_in_vec(index_ct_ffi, inputs_ffi),
                 "index_ct must not alias any element of the inputs array");
  PANIC_IF_FALSE(!ffi_alias_in_vec(match_ct_ffi, inputs_ffi),
                 "match_ct must not alias any element of the inputs array");
  PANIC_IF_FALSE(index_ct_ffi != match_ct_ffi,
                 "Index and match output pointers must be different for "
                 "out-of-place operations");

  host_unchecked_first_index_of_clear<uint64_t>(
      CudaStreams(streams), index_ct, match_ct, inputs, h_clear_val,
      inputs_ffi->num_ciphertexts, num_blocks, num_blocks_index,
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
    CudaStreamsFFI streams, int8_t **mem_ptr,
    CudaLweBootstrapKeyParamsFFI bsk_params,
    CudaLweKeyswitchKeyParamsFFI ksk_params, uint32_t num_inputs,
    uint32_t num_blocks, uint32_t num_blocks_index, uint32_t message_modulus,
    uint32_t carry_modulus, bool allocate_gpu_memory,
    PBS_MS_REDUCTION_T noise_reduction_type) {
  int_radix_params params(bsk_params, ksk_params, message_modulus,
                          carry_modulus, noise_reduction_type);

  return scratch_cuda_unchecked_first_index_of<uint64_t>(
      CudaStreams(streams),
      (int_unchecked_first_index_of_buffer<uint64_t> **)mem_ptr, params,
      num_inputs, num_blocks, num_blocks_index, allocate_gpu_memory);
}

void cuda_unchecked_first_index_of_64_async(
    CudaStreamsFFI streams, CudaRadixCiphertextFFI *index_ct_ffi,
    CudaRadixCiphertextFFI *match_ct_ffi,
    VecCudaRadixCiphertextFFI const *inputs_ffi,
    CudaRadixCiphertextFFI const *value_ffi, uint32_t num_blocks,
    uint32_t num_blocks_index, int8_t *mem, void *const *bsks,
    void *const *ksks) {
  CudaRadixCiphertext index_ct_local(*index_ct_ffi);
  CudaRadixCiphertext *index_ct = &index_ct_local;
  CudaRadixCiphertext match_ct_local(*match_ct_ffi);
  CudaRadixCiphertext *match_ct = &match_ct_local;
  std::vector<CudaRadixCiphertext> inputs_storage;
  inputs_storage.reserve(inputs_ffi->num_ciphertexts);
  for (uint32_t i = 0; i < inputs_ffi->num_ciphertexts; i++) {
    inputs_storage.emplace_back(inputs_ffi->ptr[i]);
  }
  const CudaRadixCiphertext *inputs = inputs_storage.data();
  const CudaRadixCiphertext value_local(*value_ffi);
  const CudaRadixCiphertext *value = &value_local;

  PANIC_IF_FALSE(!ffi_alias_in_vec(index_ct_ffi, inputs_ffi),
                 "index_ct must not alias any element of the inputs array");
  PANIC_IF_FALSE(!ffi_alias_in_vec(match_ct_ffi, inputs_ffi),
                 "match_ct must not alias any element of the inputs array");
  PANIC_IF_FALSE(index_ct_ffi != match_ct_ffi,
                 "Index and match output pointers must be different for "
                 "out-of-place operations");

  host_unchecked_first_index_of<uint64_t>(
      CudaStreams(streams), index_ct, match_ct, inputs, value,
      inputs_ffi->num_ciphertexts, num_blocks, num_blocks_index,
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
    CudaStreamsFFI streams, int8_t **mem_ptr,
    CudaLweBootstrapKeyParamsFFI bsk_params,
    CudaLweKeyswitchKeyParamsFFI ksk_params, uint32_t num_inputs,
    uint32_t num_blocks, uint32_t num_blocks_index, uint32_t message_modulus,
    uint32_t carry_modulus, bool allocate_gpu_memory,
    PBS_MS_REDUCTION_T noise_reduction_type) {
  int_radix_params params(bsk_params, ksk_params, message_modulus,
                          carry_modulus, noise_reduction_type);

  return scratch_cuda_unchecked_index_of<uint64_t>(
      CudaStreams(streams), (int_unchecked_index_of_buffer<uint64_t> **)mem_ptr,
      params, num_inputs, num_blocks, num_blocks_index, allocate_gpu_memory);
}

void cuda_unchecked_index_of_64_async(
    CudaStreamsFFI streams, CudaRadixCiphertextFFI *index_ct_ffi,
    CudaRadixCiphertextFFI *match_ct_ffi,
    VecCudaRadixCiphertextFFI const *inputs_ffi,
    CudaRadixCiphertextFFI const *value_ffi, uint32_t num_blocks,
    uint32_t num_blocks_index, int8_t *mem, void *const *bsks,
    void *const *ksks) {
  CudaRadixCiphertext index_ct_local(*index_ct_ffi);
  CudaRadixCiphertext *index_ct = &index_ct_local;
  CudaRadixCiphertext match_ct_local(*match_ct_ffi);
  CudaRadixCiphertext *match_ct = &match_ct_local;
  std::vector<CudaRadixCiphertext> inputs_storage;
  inputs_storage.reserve(inputs_ffi->num_ciphertexts);
  for (uint32_t i = 0; i < inputs_ffi->num_ciphertexts; i++) {
    inputs_storage.emplace_back(inputs_ffi->ptr[i]);
  }
  const CudaRadixCiphertext *inputs = inputs_storage.data();
  const CudaRadixCiphertext value_local(*value_ffi);
  const CudaRadixCiphertext *value = &value_local;

  PANIC_IF_FALSE(!ffi_alias_in_vec(index_ct_ffi, inputs_ffi),
                 "index_ct must not alias any element of the inputs array");
  PANIC_IF_FALSE(!ffi_alias_in_vec(match_ct_ffi, inputs_ffi),
                 "match_ct must not alias any element of the inputs array");
  PANIC_IF_FALSE(index_ct_ffi != match_ct_ffi,
                 "Index and match output pointers must be different for "
                 "out-of-place operations");

  host_unchecked_index_of<uint64_t>(
      CudaStreams(streams), index_ct, match_ct, inputs, value,
      inputs_ffi->num_ciphertexts, num_blocks, num_blocks_index,
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
    CudaStreamsFFI streams, int8_t **mem_ptr,
    CudaLweBootstrapKeyParamsFFI bsk_params,
    CudaLweKeyswitchKeyParamsFFI ksk_params, uint32_t num_inputs,
    uint32_t num_blocks, uint32_t num_blocks_index, uint32_t message_modulus,
    uint32_t carry_modulus, bool allocate_gpu_memory,
    PBS_MS_REDUCTION_T noise_reduction_type) {
  int_radix_params params(bsk_params, ksk_params, message_modulus,
                          carry_modulus, noise_reduction_type);

  return scratch_cuda_unchecked_index_of_clear<uint64_t>(
      CudaStreams(streams),
      (int_unchecked_index_of_clear_buffer<uint64_t> **)mem_ptr, params,
      num_inputs, num_blocks, num_blocks_index, allocate_gpu_memory);
}

void cuda_unchecked_index_of_clear_64_async(
    CudaStreamsFFI streams, CudaRadixCiphertextFFI *index_ct_ffi,
    CudaRadixCiphertextFFI *match_ct_ffi,
    VecCudaRadixCiphertextFFI const *inputs_ffi, const uint64_t *h_clear_val,
    bool is_scalar_obviously_bigger, uint32_t num_blocks,
    uint32_t num_blocks_index, int8_t *mem, void *const *bsks,
    void *const *ksks) {
  CudaRadixCiphertext index_ct_local(*index_ct_ffi);
  CudaRadixCiphertext *index_ct = &index_ct_local;
  CudaRadixCiphertext match_ct_local(*match_ct_ffi);
  CudaRadixCiphertext *match_ct = &match_ct_local;
  std::vector<CudaRadixCiphertext> inputs_storage;
  inputs_storage.reserve(inputs_ffi->num_ciphertexts);
  for (uint32_t i = 0; i < inputs_ffi->num_ciphertexts; i++) {
    inputs_storage.emplace_back(inputs_ffi->ptr[i]);
  }
  const CudaRadixCiphertext *inputs = inputs_storage.data();

  PANIC_IF_FALSE(!ffi_alias_in_vec(index_ct_ffi, inputs_ffi),
                 "index_ct must not alias any element of the inputs array");
  PANIC_IF_FALSE(!ffi_alias_in_vec(match_ct_ffi, inputs_ffi),
                 "match_ct must not alias any element of the inputs array");
  PANIC_IF_FALSE(index_ct_ffi != match_ct_ffi,
                 "Index and match output pointers must be different for "
                 "out-of-place operations");

  host_unchecked_index_of_clear<uint64_t>(
      CudaStreams(streams), index_ct, match_ct, inputs, h_clear_val,
      is_scalar_obviously_bigger, inputs_ffi->num_ciphertexts, num_blocks,
      num_blocks_index, (int_unchecked_index_of_clear_buffer<uint64_t> *)mem,
      bsks, (uint64_t *const *)ksks);
}

void cleanup_cuda_unchecked_index_of_clear_64(CudaStreamsFFI streams,
                                              int8_t **mem_ptr_void) {
  int_unchecked_index_of_clear_buffer<uint64_t> *mem_ptr =
      (int_unchecked_index_of_clear_buffer<uint64_t> *)(*mem_ptr_void);

  mem_ptr->release(CudaStreams(streams));

  delete mem_ptr;
  *mem_ptr_void = nullptr;
}
