#include "integer/shuffle.cuh"

uint64_t scratch_cuda_integer_bitonic_shuffle_64_async(
    CudaStreamsFFI streams, int8_t **mem_ptr,
    CudaLweBootstrapKeyParamsFFI bsk_params,
    CudaLweKeyswitchKeyParamsFFI ksk_params, uint32_t key_num_radix_blocks,
    uint32_t data_num_radix_blocks, uint32_t num_values,
    uint32_t message_modulus, uint32_t carry_modulus, bool allocate_gpu_memory,
    PBS_MS_REDUCTION_T noise_reduction_type) {

  PUSH_RANGE("scratch bitonic shuffle")
  int_radix_params params(bsk_params, ksk_params, message_modulus,
                          carry_modulus, noise_reduction_type);

  uint64_t ret = scratch_cuda_integer_bitonic_shuffle_async<uint64_t>(
      CudaStreams(streams), (int_bitonic_shuffle_buffer<uint64_t> **)mem_ptr,
      key_num_radix_blocks, data_num_radix_blocks, num_values, params,
      allocate_gpu_memory);
  POP_RANGE()
  return ret;
}

/**
 * @brief Performs a bitonic shuffle of encrypted key-value radix-ciphertexts
 * in-place, reordering keys and values according to a bitonic sorting network.
 *
 * @param keys       Array of num_values pointers to key radix-ciphertexts.
 * @param values     Array of num_values pointers to data radix-ciphertexts.
 * @param num_values Number of key-value pairs.
 * @param mem_ptr    Scratch buffer cast to
 * int_bitonic_shuffle_buffer<uint64_t>.
 */
void cuda_integer_bitonic_shuffle_64_async(CudaStreamsFFI streams,
                                           CudaRadixCiphertextFFI **keys,
                                           CudaRadixCiphertextFFI **values,
                                           uint32_t num_values, int8_t *mem_ptr,
                                           void *const *bsks,
                                           void *const *ksks) {

  PUSH_RANGE("bitonic shuffle")
  host_bitonic_shuffle<uint64_t>(
      CudaStreams(streams), keys, values, num_values,
      (int_bitonic_shuffle_buffer<uint64_t> *)mem_ptr, bsks, (uint64_t **)ksks);
  POP_RANGE()
}

void cleanup_cuda_integer_bitonic_shuffle_64(CudaStreamsFFI streams,
                                             int8_t **mem_ptr_void) {

  PUSH_RANGE("cleanup bitonic shuffle")
  int_bitonic_shuffle_buffer<uint64_t> *mem_ptr =
      (int_bitonic_shuffle_buffer<uint64_t> *)(*mem_ptr_void);
  mem_ptr->release(CudaStreams(streams));
  delete mem_ptr;
  *mem_ptr_void = nullptr;
  POP_RANGE()
}

uint64_t scratch_cuda_integer_oprf_bitonic_shuffle_64_async(
    CudaStreamsFFI streams, int8_t **mem_ptr,
    CudaLweBootstrapKeyParamsFFI bsk_params,
    CudaLweKeyswitchKeyParamsFFI ksk_params, uint32_t key_num_radix_blocks,
    uint32_t data_num_radix_blocks, uint32_t num_values,
    uint32_t message_modulus, uint32_t carry_modulus, bool allocate_gpu_memory,
    PBS_MS_REDUCTION_T noise_reduction_type, bool apply_rerand,
    CudaLweKeyswitchKeyParamsFFI rerand_ksk_params, RERAND_MODE rerand_mode) {

  PUSH_RANGE("scratch oprf bitonic shuffle")
  int_radix_params params(bsk_params, ksk_params, message_modulus,
                          carry_modulus, noise_reduction_type);

  int_radix_params rerand_params(
      PBS_TYPE::CLASSICAL, 0, 0, rerand_ksk_params.input_lwe_dimension,
      rerand_ksk_params.output_lwe_dimension, rerand_ksk_params.level_count,
      rerand_ksk_params.base_log, 0, 0, 0, message_modulus, carry_modulus,
      PBS_MS_REDUCTION_T::NO_REDUCTION);

  uint64_t ret = scratch_cuda_integer_oprf_bitonic_shuffle_async<uint64_t>(
      CudaStreams(streams),
      (int_oprf_bitonic_shuffle_buffer<uint64_t> **)mem_ptr,
      key_num_radix_blocks, data_num_radix_blocks, num_values, params,
      apply_rerand, rerand_params, rerand_mode, allocate_gpu_memory);
  POP_RANGE()
  return ret;
}

/**
 * @brief Performs a bitonic shuffle of encrypted radix-ciphertexts using
 * OPRF-generated random keys. Values are reordered in-place.
 *
 * @param values           Array of num_values pointers to data
 * radix-ciphertexts.
 * @param num_values       Number of values to shuffle.
 * @param seeded_lwe_input Seeded LWE ciphertext used as OPRF input.
 * @param mem_ptr          Scratch buffer cast to
 *                         int_oprf_bitonic_shuffle_buffer<uint64_t>.
 * @param oprf_bsks        Array of OPRF bootstrapping key pointers, one per
 * GPU.
 */
void cuda_integer_oprf_bitonic_shuffle_64_async(
    CudaStreamsFFI streams, CudaRadixCiphertextFFI **values,
    uint32_t num_values, const void *seeded_lwe_input, int8_t *mem_ptr,
    void *const *oprf_bsks, void *const *bsks, void *const *ksks,
    const void *lwe_flattened_encryptions_of_zero_compact_array_in,
    void *const *rerand_ksks) {

  PUSH_RANGE("oprf bitonic shuffle")
  host_oprf_bitonic_shuffle<uint64_t>(
      CudaStreams(streams), values, num_values,
      static_cast<const uint64_t *>(seeded_lwe_input),
      static_cast<const uint64_t *>(
          lwe_flattened_encryptions_of_zero_compact_array_in),
      reinterpret_cast<uint64_t *const *>(rerand_ksks),
      reinterpret_cast<int_oprf_bitonic_shuffle_buffer<uint64_t> *>(mem_ptr),
      oprf_bsks, bsks, reinterpret_cast<uint64_t *const *>(ksks));
  POP_RANGE()
}

void cleanup_cuda_integer_oprf_bitonic_shuffle_64(CudaStreamsFFI streams,
                                                  int8_t **mem_ptr_void) {

  PUSH_RANGE("cleanup oprf bitonic shuffle")
  int_oprf_bitonic_shuffle_buffer<uint64_t> *mem_ptr =
      (int_oprf_bitonic_shuffle_buffer<uint64_t> *)(*mem_ptr_void);
  mem_ptr->release(CudaStreams(streams));
  delete mem_ptr;
  *mem_ptr_void = nullptr;
  POP_RANGE()
}
