#include "integer/apply_keystream.cuh"

uint64_t scratch_cuda_apply_keystream_64_async(
    CudaStreamsFFI streams, int8_t **mem_ptr,
    CudaLweBootstrapKeyParamsFFI bsk_params,
    CudaLweKeyswitchKeyParamsFFI ksk_params,
    CudaKeystreamContributionFFI const *contributions,
    uint32_t num_contributions, uint32_t num_output_blocks,
    uint32_t message_modulus, uint32_t carry_modulus,
    bool allocate_gpu_memory) {
  int_radix_params params(bsk_params, ksk_params, message_modulus,
                          carry_modulus);

  return scratch_cuda_apply_keystream<uint64_t>(
      CudaStreams(streams), (int_apply_keystream_buffer<uint64_t> **)mem_ptr,
      params, contributions, num_contributions, num_output_blocks,
      allocate_gpu_memory);
}

/**
 * @brief XORs the keystream with the input bits held by the LUTs of the
 * scratch, one PBS per output block.
 *
 * @param output    One block per output block of the scratch, distinct from
 * keystream
 * @param keystream Blocks indexed by the contributions given to the scratch
 * @param mem_ptr   Scratch built for this input, its LUTs hold the input bits
 */
void cuda_apply_keystream_64_async(CudaStreamsFFI streams,
                                   CudaRadixCiphertextFFI *output,
                                   CudaRadixCiphertextFFI const *keystream,
                                   int8_t *mem_ptr, void *const *bsks,
                                   void *const *ksks) {
  PANIC_IF_FALSE(output != keystream,
                 "Output and input pointers must be different for out-of-place "
                 "operations");
  host_apply_keystream<uint64_t>(
      CudaStreams(streams), output, keystream,
      (int_apply_keystream_buffer<uint64_t> *)mem_ptr, bsks,
      (uint64_t **)(ksks));
}

void cleanup_cuda_apply_keystream_64(CudaStreamsFFI streams,
                                     int8_t **mem_ptr_void) {
  PUSH_RANGE("cleanup apply keystream")
  int_apply_keystream_buffer<uint64_t> *mem_ptr =
      (int_apply_keystream_buffer<uint64_t> *)(*mem_ptr_void);

  mem_ptr->release(CudaStreams(streams));
  delete mem_ptr;
  *mem_ptr_void = nullptr;
  POP_RANGE()
}
