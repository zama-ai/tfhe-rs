#include "count_bits.cuh"

uint64_t scratch_cuda_integer_count_bits_64_async(
    CudaStreamsFFI streams, int8_t **mem_ptr,
    CudaLweBootstrapKeyParamsFFI bsk_params,
    CudaLweKeyswitchKeyParamsFFI ksk_params, uint32_t num_blocks,
    uint32_t counter_num_blocks, uint32_t message_modulus,
    uint32_t carry_modulus, BitValue bit_value, bool allocate_gpu_memory,
    PBS_MS_REDUCTION_T noise_reduction_type) {
  int_radix_params params(bsk_params, ksk_params, message_modulus,
                          carry_modulus, noise_reduction_type);

  return scratch_integer_count_bits<uint64_t>(
      CudaStreams(streams), params, (int_count_bits_buffer<uint64_t> **)mem_ptr,
      num_blocks, counter_num_blocks, bit_value, allocate_gpu_memory);
}

/**
 * @brief GPU entry point of count_ones and count_zeros, the bit value to count
 * is the one given to the scratch call.
 *
 * @param output_ct At least the counter_num_blocks given to the scratch call,
 * the blocks above the counter are set to zero
 * @param input_ct  Ciphertext to count, with clean carries
 * @param mem_ptr   Buffer from scratch_cuda_integer_count_bits_64_async
 */
void cuda_integer_count_bits_64_async(CudaStreamsFFI streams,
                                      CudaRadixCiphertextFFI *output_ct,
                                      CudaRadixCiphertextFFI const *input_ct,
                                      int8_t *mem_ptr, void *const *bsks,
                                      void *const *ksks) {
  GPU_ASSERT(output_ct != input_ct,
             "Output and input pointers must be different for out-of-place "
             "operations");

  host_integer_count_bits<uint64_t, uint64_t>(
      CudaStreams(streams), output_ct, input_ct,
      (int_count_bits_buffer<uint64_t> *)mem_ptr, bsks, (uint64_t **)ksks);
}

void cleanup_cuda_integer_count_bits_64(CudaStreamsFFI streams,
                                        int8_t **mem_ptr_void) {

  int_count_bits_buffer<uint64_t> *mem_ptr =
      (int_count_bits_buffer<uint64_t> *)(*mem_ptr_void);

  mem_ptr->release(CudaStreams(streams));

  delete mem_ptr;
  *mem_ptr_void = nullptr;
}
