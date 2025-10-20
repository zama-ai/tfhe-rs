#include "cast.cuh"

void extend_radix_with_trivial_zero_blocks_msb_64(
    CudaRadixCiphertextFFI *output, CudaRadixCiphertextFFI const *input,
    CudaStreamsFFI streams) {
  auto cuda_streams = CudaStreams(streams);
  host_extend_radix_with_trivial_zero_blocks_msb<uint64_t>(output, input,
                                                           cuda_streams);
  cuda_synchronize_stream(cuda_streams.stream(0), cuda_streams.gpu_index(0));
}

void trim_radix_blocks_lsb_64(CudaRadixCiphertextFFI *output,
                              CudaRadixCiphertextFFI const *input,
                              CudaStreamsFFI streams) {

  auto cuda_streams = CudaStreams(streams);
  host_trim_radix_blocks_lsb<uint64_t>(output, input, cuda_streams);
  cuda_synchronize_stream(cuda_streams.stream(0), cuda_streams.gpu_index(0));
}

uint64_t scratch_cuda_extend_radix_with_sign_msb_64(
    CudaStreamsFFI streams, int8_t **mem_ptr, uint32_t glwe_dimension,
    uint32_t polynomial_size, uint32_t lwe_dimension, uint32_t ks_level,
    uint32_t ks_base_log, uint32_t pbs_level, uint32_t pbs_base_log,
    uint32_t grouping_factor, uint32_t num_blocks,
    uint32_t num_additional_blocks, uint32_t message_modulus,
    uint32_t carry_modulus, PBS_TYPE pbs_type, bool allocate_gpu_memory,
    PBS_MS_REDUCTION_T noise_reduction_type) {

  int_radix_params params(pbs_type, glwe_dimension, polynomial_size,
                          glwe_dimension * polynomial_size, lwe_dimension,
                          ks_level, ks_base_log, pbs_level, pbs_base_log,
                          grouping_factor, message_modulus, carry_modulus,
                          noise_reduction_type);

  return scratch_extend_radix_with_sign_msb<uint64_t>(
      CudaStreams(streams),
      (int_extend_radix_with_sign_msb_buffer<uint64_t> **)mem_ptr, params,
      num_blocks, num_additional_blocks, allocate_gpu_memory);
}

void cuda_extend_radix_with_sign_msb_64(CudaStreamsFFI streams,
                                        CudaRadixCiphertextFFI *output,
                                        CudaRadixCiphertextFFI const *input,
                                        int8_t *mem_ptr,
                                        uint32_t num_additional_blocks,
                                        void *const *bsks, void *const *ksks) {
  PUSH_RANGE("cast")
  host_extend_radix_with_sign_msb<uint64_t>(
      CudaStreams(streams), output, input,
      (int_extend_radix_with_sign_msb_buffer<uint64_t> *)mem_ptr,
      num_additional_blocks, bsks, (uint64_t **)ksks);
  POP_RANGE()
}

void cleanup_cuda_extend_radix_with_sign_msb_64(CudaStreamsFFI streams,
                                                int8_t **mem_ptr_void) {
  PUSH_RANGE("clean cast")
  int_extend_radix_with_sign_msb_buffer<uint64_t> *mem_ptr =
      (int_extend_radix_with_sign_msb_buffer<uint64_t> *)(*mem_ptr_void);

  mem_ptr->release(CudaStreams(streams));
  POP_RANGE()
  delete mem_ptr;
  *mem_ptr_void = nullptr;
}
