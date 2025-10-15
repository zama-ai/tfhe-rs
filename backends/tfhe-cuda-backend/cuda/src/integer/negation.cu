#include "integer/negation.cuh"

void cuda_negate_ciphertext_64(CudaStreamsFFI streams,
                               CudaRadixCiphertextFFI *lwe_array_out,
                               CudaRadixCiphertextFFI const *lwe_array_in,
                               uint32_t message_modulus, uint32_t carry_modulus,
                               uint32_t num_radix_blocks) {

  auto cuda_streams = CudaStreams(streams);
  host_negation<uint64_t>(cuda_streams, lwe_array_out, lwe_array_in,
                          message_modulus, carry_modulus, num_radix_blocks);
  cuda_synchronize_stream(cuda_streams.stream(0), cuda_streams.gpu_index(0));
}
