#include "integer/scalar_addition.cuh"

void cuda_scalar_addition_ciphertext_64_inplace(
    CudaStreamsFFI streams, CudaRadixCiphertextFFI *lwe_array,
    void const *scalar_input, void const *h_scalar_input, uint32_t num_scalars,
    uint32_t message_modulus, uint32_t carry_modulus) {

  auto cuda_streams = CudaStreams(streams);
  host_scalar_addition_inplace<uint64_t>(
      cuda_streams, lwe_array, static_cast<const uint64_t *>(scalar_input),
      static_cast<const uint64_t *>(h_scalar_input), num_scalars,
      message_modulus, carry_modulus);
  cuda_synchronize_stream(cuda_streams.stream(0), cuda_streams.gpu_index(0));
}
