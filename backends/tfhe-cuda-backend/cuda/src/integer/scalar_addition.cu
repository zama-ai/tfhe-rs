#include "integer/scalar_addition.cuh"

void cuda_scalar_addition_integer_radix_ciphertext_64_inplace(
    CudaStreamsFFI streams, CudaRadixCiphertextFFI *lwe_array,
    void const *scalar_input, void const *h_scalar_input, uint32_t num_scalars,
    uint32_t message_modulus, uint32_t carry_modulus) {

  host_integer_radix_scalar_addition_inplace<uint64_t>(
      CudaStreams(streams), lwe_array,
      static_cast<const uint64_t *>(scalar_input),
      static_cast<const uint64_t *>(h_scalar_input), num_scalars,
      message_modulus, carry_modulus);
}
