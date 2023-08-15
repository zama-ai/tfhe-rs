#include "integer/scalar_addition.cuh"

void cuda_scalar_addition_integer_radix_ciphertext_64_inplace(
    cuda_stream_t *stream, void *lwe_array, void *scalar_input,
    uint32_t lwe_dimension, uint32_t lwe_ciphertext_count,
    uint32_t message_modulus, uint32_t carry_modulus) {

  host_integer_radix_scalar_addition_inplace(
      stream, static_cast<uint64_t *>(lwe_array),
      static_cast<uint64_t *>(scalar_input), lwe_dimension,
      lwe_ciphertext_count, message_modulus, carry_modulus);
}
