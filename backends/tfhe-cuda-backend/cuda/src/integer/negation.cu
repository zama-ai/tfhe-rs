#include "integer/negation.cuh"

void cuda_negate_integer_radix_ciphertext_64(
    void *const *streams, uint32_t const *gpu_indexes, uint32_t gpu_count,
    void *lwe_array_out, void const *lwe_array_in, uint32_t lwe_dimension,
    uint32_t lwe_ciphertext_count, uint32_t message_modulus,
    uint32_t carry_modulus) {

  host_integer_radix_negation<uint64_t>(
      (cudaStream_t *)(streams), gpu_indexes, gpu_count,
      static_cast<uint64_t *>(lwe_array_out),
      static_cast<const uint64_t *>(lwe_array_in), lwe_dimension,
      lwe_ciphertext_count, message_modulus, carry_modulus);
}
