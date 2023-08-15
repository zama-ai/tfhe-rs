#include "integer/negation.cuh"

void cuda_negate_integer_radix_ciphertext_64_inplace(
    cuda_stream_t *stream, void *lwe_array, uint32_t lwe_dimension,
    uint32_t lwe_ciphertext_count, uint32_t message_modulus,
    uint32_t carry_modulus) {

  host_integer_radix_negation(stream, static_cast<uint64_t *>(lwe_array),
                              static_cast<uint64_t *>(lwe_array), lwe_dimension,
                              lwe_ciphertext_count, message_modulus,
                              carry_modulus);
}
