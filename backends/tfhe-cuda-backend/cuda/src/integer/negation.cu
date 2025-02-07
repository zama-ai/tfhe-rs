#include "integer/negation.cuh"

void cuda_negate_integer_radix_ciphertext_64(
    void *const *streams, uint32_t const *gpu_indexes, uint32_t gpu_count,
    CudaRadixCiphertextFFI *lwe_array_out,
    CudaRadixCiphertextFFI const *lwe_array_in, uint32_t message_modulus,
    uint32_t carry_modulus, uint32_t num_radix_blocks) {

  host_integer_radix_negation<uint64_t>(
      (cudaStream_t *)(streams), gpu_indexes, gpu_count, lwe_array_out,
      lwe_array_in, message_modulus, carry_modulus, num_radix_blocks);
}
