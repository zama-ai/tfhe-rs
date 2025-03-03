#include "integer/scalar_addition.cuh"

void cuda_scalar_addition_integer_radix_ciphertext_64_inplace(
    void *const *streams, uint32_t const *gpu_indexes, uint32_t gpu_count,
    CudaRadixCiphertextFFI *lwe_array, void const *scalar_input,
    void const *h_scalar_input, uint32_t num_scalars, uint32_t message_modulus,
    uint32_t carry_modulus) {

  host_integer_radix_scalar_addition_inplace<uint64_t>(
      (cudaStream_t *)(streams), gpu_indexes, gpu_count, lwe_array,
      static_cast<const uint64_t *>(scalar_input),
      static_cast<const uint64_t *>(h_scalar_input), num_scalars,
      message_modulus, carry_modulus);
}
