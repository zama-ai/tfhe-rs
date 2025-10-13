#include "integer/negation.cuh"

void cuda_negate_ciphertext_64(CudaStreamsFFI streams,
                               CudaRadixCiphertextFFI *lwe_array_out,
                               CudaRadixCiphertextFFI const *lwe_array_in,
                               uint32_t message_modulus, uint32_t carry_modulus,
                               uint32_t num_radix_blocks) {

  host_negation<uint64_t>(CudaStreams(streams), lwe_array_out, lwe_array_in,
                          message_modulus, carry_modulus, num_radix_blocks);
}
