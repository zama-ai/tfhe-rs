#include "integer/negation.cuh"

void cuda_negate_ciphertext_64(CudaStreamsFFI streams,
                               CudaRadixCiphertextFFI *lwe_array_out_ffi,
                               CudaRadixCiphertextFFI const *lwe_array_in_ffi,
                               uint32_t message_modulus, uint32_t carry_modulus,
                               uint32_t num_radix_blocks) {
  CudaRadixCiphertext lwe_array_out_local(*lwe_array_out_ffi);
  CudaRadixCiphertext *lwe_array_out = &lwe_array_out_local;
  const CudaRadixCiphertext lwe_array_in_local(*lwe_array_in_ffi);
  const CudaRadixCiphertext *lwe_array_in = &lwe_array_in_local;

  PANIC_IF_FALSE(lwe_array_out_ffi != lwe_array_in_ffi,
                 "Output and input pointers must be different for out-of-place "
                 "operations");

  auto cuda_streams = CudaStreams(streams);
  host_negation_with_correcting_term<uint64_t>(cuda_streams, lwe_array_out,
                                               lwe_array_in, message_modulus,
                                               carry_modulus, num_radix_blocks);
  cuda_synchronize_stream(cuda_streams.stream(0), cuda_streams.gpu_index(0));
}
