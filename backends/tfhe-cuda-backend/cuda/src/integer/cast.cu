#include "cast.cuh"

void extend_radix_with_trivial_zero_blocks_msb_64(
    CudaRadixCiphertextFFI *output, CudaRadixCiphertextFFI const *input,
    void *const *streams, uint32_t const *gpu_indexes) {
  host_extend_radix_with_trivial_zero_blocks_msb<uint64_t>(
      output, input, (cudaStream_t *)streams, gpu_indexes);
}

void trim_radix_blocks_lsb_64(CudaRadixCiphertextFFI *output,
                              CudaRadixCiphertextFFI const *input,
                              void *const *streams,
                              uint32_t const *gpu_indexes) {

  host_trim_radix_blocks_lsb<uint64_t>(output, input, (cudaStream_t *)streams,
                                       gpu_indexes);
}
