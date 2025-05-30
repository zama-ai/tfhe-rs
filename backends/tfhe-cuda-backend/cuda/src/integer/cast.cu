#include "cast.cuh"

void trim_radix_blocks_lsb_64(CudaRadixCiphertextFFI *output,
                              CudaRadixCiphertextFFI const *input,
                              void *const *streams,
                              uint32_t const *gpu_indexes) {

  host_trim_radix_blocks_lsb<uint64_t>(output, input, (cudaStream_t *)streams,
                                       gpu_indexes);
}
