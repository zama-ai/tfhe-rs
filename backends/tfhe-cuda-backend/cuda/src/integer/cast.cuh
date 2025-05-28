#ifndef CAST_CUH
#define CAST_CUH

#include "device.h"
#include "integer.cuh"
#include "integer/integer_utilities.h"

template <typename Torus>
__host__ void host_extend_radix_with_trivial_zero_blocks_msb(
    CudaRadixCiphertextFFI *output, CudaRadixCiphertextFFI const *input,
    cudaStream_t const *streams, uint32_t const *gpu_indexes) {

  copy_radix_ciphertext_slice_async<Torus>(streams[0], gpu_indexes[0], output,
                                           0, input->num_radix_blocks, input, 0,
                                           input->num_radix_blocks);
}

#endif
