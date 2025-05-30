#ifndef CAST_CUH
#define CAST_CUH

#include "device.h"
#include "integer.cuh"
#include "integer/integer_utilities.h"

template <typename Torus>
__host__ void host_trim_radix_blocks_lsb(CudaRadixCiphertextFFI *output,
                                         CudaRadixCiphertextFFI const *input,
                                         cudaStream_t const *streams,
                                         uint32_t const *gpu_indexes) {

  const uint32_t input_start_lwe_index =
      input->num_radix_blocks - output->num_radix_blocks;

  if (input_start_lwe_index < 0 ||
      input_start_lwe_index == input->num_radix_blocks) {
    PANIC("Cuda error: input_start_lwe_index should be >= 0 and < "
          "input->num_radix_blocks");
  }

  copy_radix_ciphertext_slice_async<Torus>(
      streams[0], gpu_indexes[0], output, 0, output->num_radix_blocks, input,
      input_start_lwe_index, input->num_radix_blocks);
}

#endif
