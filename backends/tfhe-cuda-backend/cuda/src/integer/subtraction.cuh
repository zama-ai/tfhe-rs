#ifndef CUDA_SUB_CUH
#define CUDA_SUB_CUH

#ifdef __CDT_PARSER__
#undef __CUDA_RUNTIME_H__
#include <cuda_runtime.h>
#endif

#include "device.h"
#include "integer/integer.h"
#include "linear_algebra.h"

template <typename Torus>
__host__ void host_integer_radix_subtraction(
    cudaStream_t const *streams, uint32_t const *gpu_indexes,
    uint32_t gpu_count, CudaRadixCiphertextFFI *lwe_array_out,
    CudaRadixCiphertextFFI const *lwe_array_in_1,
    CudaRadixCiphertextFFI const *lwe_array_in_2, uint64_t message_modulus,
    uint64_t carry_modulus, uint32_t num_radix_blocks) {
  cuda_set_device(gpu_indexes[0]);

  if (lwe_array_out->num_radix_blocks < num_radix_blocks ||
      lwe_array_in_1->num_radix_blocks < num_radix_blocks ||
      lwe_array_in_2->num_radix_blocks < num_radix_blocks)
    PANIC("Cuda error: input and output num radix blocks must be "
          "larger than the one used in sbutraction")

  if (lwe_array_out->lwe_dimension != lwe_array_in_1->lwe_dimension ||
      lwe_array_out->lwe_dimension != lwe_array_in_2->lwe_dimension)
    PANIC("Cuda error: lwe_array_in and lwe_array_out lwe_dimension must be "
          "the same")

  host_integer_radix_negation<Torus>(
      streams, gpu_indexes, gpu_count, lwe_array_out, lwe_array_in_2,
      message_modulus, carry_modulus, num_radix_blocks);
  host_addition<Torus>(streams[0], gpu_indexes[0], lwe_array_out, lwe_array_out,
                       lwe_array_in_1, num_radix_blocks);
}
#endif
