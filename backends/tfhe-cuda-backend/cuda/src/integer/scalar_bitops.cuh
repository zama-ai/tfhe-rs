#ifndef CUDA_INTEGER_SCALAR_BITWISE_OPS_CUH
#define CUDA_INTEGER_SCALAR_BITWISE_OPS_CUH

#include "integer/bitwise_ops.cuh"
#include <omp.h>

template <typename Torus>
__host__ void host_integer_radix_scalar_bitop_kb(
    cudaStream_t const *streams, uint32_t const *gpu_indexes,
    uint32_t gpu_count, Torus *lwe_array_out, Torus const *lwe_array_input,
    Torus const *clear_blocks, uint32_t num_clear_blocks,
    int_bitop_buffer<Torus> *mem_ptr, void *const *bsks, Torus *const *ksks,
    uint32_t num_radix_blocks, BITOP_TYPE op) {

  auto lut = mem_ptr->lut;
  auto params = lut->params;
  auto big_lwe_dimension = params.big_lwe_dimension;

  uint32_t lwe_size = big_lwe_dimension + 1;

  if (num_clear_blocks == 0) {
    if (op == SCALAR_BITAND) {
      cuda_memset_async(lwe_array_out, 0,
                        num_radix_blocks * lwe_size * sizeof(Torus), streams[0],
                        gpu_indexes[0]);
    } else {
      cuda_memcpy_async_gpu_to_gpu(lwe_array_out, lwe_array_input,
                                   num_radix_blocks * lwe_size * sizeof(Torus),
                                   streams[0], gpu_indexes[0]);
    }
  } else {
    // We have all possible LUTs pre-computed and we use the decomposed scalar
    // as index to recover the right one
    cuda_memcpy_async_gpu_to_gpu(lut->get_lut_indexes(0, 0), clear_blocks,
                                 num_clear_blocks * sizeof(Torus), streams[0],
                                 gpu_indexes[0]);
    lut->broadcast_lut(streams, gpu_indexes, 0);

    integer_radix_apply_univariate_lookup_table_kb<Torus>(
        streams, gpu_indexes, gpu_count, lwe_array_out, lwe_array_input, bsks,
        ksks, num_clear_blocks, lut);

    if (op == SCALAR_BITAND && num_clear_blocks < num_radix_blocks) {
      auto lwe_array_out_block = lwe_array_out + num_clear_blocks * lwe_size;
      cuda_memset_async(lwe_array_out_block, 0,
                        (num_radix_blocks - num_clear_blocks) * lwe_size *
                            sizeof(Torus),
                        streams[0], gpu_indexes[0]);
    }
  }
}

#endif
