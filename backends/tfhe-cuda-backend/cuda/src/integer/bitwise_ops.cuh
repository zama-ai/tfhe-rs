#ifndef CUDA_INTEGER_BITWISE_OPS_CUH
#define CUDA_INTEGER_BITWISE_OPS_CUH

#include "crypto/keyswitch.cuh"
#include "device.h"
#include "integer.cuh"
#include "integer/integer_utilities.h"
#include "pbs/programmable_bootstrap_classic.cuh"
#include "pbs/programmable_bootstrap_multibit.cuh"
#include "polynomial/functions.cuh"
#include "utils/kernel_dimensions.cuh"
#include <omp.h>

template <typename Torus>
__host__ void host_integer_radix_bitop_kb(
    cudaStream_t const *streams, uint32_t const *gpu_indexes,
    uint32_t gpu_count, Torus *lwe_array_out, Torus const *lwe_array_1,
    Torus const *lwe_array_2, int_bitop_buffer<Torus> *mem_ptr,
    void *const *bsks, Torus *const *ksks, uint32_t num_radix_blocks) {

  auto lut = mem_ptr->lut;

  integer_radix_apply_bivariate_lookup_table_kb<Torus>(
      streams, gpu_indexes, gpu_count, lwe_array_out, lwe_array_1, lwe_array_2,
      bsks, ksks, num_radix_blocks, lut, lut->params.message_modulus);
}

template <typename Torus>
__host__ void scratch_cuda_integer_radix_bitop_kb(
    cudaStream_t const *streams, uint32_t const *gpu_indexes,
    uint32_t gpu_count, int_bitop_buffer<Torus> **mem_ptr,
    uint32_t num_radix_blocks, int_radix_params params, BITOP_TYPE op,
    bool allocate_gpu_memory) {

  *mem_ptr =
      new int_bitop_buffer<Torus>(streams, gpu_indexes, gpu_count, op, params,
                                  num_radix_blocks, allocate_gpu_memory);
}

#endif
