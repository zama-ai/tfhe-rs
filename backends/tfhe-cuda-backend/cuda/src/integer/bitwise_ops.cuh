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
    uint32_t gpu_count, CudaRadixCiphertextFFI *lwe_array_out,
    CudaRadixCiphertextFFI const *lwe_array_1,
    CudaRadixCiphertextFFI const *lwe_array_2, int_bitop_buffer<Torus> *mem_ptr,
    void *const *bsks, Torus *const *ksks) {

  auto lut = mem_ptr->lut;
  uint64_t degrees[lwe_array_1->num_radix_blocks];
  if (mem_ptr->op == BITOP_TYPE::BITAND) {
    for (uint i = 0; i < lwe_array_out->num_radix_blocks; i++) {
      degrees[i] = std::min(lwe_array_1->degrees[i], lwe_array_2->degrees[i]);
    }
  } else if (mem_ptr->op == BITOP_TYPE::BITOR) {
    for (uint i = 0; i < lwe_array_out->num_radix_blocks; i++) {
      auto max = std::max(lwe_array_1->degrees[i], lwe_array_2->degrees[i]);
      auto min = std::min(lwe_array_1->degrees[i], lwe_array_2->degrees[i]);
      auto result = max;

      for (uint j = 0; j < min + 1; j++) {
        if (max | j > result) {
          result = max | j;
        }
      }
      degrees[i] = result;
    }
  } else if (mem_ptr->op == BITXOR) {
    for (uint i = 0; i < lwe_array_out->num_radix_blocks; i++) {
      auto max = std::max(lwe_array_1->degrees[i], lwe_array_2->degrees[i]);
      auto min = std::min(lwe_array_1->degrees[i], lwe_array_2->degrees[i]);
      auto result = max;

      // Try every possibility to find the worst case
      for (uint j = 0; j < min + 1; j++) {
        if (max ^ j > result) {
          result = max ^ j;
        }
      }
      degrees[i] = result;
    }
  }

  integer_radix_apply_bivariate_lookup_table_kb<Torus>(
      streams, gpu_indexes, gpu_count, lwe_array_out, lwe_array_1, lwe_array_2,
      bsks, ksks, lut, lut->params.message_modulus);

  memcpy(lwe_array_out->degrees, degrees,
         lwe_array_out->num_radix_blocks * sizeof(uint64_t));
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
