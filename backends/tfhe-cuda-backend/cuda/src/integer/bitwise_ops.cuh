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
    void *const *bsks, Torus *const *ksks,
    CudaModulusSwitchNoiseReductionKeyFFI const *ms_noise_reduction_key) {

  if (lwe_array_out->num_radix_blocks != lwe_array_1->num_radix_blocks ||
      lwe_array_out->num_radix_blocks != lwe_array_2->num_radix_blocks)
    PANIC("Cuda error: input and output num radix blocks must be equal")
  if (lwe_array_out->lwe_dimension != lwe_array_1->lwe_dimension ||
      lwe_array_out->lwe_dimension != lwe_array_2->lwe_dimension)
    PANIC("Cuda error: input and output lwe dimension must be equal")
  auto lut = mem_ptr->lut;
  uint64_t degrees[lwe_array_1->num_radix_blocks];
  if (mem_ptr->op == BITOP_TYPE::BITAND) {
    update_degrees_after_bitand(degrees, lwe_array_1->degrees,
                                lwe_array_2->degrees,
                                lwe_array_1->num_radix_blocks);
  } else if (mem_ptr->op == BITOP_TYPE::BITOR) {
    update_degrees_after_bitor(degrees, lwe_array_1->degrees,
                               lwe_array_2->degrees,
                               lwe_array_1->num_radix_blocks);
  } else if (mem_ptr->op == BITOP_TYPE::BITXOR) {
    update_degrees_after_bitxor(degrees, lwe_array_1->degrees,
                                lwe_array_2->degrees,
                                lwe_array_1->num_radix_blocks);
  }

  integer_radix_apply_bivariate_lookup_table_kb<Torus>(
      streams, gpu_indexes, gpu_count, lwe_array_out, lwe_array_1, lwe_array_2,
      bsks, ksks, ms_noise_reduction_key, lut, lwe_array_out->num_radix_blocks,
      lut->params.message_modulus);

  memcpy(lwe_array_out->degrees, degrees,
         lwe_array_out->num_radix_blocks * sizeof(uint64_t));
}

template <typename Torus>
__host__ uint64_t scratch_cuda_integer_radix_bitop_kb(
    cudaStream_t const *streams, uint32_t const *gpu_indexes,
    uint32_t gpu_count, int_bitop_buffer<Torus> **mem_ptr,
    uint32_t num_radix_blocks, int_radix_params params, BITOP_TYPE op,
    bool allocate_gpu_memory) {

  uint64_t size_tracker = 0;
  *mem_ptr = new int_bitop_buffer<Torus>(streams, gpu_indexes, gpu_count, op,
                                         params, num_radix_blocks,
                                         allocate_gpu_memory, &size_tracker);
  return size_tracker;
}

#endif
