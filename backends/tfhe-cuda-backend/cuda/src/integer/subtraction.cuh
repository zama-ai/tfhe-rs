#ifndef CUDA_SUB_CUH
#define CUDA_SUB_CUH

#ifdef __CDT_PARSER__
#undef __CUDA_RUNTIME_H__
#include <cuda_runtime.h>
#endif

#include "device.h"
#include "integer/integer.h"
#include "integer/integer_utilities.h"
#include "negation.cuh"
#include "pbs/pbs_enums.h"

template <typename Torus>
uint64_t scratch_cuda_sub_and_propagate_single_carry(
    cudaStream_t const *streams, uint32_t const *gpu_indexes,
    uint32_t gpu_count, int_sub_and_propagate<Torus> **mem_ptr,
    uint32_t num_radix_blocks, int_radix_params params, uint32_t requested_flag,
    bool allocate_gpu_memory) {

  uint64_t size_tracker = 0;

  *mem_ptr = new int_sub_and_propagate<Torus>(
      streams, gpu_indexes, gpu_count, params, num_radix_blocks, requested_flag,
      allocate_gpu_memory, size_tracker);

  return size_tracker;
}

template <typename Torus>
void host_sub_and_propagate_single_carry(
    cudaStream_t const *streams, uint32_t const *gpu_indexes,
    uint32_t gpu_count, CudaRadixCiphertextFFI *lhs_array,
    const CudaRadixCiphertextFFI *rhs_array, CudaRadixCiphertextFFI *carry_out,
    const CudaRadixCiphertextFFI *input_carries,
    int_sub_and_propagate<Torus> *mem, void *const *bsks, Torus *const *ksks,
    CudaModulusSwitchNoiseReductionKeyFFI const *ms_noise_reduction_key,
    uint32_t requested_flag, uint32_t uses_carry) {

  host_integer_radix_negation<Torus>(
      streams, gpu_indexes, gpu_count, mem->neg_rhs_array, rhs_array,
      mem->params.message_modulus, mem->params.carry_modulus,
      mem->neg_rhs_array->num_radix_blocks);

  host_add_and_propagate_single_carry<Torus>(
      streams, gpu_indexes, gpu_count, lhs_array, mem->neg_rhs_array, carry_out,
      input_carries, mem->sc_prop_mem, bsks, ksks, ms_noise_reduction_key,
      requested_flag, uses_carry);
}

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
                       lwe_array_in_1, num_radix_blocks, message_modulus,
                       carry_modulus);
}
#endif
