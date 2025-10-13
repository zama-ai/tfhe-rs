#ifndef CUDA_SUB_CUH
#define CUDA_SUB_CUH

#ifdef __CDT_PARSER__
#undef __CUDA_RUNTIME_H__
#include <cuda_runtime.h>
#endif

#include "device.h"
#include "integer/integer.h"
#include "integer/integer_utilities.h"
#include "integer/subtraction.h"
#include "negation.cuh"
#include "pbs/pbs_enums.h"

template <typename Torus>
uint64_t scratch_cuda_sub_and_propagate_single_carry(
    CudaStreams streams, int_sub_and_propagate<Torus> **mem_ptr,
    uint32_t num_radix_blocks, int_radix_params params, uint32_t requested_flag,
    bool allocate_gpu_memory) {
  PUSH_RANGE("scratch sub")
  uint64_t size_tracker = 0;

  *mem_ptr = new int_sub_and_propagate<Torus>(
      streams, params, num_radix_blocks, requested_flag, allocate_gpu_memory,
      size_tracker);
  POP_RANGE()
  return size_tracker;
}

template <typename Torus>
void host_sub_and_propagate_single_carry(
    CudaStreams streams, CudaRadixCiphertextFFI *lhs_array,
    const CudaRadixCiphertextFFI *rhs_array, CudaRadixCiphertextFFI *carry_out,
    const CudaRadixCiphertextFFI *input_carries,
    int_sub_and_propagate<Torus> *mem, void *const *bsks, Torus *const *ksks,
    uint32_t requested_flag, uint32_t uses_carry) {

  host_negation<Torus>(streams, mem->neg_rhs_array, rhs_array,
                       mem->params.message_modulus, mem->params.carry_modulus,
                       mem->neg_rhs_array->num_radix_blocks);

  host_add_and_propagate_single_carry<Torus>(
      streams, lhs_array, mem->neg_rhs_array, carry_out, input_carries,
      mem->sc_prop_mem, bsks, ksks, requested_flag, uses_carry);
}

template <typename Torus>
__host__ void host_subtraction(CudaStreams streams,
                               CudaRadixCiphertextFFI *lwe_array_out,
                               CudaRadixCiphertextFFI const *lwe_array_in_1,
                               CudaRadixCiphertextFFI const *lwe_array_in_2,
                               uint64_t message_modulus, uint64_t carry_modulus,
                               uint32_t num_radix_blocks) {
  cuda_set_device(streams.gpu_index(0));

  if (lwe_array_out->num_radix_blocks < num_radix_blocks ||
      lwe_array_in_1->num_radix_blocks < num_radix_blocks ||
      lwe_array_in_2->num_radix_blocks < num_radix_blocks)
    PANIC("Cuda error: input and output num radix blocks must be "
          "larger than the one used in sbutraction")

  if (lwe_array_out->lwe_dimension != lwe_array_in_1->lwe_dimension ||
      lwe_array_out->lwe_dimension != lwe_array_in_2->lwe_dimension)
    PANIC("Cuda error: lwe_array_in and lwe_array_out lwe_dimension must be "
          "the same")

  host_negation<Torus>(streams, lwe_array_out, lwe_array_in_2, message_modulus,
                       carry_modulus, num_radix_blocks);
  host_addition<Torus>(streams.stream(0), streams.gpu_index(0), lwe_array_out,
                       lwe_array_out, lwe_array_in_1, num_radix_blocks,
                       message_modulus, carry_modulus);
}

template <typename Torus>
__host__ uint64_t scratch_cuda_integer_overflowing_sub(
    CudaStreams streams, int_overflowing_sub_memory<Torus> **mem_ptr,
    uint32_t num_blocks, int_radix_params params, bool allocate_gpu_memory,
    PBS_MS_REDUCTION_T noise_reduction_type) {

  PUSH_RANGE("scratch overflowing sub")
  uint64_t size_tracker = 0;
  *mem_ptr = new int_overflowing_sub_memory<Torus>(
      streams, params, num_blocks, allocate_gpu_memory, noise_reduction_type,
      size_tracker);
  POP_RANGE()
  return size_tracker;
}

template <typename Torus>
__host__ void host_integer_overflowing_sub(
    CudaStreams streams, CudaRadixCiphertextFFI *output,
    CudaRadixCiphertextFFI *input_left,
    const CudaRadixCiphertextFFI *input_right,
    CudaRadixCiphertextFFI *overflow_block,
    const CudaRadixCiphertextFFI *input_borrow,
    int_borrow_prop_memory<uint64_t> *mem_ptr, void *const *bsks,
    Torus *const *ksks, uint32_t compute_overflow, uint32_t uses_input_borrow) {
  PUSH_RANGE("overflowing sub")
  if (output->num_radix_blocks != input_left->num_radix_blocks ||
      output->num_radix_blocks != input_right->num_radix_blocks)
    PANIC("Cuda error: lwe_array_in and output num radix blocks must be "
          "the same")

  if (output->lwe_dimension != input_left->lwe_dimension ||
      output->lwe_dimension != input_right->lwe_dimension)
    PANIC("Cuda error: lwe_array_in and output lwe_dimension must be "
          "the same")

  auto num_blocks = output->num_radix_blocks;
  auto radix_params = mem_ptr->params;

  // We need to recalculate the num_groups, because on the division the number
  // of num_blocks changes
  uint32_t block_modulus =
      radix_params.message_modulus * radix_params.carry_modulus;
  uint32_t num_bits_in_block = log2_int(block_modulus);
  uint32_t grouping_size = num_bits_in_block;
  uint32_t num_groups = (num_blocks + grouping_size - 1) / grouping_size;

  host_unchecked_sub_with_correcting_term<Torus>(
      streams.stream(0), streams.gpu_index(0), output, input_left, input_right,
      num_blocks, radix_params.message_modulus, radix_params.carry_modulus);

  host_single_borrow_propagate<Torus>(
      streams, output, overflow_block, input_borrow,
      (int_borrow_prop_memory<Torus> *)mem_ptr, bsks, (Torus **)(ksks),
      num_groups, compute_overflow, uses_input_borrow);
  POP_RANGE()
}

#endif
