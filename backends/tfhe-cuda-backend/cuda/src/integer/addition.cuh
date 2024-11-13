#ifndef TFHE_RS_ADDITION_CUH
#define TFHE_RS_ADDITION_CUH

#include "crypto/keyswitch.cuh"
#include "device.h"
#include "integer/comparison.cuh"
#include "integer/integer.cuh"
#include "integer/integer_utilities.h"
#include "integer/negation.cuh"
#include "integer/scalar_shifts.cuh"
#include "linear_algebra.h"
#include "pbs/programmable_bootstrap.h"
#include "utils/helper.cuh"
#include "utils/kernel_dimensions.cuh"
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

template <typename Torus>
void host_resolve_signed_overflow(
    cudaStream_t const *streams, uint32_t const *gpu_indexes,
    uint32_t gpu_count, Torus *result, Torus *last_block_inner_propagation,
    Torus const *last_block_input_carry, Torus *last_block_output_carry,
    int_resolve_signed_overflow_memory<Torus> *mem, void *const *bsks,
    Torus *const *ksks) {

  auto x = mem->x;

  Torus *d_clears =
      (Torus *)cuda_malloc_async(sizeof(Torus), streams[0], gpu_indexes[0]);

  cuda_set_value_async<Torus>(streams[0], gpu_indexes[0], d_clears, 2, 1);

  // replace with host function call
  cuda_mult_lwe_ciphertext_vector_cleartext_vector_64(
      streams[0], gpu_indexes[0], x, last_block_output_carry, d_clears,
      mem->params.big_lwe_dimension, 1);

  host_addition<Torus>(streams[0], gpu_indexes[0], last_block_inner_propagation,
                       last_block_inner_propagation, x,
                       mem->params.big_lwe_dimension, 1);
  host_addition<Torus>(streams[0], gpu_indexes[0], last_block_inner_propagation,
                       last_block_inner_propagation, last_block_input_carry,
                       mem->params.big_lwe_dimension, 1);

  host_apply_univariate_lut_kb<Torus>(streams, gpu_indexes, gpu_count, result,
                                      last_block_inner_propagation,
                                      mem->resolve_overflow_lut, ksks, bsks, 1);

  cuda_drop_async(d_clears, streams[0], gpu_indexes[0]);
}

template <typename Torus>
__host__ void scratch_cuda_integer_signed_overflowing_add_or_sub_kb(
    cudaStream_t const *streams, uint32_t const *gpu_indexes,
    uint32_t gpu_count,
    int_signed_overflowing_add_or_sub_memory<Torus> **mem_ptr,
    uint32_t num_blocks, SIGNED_OPERATION op, int_radix_params params,
    bool allocate_gpu_memory) {

  *mem_ptr = new int_signed_overflowing_add_or_sub_memory<Torus>(
      streams, gpu_indexes, gpu_count, params, num_blocks, op,
      allocate_gpu_memory);
}

/*
 * Addition - signed_operation = 1
 * Subtraction - signed_operation = -1
 */
template <typename Torus>
__host__ void host_integer_signed_overflowing_add_or_sub_kb(
    cudaStream_t const *streams, uint32_t const *gpu_indexes,
    uint32_t gpu_count, Torus *lhs, Torus const *rhs, Torus *overflowed,
    SIGNED_OPERATION op, void *const *bsks, uint64_t *const *ksks,
    int_signed_overflowing_add_or_sub_memory<uint64_t> *mem_ptr,
    uint32_t num_blocks) {

  auto radix_params = mem_ptr->params;

  uint32_t big_lwe_dimension = radix_params.big_lwe_dimension;
  uint32_t big_lwe_size = big_lwe_dimension + 1;
  uint32_t big_lwe_size_bytes = big_lwe_size * sizeof(Torus);

  assert(radix_params.message_modulus >= 4 && radix_params.carry_modulus >= 4);

  auto result = mem_ptr->result;
  auto neg_rhs = mem_ptr->neg_rhs;
  auto input_carries = mem_ptr->input_carries;
  auto output_carry = mem_ptr->output_carry;
  auto last_block_inner_propagation = mem_ptr->last_block_inner_propagation;

  cuda_memcpy_async_gpu_to_gpu(result, lhs, num_blocks * big_lwe_size_bytes,
                               streams[0], gpu_indexes[0]);

  // phase 1
  if (op == SIGNED_OPERATION::ADDITION) {
    host_addition<Torus>(streams[0], gpu_indexes[0], result, lhs, rhs,
                         big_lwe_dimension, num_blocks);
  } else {
    host_integer_radix_negation<Torus>(
        streams, gpu_indexes, gpu_count, neg_rhs, rhs, big_lwe_dimension,
        num_blocks, radix_params.message_modulus, radix_params.carry_modulus);
    host_addition<Torus>(streams[0], gpu_indexes[0], result, lhs, neg_rhs,
                         big_lwe_dimension, num_blocks);
  }

  // phase 2
  for (uint j = 0; j < gpu_count; j++) {
    cuda_synchronize_stream(streams[j], gpu_indexes[j]);
  }

  host_propagate_single_carry<Torus>(
      mem_ptr->sub_streams_1, gpu_indexes, gpu_count, result, output_carry,
      input_carries, mem_ptr->scp_mem, bsks, ksks, num_blocks);
  host_generate_last_block_inner_propagation<Torus>(
      mem_ptr->sub_streams_2, gpu_indexes, gpu_count,
      last_block_inner_propagation, &lhs[(num_blocks - 1) * big_lwe_size],
      &rhs[(num_blocks - 1) * big_lwe_size], mem_ptr->las_block_prop_mem, bsks,
      ksks);

  for (uint j = 0; j < mem_ptr->active_gpu_count; j++) {
    cuda_synchronize_stream(mem_ptr->sub_streams_1[j], gpu_indexes[j]);
    cuda_synchronize_stream(mem_ptr->sub_streams_2[j], gpu_indexes[j]);
  }

  // phase 3
  auto input_carry = &input_carries[(num_blocks - 1) * big_lwe_size];
  if (op == SIGNED_OPERATION::SUBTRACTION && num_blocks == 1) {
    // Quick fix for the case where the subtraction is done on a single block
    Torus *one_scalar =
        (Torus *)cuda_malloc_async(sizeof(Torus), streams[0], gpu_indexes[0]);
    cuda_set_value_async<Torus>(streams[0], gpu_indexes[0], one_scalar, 1, 1);
    create_trivial_radix<Torus>(
        streams[0], gpu_indexes[0], input_carry, one_scalar, big_lwe_dimension,
        1, 1, radix_params.message_modulus, radix_params.carry_modulus);
    cuda_drop_async(one_scalar, streams[0], gpu_indexes[0]);
  }

  host_resolve_signed_overflow<Torus>(
      streams, gpu_indexes, gpu_count, overflowed, last_block_inner_propagation,
      input_carry, output_carry, mem_ptr->resolve_overflow_mem, bsks, ksks);

  cuda_memcpy_async_gpu_to_gpu(lhs, result, num_blocks * big_lwe_size_bytes,
                               streams[0], gpu_indexes[0]);
}

#endif // TFHE_RS_ADDITION_CUH
