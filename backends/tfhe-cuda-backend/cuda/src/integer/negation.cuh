#ifndef CUDA_INTEGER_NEGATE_CUH
#define CUDA_INTEGER_NEGATE_CUH

#ifdef __CDT_PARSER__
#undef __CUDA_RUNTIME_H__
#include <cuda_runtime.h>
#endif

#include "crypto/keyswitch.cuh"
#include "device.h"
#include "integer/integer.cuh"
#include "integer/integer_utilities.h"
#include "linear_algebra.h"
#include "pbs/programmable_bootstrap.h"
#include "utils/helper.cuh"
#include "utils/kernel_dimensions.cuh"
#include <fstream>
#include <iostream>
#include <omp.h>
#include <sstream>
#include <string>
#include <vector>

template <typename Torus>
__global__ void
device_integer_radix_negation(Torus *output, Torus const *input,
                              int32_t num_blocks, uint64_t lwe_dimension,
                              uint64_t message_modulus, uint64_t delta) {
  int tid = blockIdx.x * blockDim.x + threadIdx.x;
  if (tid < lwe_dimension + 1) {
    bool is_body = (tid == lwe_dimension);

    // z = ceil( degree / 2^p ) * 2^p
    uint64_t z = (2 * message_modulus - 1) / message_modulus;
    z *= message_modulus;

    // (0,Delta*z) - ct
    output[tid] = (is_body ? z * delta - input[tid] : -input[tid]);

    for (int radix_block_id = 1; radix_block_id < num_blocks;
         radix_block_id++) {
      tid += (lwe_dimension + 1);

      // Subtract z/B to the next ciphertext to compensate for the addition of z
      uint64_t zb = z / message_modulus;

      uint64_t encoded_zb = zb * delta;

      // (0,Delta*z) - ct
      output[tid] =
          (is_body ? z * delta - (input[tid] + encoded_zb) : -input[tid]);
    }
  }
}

template <typename Torus>
__host__ void host_integer_radix_negation(
    cudaStream_t const *streams, uint32_t const *gpu_indexes,
    uint32_t gpu_count, CudaRadixCiphertextFFI *lwe_array_out,
    CudaRadixCiphertextFFI const *lwe_array_in, uint64_t message_modulus,
    uint64_t carry_modulus, uint32_t num_radix_blocks) {
  cuda_set_device(gpu_indexes[0]);

  if (lwe_array_out->num_radix_blocks < num_radix_blocks ||
      lwe_array_in->num_radix_blocks < num_radix_blocks)
    PANIC("Cuda error: lwe_array_in and lwe_array_out num radix blocks must be "
          "greater or equal to the number of blocks to negate")

  if (lwe_array_out->lwe_dimension != lwe_array_in->lwe_dimension)
    PANIC("Cuda error: lwe_array_in and lwe_array_out lwe_dimension must be "
          "the same")

  auto lwe_dimension = lwe_array_out->lwe_dimension;
  // lwe_size includes the presence of the body
  // whereas lwe_dimension is the number of elements in the mask
  int lwe_size = lwe_dimension + 1;
  // Create a 1-dimensional grid of threads
  int num_blocks = 0, num_threads = 0;
  int num_entries = lwe_size;
  getNumBlocksAndThreads(num_entries, 512, num_blocks, num_threads);
  dim3 grid(num_blocks, 1, 1);
  dim3 thds(num_threads, 1, 1);

  // Value of the shift we multiply our messages by
  // If message_modulus and carry_modulus are always powers of 2 we can simplify
  // this
  uint64_t delta = ((uint64_t)1 << 63) / (message_modulus * carry_modulus);

  device_integer_radix_negation<Torus><<<grid, thds, 0, streams[0]>>>(
      static_cast<Torus *>(lwe_array_out->ptr),
      static_cast<Torus *>(lwe_array_in->ptr), num_radix_blocks, lwe_dimension,
      message_modulus, delta);
  check_cuda_error(cudaGetLastError());

  uint8_t zb = 0;
  for (uint i = 0; i < lwe_array_out->num_radix_blocks; i++) {
    auto input_degree = lwe_array_in->degrees[i];

    if (zb != 0) {
      input_degree += static_cast<uint64_t>(zb);
    }
    Torus z =
        std::max(static_cast<Torus>(1),
                 static_cast<Torus>(ceil(input_degree / message_modulus))) *
        message_modulus;

    lwe_array_out->degrees[i] = z - static_cast<uint64_t>(zb);
    lwe_array_out->noise_levels[i] = lwe_array_in->noise_levels[i];
    zb = z / message_modulus;
  }
}
template <typename Torus>
__host__ void legacy_host_integer_radix_negation(
    cudaStream_t const *streams, uint32_t const *gpu_indexes,
    uint32_t gpu_count, Torus *output, Torus const *input,
    uint32_t lwe_dimension, uint32_t input_lwe_ciphertext_count,
    uint64_t message_modulus, uint64_t carry_modulus) {
  cuda_set_device(gpu_indexes[0]);

  // lwe_size includes the presence of the body
  // whereas lwe_dimension is the number of elements in the mask
  int lwe_size = lwe_dimension + 1;
  // Create a 1-dimensional grid of threads
  int num_blocks = 0, num_threads = 0;
  int num_entries = lwe_size;
  getNumBlocksAndThreads(num_entries, 512, num_blocks, num_threads);
  dim3 grid(num_blocks, 1, 1);
  dim3 thds(num_threads, 1, 1);

  // Value of the shift we multiply our messages by
  // If message_modulus and carry_modulus are always powers of 2 we can simplify
  // this
  uint64_t delta = ((uint64_t)1 << 63) / (message_modulus * carry_modulus);

  device_integer_radix_negation<<<grid, thds, 0, streams[0]>>>(
      output, input, input_lwe_ciphertext_count, lwe_dimension, message_modulus,
      delta);
  check_cuda_error(cudaGetLastError());
}

template <typename Torus>
__host__ void scratch_cuda_integer_overflowing_sub_kb(
    cudaStream_t const *streams, uint32_t const *gpu_indexes,
    uint32_t gpu_count, int_overflowing_sub_memory<Torus> **mem_ptr,
    uint32_t num_blocks, int_radix_params params, bool allocate_gpu_memory) {

  *mem_ptr = new int_overflowing_sub_memory<Torus>(
      streams, gpu_indexes, gpu_count, params, num_blocks, allocate_gpu_memory);
}
/*
template <typename Torus>
__host__ void host_integer_overflowing_sub_kb(
    cudaStream_t const *streams, uint32_t const *gpu_indexes,
    uint32_t gpu_count, Torus *radix_lwe_out, Torus *radix_lwe_overflowed,
    Torus const *radix_lwe_left, Torus const *radix_lwe_right,
    void *const *bsks, uint64_t *const *ksks,
    int_overflowing_sub_memory<uint64_t> *mem_ptr, uint32_t num_blocks) {

  auto radix_params = mem_ptr->params;

  host_unchecked_sub_with_correcting_term<Torus>(
      streams[0], gpu_indexes[0], radix_lwe_out, radix_lwe_left,
      radix_lwe_right, radix_params.big_lwe_dimension, num_blocks,
      radix_params.message_modulus, radix_params.carry_modulus,
      radix_params.message_modulus - 1);

  host_propagate_single_sub_borrow<Torus>(streams, gpu_indexes, gpu_count,
                                          radix_lwe_overflowed, radix_lwe_out,
                                          mem_ptr, bsks, ksks, num_blocks);
}

*/
template <typename Torus>
__host__ void legacy_host_integer_overflowing_sub(
    cudaStream_t const *streams, uint32_t const *gpu_indexes,
    uint32_t gpu_count, Torus *lwe_out_array, Torus *lhs_array,
    const Torus *rhs_array, Torus *overflow_block, const Torus *input_borrow,
    int_borrow_prop_memory<uint64_t> *mem_ptr, void *const *bsks,
    Torus *const *ksks, uint32_t num_blocks, uint32_t compute_overflow,
    uint32_t uses_input_borrow) {

  auto radix_params = mem_ptr->params;

  // We need to recalculate the num_groups, because on the division the number
  // of num_blocks changes
  uint32_t block_modulus =
      radix_params.message_modulus * radix_params.carry_modulus;
  uint32_t num_bits_in_block = log2_int(block_modulus);
  uint32_t grouping_size = num_bits_in_block;
  uint32_t num_groups = (num_blocks + grouping_size - 1) / grouping_size;

  auto stream = (cudaStream_t *)streams;
  legacy_host_unchecked_sub_with_correcting_term<Torus>(
      stream[0], gpu_indexes[0], static_cast<Torus *>(lwe_out_array),
      static_cast<Torus *>(lhs_array), static_cast<const Torus *>(rhs_array),
      radix_params.big_lwe_dimension, num_blocks, radix_params.message_modulus,
      radix_params.carry_modulus, radix_params.message_modulus - 1);

  legacy_host_single_borrow_propagate<Torus>(
      streams, gpu_indexes, gpu_count, static_cast<Torus *>(lwe_out_array),
      static_cast<Torus *>(overflow_block),
      static_cast<const Torus *>(input_borrow),
      (int_borrow_prop_memory<Torus> *)mem_ptr, bsks, (Torus **)(ksks),
      num_blocks, num_groups, compute_overflow, uses_input_borrow);
}

template <typename Torus>
__host__ void host_integer_overflowing_sub(
    cudaStream_t const *streams, uint32_t const *gpu_indexes,
    uint32_t gpu_count, CudaRadixCiphertextFFI *output,
    CudaRadixCiphertextFFI *input_left,
    const CudaRadixCiphertextFFI *input_right,
    CudaRadixCiphertextFFI *overflow_block,
    const CudaRadixCiphertextFFI *input_borrow,
    int_borrow_prop_memory<uint64_t> *mem_ptr, void *const *bsks,
    Torus *const *ksks, uint32_t compute_overflow, uint32_t uses_input_borrow) {

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

  auto stream = (cudaStream_t *)streams;
  host_unchecked_sub_with_correcting_term<Torus>(
      stream[0], gpu_indexes[0], output, input_left, input_right, num_blocks,
      radix_params.message_modulus, radix_params.carry_modulus);

  host_single_borrow_propagate<Torus>(
      streams, gpu_indexes, gpu_count, output, overflow_block, input_borrow,
      (int_borrow_prop_memory<Torus> *)mem_ptr, bsks, (Torus **)(ksks),
      num_groups, compute_overflow, uses_input_borrow);
}

#endif
