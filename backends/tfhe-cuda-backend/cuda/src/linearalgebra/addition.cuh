#ifndef CUDA_ADD_CUH
#define CUDA_ADD_CUH

#ifdef __CDT_PARSER__
#endif

#include "checked_arithmetic.h"
#include "device.h"
#include "helper_multi_gpu.h"
#include "integer/integer.h"
#include "integer/integer_utilities.h"
#include "polynomial/parameters.cuh"
#include "utils/helper.cuh"
#include <stdio.h>

template <typename T>
__global__ void plaintext_addition(T *output, T const *lwe_input,
                                   T const *plaintext_input,
                                   const uint32_t input_lwe_dimension,
                                   const uint32_t num_entries) {

  int tid = threadIdx.x;
  int plaintext_index = blockIdx.x * blockDim.x + tid;
  if (plaintext_index < num_entries) {
    int index =
        plaintext_index * (input_lwe_dimension + 1) + input_lwe_dimension;
    // Here we take advantage of the wrapping behaviour of uint
    output[index] = lwe_input[index] + plaintext_input[plaintext_index];
  }
}

template <typename T>
__global__ void plaintext_addition_scalar(T *output, T const *lwe_input,
                                          const T plaintext_input,
                                          const uint32_t input_lwe_dimension,
                                          const uint32_t num_entries) {

  int tid = threadIdx.x;
  int lwe_index = blockIdx.x * blockDim.x + tid;
  if (lwe_index < num_entries) {
    int index = lwe_index * (input_lwe_dimension + 1) + input_lwe_dimension;
    // Here we take advantage of the wrapping behaviour of uint
    output[index] = lwe_input[index] + plaintext_input;
  }
}

template <typename T>
__host__ void host_addition_plaintext(cudaStream_t stream, uint32_t gpu_index,
                                      T *output, T const *lwe_input,
                                      T const *plaintext_input,
                                      const uint32_t lwe_dimension,
                                      const uint32_t lwe_ciphertext_count) {

  cuda_set_device(gpu_index);
  int num_blocks = 0, num_threads = 0;
  int num_entries = lwe_ciphertext_count;
  getNumBlocksAndThreads(num_entries, 512, num_blocks, num_threads);
  dim3 grid(num_blocks, 1, 1);
  dim3 thds(num_threads, 1, 1);

  cuda_memcpy_async_gpu_to_gpu(output, lwe_input,
                               safe_mul_sizeof<T>((size_t)(lwe_dimension + 1),
                                                  (size_t)lwe_ciphertext_count),
                               stream, gpu_index);
  plaintext_addition<T><<<grid, thds, 0, stream>>>(
      output, lwe_input, plaintext_input, lwe_dimension, num_entries);
  check_cuda_error(cudaGetLastError());
}

template <typename T>
__host__ void host_addition_plaintext_scalar(
    cudaStream_t stream, uint32_t gpu_index, T *output, T const *lwe_input,
    const T plaintext_input, const uint32_t lwe_dimension,
    const uint32_t lwe_ciphertext_count) {

  cuda_set_device(gpu_index);
  int num_blocks = 0, num_threads = 0;
  int num_entries = lwe_ciphertext_count;
  getNumBlocksAndThreads(num_entries, 512, num_blocks, num_threads);
  dim3 grid(num_blocks, 1, 1);
  dim3 thds(num_threads, 1, 1);

  cuda_memcpy_async_gpu_to_gpu(output, lwe_input,
                               safe_mul_sizeof<T>((size_t)(lwe_dimension + 1),
                                                  (size_t)lwe_ciphertext_count),
                               stream, gpu_index);
  plaintext_addition_scalar<T><<<grid, thds, 0, stream>>>(
      output, lwe_input, plaintext_input, lwe_dimension, num_entries);
  check_cuda_error(cudaGetLastError());
}

template <typename T>
__global__ void addition(T *output, T const *input_1, T const *input_2,
                         uint32_t num_entries) {

  int tid = threadIdx.x;
  int index = blockIdx.x * blockDim.x + tid;
  if (index < num_entries) {
    // Here we take advantage of the wrapping behaviour of uint
    output[index] = input_1[index] + input_2[index];
  }
}

// Coefficient-wise addition
// num_radix_blocks selects the amount of blocks to be added from the inputs
template <typename T>
__host__ void
host_addition(cudaStream_t stream, uint32_t gpu_index,
              CudaRadixCiphertextFFI *output,
              CudaRadixCiphertextFFI const *input_1,
              CudaRadixCiphertextFFI const *input_2, uint32_t num_radix_blocks,
              const uint32_t message_modulus, const uint32_t carry_modulus) {
  if (output->lwe_dimension != input_1->lwe_dimension ||
      output->lwe_dimension != input_2->lwe_dimension)
    PANIC("Cuda error: input and output num radix blocks must be the same")
  if (output->num_radix_blocks < num_radix_blocks ||
      input_1->num_radix_blocks < num_radix_blocks ||
      input_2->num_radix_blocks < num_radix_blocks)
    PANIC("Cuda error: input and output num radix blocks must be larger or "
          "equal to the num blocks to add")

  cuda_set_device(gpu_index);
  // lwe_size includes the presence of the body
  // whereas lwe_dimension is the number of elements in the mask
  int lwe_size = output->lwe_dimension + 1;
  // Create a 1-dimensional grid of threads
  int num_blocks = 0, num_threads = 0;
  int num_entries = num_radix_blocks * lwe_size;
  getNumBlocksAndThreads(num_entries, 512, num_blocks, num_threads);
  dim3 grid(num_blocks, 1, 1);
  dim3 thds(num_threads, 1, 1);

  addition<T><<<grid, thds, 0, stream>>>(
      static_cast<T *>(output->ptr), static_cast<const T *>(input_1->ptr),
      static_cast<const T *>(input_2->ptr), num_entries);
  check_cuda_error(cudaGetLastError());
  for (uint i = 0; i < num_radix_blocks; i++) {
    output->degrees[i] = input_1->degrees[i] + input_2->degrees[i];
    output->noise_levels[i] =
        input_1->noise_levels[i] + input_2->noise_levels[i];
    CHECK_NOISE_LEVEL(output->noise_levels[i], message_modulus, carry_modulus);
  }
}

template <typename T>
__global__ void constant_addition(T *output, T const *input_1, T const *input_2,
                                  uint32_t lwe_size, uint32_t num_entries) {

  int tid = threadIdx.x;
  int index = blockIdx.x * blockDim.x + tid;
  if (index < num_entries) {
    // Here we take advantage of the wrapping behaviour of uint
    output[index] = input_1[index] + input_2[index % lwe_size];
  }
}

// Coefficient-wise addition by the same block
// input_with_multiple_blocks is a radix ciphertext with potentially multiple
// blocks input_with_single_block is a radix ciphertext with a single block
//
// This function adds the single block in input_with_single_block to each block
// in input_with_multiple_blocks. The result is written to output
template <typename T>
__host__ void host_add_the_same_block_to_all_blocks(
    cudaStream_t stream, uint32_t gpu_index, CudaRadixCiphertextFFI *output,
    CudaRadixCiphertextFFI const *input_with_multiple_blocks,
    CudaRadixCiphertextFFI const *input_with_single_block,
    const uint32_t message_modulus, const uint32_t carry_modulus) {
  if (output->num_radix_blocks != input_with_multiple_blocks->num_radix_blocks)
    PANIC("Cuda error: input and output num radix blocks must be the same")
  if (input_with_single_block->num_radix_blocks != 1)
    PANIC(
        "Cuda error: input_with_single_block must be a single-block ciphertext")
  if (output->lwe_dimension != input_with_multiple_blocks->lwe_dimension ||
      output->lwe_dimension != input_with_single_block->lwe_dimension)
    PANIC("Cuda error: input and output lwe dimensions must be the same")

  cuda_set_device(gpu_index);
  // lwe_size includes the presence of the body
  // whereas lwe_dimension is the number of elements in the mask
  int lwe_size = output->lwe_dimension + 1;
  // Create a 1-dimensional grid of threads
  int num_blocks = 0, num_threads = 0;
  int num_entries = output->num_radix_blocks * lwe_size;
  getNumBlocksAndThreads(num_entries, 512, num_blocks, num_threads);
  dim3 grid(num_blocks, 1, 1);
  dim3 thds(num_threads, 1, 1);

  constant_addition<T><<<grid, thds, 0, stream>>>(
      static_cast<T *>(output->ptr),
      static_cast<const T *>(input_with_multiple_blocks->ptr),
      static_cast<const T *>(input_with_single_block->ptr), lwe_size,
      num_entries);
  check_cuda_error(cudaGetLastError());
  for (uint i = 0; i < output->num_radix_blocks; i++) {
    output->degrees[i] = input_with_multiple_blocks->degrees[i] +
                         input_with_single_block->degrees[0];
    output->noise_levels[i] = input_with_multiple_blocks->noise_levels[i] +
                              input_with_single_block->noise_levels[0];
    CHECK_NOISE_LEVEL(output->noise_levels[i], message_modulus, carry_modulus);
  }
}

template <typename T>
__global__ void subtraction(T *output, T const *input_1, T const *input_2,
                            uint32_t num_entries) {

  int tid = threadIdx.x;
  int index = blockIdx.x * blockDim.x + tid;
  if (index < num_entries) {
    // Here we take advantage of the wrapping behaviour of uint
    output[index] = input_1[index] - input_2[index];
  }
}

// Coefficient-wise subtraction
template <typename T>
__host__ void host_subtraction(cudaStream_t stream, uint32_t gpu_index,
                               T *output, T const *input_1, T const *input_2,
                               uint32_t input_lwe_dimension,
                               uint32_t input_lwe_ciphertext_count) {

  cuda_set_device(gpu_index);
  // lwe_size includes the presence of the body
  // whereas lwe_dimension is the number of elements in the mask
  int lwe_size = input_lwe_dimension + 1;
  // Create a 1-dimensional grid of threads
  int num_blocks = 0, num_threads = 0;
  int num_entries = input_lwe_ciphertext_count * lwe_size;
  getNumBlocksAndThreads(num_entries, 512, num_blocks, num_threads);
  dim3 grid(num_blocks, 1, 1);
  dim3 thds(num_threads, 1, 1);

  subtraction<T>
      <<<grid, thds, 0, stream>>>(output, input_1, input_2, num_entries);
  check_cuda_error(cudaGetLastError());
}

template <typename T>
__global__ void radix_body_subtraction_inplace(T *lwe_ct, T *plaintext_input,
                                               uint32_t input_lwe_dimension,
                                               uint32_t num_entries) {

  int tid = threadIdx.x;
  int plaintext_index = blockIdx.x * blockDim.x + tid;
  if (plaintext_index < num_entries) {
    int index =
        plaintext_index * (input_lwe_dimension + 1) + input_lwe_dimension;
    // Here we take advantage of the wrapping behaviour of uint
    lwe_ct[index] -= plaintext_input[plaintext_index];
  }
}

template <typename T>
__host__ void host_subtraction_plaintext(cudaStream_t stream,
                                         uint32_t gpu_index, T *output,
                                         T *lwe_input, T *plaintext_input,
                                         uint32_t input_lwe_dimension,
                                         uint32_t input_lwe_ciphertext_count) {

  cuda_set_device(gpu_index);
  int num_blocks = 0, num_threads = 0;
  int num_entries = input_lwe_ciphertext_count;
  getNumBlocksAndThreads(num_entries, 512, num_blocks, num_threads);
  dim3 grid(num_blocks, 1, 1);
  dim3 thds(num_threads, 1, 1);

  cuda_memcpy_async_gpu_to_gpu(
      output, lwe_input,
      safe_mul_sizeof<T>((size_t)input_lwe_ciphertext_count,
                         (size_t)(input_lwe_dimension + 1)),
      stream, gpu_index);

  radix_body_subtraction_inplace<T><<<grid, thds, 0, stream>>>(
      output, plaintext_input, input_lwe_dimension, num_entries);
  check_cuda_error(cudaGetLastError());
}

template <typename T>
__global__ void
unchecked_sub_with_correcting_term(T *output, T const *input_1,
                                   T const *input_2, uint32_t num_entries,
                                   uint32_t lwe_size, uint32_t message_modulus,
                                   uint32_t carry_modulus, uint32_t degree) {
  uint32_t msg_mod = message_modulus;
  uint64_t z = max((uint64_t)ceil(degree / msg_mod), (uint64_t)1);
  z *= msg_mod;
  uint64_t delta = (1ULL << 63) / (message_modulus * carry_modulus);

  uint64_t w = z * delta;

  int tid = threadIdx.x;
  int index = blockIdx.x * blockDim.x + tid;
  if (index < num_entries) {
    // Here we take advantage of the wrapping behaviour of uint
    output[index] = input_1[index] + ((0 - input_2[index]));
    if (index % lwe_size == lwe_size - 1)
      output[index] += w;
  }
}

template <typename T>
__host__ void host_unchecked_sub_with_correcting_term(
    cudaStream_t stream, uint32_t gpu_index, CudaRadixCiphertextFFI *output,
    CudaRadixCiphertextFFI const *input_1,
    CudaRadixCiphertextFFI const *input_2, uint32_t num_radix_blocks,
    uint32_t message_modulus, uint32_t carry_modulus) {

  if (output->lwe_dimension != input_1->lwe_dimension ||
      output->lwe_dimension != input_2->lwe_dimension)
    PANIC("Cuda error: input and output num radix blocks must be the same")
  if (output->num_radix_blocks < num_radix_blocks ||
      input_1->num_radix_blocks < num_radix_blocks ||
      input_2->num_radix_blocks < num_radix_blocks)
    PANIC("Cuda error: input and output num radix blocks must be larger or "
          "equal to the num blocks to add")

  cuda_set_device(gpu_index);
  // lwe_size includes the presence of the body
  // whereas lwe_dimension is the number of elements in the mask
  int lwe_size = output->lwe_dimension + 1;
  // Create a 1-dimensional grid of threads
  int num_blocks = 0, num_threads = 0;
  int num_entries = num_radix_blocks * lwe_size;
  getNumBlocksAndThreads(num_entries, 512, num_blocks, num_threads);
  dim3 grid(num_blocks, 1, 1);
  dim3 thds(num_threads, 1, 1);

  // Here we assume this function is always called with correcting term
  // message_modulus - 1 in the radix blocks
  unchecked_sub_with_correcting_term<T><<<grid, thds, 0, stream>>>(
      (T *)output->ptr, (T *)input_1->ptr, (T *)input_2->ptr, num_entries,
      lwe_size, message_modulus, carry_modulus, message_modulus - 1);
  check_cuda_error(cudaGetLastError());
  uint8_t zb = 0;
  for (uint i = 0; i < num_radix_blocks; i++) {
    auto input_2_degree = input_2->degrees[i];

    if (zb != 0) {
      input_2_degree += static_cast<uint64_t>(zb);
    }
    T z = std::max(static_cast<T>(1),
                   static_cast<T>(ceil(input_2_degree / message_modulus))) *
          message_modulus;

    output->degrees[i] = input_1->degrees[i] + z - static_cast<uint64_t>(zb);
    output->noise_levels[i] =
        input_1->noise_levels[i] + input_2->noise_levels[i];
    zb = z / message_modulus;
    CHECK_NOISE_LEVEL(output->noise_levels[i], message_modulus, carry_modulus);
  }
}

template <typename Torus, class params>
__global__ void device_binary_tree_fold(Torus *__restrict__ data,
                                        uint32_t entry_size, uint32_t num_pairs,
                                        uint32_t right_start_entry,
                                        uint32_t total_elements) {
  uint32_t base_idx = (threadIdx.x + blockIdx.x * blockDim.x) * params::opt;

#pragma unroll
  for (int i = 0; i < params::opt; i++) {
    uint32_t idx = base_idx + i;
    if (idx >= total_elements)
      return;

    uint32_t pair = idx / entry_size;
    uint32_t elem = idx % entry_size;

    data[pair * entry_size + elem] +=
        data[(right_start_entry + pair) * entry_size + elem];
  }
}

// Mutates input in-place during reduction
template <typename Torus, class params>
__host__ void host_binary_tree_sum_impl(
    cudaStream_t stream, uint32_t gpu_index, CudaRadixCiphertextFFI *output,
    CudaRadixCiphertextFFI *input, uint32_t num_entries, uint32_t num_blocks,
    uint32_t message_modulus, uint32_t carry_modulus) {

  if (num_entries == 0) {
    set_zero_radix_ciphertext_slice_async<Torus>(stream, gpu_index, output, 0,
                                                 num_blocks);
    return;
  }

  cuda_set_device(gpu_index);

  auto lwe_size = input->lwe_dimension + 1;
  uint32_t entry_size = static_cast<uint32_t>(
      safe_mul(static_cast<size_t>(num_blocks), static_cast<size_t>(lwe_size)));
  auto *data = static_cast<Torus *>(input->ptr);

  uint32_t remaining = num_entries;
  while (remaining > 1) {
    uint32_t half = remaining / 2;
    uint32_t right_start = remaining - half;
    uint32_t total_elements = static_cast<uint32_t>(
        safe_mul(static_cast<size_t>(half), static_cast<size_t>(entry_size)));
    uint32_t total_threads = CEIL_DIV(total_elements, params::opt);

    int num_cuda_blocks = 0, num_threads = 0;
    getNumBlocksAndThreads(total_threads, 512, num_cuda_blocks, num_threads);

    device_binary_tree_fold<Torus, params>
        <<<num_cuda_blocks, num_threads, 0, stream>>>(
            data, entry_size, half, right_start, total_elements);
    check_cuda_error(cudaGetLastError());

    for (uint32_t p = 0; p < half; p++) {
      for (uint32_t b = 0; b < num_blocks; b++) {
        uint32_t left_block = p * num_blocks + b;
        uint32_t right_block = (right_start + p) * num_blocks + b;
        input->degrees[left_block] += input->degrees[right_block];
        input->noise_levels[left_block] += input->noise_levels[right_block];
        CHECK_NOISE_LEVEL(input->noise_levels[left_block], message_modulus,
                          carry_modulus);
      }
    }

    remaining = right_start;
  }

  copy_radix_ciphertext_slice_async<Torus>(stream, gpu_index, output, 0,
                                           num_blocks, input, 0, num_blocks);
}

template <typename Torus>
__host__ void
host_binary_tree_sum(cudaStream_t stream, uint32_t gpu_index,
                     CudaRadixCiphertextFFI *output,
                     CudaRadixCiphertextFFI *input, uint32_t num_entries,
                     uint32_t num_blocks, uint32_t polynomial_size,
                     uint32_t message_modulus, uint32_t carry_modulus) {
  switch (polynomial_size) {
  case 256:
    host_binary_tree_sum_impl<Torus, Degree<256>>(
        stream, gpu_index, output, input, num_entries, num_blocks,
        message_modulus, carry_modulus);
    break;
  case 512:
    host_binary_tree_sum_impl<Torus, Degree<512>>(
        stream, gpu_index, output, input, num_entries, num_blocks,
        message_modulus, carry_modulus);
    break;
  case 1024:
    host_binary_tree_sum_impl<Torus, Degree<1024>>(
        stream, gpu_index, output, input, num_entries, num_blocks,
        message_modulus, carry_modulus);
    break;
  case 2048:
    host_binary_tree_sum_impl<Torus, Degree<2048>>(
        stream, gpu_index, output, input, num_entries, num_blocks,
        message_modulus, carry_modulus);
    break;
  case 4096:
    host_binary_tree_sum_impl<Torus, Degree<4096>>(
        stream, gpu_index, output, input, num_entries, num_blocks,
        message_modulus, carry_modulus);
    break;
  case 8192:
    host_binary_tree_sum_impl<Torus, Degree<8192>>(
        stream, gpu_index, output, input, num_entries, num_blocks,
        message_modulus, carry_modulus);
    break;
  case 16384:
    host_binary_tree_sum_impl<Torus, Degree<16384>>(
        stream, gpu_index, output, input, num_entries, num_blocks,
        message_modulus, carry_modulus);
    break;
  default:
    PANIC("Cuda error (binary_tree_sum): unsupported polynomial size. "
          "Supported N's are powers of two in the interval [256..16384].")
  }
}

#endif // CUDA_ADD_H
