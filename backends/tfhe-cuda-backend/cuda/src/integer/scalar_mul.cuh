#ifndef CUDA_INTEGER_SCALAR_MUL_CUH
#define CUDA_INTEGER_SCALAR_MUL_CUH

#ifdef __CDT_PARSER__
#undef __CUDA_RUNTIME_H__
#include <cuda_runtime.h>
#endif

#include "device.h"
#include "integer/integer_utilities.h"
#include "multiplication.cuh"
#include "scalar_shifts.cuh"
#include "utils/kernel_dimensions.cuh"
#include <stdio.h>

template <typename T>
__global__ void device_small_scalar_radix_multiplication(T *output_lwe_array,
                                                         T *input_lwe_array,
                                                         T scalar,
                                                         uint32_t lwe_dimension,
                                                         uint32_t num_blocks) {
  int index = blockIdx.x * blockDim.x + threadIdx.x;
  int lwe_size = lwe_dimension + 1;
  if (index < num_blocks * lwe_size) {
    // Here we take advantage of the wrapping behaviour of uint
    output_lwe_array[index] = input_lwe_array[index] * scalar;
  }
}

template <typename T>
__host__ void scratch_cuda_integer_radix_scalar_mul_kb(
    cudaStream_t const *streams, uint32_t const *gpu_indexes,
    uint32_t gpu_count, int_scalar_mul_buffer<T> **mem_ptr,
    uint32_t num_radix_blocks, int_radix_params params,
    bool allocate_gpu_memory) {

  *mem_ptr =
      new int_scalar_mul_buffer<T>(streams, gpu_indexes, gpu_count, params,
                                   num_radix_blocks, allocate_gpu_memory, true);
}

template <typename T, class params>
__host__ void host_integer_scalar_mul_radix(
    cudaStream_t const *streams, uint32_t const *gpu_indexes,
    uint32_t gpu_count, CudaRadixCiphertextFFI *lwe_array,
    T const *decomposed_scalar, T const *has_at_least_one_set,
    int_scalar_mul_buffer<T> *mem, void *const *bsks, T *const *ksks,
    uint32_t message_modulus, uint32_t num_scalars) {

  auto num_radix_blocks = lwe_array->num_radix_blocks;
  // lwe_size includes the presence of the body
  // whereas lwe_dimension is the number of elements in the mask
  uint32_t msg_bits = log2_int(message_modulus);
  uint32_t num_ciphertext_bits = msg_bits * num_radix_blocks;

  auto preshifted_buffer = mem->preshifted_buffer;
  auto all_shifted_buffer = mem->all_shifted_buffer;

  for (size_t shift_amount = 0; shift_amount < msg_bits; shift_amount++) {
    CudaRadixCiphertextFFI shift_input;
    as_radix_ciphertext_slice<T>(&shift_input, preshifted_buffer,
                                 shift_amount * num_radix_blocks,
                                 preshifted_buffer->num_radix_blocks);
    if (has_at_least_one_set[shift_amount] == 1) {
      copy_radix_ciphertext_slice_async<T>(streams[0], gpu_indexes[0],
                                           &shift_input, 0, num_radix_blocks,
                                           lwe_array, 0, num_radix_blocks);
      host_integer_radix_logical_scalar_shift_kb_inplace<T>(
          streams, gpu_indexes, gpu_count, &shift_input, shift_amount,
          mem->logical_scalar_shift_buffer, bsks, ksks, num_radix_blocks);
    } else {
      // create trivial assign for value = 0
      set_zero_radix_ciphertext_slice_async<T>(
          streams[0], gpu_indexes[0], &shift_input, 0, num_radix_blocks);
    }
  }
  size_t j = 0;
  for (size_t i = 0; i < min(num_scalars, num_ciphertext_bits); i++) {
    if (decomposed_scalar[i] == 1) {
      // Perform a block shift
      CudaRadixCiphertextFFI preshifted_radix_ct;
      as_radix_ciphertext_slice<T>(&preshifted_radix_ct, preshifted_buffer,
                                   (i % msg_bits) * num_radix_blocks,
                                   preshifted_buffer->num_radix_blocks);
      CudaRadixCiphertextFFI block_shift_buffer;
      as_radix_ciphertext_slice<T>(&block_shift_buffer, all_shifted_buffer,
                                   j * num_radix_blocks,
                                   all_shifted_buffer->num_radix_blocks);
      host_radix_blocks_rotate_right<T>(
          streams, gpu_indexes, gpu_count, &block_shift_buffer,
          &preshifted_radix_ct, i / msg_bits, num_radix_blocks);
      // create trivial assign for value = 0
      set_zero_radix_ciphertext_slice_async<T>(
          streams[0], gpu_indexes[0], &block_shift_buffer, 0, i / msg_bits);
      j++;
    }
  }
  cuda_synchronize_stream(streams[0], gpu_indexes[0]);

  if (mem->anticipated_buffers_drop) {
    release_radix_ciphertext(streams[0], gpu_indexes[0], preshifted_buffer);
    delete preshifted_buffer;
    mem->logical_scalar_shift_buffer->release(streams, gpu_indexes, gpu_count);
    delete (mem->logical_scalar_shift_buffer);
  }

  if (j == 0) {
    // lwe array = 0
    set_zero_radix_ciphertext_slice_async<T>(streams[0], gpu_indexes[0],
                                             lwe_array, 0, num_radix_blocks);
  } else {
    for (int i = 0; i < j * num_radix_blocks; i++) {
      all_shifted_buffer->degrees[i] = message_modulus - 1;
    }
    host_integer_partial_sum_ciphertexts_vec_kb<T, params>(
        streams, gpu_indexes, gpu_count, lwe_array, all_shifted_buffer, bsks,
        ksks, mem->sum_ciphertexts_vec_mem, num_radix_blocks, j, nullptr);

    auto scp_mem_ptr = mem->sc_prop_mem;
    uint32_t requested_flag = outputFlag::FLAG_NONE;
    uint32_t uses_carry = 0;
    host_propagate_single_carry<T>(streams, gpu_indexes, gpu_count, lwe_array,
                                   nullptr, nullptr, scp_mem_ptr, bsks, ksks,
                                   requested_flag, uses_carry);
  }
}

// Small scalar_mul is used in shift/rotate
template <typename T>
__host__ void host_legacy_integer_small_scalar_mul_radix(
    cudaStream_t const *streams, uint32_t const *gpu_indexes,
    uint32_t gpu_count, T *output_lwe_array, T *input_lwe_array, T scalar,
    uint32_t input_lwe_dimension, uint32_t input_lwe_ciphertext_count) {

  cuda_set_device(gpu_indexes[0]);
  // lwe_size includes the presence of the body
  // whereas lwe_dimension is the number of elements in the mask
  int lwe_size = input_lwe_dimension + 1;
  // Create a 1-dimensional grid of threads
  int num_blocks = 0, num_threads = 0;
  int num_entries = input_lwe_ciphertext_count * lwe_size;
  getNumBlocksAndThreads(num_entries, 512, num_blocks, num_threads);
  dim3 grid(num_blocks, 1, 1);
  dim3 thds(num_threads, 1, 1);

  device_small_scalar_radix_multiplication<<<grid, thds, 0, streams[0]>>>(
      output_lwe_array, input_lwe_array, scalar, input_lwe_dimension,
      input_lwe_ciphertext_count);
  check_cuda_error(cudaGetLastError());
}

// Small scalar_mul is used in shift/rotate
template <typename T>
__host__ void host_integer_small_scalar_mul_radix(
    cudaStream_t const *streams, uint32_t const *gpu_indexes,
    uint32_t gpu_count, CudaRadixCiphertextFFI *output_lwe_array,
    CudaRadixCiphertextFFI *input_lwe_array, T scalar) {

  if (output_lwe_array->num_radix_blocks != input_lwe_array->num_radix_blocks)
    PANIC("Cuda error: input and output num radix blocks must be the same")
  if (output_lwe_array->lwe_dimension != input_lwe_array->lwe_dimension)
    PANIC("Cuda error: input and output lwe_dimension must be the same")

  cuda_set_device(gpu_indexes[0]);
  auto lwe_dimension = input_lwe_array->lwe_dimension;
  auto num_radix_blocks = input_lwe_array->num_radix_blocks;

  // lwe_size includes the presence of the body
  // whereas lwe_dimension is the number of elements in the mask
  int lwe_size = lwe_dimension + 1;
  // Create a 1-dimensional grid of threads
  int num_blocks = 0, num_threads = 0;
  int num_entries = num_radix_blocks * lwe_size;
  getNumBlocksAndThreads(num_entries, 512, num_blocks, num_threads);
  dim3 grid(num_blocks, 1, 1);
  dim3 thds(num_threads, 1, 1);

  device_small_scalar_radix_multiplication<<<grid, thds, 0, streams[0]>>>(
      (T *)output_lwe_array->ptr, (T *)input_lwe_array->ptr, scalar,
      lwe_dimension, num_radix_blocks);
  check_cuda_error(cudaGetLastError());

  for (int i = 0; i < num_radix_blocks; i++) {
    output_lwe_array->noise_levels[i] =
        input_lwe_array->noise_levels[i] * scalar;
    output_lwe_array->degrees[i] = input_lwe_array->degrees[i] * scalar;
  }
}
#endif
