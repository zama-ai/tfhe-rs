#ifndef CUDA_INTEGER_CUH
#define CUDA_INTEGER_CUH

#include "crypto/keyswitch.cuh"
#include "device.h"
#include "helper_multi_gpu.h"
#include "integer/integer_utilities.h"
#include "integer/scalar_addition.cuh"
#include "linear_algebra.h"
#include "linearalgebra/addition.cuh"
#include "linearalgebra/negation.cuh"
#include "pbs/programmable_bootstrap.h"
#include "polynomial/functions.cuh"
#include "utils/helper.cuh"
#include "utils/helper_multi_gpu.cuh"
#include "utils/kernel_dimensions.cuh"
#include <functional>

// function rotates right  radix ciphertext with specific value
// grid is one dimensional
// blockIdx.x represents x_th block of radix ciphertext
template <typename Torus>
__global__ void radix_blocks_rotate_right(Torus *dst, Torus *src,
                                          uint32_t value, uint32_t blocks_count,
                                          uint32_t lwe_size) {
  size_t tid = threadIdx.x;
  if (tid < lwe_size) {
    value %= blocks_count;
    size_t src_block_id = blockIdx.x;
    size_t dst_block_id = (src_block_id + value) % blocks_count;
    size_t stride = blockDim.x;

    auto cur_src_block = &src[src_block_id * lwe_size];
    auto cur_dst_block = &dst[dst_block_id * lwe_size];

    for (size_t i = tid; i < lwe_size; i += stride) {
      cur_dst_block[i] = cur_src_block[i];
    }
  }
}

// function rotates left  radix ciphertext with specific value
// grid is one dimensional
// blockIdx.x represents x_th block of radix ciphertext
template <typename Torus>
__global__ void radix_blocks_rotate_left(Torus *dst, Torus *src, uint32_t value,
                                         uint32_t blocks_count,
                                         uint32_t lwe_size) {
  size_t tid = threadIdx.x;
  if (tid < lwe_size) {
    value %= blocks_count;
    size_t src_block_id = blockIdx.x;

    size_t dst_block_id = (src_block_id >= value)
                              ? src_block_id - value
                              : src_block_id - value + blocks_count;
    size_t stride = blockDim.x;

    auto cur_src_block = &src[src_block_id * lwe_size];
    auto cur_dst_block = &dst[dst_block_id * lwe_size];

    for (size_t i = tid; i < lwe_size; i += stride) {
      cur_dst_block[i] = cur_src_block[i];
    }
  }
}

// rotate an array in the CPU memory by value positions
template <typename Torus>
__host__ void array_rotate_right(Torus *array_out, Torus *array_in,
                                 uint32_t value, uint32_t num_elements) {
  value %= num_elements;
  for (uint32_t i = 0; i < num_elements; i++) {
    auto src_i = (size_t)i;
    auto dst_j = (src_i + value) % num_elements;
    array_out[dst_j] = array_in[src_i];
  }
}

// rotate an array in the CPU memory by value positions
template <typename Torus>
__host__ void array_rotate_left(Torus *array_out, Torus *array_in,
                                uint32_t value, uint32_t num_elements) {
  value %= num_elements;
  for (uint32_t i = 0; i < num_elements; i++) {
    auto src_i = (size_t)i;
    auto dst_j =
        (src_i >= value) ? src_i - value : src_i - value + num_elements;
    array_out[dst_j] = array_in[src_i];
  }
}

// rotate radix ciphertext right with specific rotations
// calculation is not inplace, so `dst` and `src` must not be the same
// one block is responsible to process single lwe ciphertext
template <typename Torus>
__host__ void host_radix_blocks_rotate_right(
    cudaStream_t const *streams, uint32_t const *gpu_indexes,
    uint32_t gpu_count, CudaRadixCiphertextFFI *dst,
    CudaRadixCiphertextFFI *src, uint32_t rotations, uint32_t num_blocks) {
  if (src == dst) {
    PANIC("Cuda error (blocks_rotate_right): the source and destination "
          "pointers should be different");
  }
  if (dst->lwe_dimension != src->lwe_dimension)
    PANIC("Cuda error: input and output should have the same "
          "lwe dimension")
  if (dst->num_radix_blocks < num_blocks || src->num_radix_blocks < num_blocks)
    PANIC("Cuda error: input and output should have more blocks than asked for "
          "in the "
          "function call")

  auto lwe_size = src->lwe_dimension + 1;

  cuda_set_device(gpu_indexes[0]);
  radix_blocks_rotate_right<Torus><<<num_blocks, 1024, 0, streams[0]>>>(
      (Torus *)dst->ptr, (Torus *)src->ptr, rotations, num_blocks, lwe_size);
  check_cuda_error(cudaGetLastError());

  // Rotate degrees and noise to follow blocks
  array_rotate_right(dst->degrees, src->degrees, rotations, num_blocks);
  array_rotate_right(dst->noise_levels, src->noise_levels, rotations,
                     num_blocks);
}

// rotate radix ciphertext left with specific value
// calculation is not inplace, so `dst` and `src` must not be the same
template <typename Torus>
__host__ void host_radix_blocks_rotate_left(
    cudaStream_t const *streams, uint32_t const *gpu_indexes,
    uint32_t gpu_count, CudaRadixCiphertextFFI *dst,
    CudaRadixCiphertextFFI *src, uint32_t value, uint32_t num_blocks) {
  if (src == dst) {
    PANIC("Cuda error (blocks_rotate_left): the source and destination "
          "pointers should be different");
  }

  if (dst->lwe_dimension != src->lwe_dimension)
    PANIC("Cuda error: input and output should have the same "
          "lwe dimension")
  if (dst->num_radix_blocks < num_blocks || src->num_radix_blocks < num_blocks)
    PANIC("Cuda error: input and output should have more blocks than asked for "
          "in the "
          "function call")

  auto lwe_size = src->lwe_dimension + 1;

  cuda_set_device(gpu_indexes[0]);
  radix_blocks_rotate_left<Torus><<<num_blocks, 1024, 0, streams[0]>>>(
      (Torus *)dst->ptr, (Torus *)src->ptr, value, num_blocks, lwe_size);
  check_cuda_error(cudaGetLastError());

  // Rotate degrees and noise to follow blocks
  array_rotate_left(dst->degrees, src->degrees, value, num_blocks);
  array_rotate_left(dst->noise_levels, src->noise_levels, value, num_blocks);
}

// rotate radix ciphertext right with specific value
// calculation is not inplace, so `dst` and `src` must not be the same
// one block is responsible to process single lwe ciphertext
template <typename Torus>
__host__ void legacy_host_radix_blocks_rotate_right(
    cudaStream_t const *streams, uint32_t const *gpu_indexes,
    uint32_t gpu_count, Torus *dst, Torus *src, uint32_t value,
    uint32_t blocks_count, uint32_t lwe_size) {
  if (src == dst) {
    PANIC("Cuda error (blocks_rotate_right): the source and destination "
          "pointers should be different");
  }
  cuda_set_device(gpu_indexes[0]);
  radix_blocks_rotate_right<Torus><<<blocks_count, 1024, 0, streams[0]>>>(
      dst, src, value, blocks_count, lwe_size);
  check_cuda_error(cudaGetLastError());
}

// rotate radix ciphertext left with specific value
// calculation is not inplace, so `dst` and `src` must not be the same
template <typename Torus>
__host__ void legacy_host_radix_blocks_rotate_left(
    cudaStream_t const *streams, uint32_t const *gpu_indexes,
    uint32_t gpu_count, Torus *dst, Torus *src, uint32_t value,
    uint32_t blocks_count, uint32_t lwe_size) {
  if (src == dst) {
    PANIC("Cuda error (blocks_rotate_left): the source and destination "
          "pointers should be different");
  }
  cuda_set_device(gpu_indexes[0]);
  radix_blocks_rotate_left<Torus><<<blocks_count, 1024, 0, streams[0]>>>(
      dst, src, value, blocks_count, lwe_size);
  check_cuda_error(cudaGetLastError());
}

// reverse the blocks in a list
// each cuda block swaps a couple of blocks
template <typename Torus>
__global__ void radix_blocks_reverse_lwe_inplace(Torus *src,
                                                 uint32_t blocks_count,
                                                 uint32_t lwe_size) {

  size_t idx = blockIdx.x;
  size_t rev_idx = blocks_count - 1 - idx;

  for (int j = threadIdx.x; j < lwe_size; j += blockDim.x) {
    Torus back_element = src[rev_idx * lwe_size + j];
    Torus front_element = src[idx * lwe_size + j];
    src[idx * lwe_size + j] = back_element;
    src[rev_idx * lwe_size + j] = front_element;
  }
}

/// This function does not update noise level/degree at this stage,
/// it can be added later
template <typename Torus>
__host__ void host_radix_blocks_reverse_inplace(cudaStream_t const *streams,
                                                uint32_t const *gpu_indexes,
                                                CudaRadixCiphertextFFI *src) {
  cuda_set_device(gpu_indexes[0]);
  int num_blocks = src->num_radix_blocks / 2, num_threads = 1024;
  radix_blocks_reverse_lwe_inplace<Torus>
      <<<num_blocks, num_threads, 0, streams[0]>>>(
          (Torus *)src->ptr, src->num_radix_blocks, src->lwe_dimension + 1);
  check_cuda_error(cudaGetLastError());
}

// If group_size = 4, the first group of 4 elements will be transformed as
// follows:
//  dest[0] = src[0]
//  dest[1] = src[0] + src[1]
//  dest[2] = src[0] + src[1] + src[2]
//  dest[3] = src[0] + src[1] + src[2] + src[3]
template <typename Torus>
__global__ void device_radix_cumulative_sum_in_groups(Torus *dest, Torus *src,
                                                      uint32_t blocks_count,
                                                      uint32_t lwe_size,
                                                      uint32_t group_size) {

  size_t block_offset = blockIdx.x * group_size * lwe_size;

  for (int j = threadIdx.x; j < lwe_size; j += blockDim.x) {
    size_t idx = j + block_offset;
    Torus sum = src[idx];
    dest[idx] = sum;
    for (int gidx = 1; gidx < group_size; gidx++) {
      if (gidx + blockIdx.x * group_size <
          blocks_count) { // in case the last group is not full
        sum += src[idx + gidx * lwe_size];
        dest[idx + gidx * lwe_size] = sum;
      }
    }
  }
}

template <typename Torus>
__host__ void legacy_host_radix_cumulative_sum_in_groups(
    cudaStream_t stream, uint32_t gpu_index, Torus *dest, Torus *src,
    uint32_t radix_blocks_count, uint32_t lwe_size, uint32_t group_size) {

  cuda_set_device(gpu_index);
  // Each CUDA block is responsible for a single group
  int num_blocks = (radix_blocks_count + group_size - 1) / group_size,
      num_threads = 512;
  device_radix_cumulative_sum_in_groups<Torus>
      <<<num_blocks, num_threads, 0, stream>>>(dest, src, radix_blocks_count,
                                               lwe_size, group_size);
  check_cuda_error(cudaGetLastError());
}

/// This function does not update noise level/degree at this stage,
/// it can be added later
template <typename Torus>
__host__ void host_radix_cumulative_sum_in_groups(cudaStream_t stream,
                                                  uint32_t gpu_index,
                                                  CudaRadixCiphertextFFI *dest,
                                                  CudaRadixCiphertextFFI *src,
                                                  uint32_t num_radix_blocks,
                                                  uint32_t group_size) {
  if (dest->lwe_dimension != src->lwe_dimension)
    PANIC("Cuda error: input and output radix ciphertexts should have the same "
          "lwe dimension")
  if (num_radix_blocks > dest->num_radix_blocks ||
      num_radix_blocks > src->num_radix_blocks)
    PANIC("Cuda error: input and output num radix blocks should have more "
          "blocks than the number used in cum sum")

  auto lwe_size = dest->lwe_dimension + 1;
  cuda_set_device(gpu_index);
  // Each CUDA block is responsible for a single group
  int num_blocks = (num_radix_blocks + group_size - 1) / group_size,
      num_threads = 512;
  device_radix_cumulative_sum_in_groups<Torus>
      <<<num_blocks, num_threads, 0, stream>>>(
          (Torus *)dest->ptr, (Torus *)src->ptr, num_radix_blocks, lwe_size,
          group_size);
  check_cuda_error(cudaGetLastError());
}

template <typename Torus>
__global__ void device_radix_split_simulators_and_grouping_pgns(
    Torus *simulators, Torus *grouping_pgns, Torus *src, uint32_t blocks_count,
    uint32_t lwe_size, uint32_t group_size, Torus delta) {

  size_t block_offset = blockIdx.x * lwe_size;
  if (blockIdx.x % group_size == 0) {
    if (blockIdx.x == 0) {
      // save trivial 0
      for (int j = threadIdx.x; j < lwe_size; j += blockDim.x) {
        simulators[j] = 0;
      }
    } else {
      // save trivial 1
      for (int j = threadIdx.x; j < lwe_size - 1; j += blockDim.x) {
        size_t simu_idx = j + block_offset;
        simulators[simu_idx] = 0;
      }
      if (threadIdx.x == 0) {
        simulators[lwe_size - 1 + block_offset] = 1 * delta;
      }
    }

    if ((blockIdx.x / group_size + 1) <
        (blocks_count + group_size - 1) / group_size) {
      size_t src_offset = (blockIdx.x + group_size - 1) * lwe_size;
      size_t pgns_offset = (blockIdx.x / group_size) * lwe_size;
      for (int j = threadIdx.x; j < lwe_size; j += blockDim.x) {
        size_t in_offset = j + src_offset;
        size_t out_offset = j + pgns_offset;
        grouping_pgns[out_offset] = src[in_offset];
      }
    }
  } else {
    // save simulators
    size_t src_offset = (blockIdx.x - 1) * lwe_size;
    for (int j = threadIdx.x; j < lwe_size; j += blockDim.x) {
      simulators[j + block_offset] = src[j + src_offset];
    }
  }
}

template <typename Torus>
__host__ void legacy_host_radix_split_simulators_and_grouping_pgns(
    cudaStream_t stream, uint32_t gpu_index, Torus *simulators,
    Torus *grouping_pgns, Torus *src, uint32_t radix_blocks_count,
    uint32_t lwe_size, uint32_t group_size, Torus delta) {

  cuda_set_device(gpu_index);
  // Each CUDA block is responsible for a single group
  int num_blocks = radix_blocks_count, num_threads = 512;
  device_radix_split_simulators_and_grouping_pgns<Torus>
      <<<num_blocks, num_threads, 0, stream>>>(simulators, grouping_pgns, src,
                                               radix_blocks_count, lwe_size,
                                               group_size, delta);
  check_cuda_error(cudaGetLastError());
}

/// This function does not update noise level/degree at this stage,
/// it can be added later
template <typename Torus>
__host__ void host_radix_split_simulators_and_grouping_pgns(
    cudaStream_t stream, uint32_t gpu_index, CudaRadixCiphertextFFI *simulators,
    CudaRadixCiphertextFFI *grouping_pgns, CudaRadixCiphertextFFI *src,
    uint32_t num_radix_blocks, uint32_t group_size, Torus delta) {

  if (simulators->lwe_dimension != src->lwe_dimension ||
      simulators->lwe_dimension != grouping_pgns->lwe_dimension)
    PANIC("Cuda error: input and output radix ciphertexts should have the same "
          "lwe dimension")
  if (num_radix_blocks > simulators->num_radix_blocks)
    PANIC("Cuda error: simulators num radix blocks should have more "
          "blocks than the number used in split "
          "simulators and grouping pgns")
  if (num_radix_blocks > src->num_radix_blocks)
    PANIC("Cuda error: src num radix blocks should have more "
          "blocks than the number used in split "
          "simulators and grouping pgns")

  cuda_set_device(gpu_index);
  auto lwe_size = simulators->lwe_dimension + 1;
  // Each CUDA block is responsible for a single group
  int num_blocks = num_radix_blocks, num_threads = 512;
  device_radix_split_simulators_and_grouping_pgns<Torus>
      <<<num_blocks, num_threads, 0, stream>>>(
          (Torus *)simulators->ptr, (Torus *)grouping_pgns->ptr,
          (Torus *)src->ptr, num_radix_blocks, lwe_size, group_size, delta);
  check_cuda_error(cudaGetLastError());
}

// If group_size = 4, the first group of 4 elements will be transformed as
// follows:
//  src1 size num_radix_blocks * lwe_size
//  src2 size num_group * lwe_size
//  dest[0] = src1[0] + src2[0]
//  dest[1] = src1[1] + src2[0]
//  dest[2] = src1[2] + src2[0]
//  dest[3] = src1[3] + src2[0]
template <typename Torus>
__global__ void device_radix_sum_in_groups(Torus *dest, Torus *src1,
                                           Torus *src2, uint32_t blocks_count,
                                           uint32_t lwe_size,
                                           uint32_t group_size) {

  size_t src1_offset = blockIdx.x * lwe_size;
  size_t src2_index = (blockIdx.x / group_size) * lwe_size;
  for (int j = threadIdx.x; j < lwe_size; j += blockDim.x) {
    size_t idx = j + src1_offset;
    dest[idx] = src1[idx] + src2[j + src2_index];
  }
}

template <typename Torus>
__host__ void
legacy_host_radix_sum_in_groups(cudaStream_t stream, uint32_t gpu_index,
                                Torus *dest, Torus *src1, Torus *src2,
                                uint32_t radix_blocks_count, uint32_t lwe_size,
                                uint32_t group_size) {
  cuda_set_device(gpu_index);

  int num_blocks = radix_blocks_count, num_threads = 512;
  device_radix_sum_in_groups<Torus><<<num_blocks, num_threads, 0, stream>>>(
      dest, src1, src2, radix_blocks_count, lwe_size, group_size);
  check_cuda_error(cudaGetLastError());
}
/// This function does not update noise level
/// /degree at this stage, could be added later
template <typename Torus>
__host__ void host_radix_sum_in_groups(cudaStream_t stream, uint32_t gpu_index,
                                       CudaRadixCiphertextFFI *dest,
                                       CudaRadixCiphertextFFI *src1,
                                       CudaRadixCiphertextFFI *src2,
                                       uint32_t num_radix_blocks,
                                       uint32_t group_size) {
  if (dest->lwe_dimension != src1->lwe_dimension ||
      dest->lwe_dimension != src2->lwe_dimension)
    PANIC("Cuda error: input and output radix ciphertexts should have the same "
          "lwe dimension")
  if (num_radix_blocks > dest->num_radix_blocks ||
      num_radix_blocks > src1->num_radix_blocks)
    PANIC("Cuda error: input and output num radix blocks should have more "
          "blocks than the number used in sum in groups")
  auto num_groups = (num_radix_blocks + group_size - 1) / group_size;
  if (src2->num_radix_blocks < num_groups)
    PANIC("Cuda error: second input in sum in groups should have at least "
          "num_groups blocks")

  cuda_set_device(gpu_index);
  auto lwe_size = dest->lwe_dimension + 1;
  int num_blocks = num_radix_blocks, num_threads = 512;
  device_radix_sum_in_groups<Torus><<<num_blocks, num_threads, 0, stream>>>(
      (Torus *)dest->ptr, (Torus *)src1->ptr, (Torus *)src2->ptr,
      num_radix_blocks, lwe_size, group_size);
  check_cuda_error(cudaGetLastError());
}

// polynomial_size threads
template <typename Torus>
__global__ void
device_pack_bivariate_blocks(Torus *lwe_array_out, Torus const *lwe_indexes_out,
                             Torus const *lwe_array_1, Torus const *lwe_array_2,
                             Torus const *lwe_indexes_in,
                             uint32_t lwe_dimension, uint32_t shift,
                             uint32_t num_blocks) {
  int tid = threadIdx.x + blockIdx.x * blockDim.x;

  if (tid < num_blocks * (lwe_dimension + 1)) {
    int block_id = tid / (lwe_dimension + 1);
    int coeff_id = tid % (lwe_dimension + 1);

    const int pos_in =
        lwe_indexes_in[block_id] * (lwe_dimension + 1) + coeff_id;
    const int pos_out =
        lwe_indexes_out[block_id] * (lwe_dimension + 1) + coeff_id;
    lwe_array_out[pos_out] = lwe_array_1[pos_in] * shift + lwe_array_2[pos_in];
  }
}

template <typename Torus>
__host__ void legacy_host_pack_bivariate_blocks(
    cudaStream_t const *streams, uint32_t const *gpu_indexes,
    uint32_t gpu_count, Torus *lwe_array_out, Torus const *lwe_indexes_out,
    Torus const *lwe_array_1, Torus const *lwe_array_2,
    Torus const *lwe_indexes_in, uint32_t lwe_dimension, uint32_t shift,
    uint32_t num_radix_blocks) {

  cuda_set_device(gpu_indexes[0]);
  // Left message is shifted
  int num_blocks = 0, num_threads = 0;
  int num_entries = num_radix_blocks * (lwe_dimension + 1);
  getNumBlocksAndThreads(num_entries, 512, num_blocks, num_threads);
  device_pack_bivariate_blocks<Torus>
      <<<num_blocks, num_threads, 0, streams[0]>>>(
          lwe_array_out, lwe_indexes_out, lwe_array_1, lwe_array_2,
          lwe_indexes_in, lwe_dimension, shift, num_radix_blocks);
  check_cuda_error(cudaGetLastError());
}

/* Combine lwe_array_1 and lwe_array_2 so that each block m1 and m2
 *  becomes out = m1 * shift + m2
 */
/// This function does not update noise level/degree at this stage,
/// it can be added later
template <typename Torus>
__host__ void host_pack_bivariate_blocks(
    cudaStream_t const *streams, uint32_t const *gpu_indexes,
    uint32_t gpu_count, CudaRadixCiphertextFFI *lwe_array_out,
    Torus const *lwe_indexes_out, CudaRadixCiphertextFFI const *lwe_array_1,
    CudaRadixCiphertextFFI const *lwe_array_2, Torus const *lwe_indexes_in,
    uint32_t shift, uint32_t num_radix_blocks) {

  if (lwe_array_out->lwe_dimension != lwe_array_1->lwe_dimension ||
      lwe_array_out->lwe_dimension != lwe_array_2->lwe_dimension)
    PANIC("Cuda error: input and output radix ciphertexts should have the same "
          "lwe dimension")
  if (num_radix_blocks > lwe_array_out->num_radix_blocks ||
      num_radix_blocks > lwe_array_1->num_radix_blocks ||
      num_radix_blocks > lwe_array_2->num_radix_blocks)
    PANIC("Cuda error: num radix blocks on which packing is applied should be "
          "smaller or equal to the number of input & output radix blocks")

  auto lwe_dimension = lwe_array_out->lwe_dimension;
  cuda_set_device(gpu_indexes[0]);
  // Left message is shifted
  int num_blocks = 0, num_threads = 0;
  int num_entries = num_radix_blocks * (lwe_dimension + 1);
  getNumBlocksAndThreads(num_entries, 512, num_blocks, num_threads);
  device_pack_bivariate_blocks<Torus>
      <<<num_blocks, num_threads, 0, streams[0]>>>(
          (Torus *)lwe_array_out->ptr, lwe_indexes_out,
          (Torus *)lwe_array_1->ptr, (Torus *)lwe_array_2->ptr, lwe_indexes_in,
          lwe_dimension, shift, num_radix_blocks);
  check_cuda_error(cudaGetLastError());
}

// polynomial_size threads
template <typename Torus>
__global__ void device_pack_bivariate_blocks_with_single_block(
    Torus *lwe_array_out, Torus const *lwe_indexes_out,
    Torus const *lwe_array_1, Torus const *lwe_2, Torus const *lwe_indexes_in,
    uint32_t lwe_dimension, uint32_t shift, uint32_t num_blocks) {
  int tid = threadIdx.x + blockIdx.x * blockDim.x;

  if (tid < num_blocks * (lwe_dimension + 1)) {
    int block_id = tid / (lwe_dimension + 1);
    int coeff_id = tid % (lwe_dimension + 1);

    const int pos_in =
        lwe_indexes_in[block_id] * (lwe_dimension + 1) + coeff_id;
    const int pos_out =
        lwe_indexes_out[block_id] * (lwe_dimension + 1) + coeff_id;
    lwe_array_out[pos_out] = lwe_array_1[pos_in] * shift + lwe_2[coeff_id];
  }
}

/* Combine lwe_array_1 and lwe_2 so that each block m1 and lwe_2
 *  becomes out = m1 * shift + lwe_2
 *
 *  This is for the special case when one of the operands is not an array
 */
template <typename Torus>
__host__ void host_pack_bivariate_blocks_with_single_block(
    cudaStream_t const *streams, uint32_t const *gpu_indexes,
    uint32_t gpu_count, CudaRadixCiphertextFFI *lwe_array_out,
    Torus const *lwe_indexes_out, CudaRadixCiphertextFFI const *lwe_array_1,
    CudaRadixCiphertextFFI const *lwe_2, Torus const *lwe_indexes_in,
    uint32_t shift, uint32_t num_radix_blocks) {

  if (lwe_array_out->num_radix_blocks < num_radix_blocks ||
      lwe_array_1->num_radix_blocks < num_radix_blocks)
    PANIC("Cuda error: input or output radix ciphertexts does not have enough "
          "blocks")
  if (lwe_array_out->lwe_dimension != lwe_array_1->lwe_dimension ||
      lwe_array_1->lwe_dimension != lwe_2->lwe_dimension)
    PANIC("Cuda error: input and output radix ciphertexts must have the same "
          "lwe dimension")
  auto lwe_dimension = lwe_array_out->lwe_dimension;
  cuda_set_device(gpu_indexes[0]);
  // Left message is shifted
  int num_blocks = 0, num_threads = 0;
  int num_entries = num_radix_blocks * (lwe_dimension + 1);
  getNumBlocksAndThreads(num_entries, 512, num_blocks, num_threads);
  device_pack_bivariate_blocks_with_single_block<Torus>
      <<<num_blocks, num_threads, 0, streams[0]>>>(
          (Torus *)lwe_array_out->ptr, lwe_indexes_out,
          (Torus *)lwe_array_1->ptr, (Torus *)lwe_2->ptr, lwe_indexes_in,
          lwe_dimension, shift, num_radix_blocks);
  check_cuda_error(cudaGetLastError());
}

/// num_radix_blocks corresponds to the number of blocks on which to apply the
/// LUT In scalar bitops we use a number of blocks that may be lower or equal to
/// the input and output numbers of blocks
template <typename Torus>
__host__ void integer_radix_apply_univariate_lookup_table_kb(
    cudaStream_t const *streams, uint32_t const *gpu_indexes,
    uint32_t gpu_count, CudaRadixCiphertextFFI *lwe_array_out,
    CudaRadixCiphertextFFI const *lwe_array_in, void *const *bsks,
    Torus *const *ksks, int_radix_lut<Torus> *lut, uint32_t num_radix_blocks) {
  // apply_lookup_table
  auto params = lut->params;
  auto pbs_type = params.pbs_type;
  auto big_lwe_dimension = params.big_lwe_dimension;
  auto small_lwe_dimension = params.small_lwe_dimension;
  auto ks_level = params.ks_level;
  auto ks_base_log = params.ks_base_log;
  auto pbs_level = params.pbs_level;
  auto pbs_base_log = params.pbs_base_log;
  auto glwe_dimension = params.glwe_dimension;
  auto polynomial_size = params.polynomial_size;
  auto grouping_factor = params.grouping_factor;

  if (lwe_array_out->lwe_dimension != lwe_array_in->lwe_dimension)
    PANIC("Cuda error: input and output radix ciphertexts should have the same "
          "lwe dimension")
  if (num_radix_blocks > lut->num_blocks)
    PANIC("Cuda error: num radix blocks on which lut is applied should be "
          "smaller or equal to the number of lut radix blocks")
  if (num_radix_blocks > lwe_array_out->num_radix_blocks ||
      num_radix_blocks > lwe_array_in->num_radix_blocks)
    PANIC("Cuda error: num radix blocks on which lut is applied should be "
          "smaller or equal to the number of input & output radix blocks")

  // In the case of extracting a single LWE this parameters are dummy
  uint32_t num_many_lut = 1;
  uint32_t lut_stride = 0;
  /// For multi GPU execution we create vectors of pointers for inputs and
  /// outputs
  std::vector<Torus *> lwe_array_in_vec = lut->lwe_array_in_vec;
  std::vector<Torus *> lwe_after_ks_vec = lut->lwe_after_ks_vec;
  std::vector<Torus *> lwe_after_pbs_vec = lut->lwe_after_pbs_vec;
  std::vector<Torus *> lwe_trivial_indexes_vec = lut->lwe_trivial_indexes_vec;

  auto active_gpu_count = get_active_gpu_count(num_radix_blocks, gpu_count);
  if (active_gpu_count == 1) {
    execute_keyswitch_async<Torus>(
        streams, gpu_indexes, 1, lwe_after_ks_vec[0],
        lwe_trivial_indexes_vec[0], (Torus *)lwe_array_in->ptr,
        lut->lwe_indexes_in, ksks, big_lwe_dimension, small_lwe_dimension,
        ks_base_log, ks_level, num_radix_blocks);

    /// Apply PBS to apply a LUT, reduce the noise and go from a small LWE
    /// dimension to a big LWE dimension
    execute_pbs_async<Torus>(
        streams, gpu_indexes, 1, (Torus *)lwe_array_out->ptr,
        lut->lwe_indexes_out, lut->lut_vec, lut->lut_indexes_vec,
        lwe_after_ks_vec[0], lwe_trivial_indexes_vec[0], bsks, lut->buffer,
        glwe_dimension, small_lwe_dimension, polynomial_size, pbs_base_log,
        pbs_level, grouping_factor, num_radix_blocks, pbs_type, num_many_lut,
        lut_stride);
  } else {
    /// Make sure all data that should be on GPU 0 is indeed there
    cuda_synchronize_stream(streams[0], gpu_indexes[0]);

    /// With multiple GPUs we push to the vectors on each GPU then when we
    /// gather data to GPU 0 we can copy back to the original indexing
    multi_gpu_scatter_lwe_async<Torus>(
        streams, gpu_indexes, active_gpu_count, lwe_array_in_vec,
        (Torus *)lwe_array_in->ptr, lut->h_lwe_indexes_in,
        lut->using_trivial_lwe_indexes, num_radix_blocks,
        big_lwe_dimension + 1);

    /// Apply KS to go from a big LWE dimension to a small LWE dimension
    execute_keyswitch_async<Torus>(streams, gpu_indexes, active_gpu_count,
                                   lwe_after_ks_vec, lwe_trivial_indexes_vec,
                                   lwe_array_in_vec, lwe_trivial_indexes_vec,
                                   ksks, big_lwe_dimension, small_lwe_dimension,
                                   ks_base_log, ks_level, num_radix_blocks);

    /// Apply PBS to apply a LUT, reduce the noise and go from a small LWE
    /// dimension to a big LWE dimension
    execute_pbs_async<Torus>(
        streams, gpu_indexes, active_gpu_count, lwe_after_pbs_vec,
        lwe_trivial_indexes_vec, lut->lut_vec, lut->lut_indexes_vec,
        lwe_after_ks_vec, lwe_trivial_indexes_vec, bsks, lut->buffer,
        glwe_dimension, small_lwe_dimension, polynomial_size, pbs_base_log,
        pbs_level, grouping_factor, num_radix_blocks, pbs_type, num_many_lut,
        lut_stride);

    /// Copy data back to GPU 0 and release vecs
    multi_gpu_gather_lwe_async<Torus>(streams, gpu_indexes, active_gpu_count,
                                      (Torus *)lwe_array_out->ptr,
                                      lwe_after_pbs_vec, lut->h_lwe_indexes_out,
                                      lut->using_trivial_lwe_indexes,
                                      num_radix_blocks, big_lwe_dimension + 1);

    /// Synchronize all GPUs
    for (uint i = 0; i < active_gpu_count; i++) {
      cuda_synchronize_stream(streams[i], gpu_indexes[i]);
    }
  }
  Torus lut_indexes[lut->num_blocks];
  cuda_memcpy_async_to_cpu(&lut_indexes, lut->get_lut_indexes(0, 0),
                           lut->num_blocks * sizeof(Torus), streams[0],
                           gpu_indexes[0]);
  cuda_synchronize_stream(streams[0], gpu_indexes[0]);
  for (uint i = 0; i < num_radix_blocks; i++) {
    lwe_array_out->degrees[i] = lut->degrees[lut_indexes[i]];
    lwe_array_out->noise_levels[i] = NoiseLevel::NOMINAL;
  }
}

template <typename Torus>
__host__ void legacy_integer_radix_apply_univariate_lookup_table_kb(
    cudaStream_t const *streams, uint32_t const *gpu_indexes,
    uint32_t gpu_count, Torus *lwe_array_out, Torus const *lwe_array_in,
    void *const *bsks, Torus *const *ksks, uint32_t num_radix_blocks,
    int_radix_lut<Torus> *lut) {
  // apply_lookup_table
  auto params = lut->params;
  auto pbs_type = params.pbs_type;
  auto big_lwe_dimension = params.big_lwe_dimension;
  auto small_lwe_dimension = params.small_lwe_dimension;
  auto ks_level = params.ks_level;
  auto ks_base_log = params.ks_base_log;
  auto pbs_level = params.pbs_level;
  auto pbs_base_log = params.pbs_base_log;
  auto glwe_dimension = params.glwe_dimension;
  auto polynomial_size = params.polynomial_size;
  auto grouping_factor = params.grouping_factor;

  // In the case of extracting a single LWE this parameters are dummy
  uint32_t num_many_lut = 1;
  uint32_t lut_stride = 0;
  /// For multi GPU execution we create vectors of pointers for inputs and
  /// outputs
  std::vector<Torus *> lwe_array_in_vec = lut->lwe_array_in_vec;
  std::vector<Torus *> lwe_after_ks_vec = lut->lwe_after_ks_vec;
  std::vector<Torus *> lwe_after_pbs_vec = lut->lwe_after_pbs_vec;
  std::vector<Torus *> lwe_trivial_indexes_vec = lut->lwe_trivial_indexes_vec;

  auto active_gpu_count = get_active_gpu_count(num_radix_blocks, gpu_count);
  if (active_gpu_count == 1) {
    execute_keyswitch_async<Torus>(streams, gpu_indexes, 1, lwe_after_ks_vec[0],
                                   lwe_trivial_indexes_vec[0],
                                   (Torus *)lwe_array_in, lut->lwe_indexes_in,
                                   ksks, big_lwe_dimension, small_lwe_dimension,
                                   ks_base_log, ks_level, num_radix_blocks);

    /// Apply PBS to apply a LUT, reduce the noise and go from a small LWE
    /// dimension to a big LWE dimension
    execute_pbs_async<Torus>(
        streams, gpu_indexes, 1, lwe_array_out, lut->lwe_indexes_out,
        lut->lut_vec, lut->lut_indexes_vec, lwe_after_ks_vec[0],
        lwe_trivial_indexes_vec[0], bsks, lut->buffer, glwe_dimension,
        small_lwe_dimension, polynomial_size, pbs_base_log, pbs_level,
        grouping_factor, num_radix_blocks, pbs_type, num_many_lut, lut_stride);
  } else {
    /// Make sure all data that should be on GPU 0 is indeed there
    cuda_synchronize_stream(streams[0], gpu_indexes[0]);

    /// With multiple GPUs we push to the vectors on each GPU then when we
    /// gather data to GPU 0 we can copy back to the original indexing
    multi_gpu_scatter_lwe_async<Torus>(
        streams, gpu_indexes, active_gpu_count, lwe_array_in_vec, lwe_array_in,
        lut->h_lwe_indexes_in, lut->using_trivial_lwe_indexes, num_radix_blocks,
        big_lwe_dimension + 1);

    /// Apply KS to go from a big LWE dimension to a small LWE dimension
    execute_keyswitch_async<Torus>(streams, gpu_indexes, active_gpu_count,
                                   lwe_after_ks_vec, lwe_trivial_indexes_vec,
                                   lwe_array_in_vec, lwe_trivial_indexes_vec,
                                   ksks, big_lwe_dimension, small_lwe_dimension,
                                   ks_base_log, ks_level, num_radix_blocks);

    /// Apply PBS to apply a LUT, reduce the noise and go from a small LWE
    /// dimension to a big LWE dimension
    execute_pbs_async<Torus>(
        streams, gpu_indexes, active_gpu_count, lwe_after_pbs_vec,
        lwe_trivial_indexes_vec, lut->lut_vec, lut->lut_indexes_vec,
        lwe_after_ks_vec, lwe_trivial_indexes_vec, bsks, lut->buffer,
        glwe_dimension, small_lwe_dimension, polynomial_size, pbs_base_log,
        pbs_level, grouping_factor, num_radix_blocks, pbs_type, num_many_lut,
        lut_stride);

    /// Copy data back to GPU 0 and release vecs
    multi_gpu_gather_lwe_async<Torus>(streams, gpu_indexes, active_gpu_count,
                                      lwe_array_out, lwe_after_pbs_vec,
                                      lut->h_lwe_indexes_out,
                                      lut->using_trivial_lwe_indexes,
                                      num_radix_blocks, big_lwe_dimension + 1);

    /// Synchronize all GPUs
    for (uint i = 0; i < active_gpu_count; i++) {
      cuda_synchronize_stream(streams[i], gpu_indexes[i]);
    }
  }
}

template <typename Torus>
__host__ void legacy_integer_radix_apply_many_univariate_lookup_table_kb(
    cudaStream_t const *streams, uint32_t const *gpu_indexes,
    uint32_t gpu_count, Torus *lwe_array_out, Torus const *lwe_array_in,
    void *const *bsks, Torus *const *ksks, uint32_t num_radix_blocks,
    int_radix_lut<Torus> *lut, uint32_t num_many_lut, uint32_t lut_stride) {
  // apply_lookup_table
  auto params = lut->params;
  auto pbs_type = params.pbs_type;
  auto big_lwe_dimension = params.big_lwe_dimension;
  auto small_lwe_dimension = params.small_lwe_dimension;
  auto ks_level = params.ks_level;
  auto ks_base_log = params.ks_base_log;
  auto pbs_level = params.pbs_level;
  auto pbs_base_log = params.pbs_base_log;
  auto glwe_dimension = params.glwe_dimension;
  auto polynomial_size = params.polynomial_size;
  auto grouping_factor = params.grouping_factor;

  /// For multi GPU execution we create vectors of pointers for inputs and
  /// outputs
  std::vector<Torus *> lwe_array_in_vec = lut->lwe_array_in_vec;
  std::vector<Torus *> lwe_after_ks_vec = lut->lwe_after_ks_vec;
  std::vector<Torus *> lwe_after_pbs_vec = lut->lwe_after_pbs_vec;
  std::vector<Torus *> lwe_trivial_indexes_vec = lut->lwe_trivial_indexes_vec;

  auto active_gpu_count = get_active_gpu_count(num_radix_blocks, gpu_count);
  if (active_gpu_count == 1) {
    execute_keyswitch_async<Torus>(streams, gpu_indexes, 1, lwe_after_ks_vec[0],
                                   lwe_trivial_indexes_vec[0],
                                   (Torus *)lwe_array_in, lut->lwe_indexes_in,
                                   ksks, big_lwe_dimension, small_lwe_dimension,
                                   ks_base_log, ks_level, num_radix_blocks);

    /// Apply PBS to apply a LUT, reduce the noise and go from a small LWE
    /// dimension to a big LWE dimension
    execute_pbs_async<Torus>(
        streams, gpu_indexes, 1, lwe_array_out, lut->lwe_indexes_out,
        lut->lut_vec, lut->lut_indexes_vec, lwe_after_ks_vec[0],
        lwe_trivial_indexes_vec[0], bsks, lut->buffer, glwe_dimension,
        small_lwe_dimension, polynomial_size, pbs_base_log, pbs_level,
        grouping_factor, num_radix_blocks, pbs_type, num_many_lut, lut_stride);
  } else {
    /// Make sure all data that should be on GPU 0 is indeed there
    cuda_synchronize_stream(streams[0], gpu_indexes[0]);

    /// With multiple GPUs we push to the vectors on each GPU then when we
    /// gather data to GPU 0 we can copy back to the original indexing
    multi_gpu_scatter_lwe_async<Torus>(
        streams, gpu_indexes, active_gpu_count, lwe_array_in_vec, lwe_array_in,
        lut->h_lwe_indexes_in, lut->using_trivial_lwe_indexes, num_radix_blocks,
        big_lwe_dimension + 1);

    /// Apply KS to go from a big LWE dimension to a small LWE dimension
    execute_keyswitch_async<Torus>(streams, gpu_indexes, active_gpu_count,
                                   lwe_after_ks_vec, lwe_trivial_indexes_vec,
                                   lwe_array_in_vec, lwe_trivial_indexes_vec,
                                   ksks, big_lwe_dimension, small_lwe_dimension,
                                   ks_base_log, ks_level, num_radix_blocks);

    /// Apply PBS to apply a LUT, reduce the noise and go from a small LWE
    /// dimension to a big LWE dimension
    execute_pbs_async<Torus>(
        streams, gpu_indexes, active_gpu_count, lwe_after_pbs_vec,
        lwe_trivial_indexes_vec, lut->lut_vec, lut->lut_indexes_vec,
        lwe_after_ks_vec, lwe_trivial_indexes_vec, bsks, lut->buffer,
        glwe_dimension, small_lwe_dimension, polynomial_size, pbs_base_log,
        pbs_level, grouping_factor, num_radix_blocks, pbs_type, num_many_lut,
        lut_stride);

    /// Copy data back to GPU 0 and release vecs
    multi_gpu_gather_many_lut_lwe_async<Torus>(
        streams, gpu_indexes, active_gpu_count, lwe_array_out,
        lwe_after_pbs_vec, lut->h_lwe_indexes_out,
        lut->using_trivial_lwe_indexes, num_radix_blocks, big_lwe_dimension + 1,
        num_many_lut);

    /// Synchronize all GPUs
    for (uint i = 0; i < active_gpu_count; i++) {
      cuda_synchronize_stream(streams[i], gpu_indexes[i]);
    }
  }
}

template <typename Torus>
__host__ void integer_radix_apply_many_univariate_lookup_table_kb(
    cudaStream_t const *streams, uint32_t const *gpu_indexes,
    uint32_t gpu_count, CudaRadixCiphertextFFI *lwe_array_out,
    CudaRadixCiphertextFFI const *lwe_array_in, void *const *bsks,
    Torus *const *ksks, int_radix_lut<Torus> *lut, uint32_t num_many_lut,
    uint32_t lut_stride) {
  // apply_lookup_table
  auto params = lut->params;
  auto pbs_type = params.pbs_type;
  auto big_lwe_dimension = params.big_lwe_dimension;
  auto small_lwe_dimension = params.small_lwe_dimension;
  auto ks_level = params.ks_level;
  auto ks_base_log = params.ks_base_log;
  auto pbs_level = params.pbs_level;
  auto pbs_base_log = params.pbs_base_log;
  auto glwe_dimension = params.glwe_dimension;
  auto polynomial_size = params.polynomial_size;
  auto grouping_factor = params.grouping_factor;

  if (lwe_array_out->num_radix_blocks !=
      lwe_array_in->num_radix_blocks * num_many_lut)
    PANIC("Cuda error: output radix ciphertext should have num_many_lut times "
          "the number of blocks of the input")
  if (lwe_array_out->lwe_dimension != lwe_array_in->lwe_dimension)
    PANIC("Cuda error: input and output radix ciphertexts should have the same "
          "lwe dimension")

  auto num_radix_blocks = lwe_array_in->num_radix_blocks;
  /// For multi GPU execution we create vectors of pointers for inputs and
  /// outputs
  std::vector<Torus *> lwe_array_in_vec = lut->lwe_array_in_vec;
  std::vector<Torus *> lwe_after_ks_vec = lut->lwe_after_ks_vec;
  std::vector<Torus *> lwe_after_pbs_vec = lut->lwe_after_pbs_vec;
  std::vector<Torus *> lwe_trivial_indexes_vec = lut->lwe_trivial_indexes_vec;

  auto active_gpu_count = get_active_gpu_count(num_radix_blocks, gpu_count);
  if (active_gpu_count == 1) {
    execute_keyswitch_async<Torus>(
        streams, gpu_indexes, 1, lwe_after_ks_vec[0],
        lwe_trivial_indexes_vec[0], (Torus *)lwe_array_in->ptr,
        lut->lwe_indexes_in, ksks, big_lwe_dimension, small_lwe_dimension,
        ks_base_log, ks_level, num_radix_blocks);

    /// Apply PBS to apply a LUT, reduce the noise and go from a small LWE
    /// dimension to a big LWE dimension
    execute_pbs_async<Torus>(
        streams, gpu_indexes, 1, (Torus *)lwe_array_out->ptr,
        lut->lwe_indexes_out, lut->lut_vec, lut->lut_indexes_vec,
        lwe_after_ks_vec[0], lwe_trivial_indexes_vec[0], bsks, lut->buffer,
        glwe_dimension, small_lwe_dimension, polynomial_size, pbs_base_log,
        pbs_level, grouping_factor, num_radix_blocks, pbs_type, num_many_lut,
        lut_stride);
  } else {
    /// Make sure all data that should be on GPU 0 is indeed there
    cuda_synchronize_stream(streams[0], gpu_indexes[0]);

    /// With multiple GPUs we push to the vectors on each GPU then when we
    /// gather data to GPU 0 we can copy back to the original indexing
    multi_gpu_scatter_lwe_async<Torus>(
        streams, gpu_indexes, active_gpu_count, lwe_array_in_vec,
        (Torus *)lwe_array_in->ptr, lut->h_lwe_indexes_in,
        lut->using_trivial_lwe_indexes, num_radix_blocks,
        big_lwe_dimension + 1);

    /// Apply KS to go from a big LWE dimension to a small LWE dimension
    execute_keyswitch_async<Torus>(streams, gpu_indexes, active_gpu_count,
                                   lwe_after_ks_vec, lwe_trivial_indexes_vec,
                                   lwe_array_in_vec, lwe_trivial_indexes_vec,
                                   ksks, big_lwe_dimension, small_lwe_dimension,
                                   ks_base_log, ks_level, num_radix_blocks);

    /// Apply PBS to apply a LUT, reduce the noise and go from a small LWE
    /// dimension to a big LWE dimension
    execute_pbs_async<Torus>(
        streams, gpu_indexes, active_gpu_count, lwe_after_pbs_vec,
        lwe_trivial_indexes_vec, lut->lut_vec, lut->lut_indexes_vec,
        lwe_after_ks_vec, lwe_trivial_indexes_vec, bsks, lut->buffer,
        glwe_dimension, small_lwe_dimension, polynomial_size, pbs_base_log,
        pbs_level, grouping_factor, num_radix_blocks, pbs_type, num_many_lut,
        lut_stride);

    /// Copy data back to GPU 0 and release vecs
    multi_gpu_gather_many_lut_lwe_async<Torus>(
        streams, gpu_indexes, active_gpu_count, (Torus *)lwe_array_out->ptr,
        lwe_after_pbs_vec, lut->h_lwe_indexes_out,
        lut->using_trivial_lwe_indexes, num_radix_blocks, big_lwe_dimension + 1,
        num_many_lut);

    /// Synchronize all GPUs
    for (uint i = 0; i < active_gpu_count; i++) {
      cuda_synchronize_stream(streams[i], gpu_indexes[i]);
    }
  }
  Torus lut_indexes[lut->num_blocks];
  cuda_memcpy_async_to_cpu(&lut_indexes, lut->get_lut_indexes(0, 0),
                           lut->num_blocks * sizeof(Torus), streams[0],
                           gpu_indexes[0]);
  cuda_synchronize_stream(streams[0], gpu_indexes[0]);
  for (uint i = 0; i < lwe_array_out->num_radix_blocks; i++) {
    lwe_array_out->degrees[i] = lut->degrees[i % lut->num_blocks];
    lwe_array_out->noise_levels[i] = NoiseLevel::NOMINAL;
  }
}

template <typename Torus>
__host__ void legacy_integer_radix_apply_bivariate_lookup_table_kb(
    cudaStream_t const *streams, uint32_t const *gpu_indexes,
    uint32_t gpu_count, Torus *lwe_array_out, Torus const *lwe_array_1,
    Torus const *lwe_array_2, void *const *bsks, Torus *const *ksks,
    uint32_t num_radix_blocks, int_radix_lut<Torus> *lut, uint32_t shift) {

  auto params = lut->params;
  auto pbs_type = params.pbs_type;
  auto big_lwe_dimension = params.big_lwe_dimension;
  auto small_lwe_dimension = params.small_lwe_dimension;
  auto ks_level = params.ks_level;
  auto ks_base_log = params.ks_base_log;
  auto pbs_level = params.pbs_level;
  auto pbs_base_log = params.pbs_base_log;
  auto glwe_dimension = params.glwe_dimension;
  auto polynomial_size = params.polynomial_size;
  auto grouping_factor = params.grouping_factor;

  // In the case of extracting a single LWE this parameters are dummy
  uint32_t num_many_lut = 1;
  uint32_t lut_stride = 0;

  // Left message is shifted
  auto lwe_array_pbs_in = (Torus *)lut->tmp_lwe_before_ks->ptr;
  legacy_host_pack_bivariate_blocks<Torus>(
      streams, gpu_indexes, gpu_count, lwe_array_pbs_in,
      lut->lwe_trivial_indexes, lwe_array_1, lwe_array_2, lut->lwe_indexes_in,
      big_lwe_dimension, shift, num_radix_blocks);
  check_cuda_error(cudaGetLastError());

  /// For multi GPU execution we create vectors of pointers for inputs and
  /// outputs
  std::vector<Torus *> lwe_array_in_vec = lut->lwe_array_in_vec;
  std::vector<Torus *> lwe_after_ks_vec = lut->lwe_after_ks_vec;
  std::vector<Torus *> lwe_after_pbs_vec = lut->lwe_after_pbs_vec;
  std::vector<Torus *> lwe_trivial_indexes_vec = lut->lwe_trivial_indexes_vec;

  auto active_gpu_count = get_active_gpu_count(num_radix_blocks, gpu_count);
  if (active_gpu_count == 1) {
    execute_keyswitch_async<Torus>(streams, gpu_indexes, 1, lwe_after_ks_vec[0],
                                   lwe_trivial_indexes_vec[0], lwe_array_pbs_in,
                                   lut->lwe_indexes_in, ksks, big_lwe_dimension,
                                   small_lwe_dimension, ks_base_log, ks_level,
                                   num_radix_blocks);

    /// Apply PBS to apply a LUT, reduce the noise and go from a small LWE
    /// dimension to a big LWE dimension
    execute_pbs_async<Torus>(
        streams, gpu_indexes, 1, lwe_array_out, lut->lwe_indexes_out,
        lut->lut_vec, lut->lut_indexes_vec, lwe_after_ks_vec[0],
        lwe_trivial_indexes_vec[0], bsks, lut->buffer, glwe_dimension,
        small_lwe_dimension, polynomial_size, pbs_base_log, pbs_level,
        grouping_factor, num_radix_blocks, pbs_type, num_many_lut, lut_stride);
  } else {
    cuda_synchronize_stream(streams[0], gpu_indexes[0]);
    multi_gpu_scatter_lwe_async<Torus>(
        streams, gpu_indexes, active_gpu_count, lwe_array_in_vec,
        lwe_array_pbs_in, lut->h_lwe_indexes_in, lut->using_trivial_lwe_indexes,
        num_radix_blocks, big_lwe_dimension + 1);

    /// Apply KS to go from a big LWE dimension to a small LWE dimension
    execute_keyswitch_async<Torus>(streams, gpu_indexes, active_gpu_count,
                                   lwe_after_ks_vec, lwe_trivial_indexes_vec,
                                   lwe_array_in_vec, lwe_trivial_indexes_vec,
                                   ksks, big_lwe_dimension, small_lwe_dimension,
                                   ks_base_log, ks_level, num_radix_blocks);

    /// Apply PBS to apply a LUT, reduce the noise and go from a small LWE
    /// dimension to a big LWE dimension
    execute_pbs_async<Torus>(
        streams, gpu_indexes, active_gpu_count, lwe_after_pbs_vec,
        lwe_trivial_indexes_vec, lut->lut_vec, lut->lut_indexes_vec,
        lwe_after_ks_vec, lwe_trivial_indexes_vec, bsks, lut->buffer,
        glwe_dimension, small_lwe_dimension, polynomial_size, pbs_base_log,
        pbs_level, grouping_factor, num_radix_blocks, pbs_type, num_many_lut,
        lut_stride);

    /// Copy data back to GPU 0 and release vecs
    multi_gpu_gather_lwe_async<Torus>(streams, gpu_indexes, active_gpu_count,
                                      lwe_array_out, lwe_after_pbs_vec,
                                      lut->h_lwe_indexes_out,
                                      lut->using_trivial_lwe_indexes,
                                      num_radix_blocks, big_lwe_dimension + 1);

    /// Synchronize all GPUs
    for (uint i = 0; i < active_gpu_count; i++) {
      cuda_synchronize_stream(streams[i], gpu_indexes[i]);
    }
  }
}

template <typename Torus>
__host__ void integer_radix_apply_bivariate_lookup_table_kb(
    cudaStream_t const *streams, uint32_t const *gpu_indexes,
    uint32_t gpu_count, CudaRadixCiphertextFFI *lwe_array_out,
    CudaRadixCiphertextFFI const *lwe_array_1,
    CudaRadixCiphertextFFI const *lwe_array_2, void *const *bsks,
    Torus *const *ksks, int_radix_lut<Torus> *lut, uint32_t num_radix_blocks,
    uint32_t shift) {

  if (lwe_array_out->lwe_dimension != lwe_array_1->lwe_dimension ||
      lwe_array_out->lwe_dimension != lwe_array_2->lwe_dimension)
    PANIC("Cuda error: input and output radix ciphertexts should have the same "
          "lwe dimension")
  if (num_radix_blocks > lut->num_blocks)
    PANIC("Cuda error: num radix blocks on which lut is applied should be "
          "smaller or equal to the number of lut radix blocks")
  if (num_radix_blocks > lwe_array_out->num_radix_blocks ||
      num_radix_blocks > lwe_array_1->num_radix_blocks ||
      num_radix_blocks > lwe_array_2->num_radix_blocks)
    PANIC("Cuda error: num radix blocks on which lut is applied should be "
          "smaller or equal to the number of input & output radix blocks")

  auto params = lut->params;
  auto pbs_type = params.pbs_type;
  auto big_lwe_dimension = params.big_lwe_dimension;
  auto small_lwe_dimension = params.small_lwe_dimension;
  auto ks_level = params.ks_level;
  auto ks_base_log = params.ks_base_log;
  auto pbs_level = params.pbs_level;
  auto pbs_base_log = params.pbs_base_log;
  auto glwe_dimension = params.glwe_dimension;
  auto polynomial_size = params.polynomial_size;
  auto grouping_factor = params.grouping_factor;

  // In the case of extracting a single LWE this parameters are dummy
  uint32_t num_many_lut = 1;
  uint32_t lut_stride = 0;

  // Left message is shifted
  auto lwe_array_pbs_in = lut->tmp_lwe_before_ks;
  host_pack_bivariate_blocks<Torus>(
      streams, gpu_indexes, gpu_count, lwe_array_pbs_in,
      lut->lwe_trivial_indexes, lwe_array_1, lwe_array_2, lut->lwe_indexes_in,
      shift, num_radix_blocks);
  check_cuda_error(cudaGetLastError());

  /// For multi GPU execution we create vectors of pointers for inputs and
  /// outputs
  std::vector<Torus *> lwe_array_in_vec = lut->lwe_array_in_vec;
  std::vector<Torus *> lwe_after_ks_vec = lut->lwe_after_ks_vec;
  std::vector<Torus *> lwe_after_pbs_vec = lut->lwe_after_pbs_vec;
  std::vector<Torus *> lwe_trivial_indexes_vec = lut->lwe_trivial_indexes_vec;

  auto active_gpu_count = get_active_gpu_count(num_radix_blocks, gpu_count);
  if (active_gpu_count == 1) {
    execute_keyswitch_async<Torus>(
        streams, gpu_indexes, 1, lwe_after_ks_vec[0],
        lwe_trivial_indexes_vec[0], (Torus *)lwe_array_pbs_in->ptr,
        lut->lwe_indexes_in, ksks, big_lwe_dimension, small_lwe_dimension,
        ks_base_log, ks_level, num_radix_blocks);

    /// Apply PBS to apply a LUT, reduce the noise and go from a small LWE
    /// dimension to a big LWE dimension
    execute_pbs_async<Torus>(
        streams, gpu_indexes, 1, (Torus *)(lwe_array_out->ptr),
        lut->lwe_indexes_out, lut->lut_vec, lut->lut_indexes_vec,
        lwe_after_ks_vec[0], lwe_trivial_indexes_vec[0], bsks, lut->buffer,
        glwe_dimension, small_lwe_dimension, polynomial_size, pbs_base_log,
        pbs_level, grouping_factor, num_radix_blocks, pbs_type, num_many_lut,
        lut_stride);
  } else {
    cuda_synchronize_stream(streams[0], gpu_indexes[0]);
    multi_gpu_scatter_lwe_async<Torus>(
        streams, gpu_indexes, active_gpu_count, lwe_array_in_vec,
        (Torus *)lwe_array_pbs_in->ptr, lut->h_lwe_indexes_in,
        lut->using_trivial_lwe_indexes, num_radix_blocks,
        big_lwe_dimension + 1);

    /// Apply KS to go from a big LWE dimension to a small LWE dimension
    execute_keyswitch_async<Torus>(streams, gpu_indexes, active_gpu_count,
                                   lwe_after_ks_vec, lwe_trivial_indexes_vec,
                                   lwe_array_in_vec, lwe_trivial_indexes_vec,
                                   ksks, big_lwe_dimension, small_lwe_dimension,
                                   ks_base_log, ks_level, num_radix_blocks);

    /// Apply PBS to apply a LUT, reduce the noise and go from a small LWE
    /// dimension to a big LWE dimension
    execute_pbs_async<Torus>(
        streams, gpu_indexes, active_gpu_count, lwe_after_pbs_vec,
        lwe_trivial_indexes_vec, lut->lut_vec, lut->lut_indexes_vec,
        lwe_after_ks_vec, lwe_trivial_indexes_vec, bsks, lut->buffer,
        glwe_dimension, small_lwe_dimension, polynomial_size, pbs_base_log,
        pbs_level, grouping_factor, num_radix_blocks, pbs_type, num_many_lut,
        lut_stride);

    /// Copy data back to GPU 0 and release vecs
    multi_gpu_gather_lwe_async<Torus>(streams, gpu_indexes, active_gpu_count,
                                      (Torus *)(lwe_array_out->ptr),
                                      lwe_after_pbs_vec, lut->h_lwe_indexes_out,
                                      lut->using_trivial_lwe_indexes,
                                      num_radix_blocks, big_lwe_dimension + 1);

    /// Synchronize all GPUs
    for (uint i = 0; i < active_gpu_count; i++) {
      cuda_synchronize_stream(streams[i], gpu_indexes[i]);
    }
  }
  Torus lut_indexes[lut->num_blocks];
  cuda_memcpy_async_to_cpu(&lut_indexes, lut->get_lut_indexes(0, 0),
                           lut->num_blocks * sizeof(Torus), streams[0],
                           gpu_indexes[0]);
  cuda_synchronize_stream(streams[0], gpu_indexes[0]);
  for (uint i = 0; i < num_radix_blocks; i++) {
    lwe_array_out->degrees[i] = lut->degrees[lut_indexes[i]];
    lwe_array_out->noise_levels[i] = NoiseLevel::NOMINAL;
  }
}

// Rotates the slice in-place such that the first mid elements of the slice move
// to the end while the last array_length elements move to the front. After
// calling rotate_left, the element previously at index mid will become the
// first element in the slice.
template <typename Torus>
void rotate_left(Torus *buffer, int mid, uint32_t array_length) {
  mid = mid % array_length;

  std::rotate(buffer, buffer + mid, buffer + array_length);
}

/// Caller needs to ensure that the operation applied is coherent from an
/// encoding perspective.
///
/// For example:
///
/// Input encoding has 2 bits and output encoding has 4 bits, applying the
/// identity lut would map the following:
///
/// 0|00|xx -> 0|00|00
/// 0|01|xx -> 0|00|01
/// 0|10|xx -> 0|00|10
/// 0|11|xx -> 0|00|11
///
/// The reason is the identity function is computed in the input space but the
/// scaling is done in the output space, as there are more bits in the output
/// space, the delta is smaller hence the apparent "division" happening.
template <typename Torus>
uint64_t generate_lookup_table_with_encoding(
    Torus *acc, uint32_t glwe_dimension, uint32_t polynomial_size,
    uint32_t input_message_modulus, uint32_t input_carry_modulus,
    uint32_t output_message_modulus, uint32_t output_carry_modulus,
    std::function<Torus(Torus)> f) {

  uint32_t input_modulus_sup = input_message_modulus * input_carry_modulus;
  uint32_t output_modulus_sup = output_message_modulus * output_carry_modulus;
  uint32_t box_size = polynomial_size / input_modulus_sup;
  auto nbits = sizeof(Torus) * 8;
  Torus output_delta =
      (static_cast<Torus>(1) << (nbits - 1)) / output_modulus_sup;

  memset(acc, 0, glwe_dimension * polynomial_size * sizeof(Torus));

  auto body = &acc[glwe_dimension * polynomial_size];
  uint64_t degree = 0;

  // This accumulator extracts the carry bits
  for (int i = 0; i < input_modulus_sup; i++) {
    int index = i * box_size;
    for (int j = index; j < index + box_size; j++) {
      auto f_eval = f(i);
      degree = std::max(degree, f_eval);
      body[j] = f_eval * output_delta;
    }
  }

  int half_box_size = box_size / 2;

  // Negate the first half_box_size coefficients
  for (int i = 0; i < half_box_size; i++) {
    body[i] = -body[i];
  }

  rotate_left<Torus>(body, half_box_size, polynomial_size);
  return degree;
}

template <typename Torus>
uint64_t generate_lookup_table(Torus *acc, uint32_t glwe_dimension,
                               uint32_t polynomial_size,
                               uint32_t message_modulus, uint32_t carry_modulus,
                               std::function<Torus(Torus)> f) {
  return generate_lookup_table_with_encoding(
      acc, glwe_dimension, polynomial_size, message_modulus, carry_modulus,
      message_modulus, carry_modulus, f);
}

template <typename Torus>
uint64_t generate_many_lookup_table(
    Torus *acc, uint64_t *degrees, uint32_t glwe_dimension,
    uint32_t polynomial_size, uint32_t message_modulus, uint32_t carry_modulus,
    std::vector<std::function<Torus(Torus)>> &functions) {

  uint32_t modulus_sup = message_modulus * carry_modulus;
  uint32_t box_size = polynomial_size / modulus_sup;
  auto nbits = sizeof(Torus) * 8;
  Torus delta = (static_cast<Torus>(1) << (nbits - 1)) / modulus_sup;

  memset(acc, 0, glwe_dimension * polynomial_size * sizeof(Torus));

  auto body = &acc[glwe_dimension * polynomial_size];

  size_t fn_counts = functions.size();

  if (fn_counts > modulus_sup / 2)
    PANIC("Cuda error: invalid number of functions")

  // Space used for each sub lut
  uint32_t single_function_sub_lut_size = (modulus_sup / fn_counts) * box_size;
  uint64_t max_degree = (modulus_sup / fn_counts - 1);
  for (int f = 0; f < fn_counts; f++) {
    degrees[f] = 0;
  }

  // This accumulator extracts the carry bits
  for (int f = 0; f < fn_counts; f++) {
    int lut_offset = f * single_function_sub_lut_size;
    for (int i = 0; i < modulus_sup / fn_counts; i++) {
      int index = i * box_size + lut_offset;
      for (int j = index; j < index + box_size; j++) {
        auto f_eval = functions[f](i);
        degrees[f] = max(f_eval, degrees[f]);
        body[j] = f_eval * delta;
      }
    }
  }
  int half_box_size = box_size / 2;

  // Negate the first half_box_size coefficients
  for (int i = 0; i < half_box_size; i++) {
    body[i] = -body[i];
  }

  rotate_left<Torus>(body, half_box_size, polynomial_size);
  return max_degree;
}

template <typename Torus>
uint64_t generate_lookup_table_bivariate(Torus *acc, uint32_t glwe_dimension,
                                         uint32_t polynomial_size,
                                         uint32_t message_modulus,
                                         uint32_t carry_modulus,
                                         std::function<Torus(Torus, Torus)> f) {

  Torus factor_u64 = message_modulus;
  auto wrapped_f = [factor_u64, message_modulus, f](Torus input) -> Torus {
    Torus lhs = (input / factor_u64) % message_modulus;
    Torus rhs = (input % factor_u64) % message_modulus;

    return f(lhs, rhs);
  };

  return generate_lookup_table<Torus>(acc, glwe_dimension, polynomial_size,
                                      message_modulus, carry_modulus,
                                      wrapped_f);
}

template <typename Torus>
uint64_t generate_lookup_table_bivariate_with_factor(
    Torus *acc, uint32_t glwe_dimension, uint32_t polynomial_size,
    uint32_t message_modulus, uint32_t carry_modulus,
    std::function<Torus(Torus, Torus)> f, int factor) {

  Torus factor_u64 = factor;
  auto wrapped_f = [factor_u64, message_modulus, f](Torus input) -> Torus {
    Torus lhs = (input / factor_u64) % message_modulus;
    Torus rhs = (input % factor_u64) % message_modulus;

    return f(lhs, rhs);
  };

  return generate_lookup_table<Torus>(acc, glwe_dimension, polynomial_size,
                                      message_modulus, carry_modulus,
                                      wrapped_f);
}

/*
 *  generate bivariate accumulator for device pointer
 *    stream - cuda stream
 *    acc - device pointer for bivariate accumulator
 *    ...
 *    f - wrapping function with two Torus inputs
 */
template <typename Torus>
void generate_device_accumulator_bivariate(
    cudaStream_t stream, uint32_t gpu_index, Torus *acc_bivariate,
    uint64_t *degree, uint64_t *max_degree, uint32_t glwe_dimension,
    uint32_t polynomial_size, uint32_t message_modulus, uint32_t carry_modulus,
    std::function<Torus(Torus, Torus)> f) {

  // host lut
  Torus *h_lut =
      (Torus *)malloc((glwe_dimension + 1) * polynomial_size * sizeof(Torus));
  *max_degree = message_modulus * carry_modulus - 1;
  // fill bivariate accumulator
  *degree = generate_lookup_table_bivariate<Torus>(
      h_lut, glwe_dimension, polynomial_size, message_modulus, carry_modulus,
      f);

  // copy host lut and lut_indexes_vec to device
  cuda_memcpy_async_to_gpu(acc_bivariate, h_lut,
                           (glwe_dimension + 1) * polynomial_size *
                               sizeof(Torus),
                           stream, gpu_index);

  cuda_synchronize_stream(stream, gpu_index);
  free(h_lut);
}

/*
 *  generate bivariate accumulator with factor scaling for device pointer
 *    v_stream - cuda stream
 *    acc - device pointer for bivariate accumulator
 *    ...
 *    f - wrapping function with two Torus inputs
 */
template <typename Torus>
void generate_device_accumulator_bivariate_with_factor(
    cudaStream_t stream, uint32_t gpu_index, Torus *acc_bivariate,
    uint64_t *degree, uint64_t *max_degree, uint32_t glwe_dimension,
    uint32_t polynomial_size, uint32_t message_modulus, uint32_t carry_modulus,
    std::function<Torus(Torus, Torus)> f, int factor) {

  // host lut
  Torus *h_lut =
      (Torus *)malloc((glwe_dimension + 1) * polynomial_size * sizeof(Torus));

  *max_degree = message_modulus * carry_modulus - 1;
  // fill bivariate accumulator
  *degree = generate_lookup_table_bivariate_with_factor<Torus>(
      h_lut, glwe_dimension, polynomial_size, message_modulus, carry_modulus, f,
      factor);

  cuda_synchronize_stream(stream, gpu_index);
  // copy host lut and lut_indexes_vec to device
  cuda_memcpy_async_to_gpu(acc_bivariate, h_lut,
                           (glwe_dimension + 1) * polynomial_size *
                               sizeof(Torus),
                           stream, gpu_index);

  cuda_synchronize_stream(stream, gpu_index);
  free(h_lut);
}

template <typename Torus>
void generate_device_accumulator_with_encoding(
    cudaStream_t stream, uint32_t gpu_index, Torus *acc, uint64_t *degree,
    uint64_t *max_degree, uint32_t glwe_dimension, uint32_t polynomial_size,
    uint32_t input_message_modulus, uint32_t input_carry_modulus,
    uint32_t output_message_modulus, uint32_t output_carry_modulus,
    std::function<Torus(Torus)> f) {

  // host lut
  Torus *h_lut =
      (Torus *)malloc((glwe_dimension + 1) * polynomial_size * sizeof(Torus));

  *max_degree = input_message_modulus * input_carry_modulus - 1;
  // fill accumulator
  *degree = generate_lookup_table_with_encoding<Torus>(
      h_lut, glwe_dimension, polynomial_size, input_message_modulus,
      input_carry_modulus, output_message_modulus, output_carry_modulus, f);

  // copy host lut and lut_indexes_vec to device
  cuda_memcpy_async_to_gpu(
      acc, h_lut, (glwe_dimension + 1) * polynomial_size * sizeof(Torus),
      stream, gpu_index);

  cuda_synchronize_stream(stream, gpu_index);
  free(h_lut);
}

/*
 *  generate accumulator for device pointer
 *    v_stream - cuda stream
 *    acc - device pointer for accumulator
 *    ...
 *    f - evaluating function with one Torus input
 */
template <typename Torus>
void generate_device_accumulator(cudaStream_t stream, uint32_t gpu_index,
                                 Torus *acc, uint64_t *degree,
                                 uint64_t *max_degree, uint32_t glwe_dimension,
                                 uint32_t polynomial_size,
                                 uint32_t message_modulus,
                                 uint32_t carry_modulus,
                                 std::function<Torus(Torus)> f) {

  generate_device_accumulator_with_encoding(
      stream, gpu_index, acc, degree, max_degree, glwe_dimension,
      polynomial_size, message_modulus, carry_modulus, message_modulus,
      carry_modulus, f);
}

/*
 *  generate many lut accumulator for device pointer
 *    v_stream - cuda stream
 *    acc - device pointer for accumulator
 *    ...
 *    vector<f> - evaluating functions with one Torus input
 */
template <typename Torus>
void generate_many_lut_device_accumulator(
    cudaStream_t stream, uint32_t gpu_index, Torus *acc, uint64_t *degrees,
    uint64_t *max_degree, uint32_t glwe_dimension, uint32_t polynomial_size,
    uint32_t message_modulus, uint32_t carry_modulus,
    std::vector<std::function<Torus(Torus)>> &functions) {

  // host lut
  Torus *h_lut =
      (Torus *)malloc((glwe_dimension + 1) * polynomial_size * sizeof(Torus));

  // fill accumulator
  *max_degree = generate_many_lookup_table<Torus>(
      h_lut, degrees, glwe_dimension, polynomial_size, message_modulus,
      carry_modulus, functions);

  // copy host lut and lut_indexes_vec to device
  cuda_memcpy_async_to_gpu(
      acc, h_lut, (glwe_dimension + 1) * polynomial_size * sizeof(Torus),
      stream, gpu_index);

  cuda_synchronize_stream(stream, gpu_index);
  free(h_lut);
}

template <typename Torus>
void legacy_host_compute_shifted_blocks_and_states(
    cudaStream_t const *streams, uint32_t const *gpu_indexes,
    uint32_t gpu_count, Torus *lwe_array, int_radix_params params,
    int_shifted_blocks_and_states_memory<Torus> *mem, void *const *bsks,
    Torus *const *ksks, uint32_t num_radix_blocks, uint32_t lut_stride,
    uint32_t num_many_lut) {

  auto glwe_dimension = params.glwe_dimension;
  auto polynomial_size = params.polynomial_size;
  uint32_t big_lwe_size = glwe_dimension * polynomial_size + 1;
  auto big_lwe_size_bytes = big_lwe_size * sizeof(Torus);

  auto shifted_blocks_and_states = (Torus *)mem->shifted_blocks_and_states->ptr;
  auto luts_array_first_step = mem->luts_array_first_step;

  legacy_integer_radix_apply_many_univariate_lookup_table_kb<Torus>(
      streams, gpu_indexes, gpu_count, shifted_blocks_and_states, lwe_array,
      bsks, ksks, num_radix_blocks, luts_array_first_step, num_many_lut,
      lut_stride);

  auto shifted_blocks = (Torus *)mem->shifted_blocks->ptr;
  auto block_states = (Torus *)mem->block_states->ptr;
  cuda_memcpy_async_gpu_to_gpu(block_states, shifted_blocks_and_states,
                               big_lwe_size_bytes * num_radix_blocks,
                               streams[0], gpu_indexes[0]);
  cuda_memcpy_async_gpu_to_gpu(
      shifted_blocks,
      shifted_blocks_and_states + big_lwe_size * num_radix_blocks,
      big_lwe_size_bytes * num_radix_blocks, streams[0], gpu_indexes[0]);
}

// This function is used to perform step 1 of Thomas' new carry propagation
// algorithm It uses a many lut to calculate two luts in parallel
// shifted_blocks: contains (block % message modulus) << 1
// block states: contains the propagation states for the different blocks
// depending on the group it belongs to and the internal position within the
// block.
template <typename Torus>
void host_compute_shifted_blocks_and_states(
    cudaStream_t const *streams, uint32_t const *gpu_indexes,
    uint32_t gpu_count, CudaRadixCiphertextFFI *lwe_array,
    int_shifted_blocks_and_states_memory<Torus> *mem, void *const *bsks,
    Torus *const *ksks, uint32_t lut_stride, uint32_t num_many_lut) {

  auto num_radix_blocks = lwe_array->num_radix_blocks;

  auto shifted_blocks_and_states = mem->shifted_blocks_and_states;
  auto luts_array_first_step = mem->luts_array_first_step;

  integer_radix_apply_many_univariate_lookup_table_kb<Torus>(
      streams, gpu_indexes, gpu_count, shifted_blocks_and_states, lwe_array,
      bsks, ksks, luts_array_first_step, num_many_lut, lut_stride);

  auto shifted_blocks = mem->shifted_blocks;
  auto block_states = mem->block_states;
  copy_radix_ciphertext_slice_async<Torus>(
      streams[0], gpu_indexes[0], block_states, 0, num_radix_blocks,
      shifted_blocks_and_states, 0, num_radix_blocks);
  // This works because num_many_lut is hard coded to 2
  copy_radix_ciphertext_slice_async<Torus>(
      streams[0], gpu_indexes[0], shifted_blocks, 0, num_radix_blocks,
      shifted_blocks_and_states, num_radix_blocks, 2 * num_radix_blocks);
}

template <typename Torus>
void legacy_host_resolve_group_carries_sequentially(
    cudaStream_t const *streams, uint32_t const *gpu_indexes,
    uint32_t gpu_count, Torus *resolved_carries, Torus *grouping_pgns,
    int_radix_params params, int_seq_group_prop_memory<Torus> *mem,
    void *const *bsks, Torus *const *ksks, uint32_t num_groups) {

  auto glwe_dimension = params.glwe_dimension;
  auto polynomial_size = params.polynomial_size;
  uint32_t big_lwe_size = glwe_dimension * polynomial_size + 1;
  auto big_lwe_size_bytes = big_lwe_size * sizeof(Torus);

  auto group_resolved_carries = (Torus *)mem->group_resolved_carries->ptr;
  if (num_groups > 1) {
    // First carry is just copied
    cuda_memcpy_async_gpu_to_gpu(resolved_carries + big_lwe_size, grouping_pgns,
                                 big_lwe_size_bytes, streams[0],
                                 gpu_indexes[0]);
    uint32_t solve_per_iter = mem->grouping_size - 1;
    uint32_t remaining_carries =
        num_groups -
        2; // the first one has been resolved and we ignore the last one
    uint32_t num_loops =
        ceil(double(remaining_carries) / (double)(solve_per_iter));
    uint32_t last_resolved_pos = 1;

    for (int i = 0; i < num_loops; i++) {
      uint32_t loop_offset = i * solve_per_iter;
      uint32_t blocks_to_solve = solve_per_iter;
      // In case the last iteration has to solve less
      if (loop_offset + blocks_to_solve > num_groups - 2) {
        blocks_to_solve = remaining_carries - loop_offset;
      }

      // The group_resolved carries is used as an intermediate array
      // First we need to copy the last resolved carry
      cuda_memcpy_async_gpu_to_gpu(
          group_resolved_carries,
          resolved_carries + last_resolved_pos * big_lwe_size,
          big_lwe_size_bytes, streams[0], gpu_indexes[0]);

      // The array is filled with the blocks_to_solve
      cuda_memcpy_async_gpu_to_gpu(
          group_resolved_carries + big_lwe_size,
          grouping_pgns + last_resolved_pos * big_lwe_size,
          blocks_to_solve * big_lwe_size_bytes, streams[0], gpu_indexes[0]);

      // Perform one group cumulative sum
      legacy_host_radix_cumulative_sum_in_groups<Torus>(
          streams[0], gpu_indexes[0], group_resolved_carries,
          group_resolved_carries, blocks_to_solve + 1, big_lwe_size,
          mem->grouping_size);

      // Apply the lut
      auto luts_sequential = mem->lut_sequential_algorithm;
      legacy_integer_radix_apply_univariate_lookup_table_kb<Torus>(
          streams, gpu_indexes, gpu_count,
          group_resolved_carries + big_lwe_size,
          group_resolved_carries + big_lwe_size, bsks, ksks, blocks_to_solve,
          luts_sequential);

      // Copy the result to the resolved carries array
      cuda_memcpy_async_gpu_to_gpu(
          resolved_carries + (last_resolved_pos + 1) * big_lwe_size,
          group_resolved_carries + big_lwe_size,
          blocks_to_solve * big_lwe_size_bytes, streams[0], gpu_indexes[0]);

      last_resolved_pos += blocks_to_solve;
    }
  }
}

template <typename Torus>
void host_resolve_group_carries_sequentially(
    cudaStream_t const *streams, uint32_t const *gpu_indexes,
    uint32_t gpu_count, CudaRadixCiphertextFFI *resolved_carries,
    CudaRadixCiphertextFFI *grouping_pgns, int_radix_params params,
    int_seq_group_prop_memory<Torus> *mem, void *const *bsks,
    Torus *const *ksks, uint32_t num_groups) {

  auto group_resolved_carries = mem->group_resolved_carries;
  if (num_groups > 1) {
    // First carry is just copied
    copy_radix_ciphertext_slice_async<Torus>(streams[0], gpu_indexes[0],
                                             resolved_carries, 1, 2,
                                             grouping_pgns, 0, 1);
    uint32_t solve_per_iter = mem->grouping_size - 1;
    uint32_t remaining_carries =
        num_groups -
        2; // the first one has been resolved and we ignore the last one
    uint32_t num_loops =
        ceil(double(remaining_carries) / (double)(solve_per_iter));
    uint32_t last_resolved_pos = 1;

    for (int i = 0; i < num_loops; i++) {
      uint32_t loop_offset = i * solve_per_iter;
      uint32_t blocks_to_solve = solve_per_iter;
      // In case the last iteration has to solve less
      if (loop_offset + blocks_to_solve > num_groups - 2) {
        blocks_to_solve = remaining_carries - loop_offset;
      }

      // The group_resolved carries is used as an intermediate array
      // First we need to copy the last resolved carry
      copy_radix_ciphertext_slice_async<Torus>(
          streams[0], gpu_indexes[0], group_resolved_carries, 0, 1,
          resolved_carries, last_resolved_pos, last_resolved_pos + 1);

      // The array is filled with the blocks_to_solve
      copy_radix_ciphertext_slice_async<Torus>(
          streams[0], gpu_indexes[0], group_resolved_carries, 1,
          blocks_to_solve + 1, grouping_pgns, last_resolved_pos,
          last_resolved_pos + blocks_to_solve);

      // Perform one group cumulative sum
      host_radix_cumulative_sum_in_groups<Torus>(
          streams[0], gpu_indexes[0], group_resolved_carries,
          group_resolved_carries, blocks_to_solve + 1, mem->grouping_size);

      // Apply the lut
      auto luts_sequential = mem->lut_sequential_algorithm;
      CudaRadixCiphertextFFI shifted_group_resolved_carries;
      as_radix_ciphertext_slice<Torus>(&shifted_group_resolved_carries,
                                       group_resolved_carries, 1,
                                       blocks_to_solve + 1);
      integer_radix_apply_univariate_lookup_table_kb<Torus>(
          streams, gpu_indexes, gpu_count, &shifted_group_resolved_carries,
          &shifted_group_resolved_carries, bsks, ksks, luts_sequential,
          blocks_to_solve);

      // Copy the result to the resolved carries array
      copy_radix_ciphertext_slice_async<Torus>(
          streams[0], gpu_indexes[0], resolved_carries, last_resolved_pos + 1,
          last_resolved_pos + blocks_to_solve + 1, group_resolved_carries, 1,
          blocks_to_solve + 1);

      last_resolved_pos += blocks_to_solve;
    }
  }
}

template <typename Torus>
void legacy_host_compute_prefix_sum_hillis_steele(
    cudaStream_t const *streams, uint32_t const *gpu_indexes,
    uint32_t gpu_count, Torus *step_output, Torus *generates_or_propagates,
    int_radix_params params, int_radix_lut<Torus> *luts, void *const *bsks,
    Torus *const *ksks, uint32_t num_radix_blocks) {

  auto glwe_dimension = params.glwe_dimension;
  auto polynomial_size = params.polynomial_size;
  auto big_lwe_size = glwe_dimension * polynomial_size + 1;
  auto big_lwe_size_bytes = big_lwe_size * sizeof(Torus);

  int num_steps = ceil(log2((double)num_radix_blocks));
  int space = 1;
  cuda_memcpy_async_gpu_to_gpu(step_output, generates_or_propagates,
                               big_lwe_size_bytes * num_radix_blocks,
                               streams[0], gpu_indexes[0]);

  for (int step = 0; step < num_steps; step++) {
    if (space > num_radix_blocks - 1)
      PANIC("Cuda error: step output is going out of bounds in Hillis Steele "
            "propagation")
    auto cur_blocks = &step_output[space * big_lwe_size];
    auto prev_blocks = generates_or_propagates;
    int cur_total_blocks = num_radix_blocks - space;

    legacy_integer_radix_apply_bivariate_lookup_table_kb<Torus>(
        streams, gpu_indexes, gpu_count, cur_blocks, cur_blocks, prev_blocks,
        bsks, ksks, cur_total_blocks, luts, luts->params.message_modulus);

    cuda_memcpy_async_gpu_to_gpu(
        &generates_or_propagates[space * big_lwe_size], cur_blocks,
        big_lwe_size_bytes * cur_total_blocks, streams[0], gpu_indexes[0]);
    space *= 2;
  }
}

template <typename Torus>
void host_compute_prefix_sum_hillis_steele(
    cudaStream_t const *streams, uint32_t const *gpu_indexes,
    uint32_t gpu_count, CudaRadixCiphertextFFI *step_output,
    CudaRadixCiphertextFFI *generates_or_propagates, int_radix_params params,
    int_radix_lut<Torus> *luts, void *const *bsks, Torus *const *ksks,
    uint32_t num_radix_blocks) {

  if (step_output->lwe_dimension != generates_or_propagates->lwe_dimension)
    PANIC("Cuda error: input lwe dimensions must be the same")

  int num_steps = ceil(log2((double)num_radix_blocks));
  int space = 1;
  copy_radix_ciphertext_slice_async<Torus>(
      streams[0], gpu_indexes[0], step_output, 0, num_radix_blocks,
      generates_or_propagates, 0, num_radix_blocks);

  CudaRadixCiphertextFFI cur_blocks;
  for (int step = 0; step < num_steps; step++) {
    if (space > num_radix_blocks - 1)
      PANIC("Cuda error: step output is going out of bounds in Hillis Steele "
            "propagation")
    as_radix_ciphertext_slice<Torus>(&cur_blocks, step_output, space,
                                     num_radix_blocks);
    auto prev_blocks = generates_or_propagates;
    int cur_total_blocks = num_radix_blocks - space;

    integer_radix_apply_bivariate_lookup_table_kb<Torus>(
        streams, gpu_indexes, gpu_count, &cur_blocks, &cur_blocks, prev_blocks,
        bsks, ksks, luts, cur_total_blocks, luts->params.message_modulus);

    copy_radix_ciphertext_slice_async<Torus>(
        streams[0], gpu_indexes[0], generates_or_propagates, space,
        num_radix_blocks, &cur_blocks, 0, cur_total_blocks);
    space *= 2;
  }
}

template <typename Torus>
void legacy_host_compute_propagation_simulators_and_group_carries(
    cudaStream_t const *streams, uint32_t const *gpu_indexes,
    uint32_t gpu_count, Torus *block_states, int_radix_params params,
    int_prop_simu_group_carries_memory<Torus> *mem, void *const *bsks,
    Torus *const *ksks, uint32_t num_radix_blocks, uint32_t num_groups) {

  auto glwe_dimension = params.glwe_dimension;
  auto polynomial_size = params.polynomial_size;
  auto message_modulus = params.message_modulus;
  auto carry_modulus = params.carry_modulus;

  uint32_t big_lwe_size = glwe_dimension * polynomial_size + 1;

  auto propagation_cum_sums = (Torus *)mem->propagation_cum_sums->ptr;
  auto group_size = mem->group_size;
  legacy_host_radix_cumulative_sum_in_groups<Torus>(
      streams[0], gpu_indexes[0], propagation_cum_sums, block_states,
      num_radix_blocks, big_lwe_size, group_size);

  auto luts_array_second_step = mem->luts_array_second_step;
  legacy_integer_radix_apply_univariate_lookup_table_kb<Torus>(
      streams, gpu_indexes, gpu_count, propagation_cum_sums,
      propagation_cum_sums, bsks, ksks, num_radix_blocks,
      luts_array_second_step);

  auto scalar_array_cum_sum = mem->scalar_array_cum_sum;
  auto big_lwe_dimension = big_lwe_size - 1;

  legacy_host_integer_radix_scalar_addition_inplace<Torus>(
      streams, gpu_indexes, gpu_count, propagation_cum_sums,
      scalar_array_cum_sum, big_lwe_dimension, num_radix_blocks,
      message_modulus, carry_modulus);

  uint32_t modulus_sup = message_modulus * carry_modulus;
  auto nbits = sizeof(Torus) * 8;
  Torus delta = (static_cast<Torus>(1) << (nbits - 1)) / modulus_sup;
  auto simulators = (Torus *)mem->simulators->ptr;
  auto grouping_pgns = (Torus *)mem->grouping_pgns->ptr;
  legacy_host_radix_split_simulators_and_grouping_pgns<Torus>(
      streams[0], gpu_indexes[0], simulators, grouping_pgns,
      propagation_cum_sums, num_radix_blocks, big_lwe_size, group_size, delta);

  auto resolved_carries = (Torus *)mem->resolved_carries->ptr;
  if (mem->use_sequential_algorithm_to_resolver_group_carries) {
    // Resolve group carries sequentially
    legacy_host_resolve_group_carries_sequentially(
        streams, gpu_indexes, gpu_count, resolved_carries, grouping_pgns,
        params, mem->seq_group_prop_mem, bsks, ksks, num_groups);
  } else {
    // Resolve group carries with hillis steele
    auto luts_carry_propagation_sum = mem->hs_group_prop_mem->lut_hillis_steele;
    legacy_host_compute_prefix_sum_hillis_steele<Torus>(
        streams, gpu_indexes, gpu_count, &resolved_carries[big_lwe_size],
        grouping_pgns, params, luts_carry_propagation_sum, bsks, ksks,
        num_groups - 1);
  }
}
// This function is used to perform step 2 of Thomas' new propagation algorithm
// Consist three steps:
// - propagates the carry within each group with cheap LWE operations stored in
// simulators
// - calculates the propagation state of each group
// - resolves the carries between groups, either sequentially or with hillis
// steele
template <typename Torus>
void host_compute_propagation_simulators_and_group_carries(
    cudaStream_t const *streams, uint32_t const *gpu_indexes,
    uint32_t gpu_count, CudaRadixCiphertextFFI *block_states,
    int_radix_params params, int_prop_simu_group_carries_memory<Torus> *mem,
    void *const *bsks, Torus *const *ksks, uint32_t num_radix_blocks,
    uint32_t num_groups) {

  if (num_radix_blocks > block_states->num_radix_blocks)
    PANIC("Cuda error: input does not have enough radix blocks")

  auto message_modulus = params.message_modulus;
  auto carry_modulus = params.carry_modulus;

  auto propagation_cum_sums = mem->propagation_cum_sums;
  auto group_size = mem->group_size;
  host_radix_cumulative_sum_in_groups<Torus>(streams[0], gpu_indexes[0],
                                             propagation_cum_sums, block_states,
                                             num_radix_blocks, group_size);

  auto luts_array_second_step = mem->luts_array_second_step;
  integer_radix_apply_univariate_lookup_table_kb<Torus>(
      streams, gpu_indexes, gpu_count, propagation_cum_sums,
      propagation_cum_sums, bsks, ksks, luts_array_second_step,
      num_radix_blocks);

  auto scalar_array_cum_sum = mem->scalar_array_cum_sum;

  host_integer_radix_scalar_addition_inplace<Torus>(
      streams, gpu_indexes, gpu_count, propagation_cum_sums,
      scalar_array_cum_sum, num_radix_blocks, message_modulus, carry_modulus);

  uint32_t modulus_sup = message_modulus * carry_modulus;
  auto nbits = sizeof(Torus) * 8;
  Torus delta = (static_cast<Torus>(1) << (nbits - 1)) / modulus_sup;
  auto simulators = mem->simulators;
  auto grouping_pgns = mem->grouping_pgns;
  host_radix_split_simulators_and_grouping_pgns<Torus>(
      streams[0], gpu_indexes[0], simulators, grouping_pgns,
      propagation_cum_sums, num_radix_blocks, group_size, delta);

  auto resolved_carries = mem->resolved_carries;
  if (mem->use_sequential_algorithm_to_resolver_group_carries) {
    // Resolve group carries sequentially
    host_resolve_group_carries_sequentially(
        streams, gpu_indexes, gpu_count, resolved_carries, grouping_pgns,
        params, mem->seq_group_prop_mem, bsks, ksks, num_groups);
  } else {
    // Resolve group carries with hillis steele
    auto luts_carry_propagation_sum = mem->hs_group_prop_mem->lut_hillis_steele;
    CudaRadixCiphertextFFI shifted_resolved_carries;
    as_radix_ciphertext_slice<Torus>(&shifted_resolved_carries,
                                     resolved_carries, 1, num_groups);
    host_compute_prefix_sum_hillis_steele<Torus>(
        streams, gpu_indexes, gpu_count, &shifted_resolved_carries,
        grouping_pgns, params, luts_carry_propagation_sum, bsks, ksks,
        num_groups - 1);
  }
}
template <typename Torus>
void legacy_host_compute_shifted_blocks_and_borrow_states(
    cudaStream_t const *streams, uint32_t const *gpu_indexes,
    uint32_t gpu_count, Torus *lwe_array, int_radix_params params,
    int_shifted_blocks_and_borrow_states_memory<Torus> *mem, void *const *bsks,
    Torus *const *ksks, uint32_t num_radix_blocks, uint32_t lut_stride,
    uint32_t num_many_lut) {

  auto glwe_dimension = params.glwe_dimension;
  auto polynomial_size = params.polynomial_size;
  uint32_t big_lwe_size = glwe_dimension * polynomial_size + 1;
  auto big_lwe_size_bytes = big_lwe_size * sizeof(Torus);

  auto shifted_blocks_and_borrow_states =
      (Torus *)mem->shifted_blocks_and_borrow_states->ptr;
  auto luts_array_first_step = mem->luts_array_first_step;

  legacy_integer_radix_apply_many_univariate_lookup_table_kb<Torus>(
      streams, gpu_indexes, gpu_count, shifted_blocks_and_borrow_states,
      lwe_array, bsks, ksks, num_radix_blocks, luts_array_first_step,
      num_many_lut, lut_stride);

  auto shifted_blocks = (Torus *)mem->shifted_blocks->ptr;
  auto borrow_states = (Torus *)mem->borrow_states->ptr;
  cuda_memcpy_async_gpu_to_gpu(borrow_states, shifted_blocks_and_borrow_states,
                               big_lwe_size_bytes * num_radix_blocks,
                               streams[0], gpu_indexes[0]);
  cuda_memcpy_async_gpu_to_gpu(
      shifted_blocks,
      shifted_blocks_and_borrow_states + big_lwe_size * num_radix_blocks,
      big_lwe_size_bytes * num_radix_blocks, streams[0], gpu_indexes[0]);
}

// This function is used to perform step 1 of Thomas' new borrow propagation
// algorithm It uses a many lut to calculate two luts in parallel
// shifted_blocks: contains (block % message modulus) << 1
// block states: contains the propagation states for the different blocks
// depending on the group it belongs to and the internal position within the
// block.
template <typename Torus>
void host_compute_shifted_blocks_and_borrow_states(
    cudaStream_t const *streams, uint32_t const *gpu_indexes,
    uint32_t gpu_count, CudaRadixCiphertextFFI *lwe_array,
    int_shifted_blocks_and_borrow_states_memory<Torus> *mem, void *const *bsks,
    Torus *const *ksks, uint32_t lut_stride, uint32_t num_many_lut) {
  auto num_radix_blocks = lwe_array->num_radix_blocks;

  auto shifted_blocks_and_borrow_states = mem->shifted_blocks_and_borrow_states;
  auto luts_array_first_step = mem->luts_array_first_step;

  integer_radix_apply_many_univariate_lookup_table_kb<Torus>(
      streams, gpu_indexes, gpu_count, shifted_blocks_and_borrow_states,
      lwe_array, bsks, ksks, luts_array_first_step, num_many_lut, lut_stride);

  auto shifted_blocks = mem->shifted_blocks;
  auto borrow_states = mem->borrow_states;
  copy_radix_ciphertext_slice_async<Torus>(
      streams[0], gpu_indexes[0], borrow_states, 0, num_radix_blocks,
      shifted_blocks_and_borrow_states, 0, num_radix_blocks);
  copy_radix_ciphertext_slice_async<Torus>(
      streams[0], gpu_indexes[0], shifted_blocks, 0, num_radix_blocks,
      shifted_blocks_and_borrow_states, num_radix_blocks, 2 * num_radix_blocks);
}

/*
 * input_blocks: input radix ciphertext propagation will happen inplace
 * acc_message_carry: list of two lut s, [(message_acc), (carry_acc)]
 * lut_indexes_message_carry: lut_indexes_vec for message and carry, should
 * always be  {0, 1} small_lwe_vector: output of keyswitch should have size = 2
 * * (lwe_dimension + 1) * sizeof(Torus) big_lwe_vector: output of pbs should
 * have size = 2 * (glwe_dimension * polynomial_size + 1) * sizeof(Torus)
 */
template <typename Torus>
void host_full_propagate_inplace(cudaStream_t const *streams,
                                 uint32_t const *gpu_indexes,
                                 uint32_t gpu_count,
                                 CudaRadixCiphertextFFI *input_blocks,
                                 int_fullprop_buffer<Torus> *mem_ptr,
                                 Torus *const *ksks, void *const *bsks,
                                 uint32_t num_blocks) {
  auto params = mem_ptr->lut->params;

  int big_lwe_size = (params.glwe_dimension * params.polynomial_size + 1);
  int small_lwe_size = (params.small_lwe_dimension + 1);

  // In the case of extracting a single LWE this parameters are dummy
  uint32_t num_many_lut = 1;
  uint32_t lut_stride = 0;
  for (int i = 0; i < num_blocks; i++) {
    CudaRadixCiphertextFFI cur_input_block;
    as_radix_ciphertext_slice<Torus>(&cur_input_block, input_blocks, i, i + 1);

    /// Since the keyswitch is done on one input only, use only 1 GPU
    execute_keyswitch_async<Torus>(
        streams, gpu_indexes, 1, (Torus *)(mem_ptr->tmp_small_lwe_vector->ptr),
        mem_ptr->lut->lwe_trivial_indexes, (Torus *)cur_input_block.ptr,
        mem_ptr->lut->lwe_trivial_indexes, ksks, params.big_lwe_dimension,
        params.small_lwe_dimension, params.ks_base_log, params.ks_level, 1);

    copy_radix_ciphertext_slice_async<Torus>(
        streams[0], gpu_indexes[0], mem_ptr->tmp_small_lwe_vector, 1, 2,
        mem_ptr->tmp_small_lwe_vector, 0, 1);

    execute_pbs_async<Torus>(
        streams, gpu_indexes, 1, (Torus *)mem_ptr->tmp_big_lwe_vector->ptr,
        mem_ptr->lut->lwe_trivial_indexes, mem_ptr->lut->lut_vec,
        mem_ptr->lut->lut_indexes_vec,
        (Torus *)mem_ptr->tmp_small_lwe_vector->ptr,
        mem_ptr->lut->lwe_trivial_indexes, bsks, mem_ptr->lut->buffer,
        params.glwe_dimension, params.small_lwe_dimension,
        params.polynomial_size, params.pbs_base_log, params.pbs_level,
        params.grouping_factor, 2, params.pbs_type, num_many_lut, lut_stride);

    copy_radix_ciphertext_slice_async<Torus>(streams[0], gpu_indexes[0],
                                             &cur_input_block, 0, 1,
                                             mem_ptr->tmp_big_lwe_vector, 0, 1);
    Torus lut_indexes[mem_ptr->lut->num_blocks];
    cuda_memcpy_async_to_cpu(&lut_indexes, mem_ptr->lut->get_lut_indexes(0, 0),
                             mem_ptr->lut->num_blocks * sizeof(Torus),
                             streams[0], gpu_indexes[0]);
    cuda_synchronize_stream(streams[0], gpu_indexes[0]);
    input_blocks->degrees[i] = mem_ptr->lut->degrees[lut_indexes[0]];
    input_blocks->noise_levels[i] = NoiseLevel::NOMINAL;

    if (i < num_blocks - 1) {
      CudaRadixCiphertextFFI next_input_block;
      as_radix_ciphertext_slice<Torus>(&next_input_block, input_blocks, i + 1,
                                       i + 2);
      CudaRadixCiphertextFFI second_input;
      as_radix_ciphertext_slice<Torus>(&second_input,
                                       mem_ptr->tmp_big_lwe_vector, 1, 2);

      host_addition<Torus>(streams[0], gpu_indexes[0], &next_input_block,
                           &next_input_block, &second_input, 1);
    }
  }
}

template <typename Torus>
void scratch_cuda_full_propagation(cudaStream_t const *streams,
                                   uint32_t const *gpu_indexes,
                                   uint32_t gpu_count,
                                   int_fullprop_buffer<Torus> **mem_ptr,
                                   int_radix_params params,
                                   bool allocate_gpu_memory) {

  *mem_ptr = new int_fullprop_buffer<Torus>(streams, gpu_indexes, gpu_count,
                                            params, allocate_gpu_memory);
}

// (lwe_dimension+1) threads
// (num_radix_blocks / 2) thread blocks
template <typename Torus>
__global__ void device_pack_blocks(Torus *lwe_array_out,
                                   Torus const *lwe_array_in,
                                   uint32_t lwe_dimension,
                                   uint32_t num_radix_blocks, uint32_t factor) {
  int tid = threadIdx.x + blockIdx.x * blockDim.x;

  if (tid < (lwe_dimension + 1)) {
    for (int bid = 0; bid < (num_radix_blocks / 2); bid++) {
      Torus *lsb_block =
          (Torus *)lwe_array_in + (2 * bid) * (lwe_dimension + 1);
      Torus *msb_block = lsb_block + (lwe_dimension + 1);

      Torus *packed_block = lwe_array_out + bid * (lwe_dimension + 1);

      packed_block[tid] = lsb_block[tid] + factor * msb_block[tid];
    }

    if (num_radix_blocks % 2 == 1) {
      // We couldn't host_pack the last block, so we just copy it
      Torus *lsb_block =
          (Torus *)lwe_array_in + (num_radix_blocks - 1) * (lwe_dimension + 1);
      Torus *last_block =
          lwe_array_out + (num_radix_blocks / 2) * (lwe_dimension + 1);

      last_block[tid] = lsb_block[tid];
    }
  }
}

// Packs the low ciphertext in the message parts of the high ciphertext
// and moves the high ciphertext into the carry part.
//
// This requires the block parameters to have enough room for two ciphertexts,
// so at least as many carry modulus as the message modulus
//
// Expects the carry buffer to be empty
template <typename Torus>
__host__ void pack_blocks(cudaStream_t stream, uint32_t gpu_index,
                          CudaRadixCiphertextFFI *lwe_array_out,
                          CudaRadixCiphertextFFI const *lwe_array_in,
                          uint32_t num_radix_blocks, uint32_t factor) {
  if (lwe_array_in->lwe_dimension != lwe_array_out->lwe_dimension)
    PANIC("Cuda error: the input and output should have the same lwe dimension")
  if (lwe_array_in->num_radix_blocks < num_radix_blocks)
    PANIC("Cuda error: the number of blocks to pack should be lower or equal "
          "to the number of blocks of the input")
  if (lwe_array_out->num_radix_blocks < num_radix_blocks / 2)
    PANIC("Cuda error: the number of output blocks should be greater or equal "
          "to the number of blocks to pack / 2")
  if (num_radix_blocks == 0)
    return;
  auto lwe_dimension = lwe_array_in->lwe_dimension;
  cuda_set_device(gpu_index);
  int num_blocks = 0, num_threads = 0;
  int num_entries = (lwe_dimension + 1);
  getNumBlocksAndThreads(num_entries, 1024, num_blocks, num_threads);
  device_pack_blocks<Torus><<<num_blocks, num_threads, 0, stream>>>(
      (Torus *)lwe_array_out->ptr, (Torus *)lwe_array_in->ptr, lwe_dimension,
      num_radix_blocks, factor);
  check_cuda_error(cudaGetLastError());
}

template <typename Torus>
__host__ void scalar_pack_blocks(cudaStream_t stream, uint32_t gpu_index,
                                 CudaRadixCiphertextFFI *lwe_array_out,
                                 Torus const *scalar_array_in,
                                 uint32_t num_radix_blocks, uint32_t factor) {
  if (lwe_array_out->num_radix_blocks < num_radix_blocks / 2)
    PANIC("Cuda error: the number of output blocks should be greater or equal "
          "to the number of blocks to pack / 2")
  if (num_radix_blocks == 0)
    return;
  cuda_set_device(gpu_index);
  int num_blocks = 0, num_threads = 0;
  int num_entries = 1;
  getNumBlocksAndThreads(num_entries, 1024, num_blocks, num_threads);
  device_pack_blocks<Torus><<<num_blocks, num_threads, 0, stream>>>(
      (Torus *)lwe_array_out->ptr, scalar_array_in, 0, num_radix_blocks,
      factor);
  check_cuda_error(cudaGetLastError());
}
/**
 * Each bit in lwe_array_in becomes a lwe ciphertext in lwe_array_out
 * Thus, lwe_array_out must be allocated with num_radix_blocks * bits_per_block
 * * (lwe_dimension+1) * sizeeof(Torus) bytes
 */
template <typename Torus>
__host__ void legacy_extract_n_bits(
    cudaStream_t const *streams, uint32_t const *gpu_indexes,
    uint32_t gpu_count, Torus *lwe_array_out, Torus *lwe_array_in,
    void *const *bsks, Torus *const *ksks, uint32_t num_radix_blocks,
    uint32_t bits_per_block, int_bit_extract_luts_buffer<Torus> *bit_extract) {

  legacy_integer_radix_apply_univariate_lookup_table_kb<Torus>(
      streams, gpu_indexes, gpu_count, lwe_array_out, lwe_array_in, bsks, ksks,
      num_radix_blocks * bits_per_block, bit_extract->lut);
}

/**
 * Each bit in lwe_array_in becomes a lwe ciphertext in lwe_array_out
 * Thus, lwe_array_out must be allocated with num_radix_blocks * bits_per_block
 * * (lwe_dimension+1) * sizeeof(Torus) bytes
 */
template <typename Torus>
__host__ void
extract_n_bits(cudaStream_t const *streams, uint32_t const *gpu_indexes,
               uint32_t gpu_count, CudaRadixCiphertextFFI *lwe_array_out,
               const CudaRadixCiphertextFFI *lwe_array_in, void *const *bsks,
               Torus *const *ksks, uint32_t effective_num_radix_blocks,
               uint32_t num_radix_blocks,
               int_bit_extract_luts_buffer<Torus> *bit_extract) {

  copy_radix_ciphertext_slice_async<Torus>(streams[0], gpu_indexes[0],
                                           lwe_array_out, 0, num_radix_blocks,
                                           lwe_array_in, 0, num_radix_blocks);
  if (effective_num_radix_blocks / num_radix_blocks > 0) {
    for (uint i = 1; i < effective_num_radix_blocks / num_radix_blocks; i++) {
      copy_radix_ciphertext_slice_async<Torus>(
          streams[0], gpu_indexes[0], lwe_array_out, i * num_radix_blocks,
          (i + 1) * num_radix_blocks, lwe_array_in, 0, num_radix_blocks);
    }
  }
  integer_radix_apply_univariate_lookup_table_kb<Torus>(
      streams, gpu_indexes, gpu_count, lwe_array_out, lwe_array_out, bsks, ksks,
      bit_extract->lut, effective_num_radix_blocks);
}

template <typename Torus>
__host__ void
reduce_signs(cudaStream_t const *streams, uint32_t const *gpu_indexes,
             uint32_t gpu_count, CudaRadixCiphertextFFI *signs_array_out,
             CudaRadixCiphertextFFI *signs_array_in,
             int_comparison_buffer<Torus> *mem_ptr,
             std::function<Torus(Torus)> sign_handler_f, void *const *bsks,
             Torus *const *ksks, uint32_t num_sign_blocks) {

  if (signs_array_out->lwe_dimension != signs_array_in->lwe_dimension)
    PANIC("Cuda error: input lwe dimensions must be the same")
  if (signs_array_in->num_radix_blocks < num_sign_blocks)
    PANIC("Cuda error: input num radix blocks should not be lower "
          "than the number of blocks to operate on")

  auto diff_buffer = mem_ptr->diff_buffer;

  auto params = mem_ptr->params;
  auto big_lwe_dimension = params.big_lwe_dimension;
  auto glwe_dimension = params.glwe_dimension;
  auto polynomial_size = params.polynomial_size;
  auto message_modulus = params.message_modulus;
  auto carry_modulus = params.carry_modulus;

  std::function<Torus(Torus)> reduce_two_orderings_function =
      [diff_buffer, sign_handler_f](Torus x) -> Torus {
    int msb = (x >> 2) & 3;
    int lsb = x & 3;

    return diff_buffer->tree_buffer->block_selector_f(msb, lsb);
  };

  auto signs_a = diff_buffer->tmp_signs_a;
  auto signs_b = diff_buffer->tmp_signs_b;

  copy_radix_ciphertext_slice_async<Torus>(streams[0], gpu_indexes[0], signs_a,
                                           0, num_sign_blocks, signs_array_in,
                                           0, num_sign_blocks);
  if (num_sign_blocks > 2) {
    auto lut = diff_buffer->reduce_signs_lut;
    generate_device_accumulator<Torus>(
        streams[0], gpu_indexes[0], lut->get_lut(0, 0), lut->get_degree(0),
        lut->get_max_degree(0), glwe_dimension, polynomial_size,
        message_modulus, carry_modulus, reduce_two_orderings_function);
    lut->broadcast_lut(streams, gpu_indexes, 0);

    while (num_sign_blocks > 2) {
      pack_blocks<Torus>(streams[0], gpu_indexes[0], signs_b, signs_a,
                         num_sign_blocks, 4);
      integer_radix_apply_univariate_lookup_table_kb<Torus>(
          streams, gpu_indexes, gpu_count, signs_a, signs_b, bsks, ksks, lut,
          num_sign_blocks / 2);

      if (num_sign_blocks % 2 == 1)
        copy_radix_ciphertext_slice_async<Torus>(
            streams[0], gpu_indexes[0], signs_a, num_sign_blocks / 2,
            num_sign_blocks / 2 + 1, signs_b, num_sign_blocks / 2,
            num_sign_blocks / 2 + 1);

      num_sign_blocks = (num_sign_blocks / 2) + (num_sign_blocks % 2);
    }
  }

  if (num_sign_blocks == 2) {
    std::function<Torus(Torus)> final_lut_f =
        [reduce_two_orderings_function, sign_handler_f](Torus x) -> Torus {
      Torus final_sign = reduce_two_orderings_function(x);
      return sign_handler_f(final_sign);
    };

    auto lut = diff_buffer->reduce_signs_lut;
    generate_device_accumulator<Torus>(
        streams[0], gpu_indexes[0], lut->get_lut(0, 0), lut->get_degree(0),
        lut->get_max_degree(0), glwe_dimension, polynomial_size,
        message_modulus, carry_modulus, final_lut_f);
    lut->broadcast_lut(streams, gpu_indexes, 0);

    pack_blocks<Torus>(streams[0], gpu_indexes[0], signs_b, signs_a, 2, 4);
    integer_radix_apply_univariate_lookup_table_kb<Torus>(
        streams, gpu_indexes, gpu_count, signs_array_out, signs_b, bsks, ksks,
        lut, 1);

  } else {

    std::function<Torus(Torus)> final_lut_f =
        [mem_ptr, sign_handler_f](Torus x) -> Torus {
      return sign_handler_f(x & 3);
    };

    auto lut = mem_ptr->diff_buffer->reduce_signs_lut;
    generate_device_accumulator<Torus>(
        streams[0], gpu_indexes[0], lut->get_lut(0, 0), lut->get_degree(0),
        lut->get_max_degree(0), glwe_dimension, polynomial_size,
        message_modulus, carry_modulus, final_lut_f);
    lut->broadcast_lut(streams, gpu_indexes, 0);

    integer_radix_apply_univariate_lookup_table_kb<Torus>(
        streams, gpu_indexes, gpu_count, signs_array_out, signs_a, bsks, ksks,
        lut, 1);
  }
}

template <typename Torus>
void scratch_cuda_apply_univariate_lut_kb(
    cudaStream_t const *streams, uint32_t const *gpu_indexes,
    uint32_t gpu_count, int_radix_lut<Torus> **mem_ptr, Torus const *input_lut,
    uint32_t num_radix_blocks, int_radix_params params, uint64_t lut_degree,
    bool allocate_gpu_memory) {

  *mem_ptr = new int_radix_lut<Torus>(streams, gpu_indexes, gpu_count, params,
                                      1, num_radix_blocks, allocate_gpu_memory);
  // It is safe to do this copy on GPU 0, because all LUTs always reside on GPU
  // 0
  cuda_memcpy_async_to_gpu((*mem_ptr)->get_lut(0, 0), (void *)input_lut,
                           (params.glwe_dimension + 1) *
                               params.polynomial_size * sizeof(Torus),
                           streams[0], gpu_indexes[0]);
  *(*mem_ptr)->get_degree(0) = lut_degree;
  (*mem_ptr)->broadcast_lut(streams, gpu_indexes, 0);
}

template <typename Torus>
void host_apply_univariate_lut_kb(cudaStream_t const *streams,
                                  uint32_t const *gpu_indexes,
                                  uint32_t gpu_count,
                                  CudaRadixCiphertextFFI *radix_lwe_out,
                                  CudaRadixCiphertextFFI const *radix_lwe_in,
                                  int_radix_lut<Torus> *mem, Torus *const *ksks,
                                  void *const *bsks) {

  integer_radix_apply_univariate_lookup_table_kb<Torus>(
      streams, gpu_indexes, gpu_count, radix_lwe_out, radix_lwe_in, bsks, ksks,
      mem, radix_lwe_out->num_radix_blocks);
}

template <typename Torus>
void scratch_cuda_apply_many_univariate_lut_kb(
    cudaStream_t const *streams, uint32_t const *gpu_indexes,
    uint32_t gpu_count, int_radix_lut<Torus> **mem_ptr, Torus const *input_lut,
    uint32_t num_radix_blocks, int_radix_params params, uint32_t num_many_lut,
    uint64_t lut_degree, bool allocate_gpu_memory) {

  *mem_ptr = new int_radix_lut<Torus>(streams, gpu_indexes, gpu_count, params,
                                      1, num_radix_blocks, num_many_lut,
                                      allocate_gpu_memory);
  // It is safe to do this copy on GPU 0, because all LUTs always reside on GPU
  // 0
  cuda_memcpy_async_to_gpu((*mem_ptr)->get_lut(0, 0), (void *)input_lut,
                           (params.glwe_dimension + 1) *
                               params.polynomial_size * sizeof(Torus),
                           streams[0], gpu_indexes[0]);
  *(*mem_ptr)->get_degree(0) = lut_degree;
  (*mem_ptr)->broadcast_lut(streams, gpu_indexes, 0);
}

template <typename Torus>
void host_apply_many_univariate_lut_kb(
    cudaStream_t const *streams, uint32_t const *gpu_indexes,
    uint32_t gpu_count, CudaRadixCiphertextFFI *radix_lwe_out,
    CudaRadixCiphertextFFI const *radix_lwe_in, int_radix_lut<Torus> *mem,
    Torus *const *ksks, void *const *bsks, uint32_t num_many_lut,
    uint32_t lut_stride) {

  integer_radix_apply_many_univariate_lookup_table_kb<Torus>(
      streams, gpu_indexes, gpu_count, radix_lwe_out, radix_lwe_in, bsks, ksks,
      mem, num_many_lut, lut_stride);
}

template <typename Torus>
void scratch_cuda_apply_bivariate_lut_kb(
    cudaStream_t const *streams, uint32_t const *gpu_indexes,
    uint32_t gpu_count, int_radix_lut<Torus> **mem_ptr, Torus const *input_lut,
    uint32_t num_radix_blocks, int_radix_params params, uint64_t lut_degree,
    bool allocate_gpu_memory) {

  *mem_ptr = new int_radix_lut<Torus>(streams, gpu_indexes, gpu_count, params,
                                      1, num_radix_blocks, allocate_gpu_memory);
  // It is safe to do this copy on GPU 0, because all LUTs always reside on GPU
  // 0
  cuda_memcpy_async_to_gpu((*mem_ptr)->get_lut(0, 0), (void *)input_lut,
                           (params.glwe_dimension + 1) *
                               params.polynomial_size * sizeof(Torus),
                           streams[0], gpu_indexes[0]);
  *(*mem_ptr)->get_degree(0) = lut_degree;
  (*mem_ptr)->broadcast_lut(streams, gpu_indexes, 0);
}

template <typename Torus>
void host_apply_bivariate_lut_kb(cudaStream_t const *streams,
                                 uint32_t const *gpu_indexes,
                                 uint32_t gpu_count,
                                 CudaRadixCiphertextFFI *radix_lwe_out,
                                 CudaRadixCiphertextFFI const *radix_lwe_in_1,
                                 CudaRadixCiphertextFFI const *radix_lwe_in_2,
                                 int_radix_lut<Torus> *mem, Torus *const *ksks,
                                 void *const *bsks, uint32_t num_radix_blocks,
                                 uint32_t shift) {

  integer_radix_apply_bivariate_lookup_table_kb<Torus>(
      streams, gpu_indexes, gpu_count, radix_lwe_out, radix_lwe_in_1,
      radix_lwe_in_2, bsks, ksks, mem, num_radix_blocks, shift);
}

template <typename Torus>
void scratch_cuda_propagate_single_carry_kb_inplace(
    cudaStream_t const *streams, uint32_t const *gpu_indexes,
    uint32_t gpu_count, int_sc_prop_memory<Torus> **mem_ptr,
    uint32_t num_radix_blocks, int_radix_params params, uint32_t requested_flag,
    uint32_t uses_carry, bool allocate_gpu_memory) {

  *mem_ptr = new int_sc_prop_memory<Torus>(
      streams, gpu_indexes, gpu_count, params, num_radix_blocks, requested_flag,
      uses_carry, allocate_gpu_memory);
}
template <typename Torus>
void legacy_host_propagate_single_carry(
    cudaStream_t const *streams, uint32_t const *gpu_indexes,
    uint32_t gpu_count, Torus *lwe_array, Torus *carry_out,
    const Torus *input_carries, int_sc_prop_memory<Torus> *mem,
    void *const *bsks, Torus *const *ksks, uint32_t num_radix_blocks,
    uint32_t requested_flag, uint32_t uses_carry) {
  auto params = mem->params;
  auto glwe_dimension = params.glwe_dimension;
  auto polynomial_size = params.polynomial_size;
  uint32_t big_lwe_size = glwe_dimension * polynomial_size + 1;
  auto big_lwe_size_bytes = big_lwe_size * sizeof(Torus);
  auto big_lwe_dimension = big_lwe_size - 1; // For host addition
  auto lut_stride = mem->lut_stride;
  auto num_many_lut = mem->num_many_lut;
  auto output_flag =
      (Torus *)mem->output_flag->ptr + big_lwe_size * num_radix_blocks;
  if (requested_flag == outputFlag::FLAG_OVERFLOW)
    PANIC("Cuda error: single carry propagation is not supported for overflow, "
          "try using add_and_propagate_single_carry");
  if (requested_flag == outputFlag::FLAG_CARRY && carry_out == nullptr)
    PANIC("Cuda error: when requesting FLAG_CARRY, carry_out must be a valid "
          "pointer")
  if (uses_carry == 1) {
    legacy_host_addition<Torus>(streams[0], gpu_indexes[0], lwe_array,
                                lwe_array, input_carries, big_lwe_dimension, 1);
  }
  // Step 1
  legacy_host_compute_shifted_blocks_and_states<Torus>(
      streams, gpu_indexes, gpu_count, lwe_array, params,
      mem->shifted_blocks_state_mem, bsks, ksks, num_radix_blocks, lut_stride,
      num_many_lut);
  auto block_states = (Torus *)mem->shifted_blocks_state_mem->block_states->ptr;

  if (requested_flag == outputFlag::FLAG_CARRY) {
    cuda_memcpy_async_gpu_to_gpu(
        output_flag, block_states + (num_radix_blocks - 1) * big_lwe_size,
        big_lwe_size_bytes, streams[0], gpu_indexes[0]);
  }
  // Step 2
  legacy_host_compute_propagation_simulators_and_group_carries<Torus>(
      streams, gpu_indexes, gpu_count, block_states, params,
      mem->prop_simu_group_carries_mem, bsks, ksks, num_radix_blocks,
      mem->num_groups);

  auto group_size = mem->prop_simu_group_carries_mem->group_size;

  auto prepared_blocks =
      (Torus *)mem->prop_simu_group_carries_mem->prepared_blocks->ptr;
  auto shifted_blocks =
      (Torus *)mem->shifted_blocks_state_mem->shifted_blocks->ptr;
  legacy_host_addition<Torus>(
      streams[0], gpu_indexes[0], prepared_blocks, shifted_blocks,
      (Torus *)mem->prop_simu_group_carries_mem->simulators->ptr,
      big_lwe_dimension, num_radix_blocks);

  if (requested_flag == outputFlag::FLAG_OVERFLOW ||
      requested_flag == outputFlag::FLAG_CARRY) {
    legacy_host_addition<Torus>(
        streams[0], gpu_indexes[0], output_flag, output_flag,
        (Torus *)mem->prop_simu_group_carries_mem->simulators->ptr +
            (num_radix_blocks - 1) * big_lwe_size,
        big_lwe_dimension, 1);
  }

  legacy_host_radix_sum_in_groups<Torus>(
      streams[0], gpu_indexes[0], prepared_blocks, prepared_blocks,
      (Torus *)mem->prop_simu_group_carries_mem->resolved_carries->ptr,
      num_radix_blocks, big_lwe_size, group_size);
  if (requested_flag == outputFlag::FLAG_CARRY) {
    legacy_host_addition<Torus>(
        streams[0], gpu_indexes[0], output_flag, output_flag,
        (Torus *)mem->prop_simu_group_carries_mem->resolved_carries->ptr +
            (mem->num_groups - 1) * big_lwe_size,
        big_lwe_dimension, 1);

    cuda_memcpy_async_gpu_to_gpu(
        prepared_blocks + num_radix_blocks * big_lwe_size, output_flag,
        big_lwe_size_bytes, streams[0], gpu_indexes[0]);
    legacy_integer_radix_apply_univariate_lookup_table_kb<Torus>(
        streams, gpu_indexes, gpu_count, (Torus *)mem->output_flag->ptr,
        prepared_blocks, bsks, ksks, num_radix_blocks + 1,
        mem->lut_message_extract);

    cuda_memcpy_async_gpu_to_gpu(lwe_array, (Torus *)mem->output_flag->ptr,
                                 big_lwe_size_bytes * num_radix_blocks,
                                 streams[0], gpu_indexes[0]);
    cuda_memcpy_async_gpu_to_gpu(
        carry_out,
        (Torus *)mem->output_flag->ptr + num_radix_blocks * big_lwe_size,
        big_lwe_size_bytes, streams[0], gpu_indexes[0]);
  } else {
    legacy_integer_radix_apply_univariate_lookup_table_kb<Torus>(
        streams, gpu_indexes, gpu_count, lwe_array, prepared_blocks, bsks, ksks,
        num_radix_blocks, mem->lut_message_extract);
  }
}

// This function perform the three steps of Thomas' new carry propagation
// includes the logic to extract overflow when requested
template <typename Torus>
void host_propagate_single_carry(cudaStream_t const *streams,
                                 uint32_t const *gpu_indexes,
                                 uint32_t gpu_count,
                                 CudaRadixCiphertextFFI *lwe_array,
                                 CudaRadixCiphertextFFI *carry_out,
                                 const CudaRadixCiphertextFFI *input_carries,
                                 int_sc_prop_memory<Torus> *mem,
                                 void *const *bsks, Torus *const *ksks,
                                 uint32_t requested_flag, uint32_t uses_carry) {
  auto num_radix_blocks = lwe_array->num_radix_blocks;
  auto params = mem->params;
  auto glwe_dimension = params.glwe_dimension;
  auto polynomial_size = params.polynomial_size;
  uint32_t big_lwe_size = glwe_dimension * polynomial_size + 1;
  auto lut_stride = mem->lut_stride;
  auto num_many_lut = mem->num_many_lut;
  CudaRadixCiphertextFFI output_flag;
  as_radix_ciphertext_slice<Torus>(&output_flag, mem->output_flag,
                                   num_radix_blocks, num_radix_blocks + 1);
  if (requested_flag == outputFlag::FLAG_OVERFLOW)
    PANIC("Cuda error: single carry propagation is not supported for overflow, "
          "try using add_and_propagate_single_carry");
  if (requested_flag == outputFlag::FLAG_CARRY && carry_out == nullptr)
    PANIC("Cuda error: when requesting FLAG_CARRY, carry_out must be a valid "
          "pointer")
  if (uses_carry == 1) {
    host_addition<Torus>(streams[0], gpu_indexes[0], lwe_array, lwe_array,
                         input_carries, 1);
  }
  // Step 1
  host_compute_shifted_blocks_and_states<Torus>(
      streams, gpu_indexes, gpu_count, lwe_array, mem->shifted_blocks_state_mem,
      bsks, ksks, lut_stride, num_many_lut);
  auto block_states = mem->shifted_blocks_state_mem->block_states;

  if (requested_flag == outputFlag::FLAG_CARRY) {
    copy_radix_ciphertext_slice_async<Torus>(
        streams[0], gpu_indexes[0], &output_flag, 0, 1, block_states,
        num_radix_blocks - 1, num_radix_blocks);
  }
  // Step 2
  host_compute_propagation_simulators_and_group_carries<Torus>(
      streams, gpu_indexes, gpu_count, block_states, params,
      mem->prop_simu_group_carries_mem, bsks, ksks, num_radix_blocks,
      mem->num_groups);

  auto group_size = mem->prop_simu_group_carries_mem->group_size;

  auto prepared_blocks = mem->prop_simu_group_carries_mem->prepared_blocks;
  auto shifted_blocks = mem->shifted_blocks_state_mem->shifted_blocks;
  host_addition<Torus>(
      streams[0], gpu_indexes[0], prepared_blocks, shifted_blocks,
      mem->prop_simu_group_carries_mem->simulators, num_radix_blocks);

  if (requested_flag == outputFlag::FLAG_OVERFLOW ||
      requested_flag == outputFlag::FLAG_CARRY) {
    CudaRadixCiphertextFFI shifted_simulators;
    as_radix_ciphertext_slice<Torus>(
        &shifted_simulators, mem->prop_simu_group_carries_mem->simulators,
        num_radix_blocks - 1, num_radix_blocks);
    host_addition<Torus>(streams[0], gpu_indexes[0], &output_flag, &output_flag,
                         &shifted_simulators, 1);
  }

  host_radix_sum_in_groups<Torus>(
      streams[0], gpu_indexes[0], prepared_blocks, prepared_blocks,
      mem->prop_simu_group_carries_mem->resolved_carries, num_radix_blocks,
      group_size);
  if (requested_flag == outputFlag::FLAG_CARRY) {
    CudaRadixCiphertextFFI shifted_resolved_carries;
    as_radix_ciphertext_slice<Torus>(
        &shifted_resolved_carries,
        mem->prop_simu_group_carries_mem->resolved_carries, mem->num_groups - 1,
        mem->num_groups);
    host_addition<Torus>(streams[0], gpu_indexes[0], &output_flag, &output_flag,
                         &shifted_resolved_carries, 1);

    copy_radix_ciphertext_slice_async<Torus>(
        streams[0], gpu_indexes[0], prepared_blocks, num_radix_blocks,
        num_radix_blocks + 1, &output_flag, 0, 1);
    integer_radix_apply_univariate_lookup_table_kb<Torus>(
        streams, gpu_indexes, gpu_count, mem->output_flag, prepared_blocks,
        bsks, ksks, mem->lut_message_extract, num_radix_blocks + 1);

    copy_radix_ciphertext_slice_async<Torus>(
        streams[0], gpu_indexes[0], lwe_array, 0, num_radix_blocks,
        mem->output_flag, 0, num_radix_blocks);
    copy_radix_ciphertext_slice_async<Torus>(
        streams[0], gpu_indexes[0], carry_out, 0, 1, mem->output_flag,
        num_radix_blocks, num_radix_blocks + 1);
  } else {
    auto message_extract = mem->lut_message_extract;
    integer_radix_apply_univariate_lookup_table_kb<Torus>(
        streams, gpu_indexes, gpu_count, lwe_array, prepared_blocks, bsks, ksks,
        message_extract, num_radix_blocks);
  }
}

// This function perform the three steps of Thomas' new carry propagation
// includes the logic to extract overflow when requested
template <typename Torus>
void host_add_and_propagate_single_carry(
    cudaStream_t const *streams, uint32_t const *gpu_indexes,
    uint32_t gpu_count, CudaRadixCiphertextFFI *lhs_array,
    const CudaRadixCiphertextFFI *rhs_array, CudaRadixCiphertextFFI *carry_out,
    const CudaRadixCiphertextFFI *input_carries, int_sc_prop_memory<Torus> *mem,
    void *const *bsks, Torus *const *ksks, uint32_t requested_flag,
    uint32_t uses_carry) {
  if (lhs_array->num_radix_blocks != rhs_array->num_radix_blocks)
    PANIC("Cuda error: input and output num radix blocks must be the same")
  if (lhs_array->lwe_dimension != rhs_array->lwe_dimension ||
      lhs_array->lwe_dimension != input_carries->lwe_dimension ||
      lhs_array->lwe_dimension != carry_out->lwe_dimension)
    PANIC("Cuda error: input and output lwe dimension must be the same")
  if ((requested_flag == outputFlag::FLAG_OVERFLOW ||
       requested_flag == outputFlag::FLAG_CARRY) &&
      carry_out == nullptr)
    PANIC("Cuda error: when requesting FLAG_CARRY, carry_out must be a valid "
          "pointer")

  auto num_radix_blocks = lhs_array->num_radix_blocks;
  auto params = mem->params;
  auto glwe_dimension = params.glwe_dimension;
  auto polynomial_size = params.polynomial_size;
  uint32_t big_lwe_size = glwe_dimension * polynomial_size + 1;
  auto lut_stride = mem->lut_stride;
  auto num_many_lut = mem->num_many_lut;
  CudaRadixCiphertextFFI output_flag;
  as_radix_ciphertext_slice<Torus>(&output_flag, mem->output_flag,
                                   num_radix_blocks, num_radix_blocks + 1);

  if (requested_flag == outputFlag::FLAG_OVERFLOW) {
    copy_radix_ciphertext_slice_async<Torus>(
        streams[0], gpu_indexes[0], mem->last_lhs, 0, 1, lhs_array,
        num_radix_blocks - 1, num_radix_blocks);
    copy_radix_ciphertext_slice_async<Torus>(
        streams[0], gpu_indexes[0], mem->last_rhs, 0, 1, rhs_array,
        num_radix_blocks - 1, num_radix_blocks);
  }

  host_addition<Torus>(streams[0], gpu_indexes[0], lhs_array, lhs_array,
                       rhs_array, num_radix_blocks);

  if (uses_carry == 1) {
    host_addition<Torus>(streams[0], gpu_indexes[0], lhs_array, lhs_array,
                         input_carries, 1);
  }
  // Step 1
  host_compute_shifted_blocks_and_states<Torus>(
      streams, gpu_indexes, gpu_count, lhs_array, mem->shifted_blocks_state_mem,
      bsks, ksks, lut_stride, num_many_lut);
  auto block_states = mem->shifted_blocks_state_mem->block_states;
  if (requested_flag == outputFlag::FLAG_OVERFLOW) {
    auto lut_overflow_prep = mem->lut_overflow_flag_prep;
    integer_radix_apply_bivariate_lookup_table_kb<Torus>(
        streams, gpu_indexes, gpu_count, &output_flag, mem->last_lhs,
        mem->last_rhs, bsks, ksks, lut_overflow_prep, 1,
        lut_overflow_prep->params.message_modulus);
  } else if (requested_flag == outputFlag::FLAG_CARRY) {
    copy_radix_ciphertext_slice_async<Torus>(
        streams[0], gpu_indexes[0], &output_flag, 0, 1, block_states,
        num_radix_blocks - 1, num_radix_blocks);
  }

  // Step 2
  host_compute_propagation_simulators_and_group_carries<Torus>(
      streams, gpu_indexes, gpu_count, block_states, params,
      mem->prop_simu_group_carries_mem, bsks, ksks, num_radix_blocks,
      mem->num_groups);

  auto group_size = mem->prop_simu_group_carries_mem->group_size;

  auto prepared_blocks = mem->prop_simu_group_carries_mem->prepared_blocks;
  auto shifted_blocks = mem->shifted_blocks_state_mem->shifted_blocks;
  host_addition<Torus>(
      streams[0], gpu_indexes[0], prepared_blocks, shifted_blocks,
      mem->prop_simu_group_carries_mem->simulators, num_radix_blocks);

  if (requested_flag == outputFlag::FLAG_OVERFLOW ||
      requested_flag == outputFlag::FLAG_CARRY) {
    CudaRadixCiphertextFFI shifted_simulators;
    as_radix_ciphertext_slice<Torus>(
        &shifted_simulators, mem->prop_simu_group_carries_mem->simulators,
        num_radix_blocks - 1, num_radix_blocks);
    host_addition<Torus>(streams[0], gpu_indexes[0], &output_flag, &output_flag,
                         &shifted_simulators, 1);
  }

  // Step 3
  //  Add carries and cleanup OutputFlag::None
  host_radix_sum_in_groups<Torus>(
      streams[0], gpu_indexes[0], prepared_blocks, prepared_blocks,
      mem->prop_simu_group_carries_mem->resolved_carries, num_radix_blocks,
      group_size);

  if (requested_flag == outputFlag::FLAG_OVERFLOW ||
      requested_flag == outputFlag::FLAG_CARRY) {
    if (num_radix_blocks == 1 && requested_flag == outputFlag::FLAG_OVERFLOW &&
        uses_carry == 1) {
      host_addition<Torus>(streams[0], gpu_indexes[0], &output_flag,
                           &output_flag, input_carries, 1);

    } else {
      CudaRadixCiphertextFFI shifted_resolved_carries;
      as_radix_ciphertext_slice<Torus>(
          &shifted_resolved_carries,
          mem->prop_simu_group_carries_mem->resolved_carries,
          mem->num_groups - 1, mem->num_groups);
      host_addition<Torus>(streams[0], gpu_indexes[0], &output_flag,
                           &output_flag, &shifted_resolved_carries, 1);
    }
    copy_radix_ciphertext_slice_async<Torus>(
        streams[0], gpu_indexes[0], prepared_blocks, num_radix_blocks,
        num_radix_blocks + 1, &output_flag, 0, 1);
    integer_radix_apply_univariate_lookup_table_kb<Torus>(
        streams, gpu_indexes, gpu_count, mem->output_flag, prepared_blocks,
        bsks, ksks, mem->lut_message_extract, num_radix_blocks + 1);

    copy_radix_ciphertext_slice_async<Torus>(
        streams[0], gpu_indexes[0], lhs_array, 0, num_radix_blocks,
        mem->output_flag, 0, num_radix_blocks);
    copy_radix_ciphertext_slice_async<Torus>(
        streams[0], gpu_indexes[0], carry_out, 0, 1, mem->output_flag,
        num_radix_blocks, num_radix_blocks + 1);
  } else {
    integer_radix_apply_univariate_lookup_table_kb<Torus>(
        streams, gpu_indexes, gpu_count, lhs_array, prepared_blocks, bsks, ksks,
        mem->lut_message_extract, num_radix_blocks);
  }
}

template <typename Torus>
void scratch_cuda_integer_overflowing_sub(
    cudaStream_t const *streams, uint32_t const *gpu_indexes,
    uint32_t gpu_count, int_borrow_prop_memory<Torus> **mem_ptr,
    uint32_t num_radix_blocks, int_radix_params params,
    uint32_t compute_overflow, bool allocate_gpu_memory) {

  *mem_ptr = new int_borrow_prop_memory<Torus>(
      streams, gpu_indexes, gpu_count, params, num_radix_blocks,
      compute_overflow, allocate_gpu_memory);
}

template <typename Torus>
void legacy_host_single_borrow_propagate(
    cudaStream_t const *streams, uint32_t const *gpu_indexes,
    uint32_t gpu_count, Torus *lhsrhs_array, Torus *overflow_block,
    const Torus *input_borrow, int_borrow_prop_memory<Torus> *mem,
    void *const *bsks, Torus *const *ksks, uint32_t num_radix_blocks,
    uint32_t num_groups, uint32_t compute_overflow,
    uint32_t uses_input_borrow) {
  auto params = mem->params;
  auto glwe_dimension = params.glwe_dimension;
  auto polynomial_size = params.polynomial_size;
  auto message_modulus = params.message_modulus;
  auto carry_modulus = params.carry_modulus;
  uint32_t big_lwe_size = glwe_dimension * polynomial_size + 1;
  auto big_lwe_size_bytes = big_lwe_size * sizeof(Torus);
  auto big_lwe_dimension = big_lwe_size - 1;
  auto lut_stride = mem->lut_stride;
  auto num_many_lut = mem->num_many_lut;

  if (mem->num_groups < num_groups)
    PANIC("Cuda error: inconsistency in num_groups")
  if (uses_input_borrow == 1) {
    legacy_host_unchecked_sub_with_correcting_term<Torus>(
        streams[0], gpu_indexes[0], lhsrhs_array, lhsrhs_array, input_borrow,
        big_lwe_dimension, 1, message_modulus, carry_modulus,
        message_modulus - 1);
  }
  // Step 1
  legacy_host_compute_shifted_blocks_and_borrow_states<Torus>(
      streams, gpu_indexes, gpu_count, lhsrhs_array, params,
      mem->shifted_blocks_borrow_state_mem, bsks, ksks, num_radix_blocks,
      lut_stride, num_many_lut);

  auto borrow_states =
      (Torus *)mem->shifted_blocks_borrow_state_mem->borrow_states->ptr;
  cuda_memcpy_async_gpu_to_gpu((Torus *)mem->overflow_block->ptr,
                               borrow_states +
                                   (num_radix_blocks - 1) * big_lwe_size,
                               big_lwe_size_bytes, streams[0], gpu_indexes[0]);

  // Step 2
  legacy_host_compute_propagation_simulators_and_group_carries<Torus>(
      streams, gpu_indexes, gpu_count, borrow_states, params,
      mem->prop_simu_group_carries_mem, bsks, ksks, num_radix_blocks,
      num_groups);

  auto shifted_blocks =
      (Torus *)mem->shifted_blocks_borrow_state_mem->shifted_blocks->ptr;
  auto prepared_blocks =
      (Torus *)mem->prop_simu_group_carries_mem->prepared_blocks->ptr;
  auto simulators = (Torus *)mem->prop_simu_group_carries_mem->simulators->ptr;

  host_subtraction<Torus>(streams[0], gpu_indexes[0], prepared_blocks,
                          shifted_blocks, simulators, big_lwe_dimension,
                          num_radix_blocks);

  legacy_host_integer_radix_add_scalar_one_inplace<Torus>(
      streams, gpu_indexes, gpu_count, prepared_blocks, big_lwe_dimension,
      num_radix_blocks, message_modulus, carry_modulus);

  if (compute_overflow == outputFlag::FLAG_OVERFLOW) {
    legacy_host_addition<Torus>(
        streams[0], gpu_indexes[0], (Torus *)mem->overflow_block->ptr,
        (Torus *)mem->overflow_block->ptr,
        (Torus *)mem->prop_simu_group_carries_mem->simulators->ptr +
            (num_radix_blocks - 1) * big_lwe_size,
        big_lwe_dimension, 1);
  }
  auto resolved_borrows =
      (Torus *)mem->prop_simu_group_carries_mem->resolved_carries->ptr;

  // Step 3
  //  This needs to be done before because in next step we modify the resolved
  //  borrows
  if (compute_overflow == outputFlag::FLAG_OVERFLOW) {
    legacy_host_addition<Torus>(
        streams[0], gpu_indexes[0], (Torus *)mem->overflow_block->ptr,
        (Torus *)mem->overflow_block->ptr,
        resolved_borrows + (num_groups - 1) * big_lwe_size, big_lwe_dimension,
        1);
  }

  cuda_event_record(mem->incoming_events[0], streams[0], gpu_indexes[0]);
  for (int j = 0; j < mem->active_gpu_count; j++) {
    cuda_stream_wait_event(mem->sub_streams_1[j], mem->incoming_events[0],
                           gpu_indexes[j]);
    cuda_stream_wait_event(mem->sub_streams_2[j], mem->incoming_events[0],
                           gpu_indexes[j]);
  }

  if (compute_overflow == outputFlag::FLAG_OVERFLOW) {
    auto borrow_flag = mem->lut_borrow_flag;
    legacy_integer_radix_apply_univariate_lookup_table_kb<Torus>(
        mem->sub_streams_1, gpu_indexes, gpu_count, overflow_block,
        (Torus *)mem->overflow_block->ptr, bsks, ksks, 1, borrow_flag);
  }
  for (int j = 0; j < mem->active_gpu_count; j++) {
    cuda_event_record(mem->outgoing_events1[j], mem->sub_streams_1[j],
                      gpu_indexes[j]);
  }

  // subtract borrow and cleanup prepared blocks
  host_negation<Torus>(mem->sub_streams_2[0], gpu_indexes[0], resolved_borrows,
                       resolved_borrows, big_lwe_dimension, num_groups);

  legacy_host_radix_sum_in_groups<Torus>(
      mem->sub_streams_2[0], gpu_indexes[0], prepared_blocks, prepared_blocks,
      resolved_borrows, num_radix_blocks, big_lwe_size, mem->group_size);

  auto message_extract = mem->lut_message_extract;
  legacy_integer_radix_apply_univariate_lookup_table_kb<Torus>(
      mem->sub_streams_2, gpu_indexes, gpu_count, lhsrhs_array, prepared_blocks,
      bsks, ksks, num_radix_blocks, message_extract);

  for (int j = 0; j < mem->active_gpu_count; j++) {
    cuda_event_record(mem->outgoing_events2[j], mem->sub_streams_2[j],
                      gpu_indexes[j]);
    cuda_stream_wait_event(streams[0], mem->outgoing_events1[j],
                           gpu_indexes[0]);
    cuda_stream_wait_event(streams[0], mem->outgoing_events2[j],
                           gpu_indexes[0]);
  }
}

// This function perform the three steps of Thomas' new borrow propagation
// includes the logic to extract overflow when requested
template <typename Torus>
void host_single_borrow_propagate(
    cudaStream_t const *streams, uint32_t const *gpu_indexes,
    uint32_t gpu_count, CudaRadixCiphertextFFI *lwe_array,
    CudaRadixCiphertextFFI *overflow_block,
    const CudaRadixCiphertextFFI *input_borrow,
    int_borrow_prop_memory<Torus> *mem, void *const *bsks, Torus *const *ksks,
    uint32_t num_groups, uint32_t compute_overflow,
    uint32_t uses_input_borrow) {
  auto num_radix_blocks = lwe_array->num_radix_blocks;
  auto params = mem->params;
  auto glwe_dimension = params.glwe_dimension;
  auto polynomial_size = params.polynomial_size;
  auto message_modulus = params.message_modulus;
  auto carry_modulus = params.carry_modulus;
  uint32_t big_lwe_size = glwe_dimension * polynomial_size + 1;
  auto big_lwe_dimension = big_lwe_size - 1;
  auto lut_stride = mem->lut_stride;
  auto num_many_lut = mem->num_many_lut;

  if (mem->num_groups < num_groups)
    PANIC("Cuda error: inconsistency in num_groups")
  if (uses_input_borrow == 1) {
    host_unchecked_sub_with_correcting_term<Torus>(
        streams[0], gpu_indexes[0], lwe_array, lwe_array, input_borrow, 1,
        message_modulus, carry_modulus);
  }
  // Step 1
  host_compute_shifted_blocks_and_borrow_states<Torus>(
      streams, gpu_indexes, gpu_count, lwe_array,
      mem->shifted_blocks_borrow_state_mem, bsks, ksks, lut_stride,
      num_many_lut);

  auto borrow_states = mem->shifted_blocks_borrow_state_mem->borrow_states;
  copy_radix_ciphertext_slice_async<Torus>(
      streams[0], gpu_indexes[0], mem->overflow_block, 0, 1, borrow_states,
      num_radix_blocks - 1, num_radix_blocks);

  // Step 2
  host_compute_propagation_simulators_and_group_carries<Torus>(
      streams, gpu_indexes, gpu_count, borrow_states, params,
      mem->prop_simu_group_carries_mem, bsks, ksks, num_radix_blocks,
      num_groups);

  auto shifted_blocks =
      (Torus *)mem->shifted_blocks_borrow_state_mem->shifted_blocks->ptr;
  auto prepared_blocks = mem->prop_simu_group_carries_mem->prepared_blocks;
  auto simulators = (Torus *)mem->prop_simu_group_carries_mem->simulators->ptr;

  host_subtraction<Torus>(streams[0], gpu_indexes[0],
                          (Torus *)prepared_blocks->ptr, shifted_blocks,
                          simulators, big_lwe_dimension, num_radix_blocks);

  host_integer_radix_add_scalar_one_inplace<Torus>(
      streams, gpu_indexes, gpu_count, prepared_blocks, message_modulus,
      carry_modulus);

  if (compute_overflow == outputFlag::FLAG_OVERFLOW) {
    CudaRadixCiphertextFFI shifted_simulators;
    as_radix_ciphertext_slice<Torus>(
        &shifted_simulators, mem->prop_simu_group_carries_mem->simulators,
        num_radix_blocks - 1, num_radix_blocks);
    host_addition<Torus>(streams[0], gpu_indexes[0], mem->overflow_block,
                         mem->overflow_block, &shifted_simulators, 1);
  }
  CudaRadixCiphertextFFI resolved_borrows;
  as_radix_ciphertext_slice<Torus>(
      &resolved_borrows, mem->prop_simu_group_carries_mem->resolved_carries,
      num_groups - 1, num_groups);

  // Step 3
  //  This needs to be done before because in next step we modify the resolved
  //  borrows
  if (compute_overflow == outputFlag::FLAG_OVERFLOW) {
    host_addition<Torus>(streams[0], gpu_indexes[0], mem->overflow_block,
                         mem->overflow_block, &resolved_borrows, 1);
  }

  cuda_event_record(mem->incoming_events[0], streams[0], gpu_indexes[0]);
  for (int j = 0; j < mem->active_gpu_count; j++) {
    cuda_stream_wait_event(mem->sub_streams_1[j], mem->incoming_events[0],
                           gpu_indexes[j]);
    cuda_stream_wait_event(mem->sub_streams_2[j], mem->incoming_events[0],
                           gpu_indexes[j]);
  }

  if (compute_overflow == outputFlag::FLAG_OVERFLOW) {
    auto borrow_flag = mem->lut_borrow_flag;
    integer_radix_apply_univariate_lookup_table_kb<Torus>(
        mem->sub_streams_1, gpu_indexes, gpu_count, overflow_block,
        mem->overflow_block, bsks, ksks, borrow_flag, 1);
  }
  for (int j = 0; j < mem->active_gpu_count; j++) {
    cuda_event_record(mem->outgoing_events1[j], mem->sub_streams_1[j],
                      gpu_indexes[j]);
  }

  // subtract borrow and cleanup prepared blocks
  auto resolved_carries = mem->prop_simu_group_carries_mem->resolved_carries;
  host_negation<Torus>(
      mem->sub_streams_2[0], gpu_indexes[0], (Torus *)resolved_carries->ptr,
      (Torus *)resolved_carries->ptr, big_lwe_dimension, num_groups);

  host_radix_sum_in_groups<Torus>(
      mem->sub_streams_2[0], gpu_indexes[0], prepared_blocks, prepared_blocks,
      resolved_carries, num_radix_blocks, mem->group_size);

  auto message_extract = mem->lut_message_extract;
  integer_radix_apply_univariate_lookup_table_kb<Torus>(
      mem->sub_streams_2, gpu_indexes, gpu_count, lwe_array, prepared_blocks,
      bsks, ksks, message_extract, num_radix_blocks);

  for (int j = 0; j < mem->active_gpu_count; j++) {
    cuda_event_record(mem->outgoing_events2[j], mem->sub_streams_2[j],
                      gpu_indexes[j]);
    cuda_stream_wait_event(streams[0], mem->outgoing_events1[j],
                           gpu_indexes[0]);
    cuda_stream_wait_event(streams[0], mem->outgoing_events2[j],
                           gpu_indexes[0]);
  }
}

#endif // TFHE_RS_INTERNAL_INTEGER_CUH
