#ifndef CUDA_ADD_CUH
#define CUDA_ADD_CUH

#ifdef __CDT_PARSER__
#endif

#include "checked_arithmetic.h"
#include "device.h"
#include "helper_multi_gpu.h"
#include "integer/integer.h"
#include "integer/integer_utilities.h"
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
__global__ void addition(T *output, T const *input_1, T const *input_2,
                         uint32_t num_entries) {

  int tid = threadIdx.x;
  int index = blockIdx.x * blockDim.x + tid;
  if (index < num_entries) {
    // Here we take advantage of the wrapping behaviour of uint
    output[index] = input_1[index] + input_2[index];
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

// Row accessor for a contiguous (flat) row-major 2D LWE array.
template <typename T> struct FlatRowAccessor {
  const T *base;
  uint32_t num_columns;
  uint32_t lwe_size;
  __device__ const T *row(uint32_t r, uint32_t j) const {
    return base + ((size_t)r * num_columns + j) * lwe_size;
  }
};

// Row accessor for a non-contiguous 2D LWE array (one pointer per row).
template <typename T> struct PtrTableRowAccessor {
  T *const *ptrs;
  uint32_t lwe_size;
  __device__ const T *row(uint32_t r, uint32_t j) const {
    return ptrs[r] + (size_t)j * lwe_size;
  }
};

// Column-wise reduction (sum) of chunks of rows.
// With Accumulate the result is added to the existing output ("+="),
// else it overwrites ("=").
// Grid: x covers num_columns*lwe_size, y = num_chunks.
//
// lwe_array_2d_reduce_rows_kernel
//   ├─ host_lwe_array_2d_sum_rows              (PtrTable, Accumulate=false)
//   ├─ host_lwe_flat_array_2d_sum_rows         (Flat,     Accumulate=false)
//   └─ host_lwe_flat_array_2d_accumulate_rows  (Flat,     Accumulate=true)
template <typename T, typename SrcAccessor, bool Accumulate>
__global__ void
lwe_array_2d_reduce_rows_kernel(T *dst, SrcAccessor src, uint32_t chunk_size,
                                uint32_t num_rows, uint32_t num_columns,
                                uint32_t lwe_size) {
  uint32_t g = blockIdx.y;
  uint32_t idx = blockIdx.x * blockDim.x + threadIdx.x;
  if (idx >= num_columns * lwe_size)
    return;
  uint32_t j = idx / lwe_size;
  uint32_t lane = idx - j * lwe_size;

  uint32_t r_start = g * chunk_size;
  if (r_start >= num_rows)
    return;
  uint32_t r_end = min(r_start + chunk_size, num_rows);

  T *out = dst + ((size_t)g * num_columns + j) * lwe_size + lane;
  T s = Accumulate ? *out : T(0);
  for (uint32_t r = r_start; r < r_end; r++)
    s += src.row(r, j)[lane];
  *out = s;
}

// Host-side (row, column) degree/noise accessor for a flat metadata array.
struct FlatMetaAccessor {
  const uint64_t *degrees;
  const uint64_t *noise_levels;
  uint32_t num_columns;
  uint64_t degree(uint32_t r, uint32_t j) const {
    return degrees[r * num_columns + j];
  }
  uint64_t noise(uint32_t r, uint32_t j) const {
    return noise_levels[r * num_columns + j];
  }
};

// Host-side (row, column) degree/noise accessor for scattered ciphertexts.
struct PtrTableMetaAccessor {
  const CudaRadixCiphertextFFI *cts;
  uint64_t degree(uint32_t r, uint32_t j) const { return cts[r].degrees[j]; }
  uint64_t noise(uint32_t r, uint32_t j) const {
    return cts[r].noise_levels[j];
  }
};

// Host-side counterpart of lwe_array_2d_reduce_rows_kernel: reduces the
// per-column degree and noise of each chunk of rows into out. Meta abstracts
// the source layout (flat vs scattered), with Accumulate the result is added
// to the existing metadata ("+="), else it overwrites ("=").
template <bool Accumulate, typename MetaAccessor>
void host_reduce_rows_meta(CudaRadixCiphertextFFI *out, MetaAccessor meta,
                           uint32_t chunk_size, uint32_t num_rows,
                           uint32_t num_chunks, uint32_t num_columns,
                           uint32_t message_modulus, uint32_t carry_modulus) {
  for (uint32_t g = 0; g < num_chunks; g++) {
    uint32_t r_start = g * chunk_size;
    uint32_t r_end = std::min(r_start + chunk_size, num_rows);
    for (uint32_t j = 0; j < num_columns; j++) {
      uint64_t added_deg = 0;
      uint64_t added_noise = 0;
      for (uint32_t r = r_start; r < r_end; r++) {
        added_deg += meta.degree(r, j);
        added_noise += meta.noise(r, j);
      }
      uint32_t idx = g * num_columns + j;
      if (Accumulate) {
        out->degrees[idx] += added_deg;
        out->noise_levels[idx] += added_noise;
      } else {
        out->degrees[idx] = added_deg;
        out->noise_levels[idx] = added_noise;
      }
      CHECK_NOISE_LEVEL(out->noise_levels[idx], message_modulus, carry_modulus);
    }
  }
}

// Column-wise sum of rows, no carry between columns
// NON-contiguous input: rows passed as a pointer array
template <typename T>
__host__ void host_lwe_array_2d_sum_rows(
    cudaStream_t stream, uint32_t gpu_index, CudaRadixCiphertextFFI *output,
    T *const *d_src_ptrs, CudaRadixCiphertextFFI const *inputs,
    uint32_t row_offset, uint32_t chunk_size, uint32_t num_rows,
    uint32_t num_chunks, uint32_t num_columns, uint32_t message_modulus,
    uint32_t carry_modulus) {
  if (num_chunks == 0 || num_columns == 0)
    return;
  if (chunk_size == 0)
    PANIC("Cuda error: chunk_size must be positive")
  if (row_offset >= num_rows)
    PANIC("Cuda error: row_offset is out of range")
  if (output->num_radix_blocks < num_chunks * num_columns)
    PANIC("Cuda error: output does not have enough blocks for "
          "num_chunks * num_columns")
  uint32_t k_end = std::min(row_offset + num_chunks * chunk_size, num_rows);
  for (uint32_t k = row_offset; k < k_end; k++) {
    if (inputs[k].lwe_dimension != output->lwe_dimension)
      PANIC("Cuda error: input and output lwe dimensions must match")
    if (inputs[k].num_radix_blocks < num_columns)
      PANIC("Cuda error: an input has fewer blocks than num_columns")
  }
  cuda_set_device(gpu_index);
  uint32_t lwe_size = output->lwe_dimension + 1;
  PtrTableRowAccessor<T> src_acc{d_src_ptrs + row_offset, lwe_size};
  int num_blocks = 0, num_threads = 0;
  int per_row = num_columns * lwe_size;
  getNumBlocksAndThreads(per_row, 512, num_blocks, num_threads);
  dim3 grid(num_blocks, num_chunks, 1);
  lwe_array_2d_reduce_rows_kernel<T, PtrTableRowAccessor<T>, false>
      <<<grid, num_threads, 0, stream>>>((T *)output->ptr, src_acc, chunk_size,
                                         num_rows - row_offset, num_columns,
                                         lwe_size);
  check_cuda_error(cudaGetLastError());

  PtrTableMetaAccessor meta{inputs + row_offset};
  host_reduce_rows_meta<false>(output, meta, chunk_size, num_rows - row_offset,
                               num_chunks, num_columns, message_modulus,
                               carry_modulus);
}

// Column-wise sum of rows, no carry between columns
// CONTIGUOUS input: one flat row-major buffer of num_rows x num_columns LWEs.
template <typename T>
__host__ void host_lwe_flat_array_2d_sum_rows(
    cudaStream_t stream, uint32_t gpu_index, CudaRadixCiphertextFFI *dst,
    CudaRadixCiphertextFFI const *src, uint32_t chunk_size, uint32_t num_rows,
    uint32_t num_chunks, uint32_t num_columns, uint32_t message_modulus,
    uint32_t carry_modulus) {
  if (num_chunks == 0 || num_columns == 0)
    return;
  if (chunk_size == 0)
    PANIC("Cuda error: chunk_size must be positive")
  if (dst->lwe_dimension != src->lwe_dimension)
    PANIC("Cuda error: dst and src lwe dimensions must match")
  if (src->num_radix_blocks < num_rows * num_columns)
    PANIC("Cuda error: src does not have enough blocks for "
          "num_rows * num_columns")
  if (dst->num_radix_blocks < num_chunks * num_columns)
    PANIC("Cuda error: dst does not have enough blocks for "
          "num_chunks * num_columns")
  cuda_set_device(gpu_index);
  uint32_t lwe_size = dst->lwe_dimension + 1;
  FlatRowAccessor<T> src_acc{(T const *)src->ptr, num_columns, lwe_size};
  int num_blocks = 0, num_threads = 0;
  int per_row = num_columns * lwe_size;
  getNumBlocksAndThreads(per_row, 512, num_blocks, num_threads);
  dim3 grid(num_blocks, num_chunks, 1);
  lwe_array_2d_reduce_rows_kernel<T, FlatRowAccessor<T>, false>
      <<<grid, num_threads, 0, stream>>>((T *)dst->ptr, src_acc, chunk_size,
                                         num_rows, num_columns, lwe_size);
  check_cuda_error(cudaGetLastError());

  FlatMetaAccessor meta{src->degrees, src->noise_levels, num_columns};
  host_reduce_rows_meta<false>(dst, meta, chunk_size, num_rows, num_chunks,
                               num_columns, message_modulus, carry_modulus);
}

// Column-wise accumulate of rows "+=", no carry between columns
// CONTIGUOUS input: one flat row-major buffer of rows x num_columns LWEs.
template <typename T>
__host__ void host_lwe_flat_array_2d_accumulate_rows(
    cudaStream_t stream, uint32_t gpu_index, CudaRadixCiphertextFFI *output,
    CudaRadixCiphertextFFI const *input, uint32_t row_offset,
    uint32_t row_count, uint32_t num_columns, const uint32_t message_modulus,
    const uint32_t carry_modulus) {
  if (output->lwe_dimension != input->lwe_dimension)
    PANIC("Cuda error: input and output lwe dimensions must be the same")
  if (output->num_radix_blocks < num_columns)
    PANIC("Cuda error: output must have at least num_columns blocks")
  if (input->num_radix_blocks < (row_offset + row_count) * num_columns)
    PANIC("Cuda error: input does not have enough blocks for the requested "
          "window")
  if (row_count > (message_modulus * carry_modulus - 1) / (message_modulus - 1))
    PANIC("Cuda error: row_count exceeds max_degree")

  cuda_set_device(gpu_index);
  int lwe_size = output->lwe_dimension + 1;
  FlatRowAccessor<T> src_acc{(const T *)input->ptr +
                                 (size_t)row_offset * num_columns * lwe_size,
                             num_columns, (uint32_t)lwe_size};
  int num_blocks = 0, num_threads = 0;
  int per_row = num_columns * lwe_size;
  getNumBlocksAndThreads(per_row, 512, num_blocks, num_threads);
  dim3 grid(num_blocks, 1, 1);
  dim3 thds(num_threads, 1, 1);

  lwe_array_2d_reduce_rows_kernel<T, FlatRowAccessor<T>, true>
      <<<grid, thds, 0, stream>>>((T *)output->ptr, src_acc, row_count,
                                  row_count, num_columns, lwe_size);
  check_cuda_error(cudaGetLastError());

  FlatMetaAccessor meta{input->degrees + (size_t)row_offset * num_columns,
                        input->noise_levels + (size_t)row_offset * num_columns,
                        num_columns};
  host_reduce_rows_meta<true>(output, meta, row_count, row_count, 1,
                              num_columns, message_modulus, carry_modulus);
}

#endif // CUDA_ADD_H
