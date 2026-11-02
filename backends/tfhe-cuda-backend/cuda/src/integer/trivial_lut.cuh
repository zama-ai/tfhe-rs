#ifndef CUDA_INTEGER_TRIVIAL_LUT_CUH
#define CUDA_INTEGER_TRIVIAL_LUT_CUH

#ifdef TFHE_GPU_BATCHED_TRIVIAL

#ifdef __CDT_PARSER__
#undef __CUDA_RUNTIME_H__
#include <cuda_runtime.h>
#endif

#include "device.h"
#include "integer/integer_utilities.h"
#include "utils/helper.cuh"

// One thread per (output block, coefficient) pair.
//
// Univariate (num_many_lut == 1):
//   num_out_blocks = num_in_blocks
//   out_block_id -> in_block_id = out_block_id
//   LUT slot = d_lut_indexes[in_block_id]  (null → slot 0 for all)
//
// Many-lut (num_many_lut > 1):
//   num_out_blocks = num_in_blocks * num_many_lut
//   Output layout: [lut_func=0 results ... | lut_func=1 results ... | ...]
//   out_block_id = lut_func * num_in_blocks + in_block_id
//   LUT slot = d_lut_indexes[in_block_id]  (null → slot 0 for all)
//   Combined table index = slot * num_many_lut + lut_func
//
// d_lut_values layout: [slot * num_many_lut + func][msg] with outer stride num_values
//   i.e. d_lut_values[(slot * num_many_lut + func) * num_values + msg]
//
// d_lut_indexes is Torus* (uint64_t*); values are small LUT slot IDs, read and
// cast to uint32_t.  nullptr means all blocks use slot 0.
template <typename Torus>
__global__ void device_trivial_lut_batched(
    Torus *lwe_out, Torus const *lwe_in, Torus const *d_lut_values,
    uint32_t const *lwe_indexes_in, uint32_t const *lwe_indexes_out,
    Torus const *d_lut_indexes, uint32_t lwe_dimension, uint32_t num_values,
    uint32_t num_many_lut, uint32_t num_in_blocks) {
  int tid = blockIdx.x * blockDim.x + threadIdx.x;
  int lwe_size = lwe_dimension + 1;
  uint32_t num_out_blocks =
      num_in_blocks * ((num_many_lut > 1) ? num_many_lut : 1u);
  if (tid >= (int)(num_out_blocks * lwe_size))
    return;

  int out_block_id = tid / lwe_size;
  int coeff_id = tid % lwe_size;

  uint32_t in_block_id, lut_index;
  if (num_many_lut > 1) {
    // Many-lut: output block = lut_func * num_in_blocks + in_block
    uint32_t lut_func = (uint32_t)out_block_id / num_in_blocks;
    in_block_id = (uint32_t)out_block_id % num_in_blocks;
    uint32_t slot =
        (d_lut_indexes != nullptr) ? (uint32_t)d_lut_indexes[in_block_id] : 0u;
    lut_index = slot * num_many_lut + lut_func;
  } else {
    in_block_id = (uint32_t)out_block_id;
    uint32_t slot =
        (d_lut_indexes != nullptr) ? (uint32_t)d_lut_indexes[in_block_id] : 0u;
    lut_index = slot;
  }

  uint32_t idx_in = lwe_indexes_in ? lwe_indexes_in[in_block_id] : in_block_id;
  uint32_t idx_out =
      lwe_indexes_out ? lwe_indexes_out[out_block_id] : out_block_id;

  // Raw integer value — no delta decoding needed.
  // Full cleartext space is [0, 2*num_values).
  // Lower half [0, num_values): normal range (padding bit = 0).
  // Upper half [num_values, 2*num_values): padding bit set → negacyclic rule.
  Torus val = lwe_in[idx_in * lwe_size + coeff_id];
  uint32_t full_msg = (uint32_t)(val % (2 * num_values));
  bool padding_set = full_msg >= num_values;
  uint32_t msg = padding_set ? full_msg - num_values : full_msg;

  Torus result = d_lut_values[lut_index * num_values + msg];
  if (padding_set)
    result = (Torus)(-(int64_t)result);
  lwe_out[idx_out * lwe_size + coeff_id] = result;
}

// Bivariate variant: result[coeff] = d_lut_values[lut_index * p*p + x*p + y]
// where x = lwe_in_1[coeff] % p, y = lwe_in_2[coeff] % p, p = message_modulus.
template <typename Torus>
__global__ void device_trivial_bivariate_lut_batched(
    Torus *lwe_out, Torus const *lwe_in_1, Torus const *lwe_in_2,
    Torus const *d_lut_values, uint32_t const *lwe_indexes_in,
    uint32_t const *lwe_indexes_out, Torus const *d_lut_indexes,
    uint32_t lwe_dimension, uint32_t p, uint32_t num_in_blocks) {
  int tid = blockIdx.x * blockDim.x + threadIdx.x;
  int lwe_size = lwe_dimension + 1;
  if (tid >= (int)(num_in_blocks * lwe_size))
    return;

  int block_id = tid / lwe_size;
  int coeff_id = tid % lwe_size;

  uint32_t slot =
      (d_lut_indexes != nullptr) ? (uint32_t)d_lut_indexes[block_id] : 0u;
  uint32_t idx_in = lwe_indexes_in ? lwe_indexes_in[block_id] : (uint32_t)block_id;
  uint32_t idx_out = lwe_indexes_out ? lwe_indexes_out[block_id] : (uint32_t)block_id;

  Torus x = lwe_in_1[idx_in * lwe_size + coeff_id] % p;
  Torus y = lwe_in_2[idx_in * lwe_size + coeff_id] % p;
  lwe_out[idx_out * lwe_size + coeff_id] = d_lut_values[slot * p * p + x * p + y];
}

template <typename Torus>
__host__ void execute_trivial_bivariate_lut_batched(
    CudaStreams streams, CudaRadixCiphertextFFI *lwe_array_out,
    CudaRadixCiphertextFFI const *lwe_array_in_1,
    CudaRadixCiphertextFFI const *lwe_array_in_2,
    int_radix_lut<Torus> *lut, uint32_t num_in_blocks) {
  cuda_set_device(streams.gpu_index(0));
  auto lwe_dimension = lwe_array_out->lwe_dimension;
  int lwe_size = lwe_dimension + 1;
  int num_entries = (int)(num_in_blocks * (uint32_t)lwe_size);
  int num_blocks = 0, num_threads = 0;
  getNumBlocksAndThreads(num_entries, 512, num_blocks, num_threads);

  uint32_t const *lwe_indexes_in =
      lut->using_trivial_lwe_indexes
          ? nullptr
          : reinterpret_cast<uint32_t const *>(lut->lwe_indexes_in);
  uint32_t const *lwe_indexes_out =
      lut->using_trivial_lwe_indexes
          ? nullptr
          : reinterpret_cast<uint32_t const *>(lut->lwe_indexes_out);
  Torus const *d_lut_indexes = lut->lut_indexes_vec.empty()
                                    ? nullptr
                                    : (Torus const *)lut->lut_indexes_vec[0];

  device_trivial_bivariate_lut_batched<Torus>
      <<<num_blocks, num_threads, 0, streams.stream(0)>>>(
          (Torus *)lwe_array_out->ptr,
          (Torus const *)lwe_array_in_1->ptr,
          (Torus const *)lwe_array_in_2->ptr,
          lut->d_lut_values, lwe_indexes_in, lwe_indexes_out, d_lut_indexes,
          lwe_dimension, lut->lut_num_values, num_in_blocks);
  check_cuda_error(cudaGetLastError());
}

// Host wrapper.  num_in_blocks = number of input blocks (lwe_array_in).
// For many-lut the output has num_in_blocks * num_many_lut blocks.
template <typename Torus>
__host__ void execute_trivial_lut_batched(CudaStreams streams,
                                          CudaRadixCiphertextFFI *lwe_array_out,
                                          CudaRadixCiphertextFFI const *lwe_array_in,
                                          int_radix_lut<Torus> *lut,
                                          uint32_t num_in_blocks,
                                          uint32_t num_many_lut) {
  cuda_set_device(streams.gpu_index(0));
  auto lwe_dimension = lwe_array_out->lwe_dimension;
  int lwe_size = lwe_dimension + 1;
  uint32_t num_out_blocks =
      num_in_blocks * ((num_many_lut > 1) ? num_many_lut : 1u);
  int num_entries = (int)(num_out_blocks * (uint32_t)lwe_size);
  int num_blocks = 0, num_threads = 0;
  getNumBlocksAndThreads(num_entries, 512, num_blocks, num_threads);

  // LWE index remapping: typically trivial (identity) for batched-trivial mode.
  uint32_t const *lwe_indexes_in =
      lut->using_trivial_lwe_indexes
          ? nullptr
          : reinterpret_cast<uint32_t const *>(lut->lwe_indexes_in);
  uint32_t const *lwe_indexes_out =
      lut->using_trivial_lwe_indexes
          ? nullptr
          : reinterpret_cast<uint32_t const *>(lut->lwe_indexes_out);

  // Per-block LUT slot indexes: lut_indexes_vec[0] is a device array of
  // uint64_t values (small LUT slot IDs).  The kernel reads them as Torus
  // (= uint64_t) and casts to uint32_t, so the stride is correct.
  Torus const *d_lut_indexes = lut->lut_indexes_vec.empty()
                                    ? nullptr
                                    : (Torus const *)lut->lut_indexes_vec[0];

  device_trivial_lut_batched<Torus>
      <<<num_blocks, num_threads, 0, streams.stream(0)>>>(
          (Torus *)lwe_array_out->ptr, (Torus const *)lwe_array_in->ptr,
          lut->d_lut_values, lwe_indexes_in, lwe_indexes_out, d_lut_indexes,
          lwe_dimension, lut->lut_num_values, num_many_lut, num_in_blocks);
  check_cuda_error(cudaGetLastError());
}

#endif // TFHE_GPU_BATCHED_TRIVIAL
#endif // CUDA_INTEGER_TRIVIAL_LUT_CUH
