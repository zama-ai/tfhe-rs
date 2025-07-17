#ifndef CUDA_INTEGER_MULT_CUH
#define CUDA_INTEGER_MULT_CUH

#ifdef __CDT_PARSER__
#undef __CUDA_RUNTIME_H__
#include <cuda_runtime.h>
#endif

#include "crypto/keyswitch.cuh"
#include "device.h"
#include "helper_multi_gpu.h"
#include "integer/cmux.cuh"
#include "integer/integer.cuh"
#include "integer/integer_utilities.h"
#include "linear_algebra.h"
#include "pbs/programmable_bootstrap.h"
#include "utils/helper.cuh"
#include "utils/helper_multi_gpu.cuh"
#include "utils/kernel_dimensions.cuh"
#include <fstream>
#include <iostream>
#include <omp.h>
#include <queue>
#include <sstream>
#include <string>
#include <vector>

template <typename Torus, class params>
__global__ void
all_shifted_lhs_rhs(Torus const *radix_lwe_left, Torus *lsb_ciphertext,
                    Torus *msb_ciphertext, Torus const *radix_lwe_right,
                    Torus *lsb_rhs, Torus *msb_rhs, int num_blocks) {

  size_t block_id = blockIdx.x;
  double D = sqrt((2 * num_blocks + 1) * (2 * num_blocks + 1) - 8 * block_id);
  size_t radix_id = int((2 * num_blocks + 1 - D) / 2.);
  size_t local_block_id =
      block_id - (2 * num_blocks - radix_id + 1) / 2. * radix_id;
  bool process_msb = (local_block_id < (num_blocks - radix_id - 1));
  auto cur_lsb_block = &lsb_ciphertext[block_id * (params::degree + 1)];
  auto cur_msb_block =
      (process_msb)
          ? &msb_ciphertext[(block_id - radix_id) * (params::degree + 1)]
          : nullptr;

  auto cur_lsb_rhs_block = &lsb_rhs[block_id * (params::degree + 1)];
  auto cur_msb_rhs_block =
      (process_msb) ? &msb_rhs[(block_id - radix_id) * (params::degree + 1)]
                    : nullptr;

  auto cur_ct_right = &radix_lwe_right[radix_id * (params::degree + 1)];
  auto cur_src = &radix_lwe_left[local_block_id * (params::degree + 1)];

  size_t tid = threadIdx.x;

  for (int i = 0; i < params::opt; i++) {
    Torus value = cur_src[tid];
    if (process_msb) {
      cur_lsb_block[tid] = cur_msb_block[tid] = value;
      cur_lsb_rhs_block[tid] = cur_msb_rhs_block[tid] = cur_ct_right[tid];
    } else {
      cur_lsb_block[tid] = value;
      cur_lsb_rhs_block[tid] = cur_ct_right[tid];
    }
    tid += params::degree / params::opt;
  }
  if (threadIdx.x == 0) {
    Torus value = cur_src[params::degree];
    if (process_msb) {
      cur_lsb_block[params::degree] = cur_msb_block[params::degree] = value;
      cur_lsb_rhs_block[params::degree] = cur_msb_rhs_block[params::degree] =
          cur_ct_right[params::degree];
    } else {
      cur_lsb_block[params::degree] = value;
      cur_lsb_rhs_block[params::degree] = cur_ct_right[params::degree];
    }
  }
}

__global__ inline void radix_vec_to_columns(uint32_t *const *const columns,
                                            uint32_t *const columns_counter,
                                            const uint64_t *const degrees,
                                            const uint32_t num_radix_blocks,
                                            const uint32_t num_radix_in_vec) {

  const uint32_t idx = threadIdx.x;
  size_t cnt = 0;
  for (int i = 0; i < num_radix_in_vec; i++) {
    size_t ct_id = i * num_radix_blocks + idx;
    if (degrees[ct_id] != 0) {
      columns[idx][cnt] = ct_id;
      ++cnt;
    }
  }
  columns_counter[idx] = cnt;
}

template <typename Torus>
__global__ inline void prepare_new_columns_and_pbs_indexes(
    uint32_t *const *const new_columns, uint32_t *const new_columns_counter,
    Torus *const pbs_indexes_in, Torus *const pbs_indexes_out,
    Torus *const lut_indexes, const uint32_t *const *const columns,
    const uint32_t *const columns_counter, const uint32_t chunk_size) {
  __shared__ uint32_t counter;

  if (threadIdx.x == 0) {
    counter = 0;
  }
  __syncthreads();

  const uint32_t base_id = threadIdx.x;
  const uint32_t column_len = columns_counter[base_id];

  uint32_t ct_count = 0;
  for (uint32_t i = 0; i + chunk_size <= column_len; i += chunk_size) {
    // those indexes are for message ciphertexts
    // for message ciphertexts in and out index should be same
    const uint32_t in_index = columns[base_id][i];
    new_columns[base_id][ct_count] = in_index;
    const uint32_t pbs_index = atomicAdd(&counter, 1);
    pbs_indexes_in[pbs_index] = in_index;
    pbs_indexes_out[pbs_index] = in_index;
    lut_indexes[pbs_index] = 0;
    ++ct_count;
  }
  __syncthreads();

  if (base_id > 0) {
    const uint32_t prev_base_id = base_id - 1;
    const uint32_t prev_column_len = columns_counter[prev_base_id];

    for (uint32_t i = 0; i + chunk_size <= prev_column_len; i += chunk_size) {
      // those indexes are for carry ciphertexts
      // for carry ciphertexts input is same as for message
      // output will be placed to next block in the column
      const uint32_t in_index = columns[prev_base_id][i];
      const uint32_t out_index = columns[prev_base_id][i + 1];
      new_columns[base_id][ct_count] = out_index;
      const uint32_t pbs_index = atomicAdd(&counter, 1);
      pbs_indexes_in[pbs_index] = in_index;
      pbs_indexes_out[pbs_index] = out_index;
      lut_indexes[pbs_index] = 1;
      ++ct_count;
    }
  }

  const uint32_t start_index = column_len - column_len % chunk_size;
  for (uint32_t i = start_index; i < column_len; ++i) {
    new_columns[base_id][ct_count] = columns[base_id][i];
    ++ct_count;
  }

  new_columns_counter[base_id] = ct_count;
}

template <typename Torus>
__global__ inline void prepare_final_pbs_indexes(
    Torus *const pbs_indexes_in, Torus *const pbs_indexes_out,
    Torus *const lut_indexes, const uint32_t num_radix_blocks) {
  int idx = threadIdx.x;
  pbs_indexes_in[idx] = idx % num_radix_blocks;
  pbs_indexes_out[idx] = idx + idx / num_radix_blocks;
  lut_indexes[idx] = idx / num_radix_blocks;
}

template <typename Torus>
__global__ void calculate_chunks(Torus *const input_blocks,
                                 const uint32_t *const *const columns,
                                 const uint32_t *const columns_counter,
                                 const uint32_t chunk_size,
                                 const uint32_t block_size) {

  const uint32_t part_size = blockDim.x;
  const uint32_t base_id = blockIdx.x;
  const uint32_t part_id = blockIdx.y;
  const uint32_t coef_id = part_id * part_size + threadIdx.x;

  if (coef_id >= block_size)
    return;

  const uint32_t column_len = columns_counter[base_id];

  if (column_len >= chunk_size) {
    const uint32_t num_chunks = column_len / chunk_size;
    Torus result = 0;

    for (uint32_t chunk_id = 0; chunk_id < num_chunks; ++chunk_id) {
      const uint32_t first_ct_id = columns[base_id][chunk_id * chunk_size];
      result = input_blocks[first_ct_id * block_size + coef_id];

      for (uint32_t ct_id = 1; ct_id < chunk_size; ++ct_id) {
        const uint32_t cur_ct_id =
            columns[base_id][chunk_id * chunk_size + ct_id];
        result += input_blocks[cur_ct_id * block_size + coef_id];
      }

      input_blocks[first_ct_id * block_size + coef_id] = result;
    }
  }
}

template <typename Torus>
__global__ void calculate_final_chunk_into_radix(
    Torus *const out_radix, const Torus *const input_blocks,
    const uint32_t *const *const columns, const uint32_t *const columns_counter,
    const uint32_t chunk_size, const uint32_t block_size) {

  const uint32_t part_size = blockDim.x;
  const uint32_t base_id = blockIdx.x;
  const uint32_t part_id = blockIdx.y;
  const uint32_t coef_id = part_id * part_size + threadIdx.x;

  if (coef_id >= block_size)
    return;

  const uint32_t column_len = columns_counter[base_id];

  Torus result = 0;
  if (column_len) {
    const uint32_t first_ct_id = columns[base_id][0];
    result = input_blocks[first_ct_id * block_size + coef_id];

    for (uint32_t i = 1; i < column_len; ++i) {
      const uint32_t cur_ct_it = columns[base_id][i];
      result += input_blocks[cur_ct_it * block_size + coef_id];
    }
  }
  out_radix[base_id * block_size + coef_id] = result;
}

template <typename Torus, class params>
__global__ void fill_radix_from_lsb_msb(Torus *result_blocks, Torus *lsb_blocks,
                                        Torus *msb_blocks,
                                        uint32_t big_lwe_size,
                                        uint32_t num_blocks) {
  size_t big_lwe_id = blockIdx.x;
  size_t radix_id = big_lwe_id / num_blocks;
  size_t block_id = big_lwe_id % num_blocks;
  size_t lsb_block_id = block_id - radix_id;
  size_t msb_block_id = block_id - radix_id - 1;

  bool process_lsb = (radix_id <= block_id);
  bool process_msb = (radix_id + 1 <= block_id);

  auto cur_res_lsb_ct = &result_blocks[big_lwe_id * big_lwe_size];
  auto cur_res_msb_ct = &result_blocks[num_blocks * num_blocks * big_lwe_size +
                                       big_lwe_id * big_lwe_size];
  Torus *cur_lsb_radix = &lsb_blocks[(2 * num_blocks - radix_id + 1) *
                                     radix_id / 2 * (params::degree + 1)];
  Torus *cur_msb_radix = (process_msb)
                             ? &msb_blocks[(2 * num_blocks - radix_id - 1) *
                                           radix_id / 2 * (params::degree + 1)]
                             : nullptr;
  Torus *cur_lsb_ct = (process_lsb)
                          ? &cur_lsb_radix[lsb_block_id * (params::degree + 1)]
                          : nullptr;
  Torus *cur_msb_ct = (process_msb)
                          ? &cur_msb_radix[msb_block_id * (params::degree + 1)]
                          : nullptr;
  size_t tid = threadIdx.x;

  for (int i = 0; i < params::opt; i++) {
    cur_res_lsb_ct[tid] = (process_lsb) ? cur_lsb_ct[tid] : 0;
    cur_res_msb_ct[tid] = (process_msb) ? cur_msb_ct[tid] : 0;
    tid += params::degree / params::opt;
  }

  if (threadIdx.x == 0) {
    cur_res_lsb_ct[params::degree] =
        (process_lsb) ? cur_lsb_ct[params::degree] : 0;
    cur_res_msb_ct[params::degree] =
        (process_msb) ? cur_msb_ct[params::degree] : 0;
  }
}

template <typename Torus> struct radix_columns {
  std::vector<std::vector<Torus>> columns;
  std::vector<size_t> columns_counter;
  std::vector<std::vector<Torus>> new_columns;
  std::vector<size_t> new_columns_counter;

  size_t num_blocks;
  size_t num_radix_in_vec;
  size_t chunk_size;
  radix_columns(const uint64_t *const input_degrees, size_t num_blocks,
                size_t num_radix_in_vec, size_t chunk_size,
                bool &needs_processing)
      : num_blocks(num_blocks), num_radix_in_vec(num_radix_in_vec),
        chunk_size(chunk_size) {
    needs_processing = false;
    columns.resize(num_blocks);
    columns_counter.resize(num_blocks, 0);
    new_columns.resize(num_blocks);
    new_columns_counter.resize(num_blocks, 0);
    for (size_t i = 0; i < num_blocks; ++i) {
      new_columns[i].resize(num_radix_in_vec);
    }
    for (size_t i = 0; i < num_radix_in_vec; ++i) {
      for (size_t j = 0; j < num_blocks; ++j) {
        if (input_degrees[i * num_blocks + j]) {
          columns[j].push_back(i * num_blocks + j);
          columns_counter[j]++;
        }
      }
    }
    for (size_t i = 0; i < num_blocks; ++i) {
      if (columns_counter[i] > chunk_size) {
        needs_processing = true;
        break;
      }
    }
  }

  void next_accumulation(Torus *h_indexes_in, Torus *h_indexes_out,
                         Torus *h_lut_indexes, size_t &total_ciphertexts,
                         size_t &message_ciphertexts, bool &needs_processing) {
    message_ciphertexts = 0;
    total_ciphertexts = 0;
    needs_processing = false;

    size_t pbs_count = 0;
    for (size_t c_id = 0; c_id < num_blocks; ++c_id) {
      const size_t column_len = columns_counter[c_id];
      new_columns_counter[c_id] = 0;
      size_t ct_count = 0;
      // add message cts into new columns
      for (size_t i = 0; i + chunk_size <= column_len; i += chunk_size) {
        const Torus in_index = columns[c_id][i];
        new_columns[c_id][ct_count] = in_index;
        h_indexes_in[pbs_count] = in_index;
        h_indexes_out[pbs_count] = in_index;
        h_lut_indexes[pbs_count] = 0;
        ++pbs_count;
        ++ct_count;
        ++message_ciphertexts;
      }

      // add carry cts into new columns
      if (c_id > 0) {
        const size_t prev_c_id = c_id - 1;
        const size_t prev_column_len = columns_counter[prev_c_id];
        for (size_t i = 0; i + chunk_size <= prev_column_len; i += chunk_size) {
          const Torus in_index = columns[prev_c_id][i];
          const Torus out_index = columns[prev_c_id][i + 1];
          new_columns[c_id][ct_count] = out_index;
          h_indexes_in[pbs_count] = in_index;
          h_indexes_out[pbs_count] = out_index;
          h_lut_indexes[pbs_count] = 1;
          ++pbs_count;
          ++ct_count;
        }
      }

      // add remaining cts into new columns
      const size_t start_index = column_len - column_len % chunk_size;
      for (size_t i = start_index; i < column_len; ++i) {
        new_columns[c_id][ct_count] = columns[c_id][i];
        ++ct_count;
      }
      new_columns_counter[c_id] = ct_count;
      if (ct_count > chunk_size) {
        needs_processing = true;
      }

      new_columns_counter[c_id] = ct_count;
    }

    total_ciphertexts = pbs_count;
    swap(columns, new_columns);
    swap(columns_counter, new_columns_counter);
  }

  void final_calculation(Torus *h_indexes_in, Torus *h_indexes_out,
                         Torus *h_lut_indexes) {
    for (size_t idx = 0; idx < 2 * num_blocks; ++idx) {
      h_indexes_in[idx] = idx % num_blocks;
      h_indexes_out[idx] = idx + idx / num_blocks;
      h_lut_indexes[idx] = idx / num_blocks;
    }
  }
};

inline void calculate_final_degrees(uint64_t *const out_degrees,
                                    const uint64_t *const input_degrees,
                                    size_t num_blocks, size_t num_radix_in_vec,
                                    size_t chunk_size,
                                    uint64_t message_modulus) {

  auto get_degree = [message_modulus](uint64_t degree) -> uint64_t {
    return std::min(message_modulus - 1, degree);
  };
  std::vector<std::queue<uint64_t>> columns(num_blocks);
  for (size_t i = 0; i < num_radix_in_vec; ++i) {
    for (size_t j = 0; j < num_blocks; ++j) {
      if (input_degrees[i * num_blocks + j])
        columns[j].push(input_degrees[i * num_blocks + j]);
    }
  }

  for (size_t i = 0; i < num_blocks; ++i) {
    auto &col = columns[i];
    while (col.size() > 1) {
      uint32_t cur_degree = 0;
      size_t mn = std::min(chunk_size, col.size());
      for (int j = 0; j < mn; ++j) {
        cur_degree += col.front();
        col.pop();
      }
      const uint64_t new_degree = get_degree(cur_degree);
      col.push(new_degree);
      if ((i + 1) < num_blocks) {
        columns[i + 1].push(new_degree);
      }
    }
  }

  for (int i = 0; i < num_blocks; i++) {
    out_degrees[i] = (columns[i].empty()) ? 0 : columns[i].front();
  }
}

template <typename Torus>
__host__ uint64_t scratch_cuda_integer_partial_sum_ciphertexts_vec_kb(
    cudaStream_t const *streams, uint32_t const *gpu_indexes,
    uint32_t gpu_count, int_sum_ciphertexts_vec_memory<Torus> **mem_ptr,
    uint32_t num_blocks_in_radix, uint32_t max_num_radix_in_vec,
    int_radix_params params, bool allocate_gpu_memory) {

  uint64_t size_tracker = 0;
  *mem_ptr = new int_sum_ciphertexts_vec_memory<Torus>(
      streams, gpu_indexes, gpu_count, params, num_blocks_in_radix,
      max_num_radix_in_vec, allocate_gpu_memory, &size_tracker);
  return size_tracker;
}

template <typename Torus, class params>
__host__ void host_integer_partial_sum_ciphertexts_vec_kb(
    cudaStream_t const *streams, uint32_t const *gpu_indexes,
    uint32_t gpu_count, CudaRadixCiphertextFFI *radix_lwe_out,
    CudaRadixCiphertextFFI *terms,
    bool reduce_degrees_for_single_carry_propagation, void *const *bsks,
    uint64_t *const *ksks,
    CudaModulusSwitchNoiseReductionKeyFFI const *ms_noise_reduction_key,
    int_sum_ciphertexts_vec_memory<uint64_t> *mem_ptr,
    uint32_t num_radix_blocks, uint32_t num_radix_in_vec) {
  auto big_lwe_dimension = mem_ptr->params.big_lwe_dimension;
  auto big_lwe_size = big_lwe_dimension + 1;

  if (terms->lwe_dimension != radix_lwe_out->lwe_dimension)
    PANIC("Cuda error: output and input radix ciphertexts should have the same "
          "lwe dimension")
  if (num_radix_in_vec >
      terms->num_radix_blocks / radix_lwe_out->num_radix_blocks)
    PANIC("Cuda error: input vector does not have enough blocks")
  if (num_radix_blocks > radix_lwe_out->num_radix_blocks)
    PANIC("Cuda error: output does not have enough blocks")
  if (num_radix_in_vec == 0)
    return;

  auto current_blocks = mem_ptr->current_blocks;
  auto small_lwe_vector = mem_ptr->small_lwe_vector;
  auto d_degrees = mem_ptr->d_degrees;
  auto d_columns = mem_ptr->d_columns;
  auto d_columns_counter = mem_ptr->d_columns_counter;
  auto d_new_columns = mem_ptr->d_new_columns;
  auto d_new_columns_counter = mem_ptr->d_new_columns_counter;
  auto d_pbs_indexes_in = mem_ptr->luts_message_carry->lwe_indexes_in;
  auto d_pbs_indexes_out = mem_ptr->luts_message_carry->lwe_indexes_out;

  auto luts_message_carry = mem_ptr->luts_message_carry;

  auto glwe_dimension = mem_ptr->params.glwe_dimension;
  auto polynomial_size = mem_ptr->params.polynomial_size;
  auto small_lwe_dimension = mem_ptr->params.small_lwe_dimension;
  auto chunk_size =
      (mem_ptr->params.message_modulus * mem_ptr->params.carry_modulus - 1) /
      (mem_ptr->params.message_modulus - 1);

  size_t total_blocks_in_vec = num_radix_blocks * num_radix_in_vec;

  // In the case of extracting a single LWE this parameters are dummy
  uint32_t num_many_lut = 1;
  uint32_t lut_stride = 0;

  if (terms->num_radix_blocks == 0)
    return;
  if (num_radix_in_vec == 1) {
    copy_radix_ciphertext_slice_async<Torus>(streams[0], gpu_indexes[0],
                                             radix_lwe_out, 0, num_radix_blocks,
                                             terms, 0, num_radix_blocks);
    return;
  }

  if (num_radix_in_vec == 2) {
    CudaRadixCiphertextFFI terms_slice;
    as_radix_ciphertext_slice<Torus>(&terms_slice, terms, num_radix_blocks,
                                     2 * num_radix_blocks);
    host_addition<Torus>(streams[0], gpu_indexes[0], radix_lwe_out, terms,
                         &terms_slice, num_radix_blocks);
    return;
  }

  if (mem_ptr->mem_reuse) {
    mem_ptr->setup_lookup_tables(streams, gpu_indexes, gpu_count);
  }

  if (current_blocks != terms) {
    copy_radix_ciphertext_async<Torus>(streams[0], gpu_indexes[0],
                                       current_blocks, terms);
  }

  cuda_memcpy_async_to_gpu(d_degrees, current_blocks->degrees,
                           total_blocks_in_vec * sizeof(uint64_t), streams[0],
                           gpu_indexes[0]);

  cuda_set_device(gpu_indexes[0]);
  radix_vec_to_columns<<<1, num_radix_blocks, 0, streams[0]>>>(
      d_columns, d_columns_counter, d_degrees, num_radix_blocks,
      num_radix_in_vec);

  bool needs_processing = false;
  radix_columns<Torus> current_columns(current_blocks->degrees,
                                       num_radix_blocks, num_radix_in_vec,
                                       chunk_size, needs_processing);
  int number_of_threads = min(256, params::degree);
  int part_count = (big_lwe_size + number_of_threads - 1) / number_of_threads;
  const dim3 number_of_blocks_2d(num_radix_blocks, part_count, 1);

  while (needs_processing) {
    calculate_chunks<Torus>
        <<<number_of_blocks_2d, number_of_threads, 0, streams[0]>>>(
            (Torus *)(current_blocks->ptr), d_columns, d_columns_counter,
            chunk_size, big_lwe_size);

    prepare_new_columns_and_pbs_indexes<<<1, num_radix_blocks, 0, streams[0]>>>(
        d_new_columns, d_new_columns_counter, d_pbs_indexes_in,
        d_pbs_indexes_out, luts_message_carry->get_lut_indexes(0, 0), d_columns,
        d_columns_counter, chunk_size);

    size_t total_ciphertexts;
    size_t total_messages;
    current_columns.next_accumulation(luts_message_carry->h_lwe_indexes_in,
                                      luts_message_carry->h_lwe_indexes_out,
                                      luts_message_carry->h_lut_indexes,
                                      total_ciphertexts, total_messages,
                                      needs_processing);

    auto active_gpu_count = get_active_gpu_count(total_ciphertexts, gpu_count);
    if (active_gpu_count == 1) {
      execute_keyswitch_async<Torus>(
          streams, gpu_indexes, 1, (Torus *)small_lwe_vector->ptr,
          d_pbs_indexes_in, (Torus *)current_blocks->ptr, d_pbs_indexes_in,
          ksks, big_lwe_dimension, small_lwe_dimension,
          mem_ptr->params.ks_base_log, mem_ptr->params.ks_level,
          total_messages);

      execute_pbs_async<Torus>(
          streams, gpu_indexes, 1, (Torus *)current_blocks->ptr,
          d_pbs_indexes_out, luts_message_carry->lut_vec,
          luts_message_carry->lut_indexes_vec, (Torus *)small_lwe_vector->ptr,
          d_pbs_indexes_in, bsks, ms_noise_reduction_key,
          luts_message_carry->buffer, glwe_dimension, small_lwe_dimension,
          polynomial_size, mem_ptr->params.pbs_base_log,
          mem_ptr->params.pbs_level, mem_ptr->params.grouping_factor,
          total_ciphertexts, mem_ptr->params.pbs_type, num_many_lut,
          lut_stride);
    } else {
      luts_message_carry->using_trivial_lwe_indexes = false;
      luts_message_carry->broadcast_lut(streams, gpu_indexes, 0);

      integer_radix_apply_univariate_lookup_table_kb<Torus>(
          streams, gpu_indexes, active_gpu_count, current_blocks,
          current_blocks, bsks, ksks, ms_noise_reduction_key,
          luts_message_carry, total_ciphertexts);
    }
    cuda_set_device(gpu_indexes[0]);
    std::swap(d_columns, d_new_columns);
    std::swap(d_columns_counter, d_new_columns_counter);
  }

  calculate_final_chunk_into_radix<Torus>
      <<<number_of_blocks_2d, number_of_threads, 0, streams[0]>>>(
          (Torus *)(radix_lwe_out->ptr), (Torus *)(current_blocks->ptr),
          d_columns, d_columns_counter, chunk_size, big_lwe_size);

  if (reduce_degrees_for_single_carry_propagation) {
    prepare_final_pbs_indexes<Torus>
        <<<1, 2 * num_radix_blocks, 0, streams[0]>>>(
            d_pbs_indexes_in, d_pbs_indexes_out,
            luts_message_carry->get_lut_indexes(0, 0), num_radix_blocks);

    cuda_memset_async(
        (Torus *)(current_blocks->ptr) + big_lwe_size * num_radix_blocks, 0,
        big_lwe_size * sizeof(Torus), streams[0], gpu_indexes[0]);

    current_columns.final_calculation(luts_message_carry->h_lwe_indexes_in,
                                      luts_message_carry->h_lwe_indexes_out,
                                      luts_message_carry->h_lut_indexes);
    auto active_gpu_count =
        get_active_gpu_count(2 * num_radix_blocks, gpu_count);

    if (active_gpu_count == 1) {
      execute_keyswitch_async<Torus>(
          streams, gpu_indexes, 1, (Torus *)small_lwe_vector->ptr,
          d_pbs_indexes_in, (Torus *)radix_lwe_out->ptr, d_pbs_indexes_in, ksks,
          big_lwe_dimension, small_lwe_dimension, mem_ptr->params.ks_base_log,
          mem_ptr->params.ks_level, num_radix_blocks);

      execute_pbs_async<Torus>(
          streams, gpu_indexes, 1, (Torus *)current_blocks->ptr,
          d_pbs_indexes_out, luts_message_carry->lut_vec,
          luts_message_carry->lut_indexes_vec, (Torus *)small_lwe_vector->ptr,
          d_pbs_indexes_in, bsks, ms_noise_reduction_key,
          luts_message_carry->buffer, glwe_dimension, small_lwe_dimension,
          polynomial_size, mem_ptr->params.pbs_base_log,
          mem_ptr->params.pbs_level, mem_ptr->params.grouping_factor,
          2 * num_radix_blocks, mem_ptr->params.pbs_type, num_many_lut,
          lut_stride);
    } else {
      luts_message_carry->broadcast_lut(streams, gpu_indexes, 0);
      luts_message_carry->using_trivial_lwe_indexes = false;

      integer_radix_apply_univariate_lookup_table_kb<Torus>(
          streams, gpu_indexes, active_gpu_count, current_blocks, radix_lwe_out,
          bsks, ksks, ms_noise_reduction_key, luts_message_carry,
          2 * num_radix_blocks);
    }
    calculate_final_degrees(radix_lwe_out->degrees, terms->degrees,
                            num_radix_blocks, num_radix_in_vec, chunk_size,
                            mem_ptr->params.message_modulus);
    cuda_set_device(gpu_indexes[0]);
    CudaRadixCiphertextFFI current_blocks_slice;
    as_radix_ciphertext_slice<Torus>(&current_blocks_slice, current_blocks,
                                     num_radix_blocks, 2 * num_radix_blocks);

    host_addition<Torus>(streams[0], gpu_indexes[0], radix_lwe_out,
                         current_blocks, &current_blocks_slice,
                         num_radix_blocks);
  }
}

template <typename Torus, class params>
__host__ void host_integer_mult_radix_kb(
    cudaStream_t const *streams, uint32_t const *gpu_indexes,
    uint32_t gpu_count, CudaRadixCiphertextFFI *radix_lwe_out,
    CudaRadixCiphertextFFI const *radix_lwe_left, bool const is_bool_left,
    CudaRadixCiphertextFFI const *radix_lwe_right, bool const is_bool_right,
    void *const *bsks, uint64_t *const *ksks,
    CudaModulusSwitchNoiseReductionKeyFFI const *ms_noise_reduction_key,
    int_mul_memory<Torus> *mem_ptr, uint32_t num_blocks) {

  if (radix_lwe_out->lwe_dimension != radix_lwe_left->lwe_dimension ||
      radix_lwe_right->lwe_dimension != radix_lwe_left->lwe_dimension)
    PANIC("Cuda error: input and output lwe dimensions should be the same")
  if (radix_lwe_out->num_radix_blocks < num_blocks && !is_bool_left &&
          !is_bool_right ||
      radix_lwe_left->num_radix_blocks < num_blocks && !is_bool_left ||
      radix_lwe_right->num_radix_blocks < num_blocks && !is_bool_right)
    PANIC("Cuda error: input or output does not have enough radix blocks")
  auto message_modulus = mem_ptr->params.message_modulus;

  int big_lwe_dimension = radix_lwe_left->lwe_dimension;
  int big_lwe_size = big_lwe_dimension + 1;

  if (is_bool_right) {
    zero_out_if<Torus>(streams, gpu_indexes, gpu_count, radix_lwe_out,
                       radix_lwe_left, radix_lwe_right, mem_ptr->zero_out_mem,
                       mem_ptr->zero_out_predicate_lut, bsks, ksks,
                       ms_noise_reduction_key, num_blocks);
    return;
  }

  if (is_bool_left) {
    zero_out_if<Torus>(streams, gpu_indexes, gpu_count, radix_lwe_out,
                       radix_lwe_right, radix_lwe_left, mem_ptr->zero_out_mem,
                       mem_ptr->zero_out_predicate_lut, bsks, ksks,
                       ms_noise_reduction_key, num_blocks);
    return;
  }

  // 'vector_result_lsb' contains blocks from all possible right shifts of
  // radix_lwe_left, only nonzero blocks are kept
  int lsb_vector_block_count = num_blocks * (num_blocks + 1) / 2;

  // 'vector_result_msb' contains blocks from all possible shifts of
  // radix_lwe_left except the last blocks of each shift. Only nonzero blocks
  // are kept
  int msb_vector_block_count = num_blocks * (num_blocks - 1) / 2;

  // total number of blocks msb and lsb
  int total_block_count = lsb_vector_block_count + msb_vector_block_count;

  // buffer to keep all lsb and msb shifts
  // for lsb all nonzero blocks of each right shifts are kept
  // for 0 shift num_blocks blocks
  // for 1 shift num_blocks - 1 blocks
  // for num_blocks - 1 shift 1 block
  // (num_blocks + 1) * num_blocks / 2 blocks
  // for msb we don't keep track for last blocks so
  // for 0 shift num_blocks - 1 blocks
  // for 1 shift num_blocks - 2 blocks
  // for num_blocks - 1 shift  0 blocks
  // (num_blocks - 1) * num_blocks / 2 blocks
  // in total num_blocks^2 blocks
  // in each block three is big polynomial with
  // glwe_dimension * polynomial_size + 1 coefficients
  auto vector_result_sb = mem_ptr->vector_result_sb;

  // buffer to keep lsb_vector + msb_vector
  // addition will happen in full terms so there will be
  // num_blocks terms and each term will have num_blocks block
  // num_blocks^2 blocks in total
  // and each blocks has big lwe ciphertext with
  // glwe_dimension * polynomial_size + 1 coefficients
  auto block_mul_res = mem_ptr->block_mul_res;

  // it contains two lut, first for lsb extraction,
  // second for msb extraction, with total length =
  // 2 * (glwe_dimension + 1) * polynomial_size
  auto luts_array = mem_ptr->luts_array;

  auto vector_result_lsb = vector_result_sb;
  CudaRadixCiphertextFFI vector_result_msb;
  as_radix_ciphertext_slice<Torus>(&vector_result_msb, vector_result_lsb,
                                   lsb_vector_block_count,
                                   vector_result_lsb->num_radix_blocks);

  auto vector_lsb_rhs = block_mul_res;
  CudaRadixCiphertextFFI vector_msb_rhs;
  as_radix_ciphertext_slice<Torus>(&vector_msb_rhs, block_mul_res,
                                   lsb_vector_block_count,
                                   block_mul_res->num_radix_blocks);

  dim3 grid(lsb_vector_block_count, 1, 1);
  dim3 thds(params::degree / params::opt, 1, 1);

  cuda_set_device(gpu_indexes[0]);
  all_shifted_lhs_rhs<Torus, params><<<grid, thds, 0, streams[0]>>>(
      (Torus *)radix_lwe_left->ptr, (Torus *)vector_result_lsb->ptr,
      (Torus *)vector_result_msb.ptr, (Torus *)radix_lwe_right->ptr,
      (Torus *)vector_lsb_rhs->ptr, (Torus *)vector_msb_rhs.ptr, num_blocks);
  check_cuda_error(cudaGetLastError());

  integer_radix_apply_bivariate_lookup_table_kb<Torus>(
      streams, gpu_indexes, gpu_count, block_mul_res, block_mul_res,
      vector_result_sb, bsks, ksks, ms_noise_reduction_key, luts_array,
      total_block_count, luts_array->params.message_modulus);

  vector_result_lsb = block_mul_res;
  as_radix_ciphertext_slice<Torus>(&vector_result_msb, block_mul_res,
                                   lsb_vector_block_count,
                                   block_mul_res->num_radix_blocks);

  cuda_set_device(gpu_indexes[0]);
  fill_radix_from_lsb_msb<Torus, params>
      <<<num_blocks * num_blocks, params::degree / params::opt, 0,
         streams[0]>>>(
          (Torus *)vector_result_sb->ptr, (Torus *)vector_result_lsb->ptr,
          (Torus *)vector_result_msb.ptr, big_lwe_size, num_blocks);
  check_cuda_error(cudaGetLastError());

  for (int i = 0; i < num_blocks * num_blocks; i++) {
    size_t r_id = i / num_blocks;
    size_t b_id = i % num_blocks;
    vector_result_sb->degrees[i] = (b_id >= r_id) ? message_modulus - 1 : 0;
  }
  auto terms_degree_msb = &vector_result_sb->degrees[num_blocks * num_blocks];
  for (int i = 0; i < num_blocks * num_blocks; i++) {
    size_t r_id = i / num_blocks;
    size_t b_id = i % num_blocks;
    terms_degree_msb[i] = (b_id > r_id) ? message_modulus - 2 : 0;
  }
  host_integer_partial_sum_ciphertexts_vec_kb<Torus, params>(
      streams, gpu_indexes, gpu_count, radix_lwe_out, vector_result_sb, true,
      bsks, ksks, ms_noise_reduction_key, mem_ptr->sum_ciphertexts_mem,
      num_blocks, 2 * num_blocks);

  auto scp_mem_ptr = mem_ptr->sc_prop_mem;
  uint32_t requested_flag = outputFlag::FLAG_NONE;
  uint32_t uses_carry = 0;
  host_propagate_single_carry<Torus>(
      streams, gpu_indexes, gpu_count, radix_lwe_out, nullptr, nullptr,
      scp_mem_ptr, bsks, ksks, ms_noise_reduction_key, requested_flag,
      uses_carry);
}

template <typename Torus>
__host__ uint64_t scratch_cuda_integer_mult_radix_ciphertext_kb(
    cudaStream_t const *streams, uint32_t const *gpu_indexes,
    uint32_t gpu_count, int_mul_memory<Torus> **mem_ptr,
    bool const is_boolean_left, bool const is_boolean_right,
    uint32_t num_radix_blocks, int_radix_params params,
    bool allocate_gpu_memory) {
  uint64_t size_tracker = 0;
  *mem_ptr = new int_mul_memory<Torus>(
      streams, gpu_indexes, gpu_count, params, is_boolean_left,
      is_boolean_right, num_radix_blocks, allocate_gpu_memory, &size_tracker);
  return size_tracker;
}

#endif
