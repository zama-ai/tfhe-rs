#ifndef CUDA_INTEGER_MULT_CUH
#define CUDA_INTEGER_MULT_CUH

#ifdef __CDT_PARSER__
#undef __CUDA_RUNTIME_H__
#include <cuda_runtime.h>
#endif

#include "bootstrap.h"
#include "crypto/keyswitch.cuh"
#include "device.h"
#include "integer.h"
#include "integer/integer.cuh"
#include "linear_algebra.h"
#include "utils/helper.cuh"
#include "utils/kernel_dimensions.cuh"
#include <fstream>
#include <iostream>
#include <omp.h>
#include <sstream>
#include <string>
#include <vector>

template <typename Torus, class params>
__global__ void
all_shifted_lhs_rhs(Torus *radix_lwe_left, Torus *lsb_ciphertext,
                    Torus *msb_ciphertext, Torus *radix_lwe_right,
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

template <typename Torus>
void compress_device_array_with_map(cuda_stream_t *stream, Torus *src,
                                    Torus *dst, int *S, int *F, int num_blocks,
                                    uint32_t map_size, uint32_t unit_size,
                                    int &total_copied, bool is_message) {
  cudaSetDevice(stream->gpu_index);
  for (int i = 0; i < map_size; i++) {
    int s_index = i * num_blocks + S[i];
    int number_of_unit = F[i] - S[i] + is_message;
    auto cur_dst = &dst[total_copied * unit_size];
    auto cur_src = &src[s_index * unit_size];
    size_t copy_size = unit_size * number_of_unit * sizeof(Torus);
    cuda_memcpy_async_gpu_to_gpu(cur_dst, cur_src, copy_size, stream);
    total_copied += number_of_unit;
  }
}

template <typename Torus>
void extract_message_carry_to_full_radix(cuda_stream_t *stream, Torus *src,
                                         Torus *dst, int *S, int *F,
                                         uint32_t map_size, uint32_t unit_size,
                                         int &total_copied,
                                         int &total_radix_copied,
                                         int num_blocks, bool is_message) {
  cudaSetDevice(stream->gpu_index);
  size_t radix_size = unit_size * num_blocks;
  for (int i = 0; i < map_size; i++) {
    auto cur_dst_radix = &dst[total_radix_copied * radix_size];

    int s_index = S[i];
    int number_of_unit = F[i] - s_index + is_message;

    if (!is_message) {
      int zero_block_count = num_blocks - number_of_unit;
      cuda_memset_async(cur_dst_radix, 0,
                        zero_block_count * unit_size * sizeof(Torus), stream);
      s_index = zero_block_count;
    }

    auto cur_dst = &cur_dst_radix[s_index * unit_size];
    auto cur_src = &src[total_copied * unit_size];

    size_t copy_size = unit_size * number_of_unit * sizeof(Torus);
    cuda_memcpy_async_gpu_to_gpu(cur_dst, cur_src, copy_size, stream);
    total_copied += number_of_unit;
    ++total_radix_copied;
  }
}

template <typename Torus, class params>
__global__ void tree_add_chunks(Torus *result_blocks, Torus *input_blocks,
                                uint32_t chunk_size, uint32_t num_blocks) {

  extern __shared__ Torus result[];
  size_t chunk_id = blockIdx.x;
  size_t chunk_elem_size = chunk_size * num_blocks * (params::degree + 1);
  size_t radix_elem_size = num_blocks * (params::degree + 1);
  auto src_chunk = &input_blocks[chunk_id * chunk_elem_size];
  auto dst_radix = &result_blocks[chunk_id * radix_elem_size];
  size_t block_stride = blockIdx.y * (params::degree + 1);
  auto dst_block = &dst_radix[block_stride];

  // init shared mem with first radix of chunk
  size_t tid = threadIdx.x;
  for (int i = 0; i < params::opt; i++) {
    result[tid] = src_chunk[block_stride + tid];
    tid += params::degree / params::opt;
  }

  if (threadIdx.x == 0) {
    result[params::degree] = src_chunk[block_stride + params::degree];
  }

  // accumulate rest  of the radixes
  for (int r_id = 1; r_id < chunk_size; r_id++) {
    auto cur_src_radix = &src_chunk[r_id * radix_elem_size];
    tid = threadIdx.x;
    for (int i = 0; i < params::opt; i++) {
      result[tid] += cur_src_radix[block_stride + tid];
      tid += params::degree / params::opt;
    }
    if (threadIdx.x == 0) {
      result[params::degree] += cur_src_radix[block_stride + params::degree];
    }
  }

  // put result from shared mem to global mem
  tid = threadIdx.x;
  for (int i = 0; i < params::opt; i++) {
    dst_block[tid] = result[tid];
    tid += params::degree / params::opt;
  }

  if (threadIdx.x == 0) {
    dst_block[params::degree] = result[params::degree];
  }
}

template <typename Torus, class params>
__global__ void fill_radix_from_lsb_msb(Torus *result_blocks, Torus *lsb_blocks,
                                        Torus *msb_blocks,
                                        uint32_t glwe_dimension,
                                        uint32_t lsb_count, uint32_t msb_count,
                                        uint32_t num_blocks) {
  size_t big_lwe_dimension = glwe_dimension * params::degree + 1;
  size_t big_lwe_id = blockIdx.x;
  size_t radix_id = big_lwe_id / num_blocks;
  size_t block_id = big_lwe_id % num_blocks;
  size_t lsb_block_id = block_id - radix_id;
  size_t msb_block_id = block_id - radix_id - 1;

  bool process_lsb = (radix_id <= block_id);
  bool process_msb = (radix_id + 1 <= block_id);

  auto cur_res_lsb_ct = &result_blocks[big_lwe_id * big_lwe_dimension];
  auto cur_res_msb_ct =
      &result_blocks[num_blocks * num_blocks * big_lwe_dimension +
                     big_lwe_id * big_lwe_dimension];
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

template <typename Torus, typename STorus, class params>
__host__ void host_integer_mult_radix_kb(
    cuda_stream_t *stream, uint64_t *radix_lwe_out, uint64_t *radix_lwe_left,
    uint64_t *radix_lwe_right, void *bsk, uint64_t *ksk,
    int_mul_memory<Torus> *mem_ptr, uint32_t num_blocks) {

  cudaSetDevice(stream->gpu_index);
  auto glwe_dimension = mem_ptr->params.glwe_dimension;
  auto polynomial_size = mem_ptr->params.polynomial_size;
  auto lwe_dimension = mem_ptr->params.small_lwe_dimension;
  auto message_modulus = mem_ptr->params.message_modulus;
  auto carry_modulus = mem_ptr->params.carry_modulus;

  int big_lwe_dimension = glwe_dimension * polynomial_size;
  int big_lwe_size = big_lwe_dimension + 1;

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

  // buffer to keep keyswitch result of num_blocks^2 ciphertext
  // in total it has num_blocks^2 small lwe ciphertexts with
  // lwe_dimension +1 coefficients
  auto small_lwe_vector = mem_ptr->small_lwe_vector;

  // it contains two lut, first for lsb extraction,
  // second for msb extraction, with total length =
  // 2 * (glwe_dimension + 1) * polynomial_size
  auto luts_array = mem_ptr->luts_array;

  // accumulator to extract message
  // with length (glwe_dimension + 1) * polynomial_size
  auto luts_message = mem_ptr->luts_message;

  // accumulator to extract carry
  // with length (glwe_dimension + 1) * polynomial_size
  auto luts_carry = mem_ptr->luts_carry;

  // to be used as default indexing
  auto lwe_indexes = luts_array->lwe_indexes;

  auto vector_result_lsb = &vector_result_sb[0];
  auto vector_result_msb =
      &vector_result_sb[lsb_vector_block_count *
                        (polynomial_size * glwe_dimension + 1)];

  auto vector_lsb_rhs = &block_mul_res[0];
  auto vector_msb_rhs = &block_mul_res[lsb_vector_block_count *
                                       (polynomial_size * glwe_dimension + 1)];

  dim3 grid(lsb_vector_block_count, 1, 1);
  dim3 thds(params::degree / params::opt, 1, 1);

  all_shifted_lhs_rhs<Torus, params><<<grid, thds, 0, stream->stream>>>(
      radix_lwe_left, vector_result_lsb, vector_result_msb, radix_lwe_right,
      vector_lsb_rhs, vector_msb_rhs, num_blocks);

  integer_radix_apply_bivariate_lookup_table_kb<Torus>(
      stream, block_mul_res, block_mul_res, vector_result_sb, bsk, ksk,
      total_block_count, luts_array);

  vector_result_lsb = &block_mul_res[0];
  vector_result_msb = &block_mul_res[lsb_vector_block_count *
                                     (polynomial_size * glwe_dimension + 1)];

  fill_radix_from_lsb_msb<Torus, params>
      <<<num_blocks * num_blocks, params::degree / params::opt, 0,
         stream->stream>>>(vector_result_sb, vector_result_lsb,
                           vector_result_msb, glwe_dimension,
                           lsb_vector_block_count, msb_vector_block_count,
                           num_blocks);

  auto new_blocks = block_mul_res;
  auto old_blocks = vector_result_sb;

  // amount of current radixes after block_mul
  size_t r = 2 * num_blocks;

  size_t total_modulus = message_modulus * carry_modulus;
  size_t message_max = message_modulus - 1;
  size_t chunk_size = (total_modulus - 1) / message_max;
  size_t ch_amount = r / chunk_size;

  int terms_degree[r * num_blocks];
  int f_b[ch_amount];
  int l_b[ch_amount];

  for (int i = 0; i < num_blocks * num_blocks; i++) {
    size_t r_id = i / num_blocks;
    size_t b_id = i % num_blocks;
    terms_degree[i] = (b_id >= r_id) ? 3 : 0;
  }
  auto terms_degree_msb = &terms_degree[num_blocks * num_blocks];
  for (int i = 0; i < num_blocks * num_blocks; i++) {
    size_t r_id = i / num_blocks;
    size_t b_id = i % num_blocks;
    terms_degree_msb[i] = (b_id > r_id) ? 2 : 0;
  }

  auto max_shared_memory = cuda_get_max_shared_memory(stream->gpu_index);
  while (r > chunk_size) {
    int cur_total_blocks = r * num_blocks;
    ch_amount = r / chunk_size;
    dim3 add_grid(ch_amount, num_blocks, 1);
    size_t sm_size = big_lwe_size * sizeof(Torus);
    cuda_memset_async(new_blocks, 0,
                      ch_amount * num_blocks * big_lwe_size * sizeof(Torus),
                      stream);

    tree_add_chunks<Torus, params><<<add_grid, 256, sm_size, stream->stream>>>(
        new_blocks, old_blocks, chunk_size, num_blocks);

    for (int c_id = 0; c_id < ch_amount; c_id++) {
      auto cur_chunk = &terms_degree[c_id * chunk_size * num_blocks];
      int mx = 0;
      int mn = num_blocks;
      for (int r_id = 1; r_id < chunk_size; r_id++) {
        auto cur_radix = &cur_chunk[r_id * num_blocks];
        for (int i = 0; i < num_blocks; i++) {
          if (cur_radix[i]) {
            mn = min(mn, i);
            mx = max(mx, i);
          }
        }
      }
      f_b[c_id] = mn;
      l_b[c_id] = mx;
    }

    int total_copied = 0;
    int message_count = 0;
    int carry_count = 0;
    compress_device_array_with_map<Torus>(stream, new_blocks, old_blocks, f_b,
                                          l_b, num_blocks, ch_amount,
                                          big_lwe_size, total_copied, true);

    message_count = total_copied;
    compress_device_array_with_map<Torus>(stream, new_blocks, old_blocks, f_b,
                                          l_b, num_blocks, ch_amount,
                                          big_lwe_size, total_copied, false);
    carry_count = total_copied - message_count;

    auto message_blocks_vector = old_blocks;
    auto carry_blocks_vector =
        &old_blocks[message_count * (glwe_dimension * polynomial_size + 1)];

    cuda_keyswitch_lwe_ciphertext_vector(
        stream, small_lwe_vector, lwe_indexes, old_blocks, lwe_indexes, ksk,
        polynomial_size * glwe_dimension, lwe_dimension,
        mem_ptr->params.ks_base_log, mem_ptr->params.ks_level, total_copied);

    execute_pbs<Torus>(
        stream, message_blocks_vector, lwe_indexes, luts_message->lut,
        luts_message->lut_indexes, small_lwe_vector, lwe_indexes, bsk,
        luts_message->pbs_buffer, glwe_dimension, lwe_dimension,
        polynomial_size, mem_ptr->params.pbs_base_log,
        mem_ptr->params.pbs_level, mem_ptr->params.grouping_factor,
        message_count, 1, 0, max_shared_memory, mem_ptr->params.pbs_type);

    execute_pbs<Torus>(stream, carry_blocks_vector, lwe_indexes,
                       luts_carry->lut, luts_carry->lut_indexes,
                       &small_lwe_vector[message_count * (lwe_dimension + 1)],
                       lwe_indexes, bsk, luts_carry->pbs_buffer, glwe_dimension,
                       lwe_dimension, polynomial_size,
                       mem_ptr->params.pbs_base_log, mem_ptr->params.pbs_level,
                       mem_ptr->params.grouping_factor, carry_count, 1, 0,
                       max_shared_memory, mem_ptr->params.pbs_type);

    int rem_blocks = r % chunk_size * num_blocks;
    int new_blocks_created = 2 * ch_amount * num_blocks;
    int copy_size = rem_blocks * big_lwe_size * sizeof(Torus);

    auto cur_dst = &new_blocks[new_blocks_created * big_lwe_size];
    auto cur_src = &old_blocks[(cur_total_blocks - rem_blocks) * big_lwe_size];
    cuda_memcpy_async_gpu_to_gpu(cur_dst, cur_src, copy_size, stream);

    total_copied = 0;
    int total_radix_copied = 0;
    extract_message_carry_to_full_radix<Torus>(
        stream, old_blocks, new_blocks, f_b, l_b, ch_amount, big_lwe_size,
        total_copied, total_radix_copied, num_blocks, true);
    extract_message_carry_to_full_radix<Torus>(
        stream, old_blocks, new_blocks, f_b, l_b, ch_amount, big_lwe_size,
        total_copied, total_radix_copied, num_blocks, false);

    std::swap(new_blocks, old_blocks);
    r = (new_blocks_created + rem_blocks) / num_blocks;
  }

  dim3 add_grid(1, num_blocks, 1);
  size_t sm_size = big_lwe_size * sizeof(Torus);
  cuda_memset_async(radix_lwe_out, 0, num_blocks * big_lwe_size * sizeof(Torus),
                    stream);
  tree_add_chunks<Torus, params><<<add_grid, 256, sm_size, stream->stream>>>(
      radix_lwe_out, old_blocks, r, num_blocks);

  integer_radix_apply_univariate_lookup_table_kb<Torus>(
      stream, vector_result_sb, radix_lwe_out, bsk, ksk, num_blocks,
      luts_message);
  integer_radix_apply_univariate_lookup_table_kb<Torus>(
      stream, &block_mul_res[big_lwe_size], radix_lwe_out, bsk, ksk, num_blocks,
      luts_carry);

  cuda_memset_async(block_mul_res, 0, big_lwe_size * sizeof(Torus), stream);

  host_addition(stream, radix_lwe_out, vector_result_sb, block_mul_res,
                big_lwe_size, num_blocks);

  host_propagate_single_carry_low_latency<Torus>(
      stream, radix_lwe_out, mem_ptr->scp_mem, bsk, ksk, num_blocks);
}

template <typename Torus>
__host__ void scratch_cuda_integer_mult_radix_ciphertext_kb(
    cuda_stream_t *stream, int_mul_memory<Torus> **mem_ptr,
    uint32_t num_radix_blocks, int_radix_params params,
    bool allocate_gpu_memory) {
  cudaSetDevice(stream->gpu_index);
  *mem_ptr = new int_mul_memory<Torus>(stream, params, num_radix_blocks,
                                       allocate_gpu_memory);
}

// Function to apply lookup table,
// It has two mode
//  lsb_msb_mode == true - extracts lsb and msb
//  lsb_msb_mode == false - extracts message and carry
template <typename Torus, typename STorus, class params>
void apply_lookup_table(Torus *input_ciphertexts, Torus *output_ciphertexts,
                        int_mul_memory<Torus> *mem_ptr, uint32_t glwe_dimension,
                        uint32_t lwe_dimension, uint32_t polynomial_size,
                        uint32_t pbs_base_log, uint32_t pbs_level,
                        uint32_t ks_base_log, uint32_t ks_level,
                        uint32_t grouping_factor,
                        uint32_t lsb_message_blocks_count,
                        uint32_t msb_carry_blocks_count,
                        uint32_t max_shared_memory, bool lsb_msb_mode) {

  int total_blocks_count = lsb_message_blocks_count + msb_carry_blocks_count;
  int gpu_n = mem_ptr->p2p_gpu_count;
  if (total_blocks_count < gpu_n)
    gpu_n = total_blocks_count;
  int gpu_blocks_count = total_blocks_count / gpu_n;
  int big_lwe_size = glwe_dimension * polynomial_size + 1;
  //  int small_lwe_size = lwe_dimension + 1;

#pragma omp parallel for num_threads(gpu_n)
  for (int i = 0; i < gpu_n; i++) {
    cudaSetDevice(i);
    auto this_stream = mem_ptr->streams[i];
    // Index where input and output blocks start for current gpu
    int big_lwe_start_index = i * gpu_blocks_count * big_lwe_size;

    // Last gpu might have extra blocks to process if total blocks number is not
    // divisible by gpu_n
    if (i == gpu_n - 1) {
      gpu_blocks_count += total_blocks_count % gpu_n;
    }

    int can_access_peer;
    cudaDeviceCanAccessPeer(&can_access_peer, i, 0);
    if (i == 0) {
      check_cuda_error(
          cudaMemcpyAsync(mem_ptr->pbs_output_multi_gpu[i],
                          &input_ciphertexts[big_lwe_start_index],
                          gpu_blocks_count * big_lwe_size * sizeof(Torus),
                          cudaMemcpyDeviceToDevice, *this_stream));
    } else if (can_access_peer) {
      check_cuda_error(cudaMemcpyPeerAsync(
          mem_ptr->pbs_output_multi_gpu[i], i,
          &input_ciphertexts[big_lwe_start_index], 0,
          gpu_blocks_count * big_lwe_size * sizeof(Torus), *this_stream));
    } else {
      // Uses host memory as middle ground
      cuda_memcpy_async_to_cpu(mem_ptr->device_to_device_buffer[i],
                               &input_ciphertexts[big_lwe_start_index],
                               gpu_blocks_count * big_lwe_size * sizeof(Torus),
                               this_stream, i);
      cuda_memcpy_async_to_gpu(
          mem_ptr->pbs_output_multi_gpu[i], mem_ptr->device_to_device_buffer[i],
          gpu_blocks_count * big_lwe_size * sizeof(Torus), this_stream, i);
    }

    // when lsb and msb have to be extracted
    //  for first lsb_count blocks we need lsb_acc
    //  for last msb_count blocks we need msb_acc
    // when message and carry have tobe extracted
    //  for first message_count blocks we need message_acc
    //  for last carry_count blocks we need carry_acc
    Torus *cur_lut_indexes;
    if (lsb_msb_mode) {
      cur_lut_indexes = (big_lwe_start_index < lsb_message_blocks_count)
                            ? mem_ptr->lut_indexes_lsb_multi_gpu[i]
                            : mem_ptr->lut_indexes_msb_multi_gpu[i];

    } else {
      cur_lut_indexes = (big_lwe_start_index < lsb_message_blocks_count)
                            ? mem_ptr->lut_indexes_message_multi_gpu[i]
                            : mem_ptr->lut_indexes_carry_multi_gpu[i];
    }

    // execute keyswitch on a current gpu with corresponding input and output
    // blocks pbs_output_multi_gpu[i] is an input for keyswitch and
    // pbs_input_multi_gpu[i] is an output for keyswitch
    cuda_keyswitch_lwe_ciphertext_vector(
        this_stream, i, mem_ptr->pbs_input_multi_gpu[i],
        mem_ptr->pbs_output_multi_gpu[i], mem_ptr->ksk_multi_gpu[i],
        polynomial_size * glwe_dimension, lwe_dimension, ks_base_log, ks_level,
        gpu_blocks_count);

    // execute pbs on a current gpu with corresponding input and output
    cuda_multi_bit_pbs_lwe_ciphertext_vector_64(
        this_stream, i, mem_ptr->pbs_output_multi_gpu[i],
        mem_ptr->lut_multi_gpu[i], cur_lut_indexes,
        mem_ptr->pbs_input_multi_gpu[i], mem_ptr->bsk_multi_gpu[i],
        mem_ptr->pbs_buffer_multi_gpu[i], lwe_dimension, glwe_dimension,
        polynomial_size, grouping_factor, pbs_base_log, pbs_level,
        grouping_factor, gpu_blocks_count, 2, 0, max_shared_memory);

    // lookup table is applied and now data from current gpu have to be copied
    // back to gpu_0 in 'output_ciphertexts' buffer
    if (i == 0) {
      check_cuda_error(
          cudaMemcpyAsync(&output_ciphertexts[big_lwe_start_index],
                          mem_ptr->pbs_output_multi_gpu[i],
                          gpu_blocks_count * big_lwe_size * sizeof(Torus),
                          cudaMemcpyDeviceToDevice, *this_stream));
    } else if (can_access_peer) {
      check_cuda_error(cudaMemcpyPeerAsync(
          &output_ciphertexts[big_lwe_start_index], 0,
          mem_ptr->pbs_output_multi_gpu[i], i,
          gpu_blocks_count * big_lwe_size * sizeof(Torus), *this_stream));
    } else {
      // Uses host memory as middle ground
      cuda_memcpy_async_to_cpu(
          mem_ptr->device_to_device_buffer[i], mem_ptr->pbs_output_multi_gpu[i],
          gpu_blocks_count * big_lwe_size * sizeof(Torus), this_stream, i);
      cuda_memcpy_async_to_gpu(&output_ciphertexts[big_lwe_start_index],
                               mem_ptr->device_to_device_buffer[i],
                               gpu_blocks_count * big_lwe_size * sizeof(Torus),
                               this_stream, i);
    }
  }
}

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
__host__ void host_integer_small_scalar_mult_radix(
    cuda_stream_t *stream, T *output_lwe_array, T *input_lwe_array, T scalar,
    uint32_t input_lwe_dimension, uint32_t input_lwe_ciphertext_count) {

  cudaSetDevice(stream->gpu_index);
  // lwe_size includes the presence of the body
  // whereas lwe_dimension is the number of elements in the mask
  int lwe_size = input_lwe_dimension + 1;
  // Create a 1-dimensional grid of threads
  int num_blocks = 0, num_threads = 0;
  int num_entries = input_lwe_ciphertext_count * lwe_size;
  getNumBlocksAndThreads(num_entries, 512, num_blocks, num_threads);
  dim3 grid(num_blocks, 1, 1);
  dim3 thds(num_threads, 1, 1);

  device_small_scalar_radix_multiplication<<<grid, thds, 0, stream->stream>>>(
      output_lwe_array, input_lwe_array, scalar, input_lwe_dimension,
      input_lwe_ciphertext_count);
  check_cuda_error(cudaGetLastError());
}
#endif
