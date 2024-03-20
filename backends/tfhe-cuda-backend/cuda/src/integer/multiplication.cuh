#ifndef CUDA_INTEGER_MULT_CUH
#define CUDA_INTEGER_MULT_CUH

#ifdef __CDT_PARSER__
#undef __CUDA_RUNTIME_H__
#include <cuda_runtime.h>
#endif

#include "crypto/keyswitch.cuh"
#include "device.h"
#include "integer.h"
#include "integer/integer.cuh"
#include "linear_algebra.h"
#include "programmable_bootstrap.h"
#include "utils/helper.cuh"
#include "utils/kernel_dimensions.cuh"
#include <fstream>
#include <iostream>
#include <omp.h>
#include <sstream>
#include <string>
#include <vector>

template <typename Torus>
__global__ void smart_copy(Torus *dst, Torus *src, int32_t *id_out,
                           int32_t *id_in, size_t lwe_size) {
  size_t tid = threadIdx.x;
  size_t b_id = blockIdx.x;
  size_t stride = blockDim.x;

  auto input_id = id_in[b_id];
  auto output_id = id_out[b_id];

  auto cur_src = (input_id >= 0) ? &src[input_id * lwe_size] : nullptr;
  auto cur_dst = &dst[output_id * lwe_size];

  for (int i = tid; i < lwe_size; i += stride) {
    cur_dst[i] = (input_id >= 0) ? cur_src[i] : 0;
  }
}

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
__global__ void tree_add_chunks(Torus *result_blocks, Torus *input_blocks,
                                uint32_t chunk_size, uint32_t block_size,
                                uint32_t num_blocks) {

  extern __shared__ Torus result[];
  size_t stride = blockDim.x;
  size_t chunk_id = blockIdx.x;
  size_t chunk_elem_size = chunk_size * num_blocks * block_size;
  size_t radix_elem_size = num_blocks * block_size;
  auto src_chunk = &input_blocks[chunk_id * chunk_elem_size];
  auto dst_radix = &result_blocks[chunk_id * radix_elem_size];
  size_t block_stride = blockIdx.y * block_size;
  auto dst_block = &dst_radix[block_stride];

  // init shared mem with first radix of chunk
  size_t tid = threadIdx.x;
  for (int i = tid; i < block_size; i += stride) {
    result[i] = src_chunk[block_stride + i];
  }

  // accumulate rest  of the radixes
  for (int r_id = 1; r_id < chunk_size; r_id++) {
    auto cur_src_radix = &src_chunk[r_id * radix_elem_size];
    for (int i = tid; i < block_size; i += stride) {
      result[i] += cur_src_radix[block_stride + i];
    }
  }

  // put result from shared mem to global mem
  for (int i = tid; i < block_size; i += stride) {
    dst_block[i] = result[i];
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
template <typename Torus>
__host__ void scratch_cuda_integer_sum_ciphertexts_vec_kb(
    cuda_stream_t *stream, int_sum_ciphertexts_vec_memory<Torus> **mem_ptr,
    uint32_t num_blocks_in_radix, uint32_t max_num_radix_in_vec,
    int_radix_params params, bool allocate_gpu_memory) {

  cudaSetDevice(stream->gpu_index);
  size_t sm_size = (params.big_lwe_dimension + 1) * sizeof(Torus);
  check_cuda_error(cudaFuncSetAttribute(
      tree_add_chunks<Torus>, cudaFuncAttributeMaxDynamicSharedMemorySize,
      sm_size));
  cudaFuncSetCacheConfig(tree_add_chunks<Torus>, cudaFuncCachePreferShared);
  check_cuda_error(cudaGetLastError());
  *mem_ptr = new int_sum_ciphertexts_vec_memory<Torus>(
      stream, params, num_blocks_in_radix, max_num_radix_in_vec,
      allocate_gpu_memory);
}

template <typename Torus, class params>
__host__ void host_integer_sum_ciphertexts_vec_kb(
    cuda_stream_t *stream, Torus *radix_lwe_out, Torus *terms,
    int *terms_degree, void *bsk, uint64_t *ksk,
    int_sum_ciphertexts_vec_memory<uint64_t> *mem_ptr,
    uint32_t num_blocks_in_radix, uint32_t num_radix_in_vec) {

  cudaSetDevice(stream->gpu_index);
  auto new_blocks = mem_ptr->new_blocks;
  auto old_blocks = mem_ptr->old_blocks;
  auto small_lwe_vector = mem_ptr->small_lwe_vector;

  auto luts_message_carry = mem_ptr->luts_message_carry;

  auto lwe_indexes_in = luts_message_carry->lwe_indexes_in;
  auto lwe_indexes_out = luts_message_carry->lwe_indexes_out;

  auto d_smart_copy_in = mem_ptr->d_smart_copy_in;
  auto d_smart_copy_out = mem_ptr->d_smart_copy_out;

  auto message_modulus = mem_ptr->params.message_modulus;
  auto carry_modulus = mem_ptr->params.carry_modulus;
  auto num_blocks = num_blocks_in_radix;
  auto big_lwe_size = mem_ptr->params.big_lwe_dimension + 1;
  auto glwe_dimension = mem_ptr->params.glwe_dimension;
  auto polynomial_size = mem_ptr->params.polynomial_size;
  auto lwe_dimension = mem_ptr->params.small_lwe_dimension;
  auto big_lwe_dimension = mem_ptr->params.big_lwe_dimension;

  if (old_blocks != terms) {
    cuda_memcpy_async_gpu_to_gpu(old_blocks, terms,
                                 num_blocks_in_radix * num_radix_in_vec *
                                     big_lwe_size * sizeof(Torus),
                                 stream);
  }

  size_t r = num_radix_in_vec;
  size_t total_modulus = message_modulus * carry_modulus;
  size_t message_max = message_modulus - 1;
  size_t chunk_size = (total_modulus - 1) / message_max;

  size_t h_lwe_idx_in[r * num_blocks];
  size_t h_lwe_idx_out[r * num_blocks];
  int32_t h_smart_copy_in[r * num_blocks];
  int32_t h_smart_copy_out[r * num_blocks];

  auto max_shared_memory = cuda_get_max_shared_memory(stream->gpu_index);

  while (r > 2) {
    size_t cur_total_blocks = r * num_blocks;
    size_t ch_amount = r / chunk_size;
    if (!ch_amount)
      ch_amount++;
    dim3 add_grid(ch_amount, num_blocks, 1);
    size_t sm_size = big_lwe_size * sizeof(Torus);

    tree_add_chunks<Torus><<<add_grid, 512, sm_size, stream->stream>>>(
        new_blocks, old_blocks, min(r, chunk_size), big_lwe_size, num_blocks);

    size_t total_count = 0;
    size_t message_count = 0;
    size_t carry_count = 0;
    size_t sm_copy_count = 0;

    generate_ids_update_degrees(
        terms_degree, h_lwe_idx_in, h_lwe_idx_out, h_smart_copy_in,
        h_smart_copy_out, ch_amount, r, num_blocks, chunk_size, message_max,
        total_count, message_count, carry_count, sm_copy_count);

    size_t copy_size = total_count * sizeof(Torus);
    cuda_memcpy_async_to_gpu(lwe_indexes_in, h_lwe_idx_in, copy_size, stream);
    cuda_memcpy_async_to_gpu(lwe_indexes_out, h_lwe_idx_out, copy_size, stream);
    copy_size = sm_copy_count * sizeof(int32_t);
    cuda_memcpy_async_to_gpu(d_smart_copy_in, h_smart_copy_in, copy_size,
                             stream);
    cuda_memcpy_async_to_gpu(d_smart_copy_out, h_smart_copy_out, copy_size,
                             stream);

    smart_copy<<<sm_copy_count, 256, 0, stream->stream>>>(
        new_blocks, new_blocks, d_smart_copy_out, d_smart_copy_in,
        big_lwe_size);

    if (carry_count > 0)
      cuda_set_value_async<Torus>(
          &(stream->stream), luts_message_carry->get_lut_indexes(message_count),
          1, carry_count);

    cuda_keyswitch_lwe_ciphertext_vector(
        stream, small_lwe_vector, lwe_indexes_in, new_blocks, lwe_indexes_in,
        ksk, polynomial_size * glwe_dimension, lwe_dimension,
        mem_ptr->params.ks_base_log, mem_ptr->params.ks_level, message_count);

    execute_pbs<Torus>(
        stream, new_blocks, lwe_indexes_out, luts_message_carry->lut,
        luts_message_carry->lut_indexes, small_lwe_vector, lwe_indexes_in, bsk,
        luts_message_carry->buffer, glwe_dimension, lwe_dimension,
        polynomial_size, mem_ptr->params.pbs_base_log,
        mem_ptr->params.pbs_level, mem_ptr->params.grouping_factor, total_count,
        2, 0, max_shared_memory, mem_ptr->params.pbs_type);

    int rem_blocks = (r > chunk_size) ? r % chunk_size * num_blocks : 0;
    int new_blocks_created = 2 * ch_amount * num_blocks;
    copy_size = rem_blocks * big_lwe_size * sizeof(Torus);

    auto cur_dst = &new_blocks[new_blocks_created * big_lwe_size];
    auto cur_src = &old_blocks[(cur_total_blocks - rem_blocks) * big_lwe_size];
    cuda_memcpy_async_gpu_to_gpu(cur_dst, cur_src, copy_size, stream);
    std::swap(new_blocks, old_blocks);
    r = (new_blocks_created + rem_blocks) / num_blocks;
  }

  host_addition(stream, radix_lwe_out, old_blocks,
                &old_blocks[num_blocks * big_lwe_size], big_lwe_dimension,
                num_blocks);

  host_propagate_single_carry<Torus>(stream, radix_lwe_out, mem_ptr->scp_mem,
                                     bsk, ksk, num_blocks);
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

  int terms_degree[2 * num_blocks * num_blocks];
  for (int i = 0; i < num_blocks * num_blocks; i++) {
    size_t r_id = i / num_blocks;
    size_t b_id = i % num_blocks;
    terms_degree[i] = (b_id >= r_id) ? message_modulus - 1 : 0;
  }
  auto terms_degree_msb = &terms_degree[num_blocks * num_blocks];
  for (int i = 0; i < num_blocks * num_blocks; i++) {
    size_t r_id = i / num_blocks;
    size_t b_id = i % num_blocks;
    terms_degree_msb[i] = (b_id > r_id) ? message_modulus - 2 : 0;
  }

  host_integer_sum_ciphertexts_vec_kb<Torus, params>(
      stream, radix_lwe_out, vector_result_sb, terms_degree, bsk, ksk,
      mem_ptr->sum_ciphertexts_mem, num_blocks, 2 * num_blocks);
}

template <typename Torus>
__host__ void scratch_cuda_integer_mult_radix_ciphertext_kb(
    cuda_stream_t *stream, int_mul_memory<Torus> **mem_ptr,
    uint32_t num_radix_blocks, int_radix_params params,
    bool allocate_gpu_memory) {
  cudaSetDevice(stream->gpu_index);
  size_t sm_size = (params.big_lwe_dimension + 1) * sizeof(Torus);
  check_cuda_error(cudaFuncSetAttribute(
      tree_add_chunks<Torus>, cudaFuncAttributeMaxDynamicSharedMemorySize,
      sm_size));
  cudaFuncSetCacheConfig(tree_add_chunks<Torus>, cudaFuncCachePreferShared);
  check_cuda_error(cudaGetLastError());

  *mem_ptr = new int_mul_memory<Torus>(stream, params, num_radix_blocks,
                                       allocate_gpu_memory);
}

#endif
