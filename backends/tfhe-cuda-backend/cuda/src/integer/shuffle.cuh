#ifndef TFHE_RS_SHUFFLE_CUH
#define TFHE_RS_SHUFFLE_CUH

#include "integer/comparison.cuh"
#include "integer/oprf.cuh"
#include "integer/shuffle_utilities.h"
#include "linearalgebra/addition.cuh"
#include "radix_ciphertext.cuh"

template <typename Torus, typename KSTorus>
__host__ void
bitonic_sort_compare_phase(CudaStreams streams, CudaRadixCiphertextFFI **values,
                           uint32_t num_values, uint32_t j_param,
                           int_bitonic_sort_buffer<Torus> *mem_ptr,
                           void *const *bsks, KSTorus *const *ksks) {

  auto N = mem_ptr->num_radix_blocks;
  auto cmp_mem = mem_ptr->comparison_mem;
  uint32_t pair_idx = 0;
  for (uint32_t i = 0; i < num_values; i++) {
    uint32_t l = i ^ j_param;
    if (l <= i)
      continue;
    host_difference_check<Torus>(streams, cmp_mem->tmp_lwe_array_out, values[i],
                                 values[l], cmp_mem, cmp_mem->identity_lut_f,
                                 bsks, ksks, N);
    copy_radix_ciphertext_slice_async<Torus>(
        streams.stream(0), streams.gpu_index(0), mem_ptr->comparison_results,
        pair_idx, pair_idx + 1, cmp_mem->tmp_lwe_array_out, 0, 1);
    pair_idx++;
  }
}

template <typename Torus>
__host__ void bitonic_sort_gather_cmux_batch(
    CudaStreams streams, CudaRadixCiphertextFFI **values, uint32_t num_values,
    uint32_t k_param, uint32_t j_param, int32_t direction,
    int_bitonic_sort_buffer<Torus> *mem_ptr, uint32_t &half_out) {

  auto N = mem_ptr->num_radix_blocks;
  uint32_t blocks_per_pair = 2 * N;

  uint32_t K = 0;
  for (uint32_t i = 0; i < num_values; i++) {
    if ((i ^ j_param) > i)
      K++;
  }
  uint32_t half = K * blocks_per_pair;

  uint32_t pair_idx = 0;
  for (uint32_t i = 0; i < num_values; i++) {
    uint32_t l = i ^ j_param;
    if (l <= i)
      continue;

    bool ascending = ((i & k_param) == 0);
    if (direction == 0)
      ascending = !ascending;

    uint32_t base = pair_idx * blocks_per_pair;
    CudaRadixCiphertextFFI *min_t = ascending ? values[l] : values[i];
    CudaRadixCiphertextFFI *max_t = ascending ? values[i] : values[l];
    CudaRadixCiphertextFFI *min_f = ascending ? values[i] : values[l];
    CudaRadixCiphertextFFI *max_f = ascending ? values[l] : values[i];

    copy_radix_ciphertext_slice_async<Torus>(
        streams.stream(0), streams.gpu_index(0), mem_ptr->batch_buffer_in, base,
        base + N, min_t, 0, N);
    copy_radix_ciphertext_slice_async<Torus>(
        streams.stream(0), streams.gpu_index(0), mem_ptr->batch_buffer_in,
        base + N, base + blocks_per_pair, max_t, 0, N);
    copy_radix_ciphertext_slice_async<Torus>(
        streams.stream(0), streams.gpu_index(0), mem_ptr->batch_buffer_in,
        half + base, half + base + N, min_f, 0, N);
    copy_radix_ciphertext_slice_async<Torus>(
        streams.stream(0), streams.gpu_index(0), mem_ptr->batch_buffer_in,
        half + base + N, half + base + blocks_per_pair, max_f, 0, N);
    for (uint32_t b = 0; b < blocks_per_pair; b++) {
      copy_radix_ciphertext_slice_async<Torus>(
          streams.stream(0), streams.gpu_index(0), mem_ptr->batch_condition,
          base + b, base + b + 1, mem_ptr->comparison_results, pair_idx,
          pair_idx + 1);
      copy_radix_ciphertext_slice_async<Torus>(
          streams.stream(0), streams.gpu_index(0), mem_ptr->batch_condition,
          half + base + b, half + base + b + 1, mem_ptr->comparison_results,
          pair_idx, pair_idx + 1);
    }
    pair_idx++;
  }

  half_out = half;
}

template <typename Torus, typename KSTorus>
__host__ void bitonic_sort_apply_cmux_batch(
    CudaStreams streams, CudaRadixCiphertextFFI **values, uint32_t num_values,
    uint32_t j_param, uint32_t half, int_bitonic_sort_buffer<Torus> *mem_ptr,
    void *const *bsks, KSTorus *const *ksks) {

  auto N = mem_ptr->num_radix_blocks;
  auto params = mem_ptr->params;
  uint32_t blocks_per_pair = 2 * N;
  uint32_t total_bivariate = 2 * half;

  integer_radix_apply_bivariate_lookup_table<Torus>(
      streams, mem_ptr->batch_buffer_out, mem_ptr->batch_buffer_in,
      mem_ptr->batch_condition, bsks, ksks, mem_ptr->batch_predicate_lut,
      total_bivariate, params.message_modulus);

  CudaRadixCiphertextFFI true_half, false_half;
  as_radix_ciphertext_slice<Torus>(&true_half, mem_ptr->batch_buffer_out, 0,
                                   half);
  as_radix_ciphertext_slice<Torus>(&false_half, mem_ptr->batch_buffer_out, half,
                                   total_bivariate);
  host_addition<Torus>(streams.stream(0), streams.gpu_index(0), &true_half,
                       &true_half, &false_half, half, params.message_modulus,
                       params.carry_modulus);

  CudaRadixCiphertextFFI extract_out;
  as_radix_ciphertext_slice<Torus>(&extract_out, mem_ptr->batch_buffer_out, 0,
                                   half);
  integer_radix_apply_univariate_lookup_table<Torus>(
      streams, &extract_out, &true_half, bsks, ksks,
      mem_ptr->batch_message_extract_lut, half);

  uint32_t pair_idx = 0;
  for (uint32_t i = 0; i < num_values; i++) {
    uint32_t l = i ^ j_param;
    if (l <= i)
      continue;
    uint32_t base = pair_idx * blocks_per_pair;
    copy_radix_ciphertext_slice_async<Torus>(streams.stream(0),
                                             streams.gpu_index(0), values[i], 0,
                                             N, &extract_out, base, base + N);
    copy_radix_ciphertext_slice_async<Torus>(
        streams.stream(0), streams.gpu_index(0), values[l], 0, N, &extract_out,
        base + N, base + blocks_per_pair);
    pair_idx++;
  }
}

template <typename Torus>
__host__ uint64_t scratch_cuda_integer_bitonic_shuffle(
    CudaStreams streams, int_bitonic_shuffle_buffer<Torus> **mem_ptr,
    uint32_t key_num_radix_blocks, uint32_t data_num_radix_blocks,
    uint32_t num_values, int_radix_params params, bool data_is_signed,
    bool allocate_gpu_memory) {

  uint64_t size_tracker = 0;
  *mem_ptr = new int_bitonic_shuffle_buffer<Torus>(
      streams, params, key_num_radix_blocks, data_num_radix_blocks, num_values,
      data_is_signed, allocate_gpu_memory, size_tracker);
  return size_tracker;
}

template <typename Torus, typename KSTorus>
__host__ void
bitonic_shuffle_substep(CudaStreams streams, CudaRadixCiphertextFFI **keys,
                        CudaRadixCiphertextFFI **values, uint32_t num_values,
                        uint32_t k_param, uint32_t j_param, int32_t direction,
                        int_bitonic_shuffle_buffer<Torus> *mem_ptr,
                        void *const *bsks, KSTorus *const *ksks) {

  auto key_buf = mem_ptr->keys_buffer;
  auto data_buf = mem_ptr->data_buffer;

  bitonic_sort_compare_phase<Torus>(streams, keys, num_values, j_param, key_buf,
                                    bsks, ksks);

  uint32_t half_keys;
  bitonic_sort_gather_cmux_batch<Torus>(streams, keys, num_values, k_param,
                                        j_param, direction, key_buf, half_keys);
  bitonic_sort_apply_cmux_batch<Torus>(streams, keys, num_values, j_param,
                                       half_keys, key_buf, bsks, ksks);

  uint32_t K_pairs = num_values / 2;
  copy_radix_ciphertext_slice_async<Torus>(
      streams.stream(0), streams.gpu_index(0), data_buf->comparison_results, 0,
      K_pairs, key_buf->comparison_results, 0, K_pairs);

  uint32_t half_data;
  bitonic_sort_gather_cmux_batch<Torus>(streams, values, num_values, k_param,
                                        j_param, direction, data_buf,
                                        half_data);
  bitonic_sort_apply_cmux_batch<Torus>(streams, values, num_values, j_param,
                                       half_data, data_buf, bsks, ksks);
}

template <typename Torus>
__host__ void bitonic_shuffle_setup_padded(
    CudaStreams streams, CudaRadixCiphertextFFI **keys,
    CudaRadixCiphertextFFI **values, uint32_t num_values,
    int_bitonic_shuffle_buffer<Torus> *mem_ptr,
    CudaRadixCiphertextFFI ***eff_keys, CudaRadixCiphertextFFI ***eff_values,
    uint32_t *eff_num_values) {

  if (!mem_ptr->needs_pad) {
    *eff_keys = keys;
    *eff_values = values;
    *eff_num_values = num_values;
    return;
  }

  uint32_t Kp = mem_ptr->key_num_blocks_padded;
  uint32_t K0 = mem_ptr->key_num_blocks;
  uint32_t padded_n = mem_ptr->padded_num_values;
  uint32_t data_n_blocks = mem_ptr->data_num_blocks;

  for (uint32_t i = 0; i < num_values; i++) {
    copy_radix_ciphertext_slice_async<Torus>(
        streams.stream(0), streams.gpu_index(0), &mem_ptr->padded_keys_views[i],
        0, K0, keys[i], 0, K0);
    if (Kp > K0) {
      set_zero_radix_ciphertext_slice_async<Torus>(
          streams.stream(0), streams.gpu_index(0),
          &mem_ptr->padded_keys_views[i], K0, Kp);
    }
  }

  for (uint32_t i = num_values; i < padded_n; i++) {
    set_trivial_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), &mem_ptr->padded_keys_views[i],
        mem_ptr->d_max_scalar, mem_ptr->h_max_scalar, Kp,
        mem_ptr->params.message_modulus, mem_ptr->params.carry_modulus);
  }

  for (uint32_t i = 0; i < num_values; i++)
    mem_ptr->padded_data_ptrs[i] = values[i];

  for (uint32_t i = 0; i < padded_n - num_values; i++) {
    set_zero_radix_ciphertext_slice_async<Torus>(
        streams.stream(0), streams.gpu_index(0),
        &mem_ptr->sentinel_data_views[i], 0, data_n_blocks);
  }

  *eff_keys = mem_ptr->padded_keys_ptrs;
  *eff_values = mem_ptr->padded_data_ptrs;
  *eff_num_values = padded_n;
}

template <typename Torus, typename KSTorus>
__host__ void
host_bitonic_shuffle(CudaStreams streams, CudaRadixCiphertextFFI **keys,
                     CudaRadixCiphertextFFI **values, uint32_t num_values,
                     int_bitonic_shuffle_buffer<Torus> *mem_ptr,
                     void *const *bsks, KSTorus *const *ksks) {

  CudaRadixCiphertextFFI **eff_keys;
  CudaRadixCiphertextFFI **eff_values;
  uint32_t eff_n;
  bitonic_shuffle_setup_padded<Torus>(streams, keys, values, num_values,
                                      mem_ptr, &eff_keys, &eff_values, &eff_n);

  for (uint32_t k = 2; k <= eff_n; k <<= 1)
    for (uint32_t j = k >> 1; j > 0; j >>= 1)
      bitonic_shuffle_substep<Torus>(streams, eff_keys, eff_values, eff_n, k, j,
                                     1, mem_ptr, bsks, ksks);
}

template <typename Torus>
__host__ uint64_t scratch_cuda_integer_oprf_bitonic_shuffle(
    CudaStreams streams, int_oprf_bitonic_shuffle_buffer<Torus> **mem_ptr,
    uint32_t key_num_blocks, uint32_t data_num_blocks, uint32_t num_values,
    int_radix_params params, bool data_is_signed, bool allocate_gpu_memory) {

  uint64_t size_tracker = 0;
  *mem_ptr = new int_oprf_bitonic_shuffle_buffer<Torus>(
      streams, params, key_num_blocks, data_num_blocks, num_values,
      data_is_signed, allocate_gpu_memory, size_tracker);
  return size_tracker;
}

template <typename Torus, typename KSTorus>
__host__ void
host_oprf_bitonic_shuffle(CudaStreams streams, CudaRadixCiphertextFFI **values,
                          uint32_t num_values, const Torus *seeded_lwe_input,
                          int_oprf_bitonic_shuffle_buffer<Torus> *mem_ptr,
                          void *const *bsks, KSTorus *const *ksks) {

  uint32_t key_num_blocks = mem_ptr->key_num_blocks;

  host_integer_grouped_oprf<Torus>(
      streams, mem_ptr->keys_storage, seeded_lwe_input,
      num_values * key_num_blocks, mem_ptr->oprf_memory, bsks);

  host_bitonic_shuffle<Torus>(streams, mem_ptr->keys_ptrs, values, num_values,
                              mem_ptr->shuffle_buffer, bsks, ksks);
}

#endif
