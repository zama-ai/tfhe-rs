#ifndef AES_CUH
#define AES_CUH

#include "integer.cuh"
#include "integer/integer_utilities.h"
#include "integer/scalar_addition.cuh"
#include "linearalgebra/addition.cuh"
#include "radix_ciphertext.cuh"

template <typename Torus>
uint64_t scratch_cuda_integer_aes_encrypt(
    cudaStream_t const *streams, uint32_t const *gpu_indexes,
    uint32_t gpu_count, int_aes_encrypt_buffer<Torus> **mem_ptr,
    int_radix_params params, bool allocate_gpu_memory, uint32_t num_blocks) {
  uint64_t size_tracker = 0;
  *mem_ptr = new int_aes_encrypt_buffer<Torus>(streams, gpu_indexes, gpu_count,
                                               params, allocate_gpu_memory,
                                               num_blocks, size_tracker);
  return size_tracker;
}

template <typename Torus>
__host__ void
transpose_blocks_to_bitsliced(cudaStream_t stream, uint32_t gpu_index,
                              CudaRadixCiphertextFFI *dest_bitsliced,
                              const CudaRadixCiphertextFFI *source_blocks,
                              uint32_t num_blocks, uint32_t block_size_bits) {
  for (uint32_t i = 0; i < block_size_bits; ++i) {
    for (uint32_t j = 0; j < num_blocks; ++j) {
      uint32_t src_idx = j * block_size_bits + i;
      uint32_t dest_idx = i * num_blocks + j;
      copy_radix_ciphertext_slice_async<Torus>(
          stream, gpu_index, dest_bitsliced, dest_idx, dest_idx + 1,
          source_blocks, src_idx, src_idx + 1);
    }
  }
}

template <typename Torus>
__host__ void
transpose_bitsliced_to_blocks(cudaStream_t stream, uint32_t gpu_index,
                              CudaRadixCiphertextFFI *dest_blocks,
                              const CudaRadixCiphertextFFI *source_bitsliced,
                              uint32_t num_blocks, uint32_t block_size_bits) {
  for (uint32_t i = 0; i < block_size_bits; ++i) {
    for (uint32_t j = 0; j < num_blocks; ++j) {
      uint32_t src_idx = i * num_blocks + j;
      uint32_t dest_idx = j * block_size_bits + i;
      copy_radix_ciphertext_slice_async<Torus>(
          stream, gpu_index, dest_blocks, dest_idx, dest_idx + 1,
          source_bitsliced, src_idx, src_idx + 1);
    }
  }
}

template <typename Torus>
__host__ __forceinline__ void
vectorized_aes_xor(cudaStream_t const *streams, uint32_t const *gpu_indexes,
                   uint32_t gpu_count, int_aes_encrypt_buffer<Torus> *mem,
                   CudaRadixCiphertextFFI *out,
                   const CudaRadixCiphertextFFI *lhs,
                   const CudaRadixCiphertextFFI *rhs) {
  host_addition<Torus>(streams[0], gpu_indexes[0], out, lhs, rhs,
                       out->num_radix_blocks, mem->params.message_modulus,
                       mem->params.carry_modulus);
}

template <typename Torus>
__host__ __forceinline__ void vectorized_aes_and(
    cudaStream_t const *streams, uint32_t const *gpu_indexes,
    uint32_t gpu_count, CudaRadixCiphertextFFI *out,
    const CudaRadixCiphertextFFI *lhs, const CudaRadixCiphertextFFI *rhs,
    int_aes_encrypt_buffer<Torus> *mem, void *const *bsks, Torus *const *ksks,
    CudaModulusSwitchNoiseReductionKeyFFI const *ms_noise_reduction_key) {
  integer_radix_apply_bivariate_lookup_table_kb<Torus>(
      streams, gpu_indexes, gpu_count, out, lhs, rhs, bsks, ksks,
      ms_noise_reduction_key, mem->and_lut, out->num_radix_blocks,
      mem->params.message_modulus);
}

template <typename Torus>
__host__ __forceinline__ void vectorized_aes_flush(
    cudaStream_t const *streams, uint32_t const *gpu_indexes,
    uint32_t gpu_count, CudaRadixCiphertextFFI *data,
    int_aes_encrypt_buffer<Torus> *mem, void *const *bsks, Torus *const *ksks,
    CudaModulusSwitchNoiseReductionKeyFFI const *ms_noise_reduction_key) {
  integer_radix_apply_univariate_lookup_table_kb<Torus>(
      streams, gpu_indexes, gpu_count, data, data, bsks, ksks,
      ms_noise_reduction_key, mem->flush_lut, data->num_radix_blocks);
}

template <typename Torus>
__host__ __forceinline__ void vectorized_sbox_flush(
    cudaStream_t const *streams, uint32_t const *gpu_indexes,
    uint32_t gpu_count, CudaRadixCiphertextFFI *out,
    const CudaRadixCiphertextFFI *in, int_aes_encrypt_buffer<Torus> *mem,
    void *const *bsks, Torus *const *ksks,
    CudaModulusSwitchNoiseReductionKeyFFI const *ms_noise_reduction_key) {

  integer_radix_apply_univariate_lookup_table_kb<Torus>(
      streams, gpu_indexes, gpu_count, out, in, bsks, ksks,
      ms_noise_reduction_key, mem->sbox_flush_lut, out->num_radix_blocks);
}

template <typename Torus>
__host__ __forceinline__ void vectorized_scalar_add_one_flush(
    cudaStream_t const *streams, uint32_t const *gpu_indexes,
    uint32_t gpu_count, CudaRadixCiphertextFFI *data,
    int_aes_encrypt_buffer<Torus> *mem, void *const *bsks, Torus *const *ksks,
    CudaModulusSwitchNoiseReductionKeyFFI const *ms_noise_reduction_key) {
  host_integer_radix_add_scalar_one_inplace<Torus>(
      streams, gpu_indexes, gpu_count, data, mem->params.message_modulus,
      mem->params.carry_modulus);
  vectorized_sbox_flush<Torus>(streams, gpu_indexes, gpu_count, data, data, mem,
                               bsks, ksks, ms_noise_reduction_key);
}

template <typename Torus>
__host__ void batch_vec_flush(
    cudaStream_t const *streams, uint32_t const *gpu_indexes,
    uint32_t gpu_count, CudaRadixCiphertextFFI **targets, size_t count,
    int_aes_encrypt_buffer<Torus> *mem, void *const *bsks, Torus *const *ksks,
    CudaModulusSwitchNoiseReductionKeyFFI const *ms_noise_reduction_key) {

  if (count == 0)
    return;
  uint32_t num_blocks = targets[0]->num_radix_blocks;

  CudaRadixCiphertextFFI batch_in, batch_out;
  as_radix_ciphertext_slice<Torus>(&batch_in, mem->batch_processing_buffer, 0,
                                   count * num_blocks);
  as_radix_ciphertext_slice<Torus>(&batch_out, mem->batch_processing_buffer,
                                   count * num_blocks,
                                   (2 * count) * num_blocks);

  for (size_t i = 0; i < count; ++i) {
    CudaRadixCiphertextFFI dest_slice;
    as_radix_ciphertext_slice<Torus>(&dest_slice, &batch_in, i * num_blocks,
                                     (i + 1) * num_blocks);
    copy_radix_ciphertext_async<Torus>(streams[0], gpu_indexes[0], &dest_slice,
                                       targets[i]);
  }

  vectorized_sbox_flush<Torus>(streams, gpu_indexes, gpu_count, &batch_out,
                               &batch_in, mem, bsks, ksks,
                               ms_noise_reduction_key);

  for (size_t i = 0; i < count; ++i) {
    CudaRadixCiphertextFFI src_slice;
    as_radix_ciphertext_slice<Torus>(&src_slice, &batch_out, i * num_blocks,
                                     (i + 1) * num_blocks);
    copy_radix_ciphertext_async<Torus>(streams[0], gpu_indexes[0], targets[i],
                                       &src_slice);
  }
}

template <typename Torus>
__host__ void batch_vec_and(
    cudaStream_t const *streams, uint32_t const *gpu_indexes,
    uint32_t gpu_count, CudaRadixCiphertextFFI **outs,
    CudaRadixCiphertextFFI **lhs, CudaRadixCiphertextFFI **rhs, size_t count,
    int_aes_encrypt_buffer<Torus> *mem, void *const *bsks, Torus *const *ksks,
    CudaModulusSwitchNoiseReductionKeyFFI const *ms_noise_reduction_key) {

  if (count == 0)
    return;
  uint32_t num_blocks = outs[0]->num_radix_blocks;

  CudaRadixCiphertextFFI batch_lhs, batch_rhs, batch_out;
  as_radix_ciphertext_slice<Torus>(&batch_lhs, mem->batch_processing_buffer, 0,
                                   count * num_blocks);
  as_radix_ciphertext_slice<Torus>(&batch_rhs, mem->batch_processing_buffer,
                                   count * num_blocks,
                                   (2 * count) * num_blocks);
  as_radix_ciphertext_slice<Torus>(&batch_out, mem->batch_processing_buffer,
                                   (2 * count) * num_blocks,
                                   (3 * count) * num_blocks);

  for (size_t i = 0; i < count; ++i) {
    CudaRadixCiphertextFFI dest_lhs_slice, dest_rhs_slice;
    as_radix_ciphertext_slice<Torus>(&dest_lhs_slice, &batch_lhs,
                                     i * num_blocks, (i + 1) * num_blocks);
    as_radix_ciphertext_slice<Torus>(&dest_rhs_slice, &batch_rhs,
                                     i * num_blocks, (i + 1) * num_blocks);
    copy_radix_ciphertext_async<Torus>(streams[0], gpu_indexes[0],
                                       &dest_lhs_slice, lhs[i]);
    copy_radix_ciphertext_async<Torus>(streams[0], gpu_indexes[0],
                                       &dest_rhs_slice, rhs[i]);
  }

  vectorized_aes_and<Torus>(streams, gpu_indexes, gpu_count, &batch_out,
                            &batch_lhs, &batch_rhs, mem, bsks, ksks,
                            ms_noise_reduction_key);

  for (size_t i = 0; i < count; ++i) {
    CudaRadixCiphertextFFI src_slice;
    as_radix_ciphertext_slice<Torus>(&src_slice, &batch_out, i * num_blocks,
                                     (i + 1) * num_blocks);
    copy_radix_ciphertext_async<Torus>(streams[0], gpu_indexes[0], outs[i],
                                       &src_slice);
  }
}

template <typename Torus>
__host__ void vectorized_sbox_byte(
    cudaStream_t const *streams, uint32_t const *gpu_indexes,
    uint32_t gpu_count, CudaRadixCiphertextFFI *x, uint32_t num_blocks,
    int_aes_encrypt_buffer<Torus> *mem, void *const *bsks, Torus *const *ksks,
    CudaModulusSwitchNoiseReductionKeyFFI const *ms_noise_reduction_key) {

  CudaRadixCiphertextFFI y[22], t[68], z[18];
  for (int i = 0; i < 22; ++i)
    as_radix_ciphertext_slice<Torus>(&y[i], mem->sbox_internal_workspace,
                                     i * num_blocks, (i + 1) * num_blocks);
  for (int i = 0; i < 68; ++i)
    as_radix_ciphertext_slice<Torus>(&t[i], mem->sbox_internal_workspace,
                                     (22 + i) * num_blocks,
                                     (22 + i + 1) * num_blocks);
  for (int i = 0; i < 18; ++i)
    as_radix_ciphertext_slice<Torus>(&z[i], mem->sbox_internal_workspace,
                                     (22 + 68 + i) * num_blocks,
                                     (22 + 68 + i + 1) * num_blocks);

#define VEC_XOR(out, a, b)                                                     \
  vectorized_aes_xor<Torus>(streams, gpu_indexes, gpu_count, mem, out, a, b)

#define BATCH_VEC_FLUSH(...)                                                   \
  do {                                                                         \
    CudaRadixCiphertextFFI *targets[] = {__VA_ARGS__};                         \
    batch_vec_flush(streams, gpu_indexes, gpu_count, targets,                  \
                    sizeof(targets) / sizeof(targets[0]), mem, bsks, ksks,     \
                    ms_noise_reduction_key);                                   \
  } while (0)

  VEC_XOR(&y[14], &x[3], &x[5]);
  VEC_XOR(&y[13], &x[0], &x[6]);
  VEC_XOR(&y[9], &x[0], &x[3]);
  VEC_XOR(&y[8], &x[0], &x[5]);
  VEC_XOR(&t[0], &x[1], &x[2]);

  BATCH_VEC_FLUSH(&y[14], &y[13], &y[9], &y[8]);
  VEC_XOR(&y[1], &t[0], &x[7]);

  BATCH_VEC_FLUSH(&y[1]);
  VEC_XOR(&y[12], &y[13], &y[14]);
  VEC_XOR(&y[4], &y[1], &x[3]);
  VEC_XOR(&y[2], &y[1], &x[0]);
  VEC_XOR(&y[5], &y[1], &x[6]);

  BATCH_VEC_FLUSH(&y[12], &y[4], &y[2], &y[5]);
  VEC_XOR(&y[3], &y[5], &y[8]);
  VEC_XOR(&t[1], &x[4], &y[12]);

  BATCH_VEC_FLUSH(&y[3]);
  VEC_XOR(&y[15], &t[1], &x[5]);
  VEC_XOR(&y[20], &t[1], &x[1]);

  BATCH_VEC_FLUSH(&y[15], &y[20]);
  VEC_XOR(&y[6], &y[15], &x[7]);
  VEC_XOR(&y[10], &y[15], &t[0]);
  VEC_XOR(&y[11], &y[20], &y[9]);

  BATCH_VEC_FLUSH(&y[6], &y[10]);
  VEC_XOR(&y[7], &x[7], &y[11]);

  BATCH_VEC_FLUSH(&y[7]);
  VEC_XOR(&y[17], &y[10], &y[11]);
  VEC_XOR(&y[19], &y[10], &y[8]);
  VEC_XOR(&y[16], &t[0], &y[11]);

  BATCH_VEC_FLUSH(&y[17], &y[19], &y[16]);
  VEC_XOR(&y[21], &y[13], &y[16]);
  VEC_XOR(&y[18], &x[0], &y[16]);

  CudaRadixCiphertextFFI *and_outs_1[] = {&t[2],  &t[3],  &t[5],  &t[7], &t[8],
                                          &t[10], &t[12], &t[13], &t[15]};
  CudaRadixCiphertextFFI *and_lhs_1[] = {&y[15], &y[3], &x[7],  &y[13], &y[1],
                                         &y[2],  &y[9], &y[14], &y[8]};
  CudaRadixCiphertextFFI *and_rhs_1[] = {&y[12], &y[6],  &y[4],  &y[16], &y[5],
                                         &y[7],  &y[11], &y[17], &y[10]};
  batch_vec_and(streams, gpu_indexes, gpu_count, and_outs_1, and_lhs_1,
                and_rhs_1, 9, mem, bsks, ksks, ms_noise_reduction_key);
  BATCH_VEC_FLUSH(&y[21], &y[18]);

  VEC_XOR(&t[4], &t[3], &t[2]);
  VEC_XOR(&t[6], &t[5], &t[2]);
  VEC_XOR(&t[9], &t[8], &t[7]);
  VEC_XOR(&t[11], &t[10], &t[7]);
  VEC_XOR(&t[14], &t[13], &t[12]);
  VEC_XOR(&t[16], &t[15], &t[12]);

  VEC_XOR(&t[17], &t[4], &t[14]);
  VEC_XOR(&t[18], &t[6], &t[16]);
  VEC_XOR(&t[19], &t[9], &t[14]);
  VEC_XOR(&t[20], &t[11], &t[16]);

  VEC_XOR(&t[21], &t[17], &y[20]);
  VEC_XOR(&t[22], &t[18], &y[19]);
  VEC_XOR(&t[23], &t[19], &y[21]);
  VEC_XOR(&t[24], &t[20], &y[18]);

  BATCH_VEC_FLUSH(&t[21], &t[23], &t[24]);
  VEC_XOR(&t[25], &t[21], &t[22]);

  BATCH_VEC_FLUSH(&t[25]);
  CudaRadixCiphertextFFI *and_outs_2[] = {&t[26]};
  CudaRadixCiphertextFFI *and_lhs_2[] = {&t[21]};
  CudaRadixCiphertextFFI *and_rhs_2[] = {&t[23]};
  batch_vec_and(streams, gpu_indexes, gpu_count, and_outs_2, and_lhs_2,
                and_rhs_2, 1, mem, bsks, ksks, ms_noise_reduction_key);

  VEC_XOR(&t[27], &t[24], &t[26]);
  VEC_XOR(&t[30], &t[23], &t[24]);
  VEC_XOR(&t[31], &t[22], &t[26]);

  BATCH_VEC_FLUSH(&t[27], &t[30], &t[31]);
  CudaRadixCiphertextFFI *and_outs_3[] = {&t[28]};
  CudaRadixCiphertextFFI *and_lhs_3[] = {&t[25]};
  CudaRadixCiphertextFFI *and_rhs_3[] = {&t[27]};
  batch_vec_and(streams, gpu_indexes, gpu_count, and_outs_3, and_lhs_3,
                and_rhs_3, 1, mem, bsks, ksks, ms_noise_reduction_key);

  VEC_XOR(&t[29], &t[28], &t[22]);
  CudaRadixCiphertextFFI *and_outs_4[] = {&t[32]};
  CudaRadixCiphertextFFI *and_lhs_4[] = {&t[30]};
  CudaRadixCiphertextFFI *and_rhs_4[] = {&t[31]};
  batch_vec_and(streams, gpu_indexes, gpu_count, and_outs_4, and_lhs_4,
                and_rhs_4, 1, mem, bsks, ksks, ms_noise_reduction_key);

  BATCH_VEC_FLUSH(&t[29]);
  VEC_XOR(&t[33], &t[32], &t[24]);

  BATCH_VEC_FLUSH(&t[33]);
  VEC_XOR(&t[42], &t[29], &t[33]);

  BATCH_VEC_FLUSH(&t[42]);
  VEC_XOR(&t[34], &t[23], &t[33]);
  VEC_XOR(&t[35], &t[27], &t[33]);

  BATCH_VEC_FLUSH(&t[34], &t[35]);
  CudaRadixCiphertextFFI *and_outs_5[] = {&t[36]};
  CudaRadixCiphertextFFI *and_lhs_5[] = {&t[24]};
  CudaRadixCiphertextFFI *and_rhs_5[] = {&t[35]};
  batch_vec_and(streams, gpu_indexes, gpu_count, and_outs_5, and_lhs_5,
                and_rhs_5, 1, mem, bsks, ksks, ms_noise_reduction_key);

  VEC_XOR(&t[37], &t[36], &t[34]);
  VEC_XOR(&t[38], &t[27], &t[36]);

  BATCH_VEC_FLUSH(&t[38]);
  VEC_XOR(&t[44], &t[33], &t[37]);

  CudaRadixCiphertextFFI *and_outs_6[] = {&t[39]};
  CudaRadixCiphertextFFI *and_lhs_6[] = {&t[38]};
  CudaRadixCiphertextFFI *and_rhs_6[] = {&t[29]};
  batch_vec_and(streams, gpu_indexes, gpu_count, and_outs_6, and_lhs_6,
                and_rhs_6, 1, mem, bsks, ksks, ms_noise_reduction_key);

  VEC_XOR(&t[40], &t[25], &t[39]);

  VEC_XOR(&t[41], &t[40], &t[37]);
  VEC_XOR(&t[43], &t[29], &t[40]);

  BATCH_VEC_FLUSH(&t[41]);
  VEC_XOR(&t[45], &t[42], &t[41]);

  BATCH_VEC_FLUSH(&t[45]);
  CudaRadixCiphertextFFI *and_outs_7[] = {
      &z[0], &z[1],  &z[2],  &z[3],  &z[4],  &z[5],  &z[6],  &z[7],  &z[8],
      &z[9], &z[10], &z[11], &z[12], &z[13], &z[14], &z[15], &z[16], &z[17]};
  CudaRadixCiphertextFFI *and_lhs_7[] = {
      &y[15], &y[6], &t[33], &y[16], &y[1], &t[29], &t[42], &y[17], &y[10],
      &y[12], &y[3], &t[33], &y[13], &y[5], &t[29], &t[42], &t[45], &t[41]};
  CudaRadixCiphertextFFI *and_rhs_7[] = {
      &t[44], &t[37], &x[7], &t[43], &t[40], &y[7], &y[11], &t[45], &t[41],
      &t[44], &t[37], &y[4], &t[43], &t[40], &y[2], &y[9],  &y[14], &y[8]};
  batch_vec_and(streams, gpu_indexes, gpu_count, and_outs_7, and_lhs_7,
                and_rhs_7, 18, mem, bsks, ksks, ms_noise_reduction_key);

  VEC_XOR(&t[46], &z[15], &z[16]);
  VEC_XOR(&t[47], &z[10], &z[11]);
  VEC_XOR(&t[48], &z[5], &z[13]);
  VEC_XOR(&t[49], &z[9], &z[10]);
  VEC_XOR(&t[50], &z[2], &z[12]);
  VEC_XOR(&t[51], &z[2], &z[5]);
  VEC_XOR(&t[52], &z[7], &z[8]);
  VEC_XOR(&t[53], &z[0], &z[3]);
  VEC_XOR(&t[54], &z[6], &z[7]);
  VEC_XOR(&t[55], &z[16], &z[17]);

  VEC_XOR(&t[56], &z[12], &t[48]);
  VEC_XOR(&t[57], &t[50], &t[53]);
  VEC_XOR(&t[58], &z[4], &t[46]);
  VEC_XOR(&t[59], &z[3], &t[54]);

  VEC_XOR(&t[60], &t[46], &t[57]);
  VEC_XOR(&t[61], &z[14], &t[57]);
  VEC_XOR(&t[62], &t[52], &t[58]);
  VEC_XOR(&t[63], &t[49], &t[58]);
  VEC_XOR(&t[64], &z[4], &t[59]);

  BATCH_VEC_FLUSH(&t[61], &t[63], &t[64]);
  VEC_XOR(&t[65], &t[61], &t[62]);

  BATCH_VEC_FLUSH(&t[65]);
  VEC_XOR(&t[66], &z[1], &t[63]);

  BATCH_VEC_FLUSH(&t[66]);

  CudaRadixCiphertextFFI s[8];
  for (int i = 0; i < 8; i++)
    as_radix_ciphertext_slice<Torus>(&s[i], mem->sbox_internal_workspace,
                                     i * num_blocks, (i + 1) * num_blocks);
  CudaRadixCiphertextFFI tmp_bit;
  as_radix_ciphertext_slice<Torus>(&tmp_bit, mem->sbox_internal_workspace,
                                   (8 * num_blocks),
                                   (8 * num_blocks) + num_blocks);

  VEC_XOR(&s[0], &t[59], &t[63]);
  VEC_XOR(&t[67], &t[64], &t[65]);
  VEC_XOR(&s[3], &t[53], &t[66]);
  VEC_XOR(&s[4], &t[51], &t[66]);
  VEC_XOR(&s[5], &t[47], &t[65]);

  copy_radix_ciphertext_async<Torus>(streams[0], gpu_indexes[0], &tmp_bit,
                                     &t[62]);
  vectorized_scalar_add_one_flush<Torus>(streams, gpu_indexes, gpu_count,
                                         &tmp_bit, mem, bsks, ksks,
                                         ms_noise_reduction_key);
  VEC_XOR(&s[6], &t[56], &tmp_bit);

  copy_radix_ciphertext_async<Torus>(streams[0], gpu_indexes[0], &tmp_bit,
                                     &t[60]);
  vectorized_scalar_add_one_flush<Torus>(streams, gpu_indexes, gpu_count,
                                         &tmp_bit, mem, bsks, ksks,
                                         ms_noise_reduction_key);
  VEC_XOR(&s[7], &t[48], &tmp_bit);

  copy_radix_ciphertext_async<Torus>(streams[0], gpu_indexes[0], &tmp_bit,
                                     &s[3]);
  host_integer_radix_add_scalar_one_inplace<Torus>(
      streams, gpu_indexes, gpu_count, &tmp_bit, mem->params.message_modulus,
      mem->params.carry_modulus);
  VEC_XOR(&s[1], &t[64], &tmp_bit);

  copy_radix_ciphertext_async<Torus>(streams[0], gpu_indexes[0], &tmp_bit,
                                     &t[67]);
  vectorized_scalar_add_one_flush<Torus>(streams, gpu_indexes, gpu_count,
                                         &tmp_bit, mem, bsks, ksks,
                                         ms_noise_reduction_key);
  VEC_XOR(&s[2], &t[55], &tmp_bit);

  BATCH_VEC_FLUSH(&s[0], &s[1], &s[2], &s[3], &s[4], &s[5], &s[6], &s[7]);

  for (int i = 0; i < 8; ++i) {
    copy_radix_ciphertext_async<Torus>(streams[0], gpu_indexes[0], &x[i],
                                       &s[i]);
  }

#undef VEC_XOR
#undef BATCH_VEC_FLUSH
}

template <typename Torus>
__host__ void
vectorized_shift_rows(cudaStream_t const *streams, uint32_t const *gpu_indexes,
                      uint32_t gpu_count,
                      CudaRadixCiphertextFFI *state_bitsliced,
                      uint32_t num_blocks, int_aes_encrypt_buffer<Torus> *mem) {

  CudaRadixCiphertextFFI *tmp_full_state_bitsliced =
      mem->sbox_internal_workspace;
  copy_radix_ciphertext_async<Torus>(streams[0], gpu_indexes[0],
                                     tmp_full_state_bitsliced, state_bitsliced);

  CudaRadixCiphertextFFI s_bits[128];
  for (int i = 0; i < 128; i++) {
    as_radix_ciphertext_slice<Torus>(&s_bits[i], state_bitsliced,
                                     i * num_blocks, (i + 1) * num_blocks);
  }

  CudaRadixCiphertextFFI tmp_s_bits_slices[128];
  for (int i = 0; i < 128; i++) {
    as_radix_ciphertext_slice<Torus>(&tmp_s_bits_slices[i],
                                     tmp_full_state_bitsliced, i * num_blocks,
                                     (i + 1) * num_blocks);
  }

  const int shift_rows_map[] = {0, 5,  10, 15, 4,  9, 14, 3,
                                8, 13, 2,  7,  12, 1, 6,  11};

  for (int i = 0; i < 16; i++) {
    for (int bit = 0; bit < 8; bit++) {
      CudaRadixCiphertextFFI *dest_slice = &s_bits[i * 8 + bit];
      CudaRadixCiphertextFFI *src_slice =
          &tmp_s_bits_slices[shift_rows_map[i] * 8 + bit];
      copy_radix_ciphertext_async<Torus>(streams[0], gpu_indexes[0], dest_slice,
                                         src_slice);
    }
  }
}

template <typename Torus>
__host__ void vectorized_mul_by_2(
    cudaStream_t const *streams, uint32_t const *gpu_indexes,
    uint32_t gpu_count, CudaRadixCiphertextFFI *res_byte,
    CudaRadixCiphertextFFI *in_byte, int_aes_encrypt_buffer<Torus> *mem,
    void *const *bsks, Torus *const *ksks,
    CudaModulusSwitchNoiseReductionKeyFFI const *ms_noise_reduction_key) {

  CudaRadixCiphertextFFI *msb = &in_byte[0];

  for (int i = 0; i < 7; ++i) {
    copy_radix_ciphertext_async<Torus>(streams[0], gpu_indexes[0], &res_byte[i],
                                       &in_byte[i + 1]);
  }

  set_zero_radix_ciphertext_slice_async<Torus>(streams[0], gpu_indexes[0],
                                               &res_byte[7], 0,
                                               res_byte[7].num_radix_blocks);

  const int indices_to_xor[] = {3, 4, 6, 7};
  for (int index : indices_to_xor) {
    vectorized_aes_xor<Torus>(streams, gpu_indexes, gpu_count, mem,
                              &res_byte[index], &res_byte[index], msb);
  }
}

template <typename Torus>
__host__ void vectorized_mix_columns(
    cudaStream_t const *streams, uint32_t const *gpu_indexes,
    uint32_t gpu_count, CudaRadixCiphertextFFI *s_bits, uint32_t num_blocks,
    int_aes_encrypt_buffer<Torus> *mem, void *const *bsks, Torus *const *ksks,
    CudaModulusSwitchNoiseReductionKeyFFI const *ms_noise_reduction_key) {

  for (int col = 0; col < 4; ++col) {
    CudaRadixCiphertextFFI *col_copy_buffer = mem->mix_columns_col_copy_buffer;
    for (int i = 0; i < 32; ++i) {
      CudaRadixCiphertextFFI dest_slice, src_slice;
      as_radix_ciphertext_slice<Torus>(&dest_slice, col_copy_buffer,
                                       i * num_blocks, (i + 1) * num_blocks);
      as_radix_ciphertext_slice<Torus>(&src_slice, s_bits,
                                       (col * 32 + i) * num_blocks,
                                       (col * 32 + i + 1) * num_blocks);
      copy_radix_ciphertext_async<Torus>(streams[0], gpu_indexes[0],
                                         &dest_slice, &src_slice);
    }

    CudaRadixCiphertextFFI b_orig[4][8];
    for (int i = 0; i < 4; ++i) {
      for (int j = 0; j < 8; j++) {
        as_radix_ciphertext_slice<Torus>(&b_orig[i][j], col_copy_buffer,
                                         (i * 8 + j) * num_blocks,
                                         (i * 8 + j + 1) * num_blocks);
      }
    }

    CudaRadixCiphertextFFI *mul_workspace =
        mem->mix_columns_mul_workspace_buffer;
    CudaRadixCiphertextFFI b_mul2[4][8];
    CudaRadixCiphertextFFI b_mul2_tmp_buffers[4];
    for (int i = 0; i < 4; i++) {
      as_radix_ciphertext_slice<Torus>(&b_mul2_tmp_buffers[i], mul_workspace,
                                       (i * 8) * num_blocks,
                                       (i * 8 + 8) * num_blocks);
      for (int j = 0; j < 8; j++) {
        as_radix_ciphertext_slice<Torus>(&b_mul2[i][j], &b_mul2_tmp_buffers[i],
                                         j * num_blocks, (j + 1) * num_blocks);
      }
    }

    for (int i = 0; i < 4; ++i) {
      vectorized_mul_by_2<Torus>(streams, gpu_indexes, gpu_count, b_mul2[i],
                                 b_orig[i], mem, bsks, ksks,
                                 ms_noise_reduction_key);
    }
    vectorized_aes_flush<Torus>(streams, gpu_indexes, gpu_count, mul_workspace,
                                mem, bsks, ksks, ms_noise_reduction_key);

    CudaRadixCiphertextFFI b0_mul2_copy_buffer;
    as_radix_ciphertext_slice<Torus>(&b0_mul2_copy_buffer, mul_workspace,
                                     (4 * 8) * num_blocks,
                                     (4 * 8 + 8) * num_blocks);
    CudaRadixCiphertextFFI b0_mul2_copy[8];
    for (int j = 0; j < 8; j++) {
      as_radix_ciphertext_slice<Torus>(&b0_mul2_copy[j], &b0_mul2_copy_buffer,
                                       j * num_blocks, (j + 1) * num_blocks);
      copy_radix_ciphertext_async<Torus>(streams[0], gpu_indexes[0],
                                         &b0_mul2_copy[j], &b_mul2[0][j]);
    }

    for (int bit = 0; bit < 8; bit++) {
      CudaRadixCiphertextFFI *dest_bit_0 = &s_bits[(col * 4 + 0) * 8 + bit];
      CudaRadixCiphertextFFI *dest_bit_1 = &s_bits[(col * 4 + 1) * 8 + bit];
      CudaRadixCiphertextFFI *dest_bit_2 = &s_bits[(col * 4 + 2) * 8 + bit];
      CudaRadixCiphertextFFI *dest_bit_3 = &s_bits[(col * 4 + 3) * 8 + bit];

#define VEC_XOR_INPLACE(DEST, SRC)                                             \
  vectorized_aes_xor<Torus>(streams, gpu_indexes, gpu_count, mem, DEST, DEST,  \
                            SRC)

      copy_radix_ciphertext_async<Torus>(streams[0], gpu_indexes[0], dest_bit_0,
                                         &b_mul2[0][bit]);
      VEC_XOR_INPLACE(dest_bit_0, &b_mul2[1][bit]);
      VEC_XOR_INPLACE(dest_bit_0, &b_orig[1][bit]);
      VEC_XOR_INPLACE(dest_bit_0, &b_orig[2][bit]);
      VEC_XOR_INPLACE(dest_bit_0, &b_orig[3][bit]);

      copy_radix_ciphertext_async<Torus>(streams[0], gpu_indexes[0], dest_bit_1,
                                         &b_orig[0][bit]);
      VEC_XOR_INPLACE(dest_bit_1, &b_mul2[1][bit]);
      VEC_XOR_INPLACE(dest_bit_1, &b_mul2[2][bit]);
      VEC_XOR_INPLACE(dest_bit_1, &b_orig[2][bit]);
      VEC_XOR_INPLACE(dest_bit_1, &b_orig[3][bit]);

      copy_radix_ciphertext_async<Torus>(streams[0], gpu_indexes[0], dest_bit_2,
                                         &b_orig[0][bit]);
      VEC_XOR_INPLACE(dest_bit_2, &b_orig[1][bit]);
      VEC_XOR_INPLACE(dest_bit_2, &b_mul2[2][bit]);
      VEC_XOR_INPLACE(dest_bit_2, &b_orig[3][bit]);
      VEC_XOR_INPLACE(dest_bit_2, &b_mul2[3][bit]);

      copy_radix_ciphertext_async<Torus>(streams[0], gpu_indexes[0], dest_bit_3,
                                         &b0_mul2_copy[bit]);
      VEC_XOR_INPLACE(dest_bit_3, &b_orig[0][bit]);
      VEC_XOR_INPLACE(dest_bit_3, &b_orig[1][bit]);
      VEC_XOR_INPLACE(dest_bit_3, &b_orig[2][bit]);
      VEC_XOR_INPLACE(dest_bit_3, &b_mul2[3][bit]);
#undef VEC_XOR_INPLACE
    }
  }
}

template <typename Torus>
__host__ void vectorized_aes_encrypt_inplace(
    cudaStream_t const *streams, uint32_t const *gpu_indexes,
    uint32_t gpu_count, CudaRadixCiphertextFFI *all_states_bitsliced,
    CudaRadixCiphertextFFI const *round_keys, uint32_t num_blocks,
    int_aes_encrypt_buffer<Torus> *mem, void *const *bsks, Torus *const *ksks,
    CudaModulusSwitchNoiseReductionKeyFFI const *ms_noise_reduction_key) {

  CudaRadixCiphertextFFI *jit_transposed_key =
      mem->initial_states_and_jit_key_workspace;

  CudaRadixCiphertextFFI round_0_key_slice;
  as_radix_ciphertext_slice<Torus>(
      &round_0_key_slice, (CudaRadixCiphertextFFI *)round_keys, 0, 128);
  for (uint32_t block = 0; block < num_blocks; ++block) {
    CudaRadixCiphertextFFI tile_slice;
    as_radix_ciphertext_slice<Torus>(&tile_slice, mem->tmp_tiled_key_buffer,
                                     block * 128, (block + 1) * 128);
    copy_radix_ciphertext_async<Torus>(streams[0], gpu_indexes[0], &tile_slice,
                                       &round_0_key_slice);
  }
  transpose_blocks_to_bitsliced<Torus>(
      streams[0], gpu_indexes[0], jit_transposed_key, mem->tmp_tiled_key_buffer,
      num_blocks, 128);

  vectorized_aes_xor<Torus>(streams, gpu_indexes, gpu_count, mem,
                            all_states_bitsliced, all_states_bitsliced,
                            jit_transposed_key);

  vectorized_aes_flush<Torus>(streams, gpu_indexes, gpu_count,
                              all_states_bitsliced, mem, bsks, ksks,
                              ms_noise_reduction_key);

  for (int round = 1; round <= 10; ++round) {
    CudaRadixCiphertextFFI s_bits[128];
    for (int i = 0; i < 128; i++) {
      as_radix_ciphertext_slice<Torus>(&s_bits[i], all_states_bitsliced,
                                       i * num_blocks, (i + 1) * num_blocks);
    }

    for (int i = 0; i < 16; ++i) {
      vectorized_sbox_byte<Torus>(streams, gpu_indexes, gpu_count,
                                  &s_bits[i * 8], num_blocks, mem, bsks, ksks,
                                  ms_noise_reduction_key);
    }

    vectorized_shift_rows<Torus>(streams, gpu_indexes, gpu_count,
                                 all_states_bitsliced, num_blocks, mem);

    if (round != 10) {
      vectorized_mix_columns<Torus>(streams, gpu_indexes, gpu_count, s_bits,
                                    num_blocks, mem, bsks, ksks,
                                    ms_noise_reduction_key);
      vectorized_aes_flush<Torus>(streams, gpu_indexes, gpu_count,
                                  all_states_bitsliced, mem, bsks, ksks,
                                  ms_noise_reduction_key);
    }

    CudaRadixCiphertextFFI round_key_slice;
    as_radix_ciphertext_slice<Torus>(&round_key_slice,
                                     (CudaRadixCiphertextFFI *)round_keys,
                                     round * 128, (round + 1) * 128);
    for (uint32_t block = 0; block < num_blocks; ++block) {
      CudaRadixCiphertextFFI tile_slice;
      as_radix_ciphertext_slice<Torus>(&tile_slice, mem->tmp_tiled_key_buffer,
                                       block * 128, (block + 1) * 128);
      copy_radix_ciphertext_async<Torus>(streams[0], gpu_indexes[0],
                                         &tile_slice, &round_key_slice);
    }
    transpose_blocks_to_bitsliced<Torus>(
        streams[0], gpu_indexes[0], jit_transposed_key,
        mem->tmp_tiled_key_buffer, num_blocks, 128);

    vectorized_aes_xor<Torus>(streams, gpu_indexes, gpu_count, mem,
                              all_states_bitsliced, all_states_bitsliced,
                              jit_transposed_key);

    vectorized_aes_flush<Torus>(streams, gpu_indexes, gpu_count,
                                all_states_bitsliced, mem, bsks, ksks,
                                ms_noise_reduction_key);
  }
}

template <typename Torus>
__host__ void vectorized_aes_full_adder_inplace(
    cudaStream_t const *streams, uint32_t const *gpu_indexes,
    uint32_t gpu_count, CudaRadixCiphertextFFI *transposed_states,
    const Torus *counter_bits_le_all_blocks, uint32_t num_blocks,
    int_aes_encrypt_buffer<Torus> *mem, void *const *bsks, Torus *const *ksks,
    CudaModulusSwitchNoiseReductionKeyFFI const *ms_noise_reduction_key) {

  CudaRadixCiphertextFFI *carry_vec = mem->vec_tmp_carry_buffer;
  CudaRadixCiphertextFFI *trivial_b_bits_vec = mem->vec_trivial_b_bits_buffer;
  CudaRadixCiphertextFFI *sum_plus_carry_vec = mem->vec_tmp_sum_buffer;

  set_zero_radix_ciphertext_slice_async<Torus>(streams[0], gpu_indexes[0],
                                               carry_vec, 0, num_blocks);

  for (int i = 0; i < 128; ++i) {
    int state_bit_index = 127 - i;

    CudaRadixCiphertextFFI a_i_vec;
    as_radix_ciphertext_slice<Torus>(&a_i_vec, transposed_states,
                                     state_bit_index * num_blocks,
                                     (state_bit_index + 1) * num_blocks);

    for (uint32_t block = 0; block < num_blocks; ++block) {
      mem->h_counter_bits_buffer[block] =
          counter_bits_le_all_blocks[block * 128 + i];
    }
    cuda_memcpy_async_to_gpu(
        mem->d_counter_bits_buffer, mem->h_counter_bits_buffer,
        num_blocks * sizeof(Torus), streams[0], gpu_indexes[0]);
    set_trivial_radix_ciphertext_async<Torus>(
        streams[0], gpu_indexes[0], trivial_b_bits_vec,
        mem->d_counter_bits_buffer, mem->h_counter_bits_buffer, num_blocks,
        mem->params.message_modulus, mem->params.carry_modulus);

    CudaRadixCiphertextFFI tmp_sum_vec;
    as_radix_ciphertext_slice<Torus>(&tmp_sum_vec, mem->vec_tmp_bit_buffer, 0,
                                     num_blocks);

    vectorized_aes_xor<Torus>(streams, gpu_indexes, gpu_count, mem,
                              &tmp_sum_vec, &a_i_vec, trivial_b_bits_vec);

    vectorized_aes_xor<Torus>(streams, gpu_indexes, gpu_count, mem,
                              sum_plus_carry_vec, &tmp_sum_vec, carry_vec);

    integer_radix_apply_univariate_lookup_table_kb<Torus>(
        streams, gpu_indexes, gpu_count, carry_vec, sum_plus_carry_vec, bsks,
        ksks, ms_noise_reduction_key, mem->carry_lut, num_blocks);

    integer_radix_apply_univariate_lookup_table_kb<Torus>(
        streams, gpu_indexes, gpu_count, &a_i_vec, sum_plus_carry_vec, bsks,
        ksks, ms_noise_reduction_key, mem->flush_lut, num_blocks);
  }
}

template <typename Torus>
__host__ void host_integer_aes_ctr_encrypt(
    cudaStream_t const *streams, uint32_t const *gpu_indexes,
    uint32_t gpu_count, CudaRadixCiphertextFFI *output,
    CudaRadixCiphertextFFI const *iv, CudaRadixCiphertextFFI const *round_keys,
    const Torus *counter_bits_le_all_blocks, uint32_t num_blocks,
    int_aes_encrypt_buffer<Torus> *mem, void *const *bsks, Torus *const *ksks,
    CudaModulusSwitchNoiseReductionKeyFFI const *ms_noise_reduction_key) {

  const uint32_t block_size = 128;
  CudaRadixCiphertextFFI *initial_states =
      mem->initial_states_and_jit_key_workspace;

  for (uint32_t block = 0; block < num_blocks; ++block) {
    CudaRadixCiphertextFFI output_slice;
    as_radix_ciphertext_slice<Torus>(&output_slice, initial_states,
                                     block * block_size,
                                     (block + 1) * block_size);
    copy_radix_ciphertext_async<Torus>(streams[0], gpu_indexes[0],
                                       &output_slice, iv);
  }

  CudaRadixCiphertextFFI *transposed_states = mem->main_bitsliced_states_buffer;
  transpose_blocks_to_bitsliced<Torus>(streams[0], gpu_indexes[0],
                                       transposed_states, initial_states,
                                       num_blocks, block_size);

  vectorized_aes_full_adder_inplace<Torus>(
      streams, gpu_indexes, gpu_count, transposed_states,
      counter_bits_le_all_blocks, num_blocks, mem, bsks, ksks,
      ms_noise_reduction_key);

  vectorized_aes_encrypt_inplace<Torus>(
      streams, gpu_indexes, gpu_count, transposed_states, round_keys,
      num_blocks, mem, bsks, ksks, ms_noise_reduction_key);

  transpose_bitsliced_to_blocks<Torus>(streams[0], gpu_indexes[0], output,
                                       transposed_states, num_blocks,
                                       block_size);
}

#endif