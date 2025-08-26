#ifndef AES_CUH
#define AES_CUH

#include "integer.cuh"
#include "integer/integer_utilities.h"
#include "radix_ciphertext.cuh"

template <typename Torus>
uint64_t scratch_cuda_integer_aes_encrypt(
    cudaStream_t const *streams, uint32_t const *gpu_indexes,
    uint32_t gpu_count, int_aes_encrypt_buffer<Torus> **mem_ptr,
    int_radix_params params, bool allocate_gpu_memory) {
  uint64_t size_tracker = 0;

  *mem_ptr =
      new int_aes_encrypt_buffer<Torus>(streams, gpu_indexes, gpu_count, params,
                                        allocate_gpu_memory, size_tracker);

  return size_tracker;
}

template <typename Torus>
__host__ void fhe_add_round_key(cudaStream_t const *streams,
                                uint32_t const *gpu_indexes, uint32_t gpu_count,
                                CudaRadixCiphertextFFI *lhs,
                                const CudaRadixCiphertextFFI *rhs,
                                int_aes_encrypt_buffer<Torus> *mem_ptr) {

  host_addition<Torus>(streams[0], gpu_indexes[0], lhs, lhs, rhs,
                       lhs->num_radix_blocks, mem_ptr->params.message_modulus,
                       mem_ptr->params.carry_modulus);
}

// Bitwise AND via a single shared bivariate LUT.
//
template <typename Torus>
__host__ void
fhe_and(cudaStream_t const *streams, uint32_t const *gpu_indexes,
        uint32_t gpu_count, CudaRadixCiphertextFFI *out,
        const CudaRadixCiphertextFFI *lhs, const CudaRadixCiphertextFFI *rhs,
        int_aes_encrypt_buffer<Torus> *mem_ptr, void *const *bsks,
        Torus *const *ksks,
        CudaModulusSwitchNoiseReductionKeyFFI const *ms_noise_reduction_key) {

  if (lhs->num_radix_blocks < out->num_radix_blocks) {
    PANIC("We should have lhs->num_radix_blocks >= out->num_radix_blocks");
  }
  if (rhs->num_radix_blocks < out->num_radix_blocks) {
    PANIC("We should have rhs->num_radix_blocks >= out->num_radix_blocks");
  }

  integer_radix_apply_bivariate_lookup_table_kb<Torus>(
      streams, gpu_indexes, gpu_count, out, lhs, rhs, bsks, ksks,
      ms_noise_reduction_key, mem_ptr->and_lut, out->num_radix_blocks,
      mem_ptr->params.message_modulus);
}

// Univariate LUT: x -> (x & 1).
// Use to clamp values to [0,1].
//
template <typename Torus>
__host__ void
fhe_flush(cudaStream_t const *streams, uint32_t const *gpu_indexes,
          uint32_t gpu_count, CudaRadixCiphertextFFI *data,
          int_aes_encrypt_buffer<Torus> *mem_ptr, void *const *bsks,
          Torus *const *ksks,
          CudaModulusSwitchNoiseReductionKeyFFI const *ms_noise_reduction_key) {

  integer_radix_apply_univariate_lookup_table_kb<Torus>(
      streams, gpu_indexes, gpu_count, data, data, bsks, ksks,
      ms_noise_reduction_key, mem_ptr->flush_lut, data->num_radix_blocks);
}

template <typename Torus>
__host__ void
fhe_sbox(cudaStream_t const *streams, uint32_t const *gpu_indexes,
         uint32_t gpu_count, CudaRadixCiphertextFFI *x,
         int_aes_encrypt_buffer<Torus> *mem_ptr, void *const *bsks,
         Torus *const *ksks,
         CudaModulusSwitchNoiseReductionKeyFFI const *ms_noise_reduction_key) {

  CudaRadixCiphertextFFI x_bits[8];
  for (int i = 0; i < 8; ++i) {
    as_radix_ciphertext_slice<Torus>(&x_bits[i], x, i, i + 1);
  }

  CudaRadixCiphertextFFI y[22], t[68], z[18], s[8];
  for (int i = 0; i < 22; ++i)
    as_radix_ciphertext_slice<Torus>(&y[i], mem_ptr->sbox_vars, i, i + 1);
  for (int i = 0; i < 68; ++i)
    as_radix_ciphertext_slice<Torus>(&t[i], mem_ptr->sbox_vars, 22 + i, 23 + i);
  for (int i = 0; i < 18; ++i)
    as_radix_ciphertext_slice<Torus>(&z[i], mem_ptr->sbox_vars, 22 + 68 + i,
                                     23 + 68 + i);
  for (int i = 0; i < 8; ++i)
    as_radix_ciphertext_slice<Torus>(&s[i], mem_ptr->tmp_byte_2, i, i + 1);

  auto xor_and_flush_op = [&](CudaRadixCiphertextFFI *out,
                              const CudaRadixCiphertextFFI *a,
                              const CudaRadixCiphertextFFI *b) {
    copy_radix_ciphertext_async<Torus>(streams[0], gpu_indexes[0], out, a);
    fhe_add_round_key(streams, gpu_indexes, gpu_count, out, b, mem_ptr);
    fhe_flush(streams, gpu_indexes, gpu_count, out, mem_ptr, bsks, ksks,
              ms_noise_reduction_key);
  };

  auto xor_op = [&](CudaRadixCiphertextFFI *out,
                    const CudaRadixCiphertextFFI *a,
                    const CudaRadixCiphertextFFI *b) {
    copy_radix_ciphertext_async<Torus>(streams[0], gpu_indexes[0], out, a);
    fhe_add_round_key(streams, gpu_indexes, gpu_count, out, b, mem_ptr);
  };

#define XOR_FLUSH(out, a, b) xor_and_flush_op(out, a, b)
#define XOR(out, a, b) xor_op(out, a, b)
#define AND(out, a, b)                                                         \
  fhe_and(streams, gpu_indexes, gpu_count, out, a, b, mem_ptr, bsks, ksks,     \
          ms_noise_reduction_key)

  XOR_FLUSH(&y[14], &x_bits[3], &x_bits[5]);
  XOR_FLUSH(&y[13], &x_bits[0], &x_bits[6]);
  XOR_FLUSH(&y[9], &x_bits[0], &x_bits[3]);
  XOR_FLUSH(&y[8], &x_bits[0], &x_bits[5]);
  XOR(&t[0], &x_bits[1], &x_bits[2]);
  XOR_FLUSH(&y[1], &t[0], &x_bits[7]);
  XOR_FLUSH(&y[4], &y[1], &x_bits[3]);
  XOR_FLUSH(&y[12], &y[13], &y[14]);
  XOR_FLUSH(&y[2], &y[1], &x_bits[0]);
  XOR_FLUSH(&y[5], &y[1], &x_bits[6]);
  XOR_FLUSH(&y[3], &y[5], &y[8]);
  XOR(&t[1], &x_bits[4], &y[12]);
  XOR_FLUSH(&y[15], &t[1], &x_bits[5]);
  XOR_FLUSH(&y[20], &t[1], &x_bits[1]);
  XOR_FLUSH(&y[6], &y[15], &x_bits[7]);
  XOR_FLUSH(&y[10], &y[15], &t[0]);
  XOR(&y[11], &y[20], &y[9]);
  XOR_FLUSH(&y[7], &x_bits[7], &y[11]);
  XOR_FLUSH(&y[17], &y[10], &y[11]);
  XOR_FLUSH(&y[19], &y[10], &y[8]);
  XOR_FLUSH(&y[16], &t[0], &y[11]);
  XOR_FLUSH(&y[21], &y[13], &y[16]);
  XOR_FLUSH(&y[18], &x_bits[0], &y[16]);

  AND(&t[2], &y[15], &y[12]);
  AND(&t[3], &y[3], &y[6]);
  XOR(&t[4], &t[3], &t[2]);
  AND(&t[5], &x_bits[7], &y[4]);
  XOR(&t[6], &t[5], &t[2]);
  AND(&t[7], &y[13], &y[16]);
  AND(&t[8], &y[1], &y[5]);
  XOR(&t[9], &t[8], &t[7]);
  AND(&t[10], &y[2], &y[7]);
  XOR(&t[11], &t[10], &t[7]);
  AND(&t[12], &y[9], &y[11]);
  AND(&t[13], &y[14], &y[17]);
  XOR(&t[14], &t[13], &t[12]);
  AND(&t[15], &y[8], &y[10]);
  XOR(&t[16], &t[15], &t[12]);
  XOR(&t[17], &t[4], &t[14]);
  XOR(&t[18], &t[6], &t[16]);
  XOR(&t[19], &t[9], &t[14]);
  XOR(&t[20], &t[11], &t[16]);
  XOR_FLUSH(&t[21], &t[17], &y[20]);
  XOR(&t[22], &t[18], &y[19]);
  XOR_FLUSH(&t[23], &t[19], &y[21]);
  XOR_FLUSH(&t[24], &t[20], &y[18]);
  XOR_FLUSH(&t[25], &t[21], &t[22]);
  AND(&t[26], &t[21], &t[23]);
  XOR_FLUSH(&t[27], &t[24], &t[26]);
  AND(&t[28], &t[25], &t[27]);
  XOR_FLUSH(&t[29], &t[28], &t[22]);
  XOR_FLUSH(&t[30], &t[23], &t[24]);
  XOR_FLUSH(&t[31], &t[22], &t[26]);
  AND(&t[32], &t[30], &t[31]);
  XOR_FLUSH(&t[33], &t[32], &t[24]);
  XOR_FLUSH(&t[34], &t[23], &t[33]);
  XOR_FLUSH(&t[35], &t[27], &t[33]);
  AND(&t[36], &t[24], &t[35]);
  XOR(&t[37], &t[36], &t[34]);
  XOR_FLUSH(&t[38], &t[27], &t[36]);
  AND(&t[39], &t[38], &t[29]);
  XOR(&t[40], &t[25], &t[39]);
  XOR_FLUSH(&t[41], &t[40], &t[37]);
  XOR_FLUSH(&t[42], &t[29], &t[33]);
  XOR(&t[43], &t[29], &t[40]);
  XOR(&t[44], &t[33], &t[37]);
  XOR_FLUSH(&t[45], &t[42], &t[41]);

  AND(&z[0], &y[15], &t[44]);
  AND(&z[1], &y[6], &t[37]);
  AND(&z[2], &t[33], &x_bits[7]);
  AND(&z[3], &y[16], &t[43]);
  AND(&z[4], &y[1], &t[40]);
  AND(&z[5], &t[29], &y[7]);
  AND(&z[6], &t[42], &y[11]);
  AND(&z[7], &y[17], &t[45]);
  AND(&z[8], &y[10], &t[41]);
  AND(&z[9], &y[12], &t[44]);
  AND(&z[10], &y[3], &t[37]);
  AND(&z[11], &t[33], &y[4]);
  AND(&z[12], &y[13], &t[43]);
  AND(&z[13], &y[5], &t[40]);
  AND(&z[14], &t[29], &y[2]);
  AND(&z[15], &t[42], &y[9]);
  AND(&z[16], &t[45], &y[14]);
  AND(&z[17], &t[41], &y[8]);

  XOR(&t[46], &z[15], &z[16]);
  XOR(&t[47], &z[10], &z[11]);
  XOR(&t[48], &z[5], &z[13]);
  XOR(&t[49], &z[9], &z[10]);
  XOR(&t[50], &z[2], &z[12]);
  XOR(&t[51], &z[2], &z[5]);
  XOR(&t[52], &z[7], &z[8]);
  XOR(&t[53], &z[0], &z[3]);
  XOR(&t[54], &z[6], &z[7]);
  XOR(&t[55], &z[16], &z[17]);
  XOR(&t[56], &z[12], &t[48]);
  XOR(&t[57], &t[50], &t[53]);
  XOR(&t[58], &z[4], &t[46]);
  XOR(&t[59], &z[3], &t[54]);
  XOR(&t[60], &t[46], &t[57]);
  XOR_FLUSH(&t[61], &z[14], &t[57]);
  XOR(&t[62], &t[52], &t[58]);
  XOR_FLUSH(&t[63], &t[49], &t[58]);
  XOR_FLUSH(&t[64], &z[4], &t[59]);
  XOR_FLUSH(&t[65], &t[61], &t[62]);
  XOR_FLUSH(&t[66], &z[1], &t[63]);

  XOR(&s[0], &t[59], &t[63]);
  XOR(&t[67], &t[64], &t[65]);
  XOR(&s[3], &t[53], &t[66]);
  XOR(&s[4], &t[51], &t[66]);
  XOR(&s[5], &t[47], &t[65]);

  CudaRadixCiphertextFFI tmp_bit;
  as_radix_ciphertext_slice<Torus>(&tmp_bit, mem_ptr->tmp_byte_1, 0, 1);

  XOR_FLUSH(&tmp_bit, &t[62], mem_ptr->trivial_1_bit);
  XOR(&s[6], &t[56], &tmp_bit);

  XOR_FLUSH(&tmp_bit, &t[60], mem_ptr->trivial_1_bit);
  XOR(&s[7], &t[48], &tmp_bit);

  XOR_FLUSH(&tmp_bit, &s[3], mem_ptr->trivial_1_bit);
  XOR(&s[1], &t[64], &tmp_bit);

  XOR_FLUSH(&tmp_bit, &t[67], mem_ptr->trivial_1_bit);
  XOR(&s[2], &t[55], &tmp_bit);

  for (int i = 0; i < 8; ++i) {
    copy_radix_ciphertext_slice_async<Torus>(streams[0], gpu_indexes[0], x, i,
                                             i + 1, &s[i], 0, 1);
  }

#undef XOR_FLUSH
#undef XOR
#undef AND
}

template <typename Torus>
__host__ void fhe_shift_rows(cudaStream_t stream, uint32_t gpu_index,
                             CudaRadixCiphertextFFI *state,
                             int_aes_encrypt_buffer<Torus> *mem_ptr) {
  copy_radix_ciphertext_async<Torus>(stream, gpu_index, mem_ptr->tmp_full_state,
                                     state);

  const uint32_t bits_in_byte = 8;

  // Row 1: rotate LEFT by 1  (indices 1,5,9,13)
  {
    const int row1_map[] = {1, 5, 9, 13};
    for (int i = 0; i < 4; ++i) {
      const int dst_idx = row1_map[i];
      const int src_idx = row1_map[(i + 1) % 4];
      copy_radix_ciphertext_slice_async<Torus>(
          stream, gpu_index, state, dst_idx * bits_in_byte,
          (dst_idx + 1) * bits_in_byte, mem_ptr->tmp_full_state,
          src_idx * bits_in_byte, (src_idx + 1) * bits_in_byte);
    }
  }

  // Row 2: rotate LEFT by 2  (indices 2,6,10,14)
  {
    const int row2_map[] = {2, 6, 10, 14};
    for (int i = 0; i < 4; ++i) {
      const int dst_idx = row2_map[i];
      const int src_idx = row2_map[(i + 2) % 4];
      copy_radix_ciphertext_slice_async<Torus>(
          stream, gpu_index, state, dst_idx * bits_in_byte,
          (dst_idx + 1) * bits_in_byte, mem_ptr->tmp_full_state,
          src_idx * bits_in_byte, (src_idx + 1) * bits_in_byte);
    }
  }

  // Row 3: rotate LEFT by 3  (indices 3,7,11,15)
  {
    const int row3_map[] = {3, 7, 11, 15};
    for (int i = 0; i < 4; ++i) {
      const int dst_idx = row3_map[i];
      const int src_idx = row3_map[(i + 3) % 4];
      copy_radix_ciphertext_slice_async<Torus>(
          stream, gpu_index, state, dst_idx * bits_in_byte,
          (dst_idx + 1) * bits_in_byte, mem_ptr->tmp_full_state,
          src_idx * bits_in_byte, (src_idx + 1) * bits_in_byte);
    }
  }
}

/* Multiply "in" by 2:
 * - Left shift: r[i] = b[i+1]; r[7] = b[0] (mask = old MSB).
 * - Branchless reduction:
 *   if old MSB == 1, XOR with 0x1B,
 *   r[3] ^= b[0]; r[4] ^= b[0]; r[6] ^= b[0].
 */
template <typename Torus>
__host__ void mul_by_2(cudaStream_t const *streams, uint32_t const *gpu_indexes,
                       uint32_t gpu_count, CudaRadixCiphertextFFI *res,
                       const CudaRadixCiphertextFFI *in,
                       int_aes_encrypt_buffer<Torus> *mem_ptr) {

  CudaRadixCiphertextFFI b[8];
  for (int i = 0; i < 8; ++i) {
    as_radix_ciphertext_slice<Torus>(&b[i], in, i, i + 1);
  }

  CudaRadixCiphertextFFI r[8];
  for (int i = 0; i < 8; ++i) {
    as_radix_ciphertext_slice<Torus>(&r[i], res, i, i + 1);
  }

  for (int i = 0; i < 8; ++i) {
    copy_radix_ciphertext_async<Torus>(streams[0], gpu_indexes[0], &r[i],
                                       &b[(i + 1) % 8]);
  }

  const int indices_to_add[] = {3, 4, 6};

  for (int index : indices_to_add) {
    fhe_add_round_key(streams, gpu_indexes, gpu_count, &r[index], &b[0],
                      mem_ptr);
  }
}

/* MixColumns on one 4-byte column:
 * Let input bytes be b0,b1,b2,b3,
 * We compute:
 *   out0 = 2*b0 ^ 3*b1 ^ 1*b2 ^ 1*b3
 *   out1 = 1*b0 ^ 2*b1 ^ 3*b2 ^ 1*b3
 *   out2 = 1*b0 ^ 1*b1 ^ 2*b2 ^ 3*b3
 *   out3 = 3*b0 ^ 1*b1 ^ 1*b2 ^ 2*b3
 */
template <typename Torus>
__host__ void mix_columns(
    cudaStream_t const *streams, uint32_t const *gpu_indexes,
    uint32_t gpu_count, CudaRadixCiphertextFFI *col,
    int_aes_encrypt_buffer<Torus> *mem_ptr, void *const *bsks,
    Torus *const *ksks,
    CudaModulusSwitchNoiseReductionKeyFFI const *ms_noise_reduction_key) {

  CudaRadixCiphertextFFI b_orig[4];
  for (int i = 0; i < 4; ++i) {
    as_radix_ciphertext_slice<Torus>(&b_orig[i], mem_ptr->tmp_full_state, i * 8,
                                     (i + 1) * 8);
    copy_radix_ciphertext_slice_async<Torus>(
        streams[0], gpu_indexes[0], &b_orig[i], 0, 8, col, i * 8, (i + 1) * 8);
  }

  CudaRadixCiphertextFFI b_mul2[4];
  for (int i = 0; i < 4; ++i) {
    as_radix_ciphertext_slice<Torus>(&b_mul2[i], mem_ptr->tmp_full_state,
                                     (4 + i) * 8, (5 + i) * 8);
    mul_by_2(streams, gpu_indexes, gpu_count, &b_mul2[i], &b_orig[i], mem_ptr);
  }

  CudaRadixCiphertextFFI b0_copy;
  as_radix_ciphertext_slice<Torus>(&b0_copy, mem_ptr->tmp_full_state, (8) * 8,
                                   (9) * 8);
  copy_radix_ciphertext_async<Torus>(streams[0], gpu_indexes[0], &b0_copy,
                                     &b_mul2[0]);

  CudaRadixCiphertextFFI r[4];
  for (int i = 0; i < 4; ++i)
    as_radix_ciphertext_slice<Torus>(&r[i], col, i * 8, (i + 1) * 8);

#define XOR(A, B)                                                              \
  fhe_add_round_key(streams, gpu_indexes, gpu_count, A, B, mem_ptr)
  copy_radix_ciphertext_async<Torus>(streams[0], gpu_indexes[0], &r[0],
                                     &b_mul2[0]);
  XOR(&r[0], &b_mul2[1]);
  XOR(&r[0], &b_orig[1]);
  XOR(&r[0], &b_orig[2]);
  XOR(&r[0], &b_orig[3]);

  copy_radix_ciphertext_async<Torus>(streams[0], gpu_indexes[0], &r[1],
                                     &b_orig[0]);
  XOR(&r[1], &b_mul2[1]);
  XOR(&r[1], &b_mul2[2]);
  XOR(&r[1], &b_orig[2]);
  XOR(&r[1], &b_orig[3]);

  copy_radix_ciphertext_async<Torus>(streams[0], gpu_indexes[0], &r[2],
                                     &b_orig[0]);
  XOR(&r[2], &b_orig[1]);
  XOR(&r[2], &b_mul2[2]);
  XOR(&r[2], &b_orig[3]);
  XOR(&r[2], &b_mul2[3]);

  copy_radix_ciphertext_async<Torus>(streams[0], gpu_indexes[0], &r[3],
                                     &b0_copy);
  XOR(&r[3], &b_orig[0]);
  XOR(&r[3], &b_orig[1]);
  XOR(&r[3], &b_orig[2]);
  XOR(&r[3], &b_mul2[3]);
#undef XOR
}

/* AES-128 encryption on a 128-bit bit-sliced state.
 * Inputs:
 *   - state: 16 bytes ciphertexts
 *   - round_keys: 11 x 128-bit expanded keys concatenated
 * Algorithm:
 *   1) Initial AddRoundKey(0)
 *   2) For round in [1,9]:
 *        SubBytes()
 *        ShiftRows()
 *        MixColumns()
 *        AddRoundKey(round)
 *   3) For round 10:
 *        SubBytes() -> ShiftRows() -> AddRoundKey(10)
 */
template <typename Torus>
__host__ void host_integer_aes_encrypt(
    cudaStream_t const *streams, uint32_t const *gpu_indexes,
    uint32_t gpu_count, CudaRadixCiphertextFFI *state,
    CudaRadixCiphertextFFI const *round_keys,
    int_aes_encrypt_buffer<Torus> *mem, void *const *bsks, Torus *const *ksks,
    CudaModulusSwitchNoiseReductionKeyFFI const *ms_noise_reduction_key) {

  // Step 0
  //
  CudaRadixCiphertextFFI current_round_key;

  as_radix_ciphertext_slice<Torus>(&current_round_key, round_keys, 0, 128);
  fhe_add_round_key(streams, gpu_indexes, gpu_count, state, &current_round_key,
                    mem);
  fhe_flush(streams, gpu_indexes, gpu_count, state, mem, bsks, ksks,
            ms_noise_reduction_key);

  // Step 1..9
  //
  for (int round = 1; round < 10; ++round) {
    for (int byte_idx = 0; byte_idx < 16; ++byte_idx) {
      CudaRadixCiphertextFFI current_byte;
      as_radix_ciphertext_slice<Torus>(&current_byte, state, byte_idx * 8,
                                       (byte_idx + 1) * 8);
      fhe_sbox(streams, gpu_indexes, gpu_count, &current_byte, mem, bsks, ksks,
               ms_noise_reduction_key);
    }

    fhe_shift_rows(streams[0], gpu_indexes[0], state, mem);

    for (int col_idx = 0; col_idx < 4; ++col_idx) {
      CudaRadixCiphertextFFI current_col;
      as_radix_ciphertext_slice<Torus>(&current_col, state, col_idx * 32,
                                       (col_idx + 1) * 32);
      mix_columns(streams, gpu_indexes, gpu_count, &current_col, mem, bsks,
                  ksks, ms_noise_reduction_key);
    }

    as_radix_ciphertext_slice<Torus>(&current_round_key, round_keys,
                                     round * 128, (round + 1) * 128);
    fhe_add_round_key(streams, gpu_indexes, gpu_count, state,
                      &current_round_key, mem);
    fhe_flush(streams, gpu_indexes, gpu_count, state, mem, bsks, ksks,
              ms_noise_reduction_key);
  }

  // Step 10 (final)
  //
  for (int byte_idx = 0; byte_idx < 16; ++byte_idx) {
    CudaRadixCiphertextFFI current_byte;
    as_radix_ciphertext_slice<Torus>(&current_byte, state, byte_idx * 8,
                                     (byte_idx + 1) * 8);
    fhe_sbox(streams, gpu_indexes, gpu_count, &current_byte, mem, bsks, ksks,
             ms_noise_reduction_key);
  }

  fhe_shift_rows(streams[0], gpu_indexes[0], state, mem);

  as_radix_ciphertext_slice<Torus>(&current_round_key, round_keys, 10 * 128,
                                   11 * 128);
  fhe_add_round_key(streams, gpu_indexes, gpu_count, state, &current_round_key,
                    mem);

  fhe_flush(streams, gpu_indexes, gpu_count, state, mem, bsks, ksks,
            ms_noise_reduction_key);
}

#endif