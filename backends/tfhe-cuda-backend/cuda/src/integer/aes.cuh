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
    int_radix_params params, bool allocate_gpu_memory) {
  uint64_t size_tracker = 0;

  *mem_ptr =
      new int_aes_encrypt_buffer<Torus>(streams, gpu_indexes, gpu_count, params,
                                        allocate_gpu_memory, size_tracker);

  return size_tracker;
}

/**
 * Performs a homomorphic XOR operation between two ciphertexts.
 * Steps:
 * 1. Computes the homomorphic addition of the two ciphertexts (`lhs` and
 * `rhs`).
 * 2. Stores the result in `lhs`.
 */
template <typename Torus>
__host__ __forceinline__ void
aes_xor(cudaStream_t const *streams, uint32_t const *gpu_indexes,
        uint32_t gpu_count, CudaRadixCiphertextFFI *out,
        const CudaRadixCiphertextFFI *lhs, const CudaRadixCiphertextFFI *rhs,
        int_aes_encrypt_buffer<Torus> *mem_ptr) {

  host_addition<Torus>(streams[0], gpu_indexes[0], out, lhs, rhs,
                       lhs->num_radix_blocks, mem_ptr->params.message_modulus,
                       mem_ptr->params.carry_modulus);
}

/**
 * Performs a homomorphic AND operation between two ciphertexts.
 * Steps:
 * 1. Applies a bivariate programmable bootstrap using a lookup table for the
 * function f(a, b) = a & b.
 * 2. The result is stored in the `out` ciphertext.
 */
template <typename Torus>
__host__ __forceinline__ void
aes_and(cudaStream_t const *streams, uint32_t const *gpu_indexes,
        uint32_t gpu_count, CudaRadixCiphertextFFI *out,
        const CudaRadixCiphertextFFI *lhs, const CudaRadixCiphertextFFI *rhs,
        int_aes_encrypt_buffer<Torus> *mem_ptr, void *const *bsks,
        Torus *const *ksks,
        CudaModulusSwitchNoiseReductionKeyFFI const *ms_noise_reduction_key) {

  integer_radix_apply_bivariate_lookup_table_kb<Torus>(
      streams, gpu_indexes, gpu_count, out, lhs, rhs, bsks, ksks,
      ms_noise_reduction_key, mem_ptr->and_lut, out->num_radix_blocks,
      mem_ptr->params.message_modulus);
}

/**
 * Resets the noise of a ciphertext by applying a trivial identity lookup table.
 * Steps:
 * 1. Applies a univariate programmable bootstrap using a lookup table for the
 * function f(x) = x & 1.
 * 2. This operation refreshes the ciphertext without changing its underlying
 * value.
 */
template <typename Torus>
__host__ __forceinline__ void
aes_flush(cudaStream_t const *streams, uint32_t const *gpu_indexes,
          uint32_t gpu_count, CudaRadixCiphertextFFI *data,
          int_aes_encrypt_buffer<Torus> *mem_ptr, void *const *bsks,
          Torus *const *ksks,
          CudaModulusSwitchNoiseReductionKeyFFI const *ms_noise_reduction_key) {

  integer_radix_apply_univariate_lookup_table_kb<Torus>(
      streams, gpu_indexes, gpu_count, data, data, bsks, ksks,
      ms_noise_reduction_key, mem_ptr->flush_lut, data->num_radix_blocks);
}

/**
 * Homomorphically computes the AES S-box transformation on an 8-bit encrypted
 * byte. Steps:
 * 1. Decomposes the input byte into 8 single-bit ciphertexts.
 * 2. Slices the pre-allocated workspace buffer (`sbox_vars`) into temporary
 * variables.
 * 3. Executes the Boyar-Peralta S-box circuit using homomorphic ANDs and XORs.
 * 4. Assembles the 8 resulting bits back into the input ciphertext.
 */
template <typename Torus>
__host__ void aes_sbox_inplace(
    cudaStream_t const *streams, uint32_t const *gpu_indexes,
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

  CudaRadixCiphertextFFI tmp_bit;
  as_radix_ciphertext_slice<Torus>(&tmp_bit, mem_ptr->tmp_byte_1, 0, 1);

#define XOR(out, a, b)                                                         \
  aes_xor(streams, gpu_indexes, gpu_count, out, a, b, mem_ptr)

#define XOR_FLUSH(out, a, b)                                                   \
  aes_xor(streams, gpu_indexes, gpu_count, out, a, b, mem_ptr);                \
  aes_flush(streams, gpu_indexes, gpu_count, out, mem_ptr, bsks, ksks,         \
            ms_noise_reduction_key)

#define AND(out, a, b)                                                         \
  aes_and(streams, gpu_indexes, gpu_count, out, a, b, mem_ptr, bsks, ksks,     \
          ms_noise_reduction_key)

#define SCALAR_ADD_ONE(out, in)                                                \
  copy_radix_ciphertext_slice_async<Torus>(streams[0], gpu_indexes[0], out, 0, \
                                           1, in, 0, 1);                       \
  host_integer_radix_add_scalar_one_inplace<Torus>(                            \
      streams, gpu_indexes, gpu_count, out, mem_ptr->params.message_modulus,   \
      mem_ptr->params.carry_modulus)

#define SCALAR_ADD_ONE_FLUSH(out, in)                                          \
  SCALAR_ADD_ONE(out, in);                                                     \
  aes_flush(streams, gpu_indexes, gpu_count, out, mem_ptr, bsks, ksks,         \
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

  SCALAR_ADD_ONE_FLUSH(&tmp_bit, &t[62]);
  XOR(&s[6], &t[56], &tmp_bit);

  SCALAR_ADD_ONE_FLUSH(&tmp_bit, &t[60]);
  XOR(&s[7], &t[48], &tmp_bit);

  SCALAR_ADD_ONE(&tmp_bit, &s[3]);
  XOR(&s[1], &t[64], &tmp_bit);

  SCALAR_ADD_ONE_FLUSH(&tmp_bit, &t[67]);
  XOR(&s[2], &t[55], &tmp_bit);

  for (int i = 0; i < 8; ++i) {
    copy_radix_ciphertext_slice_async<Torus>(streams[0], gpu_indexes[0], x, i,
                                             i + 1, &s[i], 0, 1);
  }

#undef XOR
#undef XOR_FLUSH
#undef AND
#undef SCALAR_ADD_ONE
#undef SCALAR_ADD_ONE_FLUSH
}

/**
 * Homomorphically computes the ShiftRows transformation on a 128-bit encrypted
 * state. Steps:
 * 1. Copies the input state to a temporary buffer.
 * 2. Shifts the bytes of rows 1, 2, and 3 by 1, 2, and 3 positions
 * respectively.
 * 3. Copies the shifted bytes from the temporary buffer back to the input
 * state.
 */
template <typename Torus>
__host__ void aes_shift_rows_inplace(cudaStream_t stream, uint32_t gpu_index,
                                     CudaRadixCiphertextFFI *state,
                                     int_aes_encrypt_buffer<Torus> *mem_ptr) {
  copy_radix_ciphertext_async<Torus>(stream, gpu_index, mem_ptr->tmp_full_state,
                                     state);

  const uint32_t bits_in_byte = 8;

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

/**
 * Homomorphically computes the multiplication by 2 in GF(2^8) on an encrypted
 * byte. Steps:
 * 1. Implements the operation as an optimized logical circuit to avoid costly
 * multiplications.
 * 2. Performs a circular left shift on the bits of the byte.
 * 3. Performs three conditional XORs with the most significant bit to finalize
 * the computation.
 */
template <typename Torus>
__host__ void aes_mul_by_2(cudaStream_t const *streams,
                           uint32_t const *gpu_indexes, uint32_t gpu_count,
                           CudaRadixCiphertextFFI *res,
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
    aes_xor(streams, gpu_indexes, gpu_count, &r[index], &r[index], &b[0],
            mem_ptr);
  }
}

/**
 * Homomorphically computes the MixColumns transformation on a 32-bit encrypted
 * column. Steps:
 * 1. Pre-computes the multiplication by 2 for each of the 4 bytes in the
 * column.
 * 2. Combines the original bytes and the multiplied-by-2 bytes using XORs,
 * following the MixColumns matrix multiplication logic.
 * 3. Stores the 4 resulting bytes in the input column ciphertext.
 */
template <typename Torus>
__host__ void aes_mix_columns_inplace(cudaStream_t const *streams,
                                      uint32_t const *gpu_indexes,
                                      uint32_t gpu_count,
                                      CudaRadixCiphertextFFI *col,
                                      int_aes_encrypt_buffer<Torus> *mem_ptr) {

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
    aes_mul_by_2(streams, gpu_indexes, gpu_count, &b_mul2[i], &b_orig[i],
                 mem_ptr);
  }

  CudaRadixCiphertextFFI b0_copy;
  as_radix_ciphertext_slice<Torus>(&b0_copy, mem_ptr->tmp_full_state, (8) * 8,
                                   (9) * 8);
  copy_radix_ciphertext_async<Torus>(streams[0], gpu_indexes[0], &b0_copy,
                                     &b_mul2[0]);

  CudaRadixCiphertextFFI r[4];
  for (int i = 0; i < 4; ++i)
    as_radix_ciphertext_slice<Torus>(&r[i], col, i * 8, (i + 1) * 8);

#define XOR(A, B) aes_xor(streams, gpu_indexes, gpu_count, A, A, B, mem_ptr)

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

/**
 * Homomorphically performs a 128-bit full addition between a ciphertext and a
 * plaintext. Steps:
 * 1. Iterates from the LSB to the MSB.
 * 2. For each bit, computes `sum = a_bit + b_bit + carry_in`.
 * 3. Updates the ciphertext bit with the `sum` bit (using a `flush` operation).
 * 4. Computes the `carry_out` for the next iteration.
 */
template <typename Torus>
__host__ void aes_full_adder_inplace(
    cudaStream_t const *streams, uint32_t const *gpu_indexes,
    uint32_t gpu_count, CudaRadixCiphertextFFI *a, const Torus *b_plaintext_le,
    int_aes_encrypt_buffer<Torus> *mem, void *const *bsks, Torus *const *ksks,
    CudaModulusSwitchNoiseReductionKeyFFI const *ms_noise_reduction_key) {

  CudaRadixCiphertextFFI *carry = mem->tmp_carry;
  set_trivial_radix_ciphertext_async<Torus>(
      streams[0], gpu_indexes[0], carry, mem->d_trivial_scalars_zero,
      mem->h_trivial_scalars_zero, 1, mem->params.message_modulus,
      mem->params.carry_modulus);

  CudaRadixCiphertextFFI *current_a_bit = mem->tmp_bit_1;
  CudaRadixCiphertextFFI *sum_bit = mem->tmp_sum_1;
  CudaRadixCiphertextFFI *sum_plus_carry = mem->tmp_byte_1;

  for (int i = 0; i < 128; ++i) {
    int bit_index = 127 - i;
    copy_radix_ciphertext_slice_async<Torus>(streams[0], gpu_indexes[0],
                                             current_a_bit, 0, 1, a, bit_index,
                                             bit_index + 1);

    if (b_plaintext_le[i] == 1) {
      host_addition<Torus>(streams[0], gpu_indexes[0], sum_bit, current_a_bit,
                           mem->trivial_1_bit, 1, mem->params.message_modulus,
                           mem->params.carry_modulus);
    } else {
      copy_radix_ciphertext_async<Torus>(streams[0], gpu_indexes[0], sum_bit,
                                         current_a_bit);
    }

    host_addition<Torus>(streams[0], gpu_indexes[0], sum_plus_carry, sum_bit,
                         carry, 1, mem->params.message_modulus,
                         mem->params.carry_modulus);

    integer_radix_apply_univariate_lookup_table_kb<Torus>(
        streams, gpu_indexes, gpu_count, carry, sum_plus_carry, bsks, ksks,
        ms_noise_reduction_key, mem->carry_lut, 1);

    CudaRadixCiphertextFFI a_i_slice;
    as_radix_ciphertext_slice<Torus>(&a_i_slice, a, bit_index, bit_index + 1);
    integer_radix_apply_univariate_lookup_table_kb<Torus>(
        streams, gpu_indexes, gpu_count, &a_i_slice, sum_plus_carry, bsks, ksks,
        ms_noise_reduction_key, mem->flush_lut, 1);
  }
}

/**
 * Performs a full homomorphic AES-128 encryption on a 128-bit state.
 * Steps:
 * 1. Performs the initial AddRoundKey.
 * 2. Executes 9 main rounds, each consisting of S-box, ShiftRows, MixColumns,
 * and AddRoundKey.
 * 3. Executes the final round (without MixColumns).
 * 4. Ensures noise is managed by flushing ciphertexts after key additions.
 */
template <typename Torus>
__host__ void aes_encrypt_inplace(
    cudaStream_t const *streams, uint32_t const *gpu_indexes,
    uint32_t gpu_count, CudaRadixCiphertextFFI *state,
    CudaRadixCiphertextFFI const *round_keys,
    int_aes_encrypt_buffer<Torus> *mem, void *const *bsks, Torus *const *ksks,
    CudaModulusSwitchNoiseReductionKeyFFI const *ms_noise_reduction_key) {

  CudaRadixCiphertextFFI current_round_key;

  as_radix_ciphertext_slice<Torus>(&current_round_key, round_keys, 0, 128);
  aes_xor(streams, gpu_indexes, gpu_count, state, state, &current_round_key,
          mem);
  aes_flush(streams, gpu_indexes, gpu_count, state, mem, bsks, ksks,
            ms_noise_reduction_key);

  for (int round = 1; round < 10; ++round) {
    for (int byte_idx = 0; byte_idx < 16; ++byte_idx) {
      CudaRadixCiphertextFFI current_byte;
      as_radix_ciphertext_slice<Torus>(&current_byte, state, byte_idx * 8,
                                       (byte_idx + 1) * 8);
      aes_sbox_inplace(streams, gpu_indexes, gpu_count, &current_byte, mem,
                       bsks, ksks, ms_noise_reduction_key);
    }

    aes_shift_rows_inplace(streams[0], gpu_indexes[0], state, mem);

    for (int col_idx = 0; col_idx < 4; ++col_idx) {
      CudaRadixCiphertextFFI current_col;
      as_radix_ciphertext_slice<Torus>(&current_col, state, col_idx * 32,
                                       (col_idx + 1) * 32);
      aes_mix_columns_inplace(streams, gpu_indexes, gpu_count, &current_col,
                              mem);
    }

    as_radix_ciphertext_slice<Torus>(&current_round_key, round_keys,
                                     round * 128, (round + 1) * 128);
    aes_xor(streams, gpu_indexes, gpu_count, state, state, &current_round_key,
            mem);
    aes_flush(streams, gpu_indexes, gpu_count, state, mem, bsks, ksks,
              ms_noise_reduction_key);
  }

  for (int byte_idx = 0; byte_idx < 16; ++byte_idx) {
    CudaRadixCiphertextFFI current_byte;
    as_radix_ciphertext_slice<Torus>(&current_byte, state, byte_idx * 8,
                                     (byte_idx + 1) * 8);
    aes_sbox_inplace(streams, gpu_indexes, gpu_count, &current_byte, mem, bsks,
                     ksks, ms_noise_reduction_key);
  }

  aes_shift_rows_inplace(streams[0], gpu_indexes[0], state, mem);

  as_radix_ciphertext_slice<Torus>(&current_round_key, round_keys, 10 * 128,
                                   11 * 128);
  aes_xor(streams, gpu_indexes, gpu_count, state, state, &current_round_key,
          mem);
  aes_flush(streams, gpu_indexes, gpu_count, state, mem, bsks, ksks,
            ms_noise_reduction_key);
}

/**
 * Orchestrates the homomorphic AES-CTR encryption process.
 * Steps:
 * 1. If a counter value is provided, homomorphically adds it to the state (IV).
 * 2. Calls the main homomorphic AES encryption routine on the resulting state.
 */
template <typename Torus>
__host__ void host_integer_aes_ctr_encrypt(
    cudaStream_t const *streams, uint32_t const *gpu_indexes,
    uint32_t gpu_count, CudaRadixCiphertextFFI *state,
    CudaRadixCiphertextFFI const *round_keys,
    const Torus *plaintext_counter_bits, int_aes_encrypt_buffer<Torus> *mem,
    void *const *bsks, Torus *const *ksks,
    CudaModulusSwitchNoiseReductionKeyFFI const *ms_noise_reduction_key) {

  if (plaintext_counter_bits != nullptr) {
    aes_full_adder_inplace(streams, gpu_indexes, gpu_count, state,
                           plaintext_counter_bits, mem, bsks, ksks,
                           ms_noise_reduction_key);
  }

  aes_encrypt_inplace(streams, gpu_indexes, gpu_count, state, round_keys, mem,
                      bsks, ksks, ms_noise_reduction_key);
}

#endif