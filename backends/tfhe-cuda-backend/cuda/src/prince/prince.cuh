#ifndef PRINCE_CUH
#define PRINCE_CUH

#include "../../include/prince/prince_utilities.h"
#include "../integer/integer.cuh"
#include "../integer/radix_ciphertext.cuh"

/* Homomorphic PRINCEv2 [BEK+20].
 *
 * The N inputs of a batch go through together, and the state changes packing
 * depending on what the next layer wants
 *
 *   u2 : 32N blocks of 2 bits    API layout, and what a key xor reads
 *   u4 : 16N blocks of 1 nibble  what an S-box reads
 *   b  : 64N blocks of 1 bit     what the linear layer needs
 *
 * Each step in the table is one PBS launch over the whole batch, the arrows
 * are levelled gathers (no PBS).
 *
 *           +------+------------------------------------+-------+-----+
 *           | in   | layers, one PBS each               | out   | PBS |
 *           +------+------------------------------------+-------+-----+
 *   k0 xor  | u2   | k0                                 | u4    |   1 |
 *   fw x5   | u4   | S -> 3-sum + key bits              | u4    |  10 |
 *   middle  | u4   | S -> k xor -> 3-sum + key bits     | b     |   4 |
 *           |      | -> S^-1                            |       |     |
 *   bw x5   | b    | 3-sum + kap -> S^-1                | b, u2 |  10 |
 *   k1 xor  | u2   | k1                                 | u2    |   1 |
 *           +------+------------------------------------+-------+-----+
 *                                                         total |  26 |
 *
 * M' makes each output bit the XOR of 3 bits of its column, so the linear
 * layer is a levelled 3-sum and one PBS per bit. That PBS also takes the
 * round key as a 4th term and scales the bit to its weight in the nibble, so
 * going back to u4 is a plain sum. Keys added after the linear layer go in as
 * raw bits (forward and middle rounds), keys added before it as their image
 * through it (kap buffers, backward rounds).
 *
 * Map notation, "16N from 64N, K=4" means 16N outputs, each a sum of 4
 * inputs. */

/// @brief Points a multi slot LUT at the slots of the next layer, no LUT
/// regenerated.
///
/// @param lut LUT to retarget, host copy and every active GPU
/// @param lut_idx Slot of each block
template <typename Torus>
__host__ void prince_set_lut_indexes(CudaStreams streams,
                                     const int_radix_params &params,
                                     int_radix_lut<Torus> *lut,
                                     const radix_index_table<Torus> &lut_idx) {
  memcpy(lut->h_lut_indexes, lut_idx.h_table,
         safe_mul_sizeof<Torus>((size_t)lut->num_blocks));
  auto active_streams =
      streams.active_gpu_subset(lut->num_blocks, params.pbs_type);
  lut->set_lut_indexes_and_broadcast_from_gpu(active_streams, lut_idx.d_table,
                                              lut->num_blocks);
}

template <typename Torus>
__host__ uint64_t scratch_cuda_integer_prince_key_prep(
    CudaStreams streams, int_prince_key_prep_buffer<Torus> **mem_ptr,
    int_radix_params params, bool allocate_gpu_memory) {
  uint64_t size_tracker = 0;
  *mem_ptr = new int_prince_key_prep_buffer<Torus>(
      streams, params, allocate_gpu_memory, size_tracker);
  return size_tracker;
}

/// @brief One-off key prep, reused by every host_integer_prince call with the
/// same keys and direction.
///
/// Extracts the key bits and their image through the backward linear layer
/// (kap_bw), so the forward and backward rounds can just add the key inside
/// their parity PBS. 2 PBS launches for both halves. No batch dimension,
/// host_integer_prince tiles the output.
///
/// @param key_bits_first Output, the 64 bits of k_first
/// @param key_bits_second Output, the 64 bits of k_second
/// @param kap_bw_first Output, M'(SR^-1(k_first)) as 64 bits
/// @param kap_bw_second Output, same for k_second
/// @param k_first k0 to encrypt, k1 to decrypt, 32 blocks of 2 bits
/// @param k_second The other half, same layout
/// @param mem Key prep scratch
template <typename Torus>
__host__ void host_integer_prince_key_prep(
    CudaStreams streams, CudaRadixCiphertextFFI *key_bits_first,
    CudaRadixCiphertextFFI *key_bits_second,
    CudaRadixCiphertextFFI *kap_bw_first, CudaRadixCiphertextFFI *kap_bw_second,
    CudaRadixCiphertextFFI const *k_first,
    CudaRadixCiphertextFFI const *k_second,
    int_prince_key_prep_buffer<Torus> *mem, void *const *bsks,
    Torus *const *ksks) {
  using namespace prince_v2;
  PANIC_IF_FALSE(k_first->num_radix_blocks == NUM_U2 &&
                     k_second->num_radix_blocks == NUM_U2,
                 "PRINCE keys should have 32 blocks");
  for (auto *out :
       {key_bits_first, key_bits_second, kap_bw_first, kap_bw_second})
    PANIC_IF_FALSE(out->num_radix_blocks == NUM_BITS,
                   "PRINCE prepared key buffers should have 64 blocks");

  auto stream = streams.stream(0);
  auto gpu_index = streams.gpu_index(0);
  auto active_streams =
      streams.active_gpu_subset(2 * NUM_BITS, mem->params.pbs_type);

  // Both halves side by side, k_first first
  copy_radix_ciphertext_slice_async<Torus>(stream, gpu_index, mem->buf_keys, 0,
                                           NUM_U2, k_first, 0, NUM_U2);
  copy_radix_ciphertext_slice_async<Torus>(stream, gpu_index, mem->buf_keys,
                                           NUM_U2, 2 * NUM_U2, k_second, 0,
                                           NUM_U2);

  // Key bits, each u2 duplicated then high bit from one copy, low bit from
  // the other
  host_radix_gather_sum<Torus>(streams, mem->params, mem->buf_a, mem->buf_keys,
                               mem->map_dup);
  prince_set_lut_indexes<Torus>(streams, mem->params, mem->lut,
                                mem->lut_idx_keybit);
  integer_radix_apply_univariate_lookup_table<Torus>(
      streams, mem->buf_bits, mem->buf_a, bsks, ksks, mem->lut, 2 * NUM_BITS);

  // kap, 3-sums of M'(SR^-1(.)) reduced by the low bit slot
  mem->lut->set_lut_indexes_and_broadcast_constant(active_streams, 0);
  host_radix_gather_sum<Torus>(streams, mem->params, mem->buf_b, mem->buf_bits,
                               mem->map_bw_sum3);
  integer_radix_apply_univariate_lookup_table<Torus>(
      streams, mem->buf_kap, mem->buf_b, bsks, ksks, mem->lut, 2 * NUM_BITS);

  // Split back into the 4 outputs
  copy_radix_ciphertext_slice_async<Torus>(stream, gpu_index, key_bits_first, 0,
                                           NUM_BITS, mem->buf_bits, 0,
                                           NUM_BITS);
  copy_radix_ciphertext_slice_async<Torus>(stream, gpu_index, key_bits_second,
                                           0, NUM_BITS, mem->buf_bits, NUM_BITS,
                                           2 * NUM_BITS);
  copy_radix_ciphertext_slice_async<Torus>(stream, gpu_index, kap_bw_first, 0,
                                           NUM_BITS, mem->buf_kap, 0, NUM_BITS);
  copy_radix_ciphertext_slice_async<Torus>(stream, gpu_index, kap_bw_second, 0,
                                           NUM_BITS, mem->buf_kap, NUM_BITS,
                                           2 * NUM_BITS);
}

/// @brief S-box layer for when a key xor comes next, buf_u4 -> buf_u2q.
///
/// Outputs u2 in the high half of the block so the key can just be added.
///
/// @param mem Circuit scratch
/// @param lut_idx S-box u2 slots of this layer
template <typename Torus>
__host__ void host_prince_sbox_to_u2h(CudaStreams streams,
                                      int_prince_buffer<Torus> *mem,
                                      const radix_index_table<Torus> &lut_idx,
                                      void *const *bsks, Torus *const *ksks) {
  uint32_t num_u2_blocks = prince_v2::NUM_U2 * mem->num_inputs;
  host_radix_gather_sum<Torus>(streams, mem->params, mem->buf_u2q, mem->buf_u4,
                               mem->map_stage_x2);
  prince_set_lut_indexes<Torus>(streams, mem->params, mem->lut_gather64,
                                lut_idx);
  integer_radix_apply_univariate_lookup_table<Torus>(
      streams, mem->buf_u2q, mem->buf_u2q, bsks, ksks, mem->lut_gather64,
      num_u2_blocks);
}

/// @brief First key xor of the middle round, buf_u2q -> buf_b.
///
/// The only round key not folded into a parity PBS, so it pays its own
/// layer. The PBS splits the xor straight into bits, ready for the 3-sum.
///
/// @param mem Circuit scratch, buf_sum used as temp
/// @param key_buf Key half tiled over the batch, 32N
template <typename Torus>
__host__ void host_prince_xor_to_bits(CudaStreams streams,
                                      int_prince_buffer<Torus> *mem,
                                      CudaRadixCiphertextFFI const *key_buf,
                                      void *const *bsks, Torus *const *ksks) {
  uint32_t num_u2_blocks = prince_v2::NUM_U2 * mem->num_inputs;
  uint32_t num_bit_blocks = prince_v2::NUM_BITS * mem->num_inputs;
  host_addition<Torus>(streams.stream(0), streams.gpu_index(0), mem->buf_sum,
                       mem->buf_u2q, key_buf, num_u2_blocks,
                       mem->params.message_modulus, mem->params.carry_modulus);
  host_radix_gather_sum<Torus>(streams, mem->params, mem->buf_b, mem->buf_sum,
                               mem->map_stage_x2_bits);
  prince_set_lut_indexes<Torus>(streams, mem->params, mem->lut_gather64,
                                mem->lut_idx_xor_bits);
  integer_radix_apply_univariate_lookup_table<Torus>(
      streams, mem->buf_b, mem->buf_b, bsks, ksks, mem->lut_gather64,
      num_bit_blocks);
}

/// @brief Linear layer and round key in one PBS, buf_b -> buf_b.
///
/// Levelled 3-sum plus the key bit, then the PBS takes the parity and scales
/// it to its weight in the nibble, so the next S-box input is a plain sum.
///
/// @param mem Circuit scratch, buf_b2 used as temp
/// @param sum3 3-sum map of the round, permutation included
/// @param key_material Key bits added as 4th term, in the output order of
/// sum3
/// @param parity_lut_idx Parity slots, picks the weight of each output bit
template <typename Torus>
__host__ void
host_prince_parity_layer(CudaStreams streams, int_prince_buffer<Torus> *mem,
                         const radix_index_table<uint32_t> &sum3,
                         CudaRadixCiphertextFFI const *key_material,
                         const radix_index_table<Torus> &parity_lut_idx,
                         void *const *bsks, Torus *const *ksks) {
  uint32_t num_bit_blocks = prince_v2::NUM_BITS * mem->num_inputs;
  host_radix_gather_sum<Torus>(streams, mem->params, mem->buf_b2, mem->buf_b,
                               sum3);
  host_addition<Torus>(streams.stream(0), streams.gpu_index(0), mem->buf_b,
                       mem->buf_b2, key_material, num_bit_blocks,
                       mem->params.message_modulus, mem->params.carry_modulus);
  prince_set_lut_indexes<Torus>(streams, mem->params, mem->lut_gather64,
                                parity_lut_idx);
  integer_radix_apply_univariate_lookup_table<Torus>(
      streams, mem->buf_b, mem->buf_b, bsks, ksks, mem->lut_gather64,
      num_bit_blocks);
}

/// @brief S-box layer, buf_u4 -> buf_b, one bit per block out.
///
/// The S-box is basically free, it rides on the bit extraction the linear
/// layer needs anyway, round constants included.
///
/// @param mem Circuit scratch
/// @param lut_idx S-box bit slots of this layer
template <typename Torus>
__host__ void host_prince_sbox_bits(CudaStreams streams,
                                    int_prince_buffer<Torus> *mem,
                                    const radix_index_table<Torus> &lut_idx,
                                    void *const *bsks, Torus *const *ksks) {
  uint32_t num_bit_blocks = prince_v2::NUM_BITS * mem->num_inputs;
  host_radix_gather_sum<Torus>(streams, mem->params, mem->buf_b, mem->buf_u4,
                               mem->map_stage_x4);
  prince_set_lut_indexes<Torus>(streams, mem->params, mem->lut_gather64,
                                lut_idx);
  integer_radix_apply_univariate_lookup_table<Torus>(
      streams, mem->buf_b, mem->buf_b, bsks, ksks, mem->lut_gather64,
      num_bit_blocks);
}

/// @brief Forward round, S-box then linear layer and key, buf_u4 -> buf_u4.
/// 2 PBS layers.
///
/// @param mem Circuit scratch
/// @param r Round, 0 to 4
/// @param key_bits Key of this round as bits, tiled, 64N
template <typename Torus>
__host__ void host_prince_fw_round(CudaStreams streams,
                                   int_prince_buffer<Torus> *mem, uint32_t r,
                                   CudaRadixCiphertextFFI const *key_bits,
                                   void *const *bsks, Torus *const *ksks) {
  host_prince_sbox_bits<Torus>(streams, mem, mem->lut_idx_fw_sbox[r], bsks,
                               ksks);
  host_prince_parity_layer<Torus>(streams, mem, mem->map_fw_sum3, key_bits,
                                  mem->lut_idx_par_fw, bsks, ksks);
  host_radix_gather_sum<Torus>(streams, mem->params, mem->buf_u4, mem->buf_b,
                               mem->map_comb4_id);
}

/// @brief Backward round, key and linear layer then inverse S-box,
/// buf_b -> buf_b. 2 PBS layers.
///
/// The last one lands in buf_u2q instead, ready for the final key xor.
///
/// @param mem Circuit scratch
/// @param r Round, 0 to 4
/// @param kap_bw Key of this round seen through M'(SR^-1(.)), tiled, 64N
template <typename Torus>
__host__ void host_prince_bw_round(CudaStreams streams,
                                   int_prince_buffer<Torus> *mem, uint32_t r,
                                   CudaRadixCiphertextFFI const *kap_bw,
                                   void *const *bsks, Torus *const *ksks) {
  uint32_t num_u2_blocks = prince_v2::NUM_U2 * mem->num_inputs;
  host_prince_parity_layer<Torus>(streams, mem, mem->map_bw_sum3, kap_bw,
                                  mem->lut_idx_par_bw, bsks, ksks);
  host_radix_gather_sum<Torus>(streams, mem->params, mem->buf_u4, mem->buf_b,
                               mem->map_mperm_comb);
  if (r < 4) {
    host_prince_sbox_bits<Torus>(streams, mem, mem->lut_idx_bw_sbox[r], bsks,
                                 ksks);
  } else {
    host_radix_gather_sum<Torus>(streams, mem->params, mem->buf_u2q,
                                 mem->buf_u4, mem->map_stage_x2);
    prince_set_lut_indexes<Torus>(streams, mem->params, mem->lut_gather64,
                                  mem->lut_idx_bw_sbox[4]);
    integer_radix_apply_univariate_lookup_table<Torus>(
        streams, mem->buf_u2q, mem->buf_u2q, bsks, ksks, mem->lut_gather64,
        num_u2_blocks);
  }
}

/// @brief Middle round S, k_first, M', k_second, S^-1, buf_u4 -> buf_b.
/// 4 PBS layers.
///
/// k_first pays its own PBS (host_prince_xor_to_bits), k_second goes into the
/// parity PBS of M' as raw bits.
///
/// @param mem Circuit scratch, holds the tiled keys
template <typename Torus>
__host__ void host_prince_mid_round(CudaStreams streams,
                                    int_prince_buffer<Torus> *mem,
                                    void *const *bsks, Torus *const *ksks) {
  host_prince_sbox_to_u2h<Torus>(streams, mem, mem->lut_idx_mid_in, bsks, ksks);
  host_prince_xor_to_bits<Torus>(streams, mem, mem->buf_k_first, bsks, ksks);
  host_prince_parity_layer<Torus>(streams, mem, mem->map_mid_sum3,
                                  mem->key_bits_mid, mem->lut_idx_par_bw, bsks,
                                  ksks);
  host_radix_gather_sum<Torus>(streams, mem->params, mem->buf_u4, mem->buf_b,
                               mem->map_mperm_comb);
  host_prince_sbox_bits<Torus>(streams, mem, mem->lut_idx_mid_out, bsks, ksks);
}

template <typename Torus>
__host__ uint64_t scratch_cuda_integer_prince(
    CudaStreams streams, int_prince_buffer<Torus> **mem_ptr,
    int_radix_params params, bool allocate_gpu_memory, uint32_t num_inputs,
    bool is_decrypt) {
  uint64_t size_tracker = 0;

  *mem_ptr = new int_prince_buffer<Torus>(streams, params, allocate_gpu_memory,
                                          num_inputs, is_decrypt, size_tracker);

  return size_tracker;
}

/// @brief Whole PRINCEv2 on a batch, k_first xor, 5 forward rounds, middle
/// round, 5 backward rounds, k_second xor.
///
/// Inputs must be fresh, the first xor packs 4 * m + k and that already eats
/// the 2_2 noise budget.
///
/// @param output 32 blocks of 2 bits per input, MSB first, one input after
/// the other
/// @param input Same layout, fresh
/// @param k_first Raw key half, 32 blocks, same order as in key prep
/// @param k_second Raw key half, 32 blocks
/// @param key_bits_first From host_integer_prince_key_prep
/// @param key_bits_second From host_integer_prince_key_prep
/// @param kap_bw_first From host_integer_prince_key_prep
/// @param kap_bw_second From host_integer_prince_key_prep
/// @param mem Scratch for this batch size and direction
template <typename Torus>
__host__ void host_integer_prince(CudaStreams streams,
                                  CudaRadixCiphertextFFI *output,
                                  CudaRadixCiphertextFFI const *input,
                                  CudaRadixCiphertextFFI const *k_first,
                                  CudaRadixCiphertextFFI const *k_second,
                                  CudaRadixCiphertextFFI const *key_bits_first,
                                  CudaRadixCiphertextFFI const *key_bits_second,
                                  CudaRadixCiphertextFFI const *kap_bw_first,
                                  CudaRadixCiphertextFFI const *kap_bw_second,
                                  int_prince_buffer<Torus> *mem,
                                  void *const *bsks, Torus *const *ksks) {
  using namespace prince_v2;
  uint32_t N = mem->num_inputs;
  uint32_t num_u2_blocks = NUM_U2 * N;

  PANIC_IF_FALSE(input->num_radix_blocks == num_u2_blocks,
                 "PRINCE input should have 32 blocks per input");
  PANIC_IF_FALSE(output->num_radix_blocks == num_u2_blocks,
                 "PRINCE output should have 32 blocks per input");
  PANIC_IF_FALSE(k_first->num_radix_blocks == NUM_U2 &&
                     k_second->num_radix_blocks == NUM_U2,
                 "PRINCE keys should have 32 blocks");
  for (auto *k : {key_bits_first, key_bits_second, kap_bw_first, kap_bw_second})
    PANIC_IF_FALSE(k->num_radix_blocks == NUM_BITS,
                   "PRINCE prepared key buffers should have 64 blocks");

  // Key material has no batch dimension, tile it over the N lanes
  host_radix_gather_sum<Torus>(streams, mem->params, mem->buf_k_first, k_first,
                               mem->map_key_tile);
  host_radix_gather_sum<Torus>(streams, mem->params, mem->buf_k_second,
                               k_second, mem->map_key_tile);
  host_radix_gather_sum<Torus>(streams, mem->params, mem->key_bits_first,
                               key_bits_first, mem->map_tile64);
  host_radix_gather_sum<Torus>(streams, mem->params, mem->key_bits_second,
                               key_bits_second, mem->map_tile64);
  host_radix_gather_sum<Torus>(streams, mem->params, mem->kap_bw_first,
                               kap_bw_first, mem->map_tile64);
  host_radix_gather_sum<Torus>(streams, mem->params, mem->kap_bw_second,
                               kap_bw_second, mem->map_tile64);
  host_radix_gather_sum<Torus>(streams, mem->params, mem->key_bits_mid,
                               key_bits_second, mem->map_tile64_mid);

  // Inputs come instance major, the circuit runs word major
  host_radix_gather_sum<Torus>(streams, mem->params, mem->buf_u2q, input,
                               mem->map_transpose_in);

  integer_radix_apply_bivariate_lookup_table<Torus>(
      streams, mem->buf_sum, mem->buf_u2q, mem->buf_k_first, bsks, ksks,
      mem->lut_flat32, num_u2_blocks, mem->params.message_modulus);
  host_radix_gather_sum<Torus>(streams, mem->params, mem->buf_u4, mem->buf_sum,
                               mem->map_pair);

  for (uint32_t r = 0; r < 5; ++r)
    host_prince_fw_round<Torus>(
        streams, mem, r,
        (r % 2 == 0) ? mem->key_bits_second : mem->key_bits_first, bsks, ksks);

  host_prince_mid_round<Torus>(streams, mem, bsks, ksks);

  for (uint32_t r = 0; r < 5; ++r)
    host_prince_bw_round<Torus>(
        streams, mem, r, (r % 2 == 0) ? mem->kap_bw_first : mem->kap_bw_second,
        bsks, ksks);

  host_addition<Torus>(streams.stream(0), streams.gpu_index(0), mem->buf_sum,
                       mem->buf_u2q, mem->buf_k_second, num_u2_blocks,
                       mem->params.message_modulus, mem->params.carry_modulus);

  auto active_streams_flat =
      streams.active_gpu_subset(num_u2_blocks, mem->params.pbs_type);
  mem->lut_flat32->set_lut_indexes_and_broadcast_constant(active_streams_flat,
                                                          1);
  integer_radix_apply_univariate_lookup_table<Torus>(
      streams, mem->buf_sum, mem->buf_sum, bsks, ksks, mem->lut_flat32,
      num_u2_blocks);

  host_radix_gather_sum<Torus>(streams, mem->params, output, mem->buf_sum,
                               mem->map_transpose_out);
}

#endif // PRINCE_CUH
