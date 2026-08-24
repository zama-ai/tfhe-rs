#ifndef PRINCE_CUH
#define PRINCE_CUH

#include "../../include/prince/prince_utilities.h"
#include "../integer/integer.cuh"
#include "../integer/radix_ciphertext.cuh"

/* Homomorphic PRINCEv2 [BEK+20], nibble-radix design.
 *
 * The N lanes (64-bit inputs) of a batch are evaluated together, and the
 * state changes packing along the way because each layer wants a different
 * one:
 *
 *   u2 : 32N blocks of 2 bits    the layout the API takes and returns
 *   u4 : 16N blocks of 1 nibble  what an S-box table reads
 *   b  : 64N blocks of 1 bit     what the linear layer needs
 *
 * Each layer below is a single PBS launch over the whole batch; the arrows
 * between layers are levelled kernels (gather + add, no PBS).
 *
 *           +------+------------------------------------+-------+-----+
 *           | in   | layers, one PBS each               | out   | PBS |
 *           +------+------------------------------------+-------+-----+
 *   k0 xor  | u2   | k0                                 | u4    |   1 |
 *   fw x5   | u4   | S -> 3-sum + key bits              | u4    |  10 |
 *   middle  | u4   | S -> 3-sum + kap -> k xor -> S^-1  | b     |   4 |
 *   bw x5   | b    | 3-sum + kap -> S^-1                | b, u2 |  10 |
 *   k1 xor  | u2   | k1                                 | u2    |   1 |
 *           +------+------------------------------------+-------+-----+
 *                                                         total |  26 |
 *
 * The 3-sum is the linear layer: M' makes every output bit the XOR of 3 bits
 * of its column, so it is a levelled 3-term sum plus one PBS per bit. That
 * PBS also absorbs the round key and rescales the bit to its place value in
 * its nibble, so coming back to u4 is a plain addition. Gather maps carry
 * that plumbing; read "16N <- 64N, K=4" as "16N output blocks, each the sum
 * of K = 4 input blocks". */

/// @brief Points a multi slot LUT at the slots the next layer needs.
///
/// @param lut Multi slot LUT whose per-block indexes are overwritten, on the
/// host copy and on every active GPU.
/// @param lut_idx Index table to install, one slot id per block of lut.
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

/// @brief Prepares the key material of one key pair and direction, reused by
/// every host_integer_prince call on those keys.
///
/// Spreads each 32 block key into its 64 bits, then into the 3 bit parities
/// (the kap_ buffers) that let the linear layers absorb the key as a levelled
/// sum rather than a bootstrap. 5 PBS layers, paid here so the circuit itself
/// never bootstraps key material. Carries no lane dimension, whatever the
/// batch size: host_integer_prince tiles it.
///
/// The caller orders the key halves: (k0, k1) to encrypt, (k1, k0) to decrypt.
///
/// @param key_bits_first Output, 64 blocks, the bits of k_first.
/// @param key_bits_second Output, 64 blocks, the bits of k_second.
/// @param kap_bw_first Output, 64 blocks, M'(SR^-1(k_first)) as bits, what
/// the backward rounds xor in.
/// @param kap_bw_second Output, 64 blocks, same for k_second.
/// @param kap_mid_first Output, 64 blocks, M'(k_first) as bits, what the
/// middle round xors in after its S layer.
/// @param k_first First key half in circuit order, 32 blocks of 2 bits.
/// @param k_second Second key half in circuit order, 32 blocks of 2 bits.
/// @param mem Key preparation scratch.
template <typename Torus>
__host__ void host_integer_prince_key_prep(
    CudaStreams streams, CudaRadixCiphertextFFI *key_bits_first,
    CudaRadixCiphertextFFI *key_bits_second,
    CudaRadixCiphertextFFI *kap_bw_first, CudaRadixCiphertextFFI *kap_bw_second,
    CudaRadixCiphertextFFI *kap_mid_first,
    CudaRadixCiphertextFFI const *k_first,
    CudaRadixCiphertextFFI const *k_second,
    int_prince_key_prep_buffer<Torus> *mem, void *const *bsks,
    Torus *const *ksks) {
  using namespace prince_v2;
  PANIC_IF_FALSE(k_first->num_radix_blocks == NUM_U2 &&
                     k_second->num_radix_blocks == NUM_U2,
                 "PRINCE keys should have 32 blocks");
  for (auto *out : {key_bits_first, key_bits_second, kap_bw_first,
                    kap_bw_second, kap_mid_first})
    PANIC_IF_FALSE(out->num_radix_blocks == NUM_BITS,
                   "PRINCE prepared key buffers should have 64 blocks");

  auto active_streams =
      streams.active_gpu_subset(NUM_BITS, mem->params.pbs_type);

  auto extract_bits = [&](CudaRadixCiphertextFFI const *key,
                          CudaRadixCiphertextFFI *bits) {
    host_radix_gather_sum<Torus>(streams, mem->params, mem->buf_a, key,
                                 mem->map_dup);
    prince_set_lut_indexes<Torus>(streams, mem->params, mem->lut,
                                  mem->lut_idx_keybit);
    integer_radix_apply_univariate_lookup_table<Torus>(
        streams, bits, mem->buf_a, bsks, ksks, mem->lut, NUM_BITS);
  };
  auto parity_of_bits = [&](CudaRadixCiphertextFFI const *bits,
                            const radix_index_table<uint32_t> &sum3,
                            CudaRadixCiphertextFFI *kap) {
    mem->lut->set_lut_indexes_and_broadcast_constant(active_streams, 0);
    host_radix_gather_sum<Torus>(streams, mem->params, mem->buf_b, bits, sum3);
    integer_radix_apply_univariate_lookup_table<Torus>(
        streams, kap, mem->buf_b, bsks, ksks, mem->lut, NUM_BITS);
  };

  extract_bits(k_first, key_bits_first);
  parity_of_bits(key_bits_first, mem->map_bw_sum3, kap_bw_first);
  parity_of_bits(key_bits_first, mem->map_mid_sum3, kap_mid_first);
  extract_bits(k_second, key_bits_second);
  parity_of_bits(key_bits_second, mem->map_bw_sum3, kap_bw_second);
}

/// @brief The middle round's second key xor, buf_u2q -> buf_u4: the one key
/// xor no parity layer can absorb, so it costs a PBS layer of its own.
///
/// The parity layer upstream already left the state bits at weights 8 and 4,
/// so buf_u2q holds 4 * m and a levelled key add is enough to build the
/// 4 * m + k that lut_flat32 decodes. The input xor builds the same packing
/// with a bivariate apply instead, since the state arrives unscaled there.
///
/// @param mem Circuit scratch, reads buf_u2q and writes buf_u4.
/// @param key_buf Key half to xor in, 32 blocks of 2 bits per lane, tiled
/// over the batch.
template <typename Torus>
__host__ void host_prince_xor_key_to_u4(CudaStreams streams,
                                        int_prince_buffer<Torus> *mem,
                                        CudaRadixCiphertextFFI const *key_buf,
                                        void *const *bsks, Torus *const *ksks) {
  uint32_t num_u2_blocks = prince_v2::NUM_U2 * mem->num_inputs;
  host_addition<Torus>(streams.stream(0), streams.gpu_index(0), mem->buf_sum,
                       mem->buf_u2q, key_buf, num_u2_blocks,
                       mem->params.message_modulus, mem->params.carry_modulus);
  integer_radix_apply_univariate_lookup_table<Torus>(
      streams, mem->buf_sum, mem->buf_sum, bsks, ksks, mem->lut_flat32,
      num_u2_blocks);
  host_radix_gather_sum<Torus>(streams, mem->params, mem->buf_u4, mem->buf_sum,
                               mem->map_pair);
}

/// @brief Fuses the linear layer with the key xor, buf_b -> buf_b.
///
/// Sums the 3 source bits plus the key bit levelled, then one PBS takes the
/// parity and scales it by the place value that bit holds in its nibble, 8,
/// 4, 2 or 1. State bits sit one per block here, so map_comb4_id can then
/// merge 4 blocks into the single nibble block the S-box wants, by plain
/// addition.
///
/// @param mem Circuit scratch, reads and writes buf_b, uses buf_b2.
/// @param sum3 Gather map giving the 3 source bits of each output bit, with
/// the round's permutation composed in.
/// @param key_material Key bits to add as the 4th term, 64 blocks per lane,
/// in the same bit order as the output of sum3.
/// @param parity_lut_idx Per-block parity slot, selecting the place value the
/// output bit is scaled to.
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

/// @brief S-box layer emitting bits, buf_u4 -> buf_b: one nibble block in,
/// its 4 bits out, one per block.
///
/// The S-box costs no PBS of its own: its table, the round constants and the
/// alpha-reflection are pre-fused into the per-word ZLut this PBS reads, and
/// the PBS is the bit extraction the next linear layer needs anyway.
///
/// @param mem Circuit scratch, reads buf_u4 and writes buf_b.
/// @param lut_idx Per-block slot of lut_gather64 selecting the round's table,
/// word and output bit.
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

/// @brief Forward round with its key xor, buf_u4 -> buf_u4: 2 PBS layers.
///
/// @param mem Circuit scratch.
/// @param r Forward round index, 0 to 4, selecting the S-box table.
/// @param key_bits Bits of the key half this round xors in, 64 blocks per
/// lane.
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

/// @brief Backward round with its key xor, buf_b -> buf_b: 2 PBS layers.
///
/// The last round instead lands in buf_u2q, since the circuit has to be back
/// in the u2 shape for the output key xor.
///
/// @param mem Circuit scratch.
/// @param r Backward round index, 0 to 4, selecting the S-box table and, for
/// 4, the u2 output shape.
/// @param kap_bw Key half this round xors in, already pulled back through
/// M'(SR^-1(.)), 64 blocks per lane.
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

/// @brief Middle (reflective) round S -> M' -> S^-1 with both key xors,
/// buf_u4 -> buf_b: 4 PBS layers.
///
/// @param mem Circuit scratch, also holds the tiled key material.
template <typename Torus>
__host__ void host_prince_mid_round(CudaStreams streams,
                                    int_prince_buffer<Torus> *mem,
                                    void *const *bsks, Torus *const *ksks) {
  host_prince_sbox_bits<Torus>(streams, mem, mem->lut_idx_mid_in, bsks, ksks);
  host_prince_parity_layer<Torus>(streams, mem, mem->map_mid_sum3,
                                  mem->kap_mid_first, mem->lut_idx_par_mid,
                                  bsks, ksks);
  host_radix_gather_sum<Torus>(streams, mem->params, mem->buf_u2q, mem->buf_b,
                               mem->map_perm_pair_mid);
  host_prince_xor_key_to_u4<Torus>(streams, mem, mem->buf_k_second, bsks, ksks);
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

/// @brief Full PRINCEv2 on a batch: k0 xor, 5 forward rounds, middle round,
/// 5 backward rounds, k1 xor.
///
/// Fresh inputs only: the input xor packs 4 * m + k, which spends the full
/// 2_2 noise budget.
///
/// @param output 32 blocks of 2 bits per input, most significant first,
/// instance-major.
/// @param input Same layout as output, fresh encryptions.
/// @param k_first First key half in circuit order, 32 blocks.
/// @param k_second Second key half in circuit order, 32 blocks.
/// @param key_bits_first From host_integer_prince_key_prep, 64 blocks.
/// @param key_bits_second From host_integer_prince_key_prep, 64 blocks.
/// @param kap_bw_first From host_integer_prince_key_prep, 64 blocks.
/// @param kap_bw_second From host_integer_prince_key_prep, 64 blocks.
/// @param kap_mid_first From host_integer_prince_key_prep, 64 blocks.
/// @param mem Circuit scratch, sized for this batch and direction.
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
                                  CudaRadixCiphertextFFI const *kap_mid_first,
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
  for (auto *k : {key_bits_first, key_bits_second, kap_bw_first, kap_bw_second,
                  kap_mid_first})
    PANIC_IF_FALSE(k->num_radix_blocks == NUM_BITS,
                   "PRINCE prepared key buffers should have 64 blocks");

  // The prepared key material carries no lane dimension, so every call
  // broadcasts it over the N lanes before the circuit can consume it.
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
  host_radix_gather_sum<Torus>(streams, mem->params, mem->kap_mid_first,
                               kap_mid_first, mem->map_tile64);

  // Inputs arrive instance-major. The circuit runs word-major, lane-fast, so
  // that its gather maps and LUT indexes do not depend on the lane.
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
