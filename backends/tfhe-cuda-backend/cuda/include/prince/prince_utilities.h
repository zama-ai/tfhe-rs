#ifndef PRINCE_UTILITIES_H
#define PRINCE_UTILITIES_H

#include "../integer/integer_utilities.h"
#include <array>
#include <cstdint>
#include <cstring>
#include <map>
#include <vector>

/* PRINCEv2 [BEK+20] tables. Everything below is derived from the published
 * S-box, round constants and M' / SR layers; the round and alpha-reflection
 * constants are pre-fused so they cost no FHE operation. */
namespace prince_v2 {

/// @brief 4-bit nibbles in the 64-bit state
constexpr uint32_t NUM_WORDS = 16;
/// @brief 2-bit nibbles in the 64-bit state
constexpr uint32_t NUM_U2 = 32;
/// @brief Bits in the state
constexpr uint32_t NUM_BITS = 64;
/// @brief Rounds, one constant each
constexpr uint32_t NUM_ROUNDS = 12;

using ZLut = std::array<std::array<uint8_t, 16>, 16>; // 16 per-word 4->4 LUTs
using U4Vec = std::array<uint8_t, 16>;

/// @brief Round constants RC_0 to RC_11 of PRINCEv2
constexpr uint64_t RC_V2[NUM_ROUNDS] = {
    0x0000000000000000, 0x13198a2e03707344, 0xa4093822299f31d0,
    0x082efa98ec4e6c89, 0x452821e638d01377, 0xbe5466cf34e90c6c,
    0x7ef84f78fd955cb1, 0x7aacf4538d971a60, 0xc882d32f25323c54,
    0x9b8ded979cd838c7, 0xd3b5a399ca0c2399, 0x3f84d5b5b5470917,
};
/// @brief Constant of the reflective middle layer
constexpr uint64_t RC_BETA = 0x3f84d5b5b5470917;

/// @brief Nibble permutation layer SR, as a gather: word w of the output
/// takes word PERM[w] of the input
constexpr uint32_t PERM[NUM_WORDS] = {0x0, 0x5, 0xa, 0xf, 0x4, 0x9, 0xe, 0x3,
                                      0x8, 0xd, 0x2, 0x7, 0xc, 0x1, 0x6, 0xb};

/// @brief Inverts PERM: word w of the output of SR^-1 takes word IPERM[w]
constexpr std::array<uint32_t, NUM_WORDS> build_iperm() {
  std::array<uint32_t, NUM_WORDS> iperm{};
  for (uint32_t w = 0; w < NUM_WORDS; ++w)
    iperm[PERM[w]] = w;
  return iperm;
}
/// @brief Inverse nibble permutation SR^-1, as a gather
constexpr std::array<uint32_t, NUM_WORDS> IPERM = build_iperm();

/// @brief Applies the linear layer M' to a 64-bit state.
///
/// M' = diag(M0, M1, M1, M0), where block (r, c) of Mk is m_{(r + c + k) mod 4}
/// and m_i is the identity with diagonal entry i cleared. Output bit 4r + j of
/// a 16-bit group is therefore the XOR of that group's column j, skipping
/// element (j - r - k) mod 4. Bits are numbered MSB first. M' is an
/// involution.
///
/// @param x Input state, most significant nibble first.
constexpr uint64_t m_prime(uint64_t x) {
  uint64_t out = 0;
  for (uint32_t g = 0; g < 4; ++g) {
    uint32_t k = (g == 0 || g == 3) ? 0 : 1;
    for (uint32_t r = 0; r < 4; ++r)
      for (uint32_t j = 0; j < 4; ++j) {
        uint32_t skipped = (j + 8 - r - k) % 4;
        uint64_t bit = 0;
        for (uint32_t c = 0; c < 4; ++c)
          if (c != skipped)
            bit ^= (x >> (63 - (g * 16 + 4 * c + j))) & 1;
        out |= bit << (63 - (g * 16 + 4 * r + j));
      }
  }
  return out;
}

/// @brief Applies SR^-1 to a 64-bit state.
///
/// @param x Input state, most significant nibble first.
constexpr uint64_t inv_shift_rows(uint64_t x) {
  uint64_t out = 0;
  for (uint32_t w = 0; w < NUM_WORDS; ++w)
    out |= ((x >> (60 - 4 * w)) & 0xf) << (60 - 4 * PERM[w]);
  return out;
}

/// @brief Pulls every round constant back through M = SR . M' so the S-box
/// tables upstream of the linear layer can absorb it.
///
/// Derived, not transcribed, so they cannot fall out of sync with RC_V2.
constexpr std::array<uint64_t, NUM_ROUNDS> build_rc_v2_ip_im() {
  std::array<uint64_t, NUM_ROUNDS> rc{};
  for (uint32_t i = 0; i < NUM_ROUNDS; ++i)
    rc[i] = m_prime(inv_shift_rows(RC_V2[i]));
  return rc;
}
/// @brief Round constants pulled back through M: M'(SR^-1(RC_i))
constexpr std::array<uint64_t, NUM_ROUNDS> RC_V2_IP_IM = build_rc_v2_ip_im();
/// @brief Middle layer constant pulled back through M': M'(RC_BETA)
constexpr uint64_t RC_BETA_IM = m_prime(RC_BETA);

/// @brief Splits a u64 into its 16 nibbles, element 0 holding the 4 MSBs.
///
/// @param u Value to split.
constexpr U4Vec u64_to_vec_u4(uint64_t u) {
  U4Vec v{};
  for (uint32_t i = 0; i < NUM_WORDS; ++i)
    v[NUM_WORDS - i - 1] = (uint8_t)((u >> (4 * i)) & 0xf);
  return v;
}

/// @brief PRINCE S-box
constexpr uint8_t SBOX[16] = {0xb, 0xf, 0x3, 0x2, 0xa, 0xc, 0x9, 0x1,
                              0x6, 0x7, 0x8, 0x0, 0xe, 0x5, 0xd, 0x4};
/// @brief Inverse of SBOX
constexpr uint8_t INV_SBOX[16] = {0xb, 0x7, 0x3, 0x2, 0xf, 0xd, 0x8, 0x9,
                                  0xa, 0x6, 0x4, 0x0, 0x5, 0xe, 0xc, 0x1};

/// @brief Builds the 16 per-word tables zlut[w][x] = sbox[x ^ inner[w]] ^
/// outer[w], an S-box with a constant xored on each side.
///
/// @param sbox S-box or inverse S-box to wrap.
/// @param xor_inner Per-word constant xored to the input.
/// @param xor_outer Per-word constant xored to the output.
constexpr ZLut build_zlut_xsy(const uint8_t (&sbox)[16], U4Vec xor_inner,
                              U4Vec xor_outer) {
  ZLut z{};
  for (uint32_t w = 0; w < NUM_WORDS; ++w)
    for (uint32_t x = 0; x < 16; ++x)
      z[w][x] = (uint8_t)(sbox[(x ^ xor_inner[w]) & 0xf] ^ xor_outer[w]);
  return z;
}

/// @brief All-zero constant, for a table with no round constant on a side
constexpr U4Vec ZERO_NIBBLES{};

// Encryption tables, named after what they fuse. PV2_t_S_u xors RC_t, applies
// the S-box and xors RC_u pulled back through M. PV2_t_IS_u is the mirror,
// RC_t pulled back through M then the inverse S-box then RC_u. An M in a name
// is the middle layer constant RC_BETA.

/// @brief Plain S-box, rounds with no constant on either side
constexpr ZLut PV2_0_S_0 = build_zlut_xsy(SBOX, ZERO_NIBBLES, ZERO_NIBBLES);
/// @brief Encryption: RC_1 in, S-box, RC_2 out
constexpr ZLut PV2_1_S_2 = build_zlut_xsy(SBOX, u64_to_vec_u4(RC_V2[1]),
                                          u64_to_vec_u4(RC_V2_IP_IM[2]));
/// @brief Encryption: RC_3 in, S-box, RC_4 out
constexpr ZLut PV2_3_S_4 = build_zlut_xsy(SBOX, u64_to_vec_u4(RC_V2[3]),
                                          u64_to_vec_u4(RC_V2_IP_IM[4]));
/// @brief Encryption, middle round in: RC_5 in, S-box, RC_BETA out
constexpr ZLut PV2_5_S_M =
    build_zlut_xsy(SBOX, u64_to_vec_u4(RC_V2[5]), u64_to_vec_u4(RC_BETA_IM));
/// @brief Plain inverse S-box, rounds with no constant on either side
constexpr ZLut PV2_0_IS_0 =
    build_zlut_xsy(INV_SBOX, ZERO_NIBBLES, ZERO_NIBBLES);
/// @brief Encryption: RC_6 in, inverse S-box, RC_7 out
constexpr ZLut PV2_6_IS_7 = build_zlut_xsy(
    INV_SBOX, u64_to_vec_u4(RC_V2_IP_IM[6]), u64_to_vec_u4(RC_V2[7]));
/// @brief Encryption: RC_8 in, inverse S-box, RC_9 out
constexpr ZLut PV2_8_IS_9 = build_zlut_xsy(
    INV_SBOX, u64_to_vec_u4(RC_V2_IP_IM[8]), u64_to_vec_u4(RC_V2[9]));
/// @brief Encryption: RC_10 in, inverse S-box, RC_11 out
constexpr ZLut PV2_A_IS_B = build_zlut_xsy(
    INV_SBOX, u64_to_vec_u4(RC_V2_IP_IM[10]), u64_to_vec_u4(RC_V2[11]));

// Additional tables for decryption (alpha-reflection at the table level)

/// @brief Decryption: RC_11 in, S-box, RC_10 out
constexpr ZLut PV2_B_S_A = build_zlut_xsy(SBOX, u64_to_vec_u4(RC_V2[11]),
                                          u64_to_vec_u4(RC_V2_IP_IM[10]));
/// @brief Decryption: RC_9 in, S-box, RC_8 out
constexpr ZLut PV2_9_S_8 = build_zlut_xsy(SBOX, u64_to_vec_u4(RC_V2[9]),
                                          u64_to_vec_u4(RC_V2_IP_IM[8]));
/// @brief Decryption: RC_7 in, S-box, RC_6 out
constexpr ZLut PV2_7_S_6 = build_zlut_xsy(SBOX, u64_to_vec_u4(RC_V2[7]),
                                          u64_to_vec_u4(RC_V2_IP_IM[6]));
/// @brief Decryption, middle round out: RC_BETA in, inverse S-box, RC_5 out
constexpr ZLut PV2_M_IS_5 = build_zlut_xsy(INV_SBOX, u64_to_vec_u4(RC_BETA_IM),
                                           u64_to_vec_u4(RC_V2[5]));
/// @brief Decryption: RC_4 in, inverse S-box, RC_3 out
constexpr ZLut PV2_4_IS_3 = build_zlut_xsy(
    INV_SBOX, u64_to_vec_u4(RC_V2_IP_IM[4]), u64_to_vec_u4(RC_V2[3]));
/// @brief Decryption: RC_2 in, inverse S-box, RC_1 out
constexpr ZLut PV2_2_IS_1 = build_zlut_xsy(
    INV_SBOX, u64_to_vec_u4(RC_V2_IP_IM[2]), u64_to_vec_u4(RC_V2[1]));

/// @brief Index of the term each output bit of Mk reads: output bit 4r + j
/// takes column j skipping element (j - r - k) mod 4, i.e. term
/// 4j + (j - r - k) mod 4.
///
/// @param k Block index, 0 for M0 and 1 for M1.
constexpr std::array<uint32_t, 16> build_fhe_mk_perm(uint32_t k) {
  std::array<uint32_t, 16> perm{};
  for (uint32_t r = 0; r < 4; ++r)
    for (uint32_t j = 0; j < 4; ++j)
      perm[4 * r + j] = 4 * j + (j + 8 - r - k) % 4;
  return perm;
}
/// @brief Term permutation of M0
constexpr std::array<uint32_t, 16> FHE_M0_PERM = build_fhe_mk_perm(0);
/// @brief Term permutation of M1
constexpr std::array<uint32_t, 16> FHE_M1_PERM = build_fhe_mk_perm(1);

/// @brief Combined bit permutation for M' = diag(M0, M1, M1, M0)
constexpr std::array<uint32_t, NUM_BITS> build_fhe_m_perm() {
  std::array<uint32_t, NUM_BITS> m_perm{};
  for (uint32_t n = 0; n < 4; ++n)
    for (uint32_t p = 0; p < 16; ++p)
      m_perm[p + n * 16] =
          n * 16 + ((n == 0 || n == 3) ? FHE_M0_PERM[p] : FHE_M1_PERM[p]);
  return m_perm;
}
/// @brief Bit permutation of M', from output bit to the parity term it reads
constexpr std::array<uint32_t, NUM_BITS> FHE_M_PERM = build_fhe_m_perm();

/// @brief M' permutation combined with the forward nibble permutation layer SR
constexpr std::array<uint32_t, NUM_BITS> build_fhe_mp_perm_fw() {
  std::array<uint32_t, NUM_BITS> m_perm{};
  for (uint32_t b = 0; b < NUM_BITS; ++b)
    m_perm[b] = FHE_M_PERM[(PERM[b >> 2] << 2) + (b & 0x3)];
  return m_perm;
}
/// @brief Bit permutation of M = SR . M', for the forward rounds
constexpr std::array<uint32_t, NUM_BITS> FHE_MP_PERM_FW =
    build_fhe_mp_perm_fw();

/// @brief Table set per direction. The key order (first, second) is (k0, k1)
/// to encrypt, (k1, k0) to decrypt
struct prince_table_set {
  /// @brief S-box table of each forward round
  const ZLut *fw[5];
  /// @brief S-box table entering the middle round
  const ZLut *mid_in;
  /// @brief Inverse S-box table leaving the middle round
  const ZLut *mid_out;
  /// @brief Inverse S-box table of each backward round
  const ZLut *bw[5];
};

/// @brief Tables of prince_encrypt
constexpr prince_table_set ENCRYPT_TABLES = {
    {&PV2_0_S_0, &PV2_1_S_2, &PV2_0_S_0, &PV2_3_S_4, &PV2_0_S_0},
    &PV2_5_S_M,
    &PV2_0_IS_0,
    {&PV2_6_IS_7, &PV2_0_IS_0, &PV2_8_IS_9, &PV2_0_IS_0, &PV2_A_IS_B}};

/// @brief Tables of prince_decrypt
constexpr prince_table_set DECRYPT_TABLES = {
    {&PV2_B_S_A, &PV2_0_S_0, &PV2_9_S_8, &PV2_0_S_0, &PV2_7_S_6},
    &PV2_0_S_0,
    &PV2_M_IS_5,
    {&PV2_0_IS_0, &PV2_4_IS_3, &PV2_0_IS_0, &PV2_2_IS_1, &PV2_0_IS_0}};

} // namespace prince_v2

/// @brief Source bit of one term of the linear layer's 3-term sum.
///
/// Every output bit of M' is the XOR of 3 of the 4 bits in its column, which
/// is why each linear layer is a 3-term sum. This gives the tt-th of those 3
/// source bits for output bit p = 4w' + b: bit w'%4 of word k != b of nibble
/// group w'/4 (through IPERM for backward rounds).
///
/// @param p Output bit, in term order (see FHE_M_PERM).
/// @param tt Term index, 0 to 2.
/// @param iperm Whether to read the source words through SR^-1, as the
/// backward rounds do.
constexpr uint32_t prince_sum3_source(uint32_t p, uint32_t tt, bool iperm) {
  uint32_t w = p >> 2, b = p & 3;
  uint32_t k = (tt >= b) ? tt + 1 : tt;
  uint32_t ws = iperm ? prince_v2::IPERM[4 * (w >> 2) + k] : 4 * (w >> 2) + k;
  return 4 * ws + (w & 3);
}

/// @brief Key preparation scratch, turning a raw 32-block key half into 64
/// key bits and 64 three-bit key parities (the kap_ buffers the circuit reads).
///
/// Carries no lane dimension, so one instance serves any batch size.
template <typename Torus> struct int_prince_key_prep_buffer {
  int_radix_params params;
  bool allocate_gpu_memory;

  /// @brief Two slots. Slot 0 keeps the low bit, which serves both the low
  /// bit of a u2 and the 3-bit parity, slot 1 keeps the high bit
  int_radix_lut<Torus> *lut;
  /// @brief 64 blocks, each key u2 twice, about to have its bits pulled out
  CudaRadixCiphertextFFI *buf_a = nullptr;
  /// @brief 64 blocks, the 3-bit sums the parity LUT reads
  CudaRadixCiphertextFFI *buf_b = nullptr;

  /// @brief Owns every gather map below, and releases them
  radix_index_tables<uint32_t> maps;
  /// @brief Owns every LUT index table below, and releases them
  radix_index_tables<Torus> lut_indexes;

  // Gather maps, read as "out blocks from in blocks, K = terms summed per
  // output block"
  /// @brief 64 from 32, K=1, each u2 twice
  radix_index_table<uint32_t> map_dup;
  /// @brief 64 from 64, K=3, IPERM parity
  radix_index_table<uint32_t> map_bw_sum3;
  /// @brief 64 from 64, K=3, direct parity
  radix_index_table<uint32_t> map_mid_sum3;
  /// @brief 64 entries, slots 1/0 alternating: high then low bit of each u2
  radix_index_table<Torus> lut_idx_keybit;

  int_prince_key_prep_buffer(CudaStreams streams,
                             const int_radix_params &params,
                             bool allocate_gpu_memory, uint64_t &size_tracker) {
    using namespace prince_v2;
    PANIC_IF_FALSE(params.message_modulus == 4 && params.carry_modulus == 4,
                   "PRINCEv2 requires 2_2 parameters (message_modulus = "
                   "carry_modulus = 4)");
    this->params = params;
    this->allocate_gpu_memory = allocate_gpu_memory;

    this->lut = new int_radix_lut<Torus>(streams, params, 2, NUM_BITS,
                                         allocate_gpu_memory, size_tracker);
    // Only the allocations above feed the size tracker, so a size query can
    // skip filling the accumulators
    if (allocate_gpu_memory) {
      std::vector<std::function<Torus(Torus)>> fs = {
          [](Torus x) -> Torus { return x & 1; },
          [](Torus x) -> Torus { return (x >> 1) & 1; },
      };
      auto active_streams =
          streams.active_gpu_subset(NUM_BITS, params.pbs_type);
      this->lut->generate_and_broadcast_lut(active_streams, {0, 1}, fs,
                                            LUT_0_FOR_ALL_BLOCKS);
    }

    auto alloc_ct = [&](uint32_t num_blocks) {
      auto *ct = new CudaRadixCiphertextFFI;
      create_zero_radix_ciphertext_async<Torus>(
          streams.stream(0), streams.gpu_index(0), ct, num_blocks,
          params.big_lwe_dimension, size_tracker, allocate_gpu_memory);
      return ct;
    };
    this->buf_a = alloc_ct(NUM_BITS);
    this->buf_b = alloc_ct(NUM_BITS);

    // One key half, no batch to replicate over: a row is a block
    maps.create(streams, allocate_gpu_memory, size_tracker, map_dup, NUM_BITS,
                1, 1, 1, [](uint32_t o, uint32_t) { return o >> 1; });
    maps.create(streams, allocate_gpu_memory, size_tracker, map_bw_sum3,
                NUM_BITS, 3, 1, 1, [](uint32_t m, uint32_t tt) {
                  return prince_sum3_source(m, tt, true);
                });
    maps.create(streams, allocate_gpu_memory, size_tracker, map_mid_sum3,
                NUM_BITS, 3, 1, 1, [](uint32_t m, uint32_t tt) {
                  return prince_sum3_source(m, tt, false);
                });
    lut_indexes.create(
        streams, allocate_gpu_memory, size_tracker, lut_idx_keybit, NUM_BITS, 1,
        1, 1, [](uint32_t i, uint32_t) -> Torus { return 1 - (i & 1); });
  }

  void release(CudaStreams streams) {
    lut->release(streams);
    delete lut;
    lut = nullptr;
    for (auto *ct : {&buf_a, &buf_b}) {
      release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                     *ct, allocate_gpu_memory);
      delete *ct;
      *ct = nullptr;
    }
    maps.release(streams, allocate_gpu_memory);
    lut_indexes.release(streams, allocate_gpu_memory);
  }
};

/// @brief Circuit scratch of host_integer_prince, for one batch size and
/// direction.
///
/// State is word-major, lane-fast (block = word * N + lane, one lane per
/// 64-bit input of the batch) so LUT indexes and gather maps are constant
/// across the batch. lut_gather64 slots: [0, 4) parity, one per output weight
/// 8, 4, 2, 1, then one group per distinct S-box table.
template <typename Torus> struct int_prince_buffer {
  int_radix_params params;
  bool allocate_gpu_memory;
  /// @brief Lanes N, 64-bit blocks evaluated together
  uint32_t num_inputs;
  /// @brief Slots of lut_gather64
  uint32_t num_gather_luts;

  /// @brief Decodes a packed 4 * m + k into m ^ k.
  ///
  /// Slot 0 leaves the result in the high half of the block, slot 1 in the
  /// low half, and the generated indexes alternate the two per word so
  /// map_pair can add a u2 pair into one nibble. The output layer is the only
  /// caller that overrides them: it stays in u2, so it forces slot 1
  /// everywhere.
  int_radix_lut<Torus> *lut_flat32;
  /// @brief All per-word tables: parity slots then S-box bit slots
  int_radix_lut<Torus> *lut_gather64;

  /// @brief 64 * num_inputs, one state bit per block, where the bit layers land
  CudaRadixCiphertextFFI *buf_b = nullptr;
  /// @brief 64 * num_inputs, the levelled 3-sums a parity PBS reads
  CudaRadixCiphertextFFI *buf_b2 = nullptr;
  /// @brief 16 * num_inputs, the nibbles an S-box reads
  CudaRadixCiphertextFFI *buf_u4 = nullptr;
  /// @brief 32 * num_inputs, 2-bit halves at weights 8 and 4, waiting for a key
  /// xor
  CudaRadixCiphertextFFI *buf_u2q = nullptr;
  /// @brief 32 * num_inputs, the levelled 4 * m + k a key xor decodes
  CudaRadixCiphertextFFI *buf_sum = nullptr;
  /// @brief 32 * num_inputs, k_first tiled over the lanes
  CudaRadixCiphertextFFI *buf_k_first = nullptr;
  /// @brief 32 * num_inputs, k_second tiled over the lanes
  CudaRadixCiphertextFFI *buf_k_second = nullptr;

  /// @brief 64 * num_inputs, k_first bits tiled over the lanes
  CudaRadixCiphertextFFI *key_bits_first = nullptr;
  /// @brief 64 * num_inputs, k_second bits tiled over the lanes
  CudaRadixCiphertextFFI *key_bits_second = nullptr;
  /// @brief 64 * num_inputs, M'(SR^-1(k_first)) bits tiled over the lanes
  CudaRadixCiphertextFFI *kap_bw_first = nullptr;
  /// @brief 64 * num_inputs, M'(SR^-1(k_second)) bits tiled over the lanes
  CudaRadixCiphertextFFI *kap_bw_second = nullptr;
  /// @brief 64 * num_inputs, M'(k_first) bits tiled over the lanes
  CudaRadixCiphertextFFI *kap_mid_first = nullptr;

  /// @brief Owns every gather map below, and releases them
  radix_index_tables<uint32_t> maps;
  /// @brief Owns every LUT index table below, and releases them
  radix_index_tables<Torus> lut_indexes;

  // Gather maps, read as "out blocks from in blocks, K = terms summed per
  // output block". A row covers the N lanes at once, so only the transposes,
  // which cross lanes, carry N in their tables.
  /// @brief 32N from 32, K=1, lane broadcast
  radix_index_table<uint32_t> map_key_tile;
  /// @brief 64N from 64, K=1, lane broadcast
  radix_index_table<uint32_t> map_tile64;
  /// @brief 32N from 32N, K=1, instance to word major
  radix_index_table<uint32_t> map_transpose_in;
  /// @brief 32N from 32N, K=1, word to instance major
  radix_index_table<uint32_t> map_transpose_out;
  /// @brief 16N from 32N, K=2, hi/lo pair
  radix_index_table<uint32_t> map_pair;
  /// @brief 64N from 16N, K=1, each word x4
  radix_index_table<uint32_t> map_stage_x4;
  /// @brief 32N from 16N, K=1, each word x2
  radix_index_table<uint32_t> map_stage_x2;
  /// @brief 32N from 64N, K=2, FHE_M_PERM then pair
  radix_index_table<uint32_t> map_perm_pair_mid;
  /// @brief 16N from 64N, K=4, FHE_M_PERM then nibble combine
  radix_index_table<uint32_t> map_mperm_comb;
  /// @brief 64N from 64N, K=3, 3-term sum with SR composed, forward rounds
  radix_index_table<uint32_t> map_fw_sum3;
  /// @brief 64N from 64N, K=3, 3-term sum, middle round
  radix_index_table<uint32_t> map_mid_sum3;
  /// @brief 64N from 64N, K=3, 3-term sum with IPERM composed, backward rounds
  radix_index_table<uint32_t> map_bw_sum3;
  /// @brief 16N from 64N, K=4, 4 weighted bits into a nibble
  radix_index_table<uint32_t> map_comb4_id;

  /// @brief lut_gather64 slots of each forward round's S-box bits
  radix_index_table<Torus> lut_idx_fw_sbox[5];
  /// @brief lut_gather64 slots of the S-box bits entering the middle round
  radix_index_table<Torus> lut_idx_mid_in;
  /// @brief lut_gather64 slots of the inverse S-box bits leaving the middle
  /// round
  radix_index_table<Torus> lut_idx_mid_out;
  /// @brief lut_gather64 slots of each backward round's inverse S-box bits,
  /// the last one emitting u2 halves
  radix_index_table<Torus> lut_idx_bw_sbox[5];
  /// @brief Parity slots of the forward rounds, weight by bit in nibble
  radix_index_table<Torus> lut_idx_par_fw;
  /// @brief Parity slots of the backward rounds, weight by term order
  radix_index_table<Torus> lut_idx_par_bw;
  /// @brief Parity slots of the middle round, weights 8 and 4 for u2 packing
  radix_index_table<Torus> lut_idx_par_mid;

  int_prince_buffer(CudaStreams streams, const int_radix_params &params,
                    bool allocate_gpu_memory, uint32_t num_inputs,
                    bool is_decrypt, uint64_t &size_tracker) {
    using namespace prince_v2;

    PANIC_IF_FALSE(num_inputs >= 1,
                   "num_prince_inputs should be greater or equal to 1");
    PANIC_IF_FALSE(params.message_modulus == 4 && params.carry_modulus == 4,
                   "PRINCEv2 requires 2_2 parameters (message_modulus = "
                   "carry_modulus = 4)");

    this->params = params;
    this->allocate_gpu_memory = allocate_gpu_memory;
    this->num_inputs = num_inputs;

    const uint32_t N = num_inputs;
    const prince_table_set &tables =
        is_decrypt ? DECRYPT_TABLES : ENCRYPT_TABLES;

    uint32_t next_lut_id = 0;
    std::vector<std::function<Torus(Torus)>> lut_lambdas;
    auto push_slot = [&](std::function<Torus(Torus)> f) -> uint32_t {
      lut_lambdas.push_back(std::move(f));
      return next_lut_id++;
    };

    // Parity slots. Slot d keeps the low bit and scales it by 2^(3 - d), the
    // place value that bit has in the nibble map_comb4_id will add it into.
    for (uint32_t d = 0; d < 4; ++d)
      push_slot([d](Torus x) -> Torus { return (x & 1) << (3 - d); });

    std::map<const ZLut *, uint32_t> bit_bases;
    auto bit_table_base = [&](const ZLut *tbl) -> uint32_t {
      auto it = bit_bases.find(tbl);
      if (it != bit_bases.end())
        return it->second;
      uint32_t base = next_lut_id;
      bit_bases[tbl] = base;
      for (uint32_t w = 0; w < NUM_WORDS; ++w)
        for (uint32_t b = 0; b < 4; ++b)
          push_slot([tbl, w, b](Torus x) -> Torus {
            return (((*tbl)[w][x & 15] >> (3 - b)) & 1);
          });
      return base;
    };

    uint32_t fw_base[5], mid_in_base, mid_out_base, bw_base[5];
    for (uint32_t r = 0; r < 5; ++r)
      fw_base[r] = bit_table_base(tables.fw[r]);
    mid_in_base = bit_table_base(tables.mid_in);
    mid_out_base = bit_table_base(tables.mid_out);
    for (uint32_t r = 0; r < 4; ++r)
      bw_base[r] = bit_table_base(tables.bw[r]);
    bw_base[4] = next_lut_id;
    for (uint32_t w = 0; w < NUM_WORDS; ++w)
      for (uint32_t b = 0; b < 2; ++b) {
        const ZLut *tbl = tables.bw[4];
        push_slot([tbl, w, b](Torus x) -> Torus {
          return ((((*tbl)[w][x & 15] >> (2 - 2 * b)) & 3) << 2);
        });
      }
    this->num_gather_luts = next_lut_id;

    this->lut_flat32 = new int_radix_lut<Torus>(
        streams, params, 2, NUM_U2 * N, allocate_gpu_memory, size_tracker);
    this->lut_gather64 =
        new int_radix_lut<Torus>(streams, params, num_gather_luts, NUM_BITS * N,
                                 allocate_gpu_memory, size_tracker);

    // Each of the num_gather_luts + 2 accumulators costs a host polynomial
    // fill and a stream sync, and none of them feeds the size tracker
    if (allocate_gpu_memory) {
      std::function<Torus(Torus)> xor_high_lambda = [](Torus x) -> Torus {
        return (((x & 3) ^ ((x >> 2) & 3)) << 2);
      };
      std::function<Torus(Torus)> xor_low_lambda = [](Torus x) -> Torus {
        return ((x & 3) ^ ((x >> 2) & 3));
      };
      auto active_streams_flat =
          streams.active_gpu_subset(NUM_U2 * N, params.pbs_type);
      auto hl_index_generator = [N](Torus *indexes, uint32_t count) {
        for (uint32_t i = 0; i < count; ++i)
          indexes[i] = (i / N) & 1;
      };
      this->lut_flat32->generate_and_broadcast_lut(
          active_streams_flat, {0, 1}, {xor_high_lambda, xor_low_lambda},
          hl_index_generator);

      std::vector<uint32_t> lut_ids(num_gather_luts);
      for (uint32_t id = 0; id < num_gather_luts; ++id)
        lut_ids[id] = id;
      auto active_streams_gather =
          streams.active_gpu_subset(NUM_BITS * N, params.pbs_type);
      this->lut_gather64->generate_and_broadcast_lut(
          active_streams_gather, lut_ids, lut_lambdas, LUT_0_FOR_ALL_BLOCKS);
    }

    auto alloc_ct = [&](uint32_t num_blocks) {
      auto *ct = new CudaRadixCiphertextFFI;
      create_zero_radix_ciphertext_async<Torus>(
          streams.stream(0), streams.gpu_index(0), ct, num_blocks,
          params.big_lwe_dimension, size_tracker, allocate_gpu_memory);
      return ct;
    };
    this->buf_b = alloc_ct(NUM_BITS * N);
    this->buf_b2 = alloc_ct(NUM_BITS * N);
    this->buf_u4 = alloc_ct(NUM_WORDS * N);
    this->buf_u2q = alloc_ct(NUM_U2 * N);
    this->buf_sum = alloc_ct(NUM_U2 * N);
    this->buf_k_first = alloc_ct(NUM_U2 * N);
    this->buf_k_second = alloc_ct(NUM_U2 * N);
    this->key_bits_first = alloc_ct(NUM_BITS * N);
    this->key_bits_second = alloc_ct(NUM_BITS * N);
    this->kap_bw_first = alloc_ct(NUM_BITS * N);
    this->kap_bw_second = alloc_ct(NUM_BITS * N);
    this->kap_mid_first = alloc_ct(NUM_BITS * N);

    // The state is word major and lane fast, so a map in word space already
    // describes every lane
    auto build_map =
        [&](radix_index_table<uint32_t> &map, uint32_t num_words,
            uint32_t num_terms,
            const std::function<uint32_t(uint32_t, uint32_t)> &word_source) {
          maps.create(streams, allocate_gpu_memory, size_tracker, map,
                      num_words, num_terms, N, N, word_source);
        };
    // Same, reading a source the batch shares: a key half has no lane of its
    // own
    auto build_tile_map =
        [&](radix_index_table<uint32_t> &map, uint32_t num_words,
            const std::function<uint32_t(uint32_t)> &word_source) {
          maps.create(streams, allocate_gpu_memory, size_tracker, map,
                      num_words, 1, N, 1,
                      [&](uint32_t w, uint32_t) { return word_source(w); });
        };
    // Crossing lanes leaves word space, which is why the transposes, and only
    // they, are spelled out block by block
    auto build_block_map =
        [&](radix_index_table<uint32_t> &map, uint32_t num_out_blocks,
            const std::function<uint32_t(uint32_t)> &block_source) {
          maps.create(streams, allocate_gpu_memory, size_tracker, map,
                      num_out_blocks, 1, 1, 1,
                      [&](uint32_t o, uint32_t) { return block_source(o); });
        };

    build_tile_map(map_key_tile, NUM_U2, [](uint32_t w) { return w; });
    build_tile_map(map_tile64, NUM_BITS, [](uint32_t w) { return w; });
    build_block_map(map_transpose_in, NUM_U2 * N, [&](uint32_t o) {
      uint32_t w = o / N, lane = o % N;
      return lane * NUM_U2 + w;
    });
    build_block_map(map_transpose_out, NUM_U2 * N, [&](uint32_t o) {
      uint32_t lane = o / NUM_U2, w = o % NUM_U2;
      return w * N + lane;
    });
    build_map(map_pair, NUM_WORDS, 2,
              [](uint32_t w, uint32_t t) { return 2 * w + t; });
    build_map(map_stage_x4, NUM_BITS, 1,
              [](uint32_t idx, uint32_t) { return idx >> 2; });
    build_map(map_stage_x2, NUM_U2, 1,
              [](uint32_t idx, uint32_t) { return idx >> 1; });
    build_map(map_perm_pair_mid, NUM_U2, 2,
              [](uint32_t n, uint32_t t) { return FHE_M_PERM[2 * n + t]; });
    build_map(map_mperm_comb, NUM_WORDS, 4,
              [](uint32_t w, uint32_t t) { return FHE_M_PERM[4 * w + t]; });
    build_map(map_fw_sum3, NUM_BITS, 3, [](uint32_t i, uint32_t tt) {
      return prince_sum3_source(FHE_MP_PERM_FW[i], tt, false);
    });
    build_map(map_mid_sum3, NUM_BITS, 3, [](uint32_t m, uint32_t tt) {
      return prince_sum3_source(m, tt, false);
    });
    build_map(map_bw_sum3, NUM_BITS, 3, [](uint32_t m, uint32_t tt) {
      return prince_sum3_source(m, tt, true);
    });
    build_map(map_comb4_id, NUM_WORDS, 4,
              [](uint32_t w, uint32_t t) { return 4 * w + t; });

    auto build_word_lut_indexes =
        [&](radix_index_table<Torus> &lut_idx, uint32_t num_blocks,
            const std::function<uint32_t(uint32_t)> &word_lut_id) {
          lut_indexes.create(streams, allocate_gpu_memory, size_tracker,
                             lut_idx, num_blocks, 1, 1, 1,
                             [&](uint32_t i, uint32_t) -> Torus {
                               return word_lut_id(i / N);
                             });
        };
    auto build_capped_lut_indexes = [&](radix_index_table<Torus> &lut_idx,
                                        uint32_t base, uint32_t cap) {
      build_word_lut_indexes(lut_idx, NUM_BITS * N, [base, cap](uint32_t idx) {
        return idx < cap ? base + idx : 0;
      });
    };
    for (uint32_t r = 0; r < 5; ++r)
      build_capped_lut_indexes(lut_idx_fw_sbox[r], fw_base[r], NUM_BITS);
    build_capped_lut_indexes(lut_idx_mid_in, mid_in_base, NUM_BITS);
    build_capped_lut_indexes(lut_idx_mid_out, mid_out_base, NUM_BITS);
    for (uint32_t r = 0; r < 4; ++r)
      build_capped_lut_indexes(lut_idx_bw_sbox[r], bw_base[r], NUM_BITS);
    build_capped_lut_indexes(lut_idx_bw_sbox[4], bw_base[4], NUM_U2);
    build_word_lut_indexes(lut_idx_par_fw, NUM_BITS * N,
                           [](uint32_t i) { return i & 3; });
    build_word_lut_indexes(lut_idx_par_bw, NUM_BITS * N,
                           [](uint32_t m) { return (m >> 2) & 3; });
    build_word_lut_indexes(lut_idx_par_mid, NUM_BITS * N,
                           [](uint32_t m) { return (m >> 2) & 1; });
  }

  void release(CudaStreams streams) {
    lut_flat32->release(streams);
    delete lut_flat32;
    lut_flat32 = nullptr;

    lut_gather64->release(streams);
    delete lut_gather64;
    lut_gather64 = nullptr;

    for (auto *ct : {&buf_b, &buf_b2, &buf_u4, &buf_u2q, &buf_sum, &buf_k_first,
                     &buf_k_second, &key_bits_first, &key_bits_second,
                     &kap_bw_first, &kap_bw_second, &kap_mid_first}) {
      release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                     *ct, allocate_gpu_memory);
      delete *ct;
      *ct = nullptr;
    }

    maps.release(streams, allocate_gpu_memory);
    lut_indexes.release(streams, allocate_gpu_memory);
  }
};

#endif // PRINCE_UTILITIES_H
