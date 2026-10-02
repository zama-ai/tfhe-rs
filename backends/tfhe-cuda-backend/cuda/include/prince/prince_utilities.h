#ifndef PRINCE_UTILITIES_H
#define PRINCE_UTILITIES_H

#include "../integer/integer_utilities.h"
#include <array>
#include <cstdint>
#include <cstring>
#include <map>
#include <vector>

/* PRINCEv2 [BEK+20] constants and tables, all derived at compile time from
 * the spec (S-box, round constants, M' and SR). Round constants and the alpha
 * reflection get folded into the S-box tables so they cost no FHE op. */
namespace prince_v2 {

/// @brief Nibbles in the state, what an S-box reads
constexpr uint32_t NUM_WORDS = 16;
/// @brief 2-bit blocks in the state, the API layout
constexpr uint32_t NUM_U2 = 32;
/// @brief Bits in the state
constexpr uint32_t NUM_BITS = 64;
/// @brief Round constants, RC_0 to RC_11
constexpr uint32_t NUM_ROUNDS = 12;

using ZLut = std::array<std::array<uint8_t, 16>, 16>; // 16 per-word 4->4 LUTs
using U4Vec = std::array<uint8_t, 16>;

/// @brief PRINCEv2 round constants
constexpr uint64_t RC_V2[NUM_ROUNDS] = {
    0x0000000000000000, 0x13198a2e03707344, 0xa4093822299f31d0,
    0x082efa98ec4e6c89, 0x452821e638d01377, 0xbe5466cf34e90c6c,
    0x7ef84f78fd955cb1, 0x7aacf4538d971a60, 0xc882d32f25323c54,
    0x9b8ded979cd838c7, 0xd3b5a399ca0c2399, 0x3f84d5b5b5470917,
};
/// @brief Middle layer constant
constexpr uint64_t RC_BETA = 0x3f84d5b5b5470917;

/// @brief SR as a gather, output word w takes input word PERM[w]
constexpr uint32_t PERM[NUM_WORDS] = {0x0, 0x5, 0xa, 0xf, 0x4, 0x9, 0xe, 0x3,
                                      0x8, 0xd, 0x2, 0x7, 0xc, 0x1, 0x6, 0xb};

/// @brief Inverts PERM.
constexpr std::array<uint32_t, NUM_WORDS> build_iperm() {
  std::array<uint32_t, NUM_WORDS> iperm{};
  for (uint32_t w = 0; w < NUM_WORDS; ++w)
    iperm[PERM[w]] = w;
  return iperm;
}
/// @brief SR^-1 as a gather, for the backward rounds
constexpr std::array<uint32_t, NUM_WORDS> IPERM = build_iperm();

/// @brief Plaintext M', only used at compile time to pull constants back
/// through the linear layer.
///
/// M' = diag(M0, M1, M1, M0), block (r, c) of Mk is m_{(r + c + k) mod 4} with
/// m_i the identity minus entry i. So each output bit is the XOR of 3 of the 4
/// bits in its column. Bits MSB first. M' is an involution.
///
/// @param x State, MSB first
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

/// @brief Plaintext SR^-1, compile time only like m_prime.
///
/// @param x State, MSB first
constexpr uint64_t inv_shift_rows(uint64_t x) {
  uint64_t out = 0;
  for (uint32_t w = 0; w < NUM_WORDS; ++w)
    out |= ((x >> (60 - 4 * w)) & 0xf) << (60 - 4 * PERM[w]);
  return out;
}

/// @brief Round constants pulled back through M = SR . M', so an S-box table
/// sitting before the linear layer can absorb them.
///
/// Computed rather than copied so they can't drift from RC_V2.
constexpr std::array<uint64_t, NUM_ROUNDS> build_rc_v2_ip_im() {
  std::array<uint64_t, NUM_ROUNDS> rc{};
  for (uint32_t i = 0; i < NUM_ROUNDS; ++i)
    rc[i] = m_prime(inv_shift_rows(RC_V2[i]));
  return rc;
}
/// @brief M'(SR^-1(RC_i)), see build_rc_v2_ip_im
constexpr std::array<uint64_t, NUM_ROUNDS> RC_V2_IP_IM = build_rc_v2_ip_im();
/// @brief M'(RC_BETA), same idea for the middle round
constexpr uint64_t RC_BETA_IM = m_prime(RC_BETA);

/// @brief Splits a u64 into 16 nibbles, MSB first.
///
/// @param u Value to split
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

/// @brief S-box with a per-word constant xored on each side,
/// zlut[w][x] = sbox[x ^ inner[w]] ^ outer[w]. This is how the round
/// constants end up costing nothing.
///
/// @param sbox SBOX or INV_SBOX
/// @param xor_inner Per-word constant xored on the input
/// @param xor_outer Per-word constant xored on the output
constexpr ZLut build_zlut_xsy(const uint8_t (&sbox)[16], U4Vec xor_inner,
                              U4Vec xor_outer) {
  ZLut z{};
  for (uint32_t w = 0; w < NUM_WORDS; ++w)
    for (uint32_t x = 0; x < 16; ++x)
      z[w][x] = (uint8_t)(sbox[(x ^ xor_inner[w]) & 0xf] ^ xor_outer[w]);
  return z;
}

/// @brief No constant, for a side with nothing to fold
constexpr U4Vec ZERO_NIBBLES{};

// Naming, PV2_t_S_u is RC_t in, S-box, RC_u (pulled back through M) out.
// PV2_t_IS_u is the mirror, RC_t pulled back in, inverse S-box, RC_u out.
// M stands for RC_BETA, A and B for 10 and 11.

/// @brief Plain S-box, for rounds with nothing to fold
constexpr ZLut PV2_0_S_0 = build_zlut_xsy(SBOX, ZERO_NIBBLES, ZERO_NIBBLES);
/// @brief Encryption fw[1]
constexpr ZLut PV2_1_S_2 = build_zlut_xsy(SBOX, u64_to_vec_u4(RC_V2[1]),
                                          u64_to_vec_u4(RC_V2_IP_IM[2]));
/// @brief Encryption fw[3]
constexpr ZLut PV2_3_S_4 = build_zlut_xsy(SBOX, u64_to_vec_u4(RC_V2[3]),
                                          u64_to_vec_u4(RC_V2_IP_IM[4]));
/// @brief Encryption, entering the middle round
constexpr ZLut PV2_5_S_M =
    build_zlut_xsy(SBOX, u64_to_vec_u4(RC_V2[5]), u64_to_vec_u4(RC_BETA_IM));
/// @brief Plain inverse S-box, for rounds with nothing to fold
constexpr ZLut PV2_0_IS_0 =
    build_zlut_xsy(INV_SBOX, ZERO_NIBBLES, ZERO_NIBBLES);
/// @brief Encryption bw[0]
constexpr ZLut PV2_6_IS_7 = build_zlut_xsy(
    INV_SBOX, u64_to_vec_u4(RC_V2_IP_IM[6]), u64_to_vec_u4(RC_V2[7]));
/// @brief Encryption bw[2]
constexpr ZLut PV2_8_IS_9 = build_zlut_xsy(
    INV_SBOX, u64_to_vec_u4(RC_V2_IP_IM[8]), u64_to_vec_u4(RC_V2[9]));
/// @brief Encryption bw[4], also folds the final RC_11
constexpr ZLut PV2_A_IS_B = build_zlut_xsy(
    INV_SBOX, u64_to_vec_u4(RC_V2_IP_IM[10]), u64_to_vec_u4(RC_V2[11]));

// Decryption runs the same circuit with the keys swapped (alpha reflection),
// only the tables change

/// @brief Decryption fw[0], also folds the initial RC_11
constexpr ZLut PV2_B_S_A = build_zlut_xsy(SBOX, u64_to_vec_u4(RC_V2[11]),
                                          u64_to_vec_u4(RC_V2_IP_IM[10]));
/// @brief Decryption fw[2]
constexpr ZLut PV2_9_S_8 = build_zlut_xsy(SBOX, u64_to_vec_u4(RC_V2[9]),
                                          u64_to_vec_u4(RC_V2_IP_IM[8]));
/// @brief Decryption fw[4]
constexpr ZLut PV2_7_S_6 = build_zlut_xsy(SBOX, u64_to_vec_u4(RC_V2[7]),
                                          u64_to_vec_u4(RC_V2_IP_IM[6]));
/// @brief Decryption, leaving the middle round
constexpr ZLut PV2_M_IS_5 = build_zlut_xsy(INV_SBOX, u64_to_vec_u4(RC_BETA_IM),
                                           u64_to_vec_u4(RC_V2[5]));
/// @brief Decryption bw[1]
constexpr ZLut PV2_4_IS_3 = build_zlut_xsy(
    INV_SBOX, u64_to_vec_u4(RC_V2_IP_IM[4]), u64_to_vec_u4(RC_V2[3]));
/// @brief Decryption bw[3]
constexpr ZLut PV2_2_IS_1 = build_zlut_xsy(
    INV_SBOX, u64_to_vec_u4(RC_V2_IP_IM[2]), u64_to_vec_u4(RC_V2[1]));

/// @brief Maps each output bit of Mk to the parity term it reads. Terms are
/// indexed 4j + s, column j with element s left out.
///
/// @param k 0 for M0, 1 for M1
constexpr std::array<uint32_t, 16> build_fhe_mk_perm(uint32_t k) {
  std::array<uint32_t, 16> perm{};
  for (uint32_t r = 0; r < 4; ++r)
    for (uint32_t j = 0; j < 4; ++j)
      perm[4 * r + j] = 4 * j + (j + 8 - r - k) % 4;
  return perm;
}
/// @brief build_fhe_mk_perm for M0
constexpr std::array<uint32_t, 16> FHE_M0_PERM = build_fhe_mk_perm(0);
/// @brief build_fhe_mk_perm for M1
constexpr std::array<uint32_t, 16> FHE_M1_PERM = build_fhe_mk_perm(1);

/// @brief Same over the whole state, M' = diag(M0, M1, M1, M0)
constexpr std::array<uint32_t, NUM_BITS> build_fhe_m_perm() {
  std::array<uint32_t, NUM_BITS> m_perm{};
  for (uint32_t n = 0; n < 4; ++n)
    for (uint32_t p = 0; p < 16; ++p)
      m_perm[p + n * 16] =
          n * 16 + ((n == 0 || n == 3) ? FHE_M0_PERM[p] : FHE_M1_PERM[p]);
  return m_perm;
}
/// @brief Output bit of M' to the parity term it reads
constexpr std::array<uint32_t, NUM_BITS> FHE_M_PERM = build_fhe_m_perm();

/// @brief Inverts FHE_M_PERM. The middle round adds k_second right after M',
/// so it needs those bits in parity term order.
constexpr std::array<uint32_t, NUM_BITS> build_inv_fhe_m_perm() {
  std::array<uint32_t, NUM_BITS> inv{};
  for (uint32_t q = 0; q < NUM_BITS; ++q)
    inv[FHE_M_PERM[q]] = q;
  return inv;
}
/// @brief Parity term to the state bit it becomes
constexpr std::array<uint32_t, NUM_BITS> INV_FHE_M_PERM =
    build_inv_fhe_m_perm();

/// @brief FHE_M_PERM with SR composed in, for the forward rounds
constexpr std::array<uint32_t, NUM_BITS> build_fhe_mp_perm_fw() {
  std::array<uint32_t, NUM_BITS> m_perm{};
  for (uint32_t b = 0; b < NUM_BITS; ++b)
    m_perm[b] = FHE_M_PERM[(PERM[b >> 2] << 2) + (b & 0x3)];
  return m_perm;
}
/// @brief Output bit of M = SR . M' to the parity term it reads
constexpr std::array<uint32_t, NUM_BITS> FHE_MP_PERM_FW =
    build_fhe_mp_perm_fw();

/// @brief S-box tables of one direction. Encryption and decryption share the
/// circuit, only these tables and the key order differ
struct prince_table_set {
  /// @brief One per forward round
  const ZLut *fw[5];
  /// @brief S-box entering the middle round
  const ZLut *mid_in;
  /// @brief Inverse S-box leaving it
  const ZLut *mid_out;
  /// @brief One per backward round
  const ZLut *bw[5];
};

/// @brief Encryption tables
constexpr prince_table_set ENCRYPT_TABLES = {
    {&PV2_0_S_0, &PV2_1_S_2, &PV2_0_S_0, &PV2_3_S_4, &PV2_0_S_0},
    &PV2_5_S_M,
    &PV2_0_IS_0,
    {&PV2_6_IS_7, &PV2_0_IS_0, &PV2_8_IS_9, &PV2_0_IS_0, &PV2_A_IS_B}};

/// @brief Decryption tables
constexpr prince_table_set DECRYPT_TABLES = {
    {&PV2_B_S_A, &PV2_0_S_0, &PV2_9_S_8, &PV2_0_S_0, &PV2_7_S_6},
    &PV2_0_S_0,
    &PV2_M_IS_5,
    {&PV2_0_IS_0, &PV2_4_IS_3, &PV2_0_IS_0, &PV2_2_IS_1, &PV2_0_IS_0}};

} // namespace prince_v2

/// @brief Source bit of term tt of the 3-sum behind parity output p.
///
/// Every linear layer map is built from this. p = 4w + s reads bit w % 4 of
/// the 3 words of its group other than s.
///
/// @param p Parity output, in term order (see FHE_M_PERM)
/// @param tt Term, 0 to 2
/// @param iperm Read the words through SR^-1, as the backward rounds do
constexpr uint32_t prince_sum3_source(uint32_t p, uint32_t tt, bool iperm) {
  uint32_t w = p >> 2, b = p & 3;
  uint32_t k = (tt >= b) ? tt + 1 : tt;
  uint32_t ws = iperm ? prince_v2::IPERM[4 * (w >> 2) + k] : 4 * (w >> 2) + k;
  return 4 * ws + (w & 3);
}

/// @brief Scratch of the one-off key prep, see host_integer_prince_key_prep.
///
/// Both key halves go through together, 2 PBS launches of 128 blocks instead
/// of 4 of 64, which cost about the same each at that width. No batch
/// dimension, one prep serves any batch size.
template <typename Torus> struct int_prince_key_prep_buffer {
  int_radix_params params;
  bool allocate_gpu_memory;

  /// @brief Slot 0 keeps the low bit (low key bit, and parity of a 3-sum),
  /// slot 1 the high bit
  int_radix_lut<Torus> *lut;
  /// @brief k_first then k_second, 64 blocks
  CudaRadixCiphertextFFI *buf_keys = nullptr;
  /// @brief Each key u2 twice, one copy per bit to extract
  CudaRadixCiphertextFFI *buf_a = nullptr;
  /// @brief Key bits of both halves, 128 blocks
  CudaRadixCiphertextFFI *buf_bits = nullptr;
  /// @brief 3-sums waiting for the parity PBS
  CudaRadixCiphertextFFI *buf_b = nullptr;
  /// @brief kap of both halves, 128 blocks
  CudaRadixCiphertextFFI *buf_kap = nullptr;

  /// @brief Owner of the gather maps below
  radix_index_tables<uint32_t> maps;
  /// @brief Owner of the LUT index tables below
  radix_index_tables<Torus> lut_indexes;

  // Gather maps, "128 from 64, K=1" reads 128 outputs from 64 inputs, K terms
  // each
  /// @brief 128 from 64, K=1, each u2 twice
  radix_index_table<uint32_t> map_dup;
  /// @brief 128 from 128, K=3, 3-sums of M'(SR^-1(.)) for each half
  radix_index_table<uint32_t> map_bw_sum3;
  /// @brief Alternates slot 1 and 0, high then low bit of each u2
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

    this->lut = new int_radix_lut<Torus>(streams, params, 2, 2 * NUM_BITS,
                                         allocate_gpu_memory, size_tracker);
    // A size query only needs the allocations, skip the LUT fill
    if (allocate_gpu_memory) {
      std::vector<std::function<Torus(Torus)>> fs = {
          [](Torus x) -> Torus { return x & 1; },
          [](Torus x) -> Torus { return (x >> 1) & 1; },
      };
      auto active_streams =
          streams.active_gpu_subset(2 * NUM_BITS, params.pbs_type);
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
    this->buf_keys = alloc_ct(2 * NUM_U2);
    this->buf_a = alloc_ct(2 * NUM_BITS);
    this->buf_bits = alloc_ct(2 * NUM_BITS);
    this->buf_b = alloc_ct(2 * NUM_BITS);
    this->buf_kap = alloc_ct(2 * NUM_BITS);

    // No batch here, a row is a block and each half reads its own 64 bits
    maps.create(streams, allocate_gpu_memory, size_tracker, map_dup,
                2 * NUM_BITS, 1, 1, 1,
                [](uint32_t o, uint32_t) { return o >> 1; });
    maps.create(streams, allocate_gpu_memory, size_tracker, map_bw_sum3,
                2 * NUM_BITS, 3, 1, 1, [](uint32_t m, uint32_t tt) {
                  uint32_t half = m / NUM_BITS;
                  return half * NUM_BITS +
                         prince_sum3_source(m % NUM_BITS, tt, true);
                });
    lut_indexes.create(
        streams, allocate_gpu_memory, size_tracker, lut_idx_keybit,
        2 * NUM_BITS, 1, 1, 1,
        [](uint32_t i, uint32_t) -> Torus { return 1 - (i & 1); });
  }

  void release(CudaStreams streams) {
    lut->release(streams);
    delete lut;
    lut = nullptr;
    for (auto *ct : {&buf_keys, &buf_a, &buf_bits, &buf_b, &buf_kap}) {
      release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                     *ct, allocate_gpu_memory);
      delete *ct;
      *ct = nullptr;
    }
    maps.release(streams, allocate_gpu_memory);
    lut_indexes.release(streams, allocate_gpu_memory);
  }
};

/// @brief Scratch of host_integer_prince, for one batch size and direction.
///
/// The state is word major and lane fast (block = word * N + lane) so maps
/// and LUT indexes are the same for every lane and get built once. Every
/// univariate function of the circuit lives in lut_gather64 as a slot, a
/// layer just swaps indexes instead of regenerating LUTs.
template <typename Torus> struct int_prince_buffer {
  int_radix_params params;
  bool allocate_gpu_memory;
  /// @brief Batch size N
  uint32_t num_inputs;
  /// @brief Slots of lut_gather64
  uint32_t num_gather_luts;

  /// @brief Decodes 4 * m + k into m xor k, for the first and last key xor.
  ///
  /// Slot 0 puts the result in the high half, slot 1 in the low half. The
  /// input layer alternates them so map_pair can add each u2 pair into a
  /// nibble, the output layer stays in u2 and uses slot 1 everywhere.
  int_radix_lut<Torus> *lut_flat32;
  /// @brief Parity slots (weights 8, 4, 2, 1), the 2 xor to bit slots of the
  /// middle round, then a group per distinct S-box table
  int_radix_lut<Torus> *lut_gather64;

  /// @brief State as bits, 64N
  CudaRadixCiphertextFFI *buf_b = nullptr;
  /// @brief 3-sums waiting for the parity PBS, 64N
  CudaRadixCiphertextFFI *buf_b2 = nullptr;
  /// @brief State as nibbles, what the S-box reads, 16N
  CudaRadixCiphertextFFI *buf_u4 = nullptr;
  /// @brief State as u2 in the high half (weights 8 and 4), ready for a key
  /// to be added, 32N
  CudaRadixCiphertextFFI *buf_u2q = nullptr;
  /// @brief 4 * m + k sums for the key xor PBS, 32N
  CudaRadixCiphertextFFI *buf_sum = nullptr;
  /// @brief k_first tiled over the batch, 32N
  CudaRadixCiphertextFFI *buf_k_first = nullptr;
  /// @brief k_second tiled over the batch, 32N
  CudaRadixCiphertextFFI *buf_k_second = nullptr;

  /// @brief Bits of k_first tiled over the batch, 64N
  CudaRadixCiphertextFFI *key_bits_first = nullptr;
  /// @brief Bits of k_second tiled over the batch, 64N
  CudaRadixCiphertextFFI *key_bits_second = nullptr;
  /// @brief M'(SR^-1(k_first)) tiled over the batch, 64N
  CudaRadixCiphertextFFI *kap_bw_first = nullptr;
  /// @brief M'(SR^-1(k_second)) tiled over the batch, 64N
  CudaRadixCiphertextFFI *kap_bw_second = nullptr;
  /// @brief Bits of k_second in parity term order, tiled, 64N. Added by the
  /// middle round right after M'
  CudaRadixCiphertextFFI *key_bits_mid = nullptr;

  /// @brief Owner of the gather maps below
  radix_index_tables<uint32_t> maps;
  /// @brief Owner of the LUT index tables below
  radix_index_tables<Torus> lut_indexes;

  // Gather maps, same notation. Rows cover the N lanes at once, only the
  // transposes cross lanes and list every block
  /// @brief 32N from 32, K=1, lane broadcast
  radix_index_table<uint32_t> map_key_tile;
  /// @brief 64N from 64, K=1, lane broadcast
  radix_index_table<uint32_t> map_tile64;
  /// @brief 64N from 64, K=1, lane broadcast through INV_FHE_M_PERM
  radix_index_table<uint32_t> map_tile64_mid;
  /// @brief 32N from 32N, K=1, instance to word major
  radix_index_table<uint32_t> map_transpose_in;
  /// @brief 32N from 32N, K=1, word to instance major
  radix_index_table<uint32_t> map_transpose_out;
  /// @brief 16N from 32N, K=2, high and low u2 into a nibble
  radix_index_table<uint32_t> map_pair;
  /// @brief 64N from 16N, K=1, each nibble 4 times, one per bit to extract
  radix_index_table<uint32_t> map_stage_x4;
  /// @brief 32N from 16N, K=1, each nibble twice, one per u2 half
  radix_index_table<uint32_t> map_stage_x2;
  /// @brief 64N from 32N, K=1, each 4 * m + k twice, one per bit of the xor
  radix_index_table<uint32_t> map_stage_x2_bits;
  /// @brief 16N from 64N, K=4, parities back into nibbles through FHE_M_PERM
  radix_index_table<uint32_t> map_mperm_comb;
  /// @brief 64N from 64N, K=3, forward round 3-sums, SR composed in
  radix_index_table<uint32_t> map_fw_sum3;
  /// @brief 64N from 64N, K=3, middle round 3-sums
  radix_index_table<uint32_t> map_mid_sum3;
  /// @brief 64N from 64N, K=3, backward round 3-sums, SR^-1 composed in
  radix_index_table<uint32_t> map_bw_sum3;
  /// @brief 16N from 64N, K=4, 4 weighted bits into a nibble
  radix_index_table<uint32_t> map_comb4_id;

  /// @brief S-box bit slots of each forward round
  radix_index_table<Torus> lut_idx_fw_sbox[5];
  /// @brief S-box u2 slots entering the middle round, before its first key
  /// xor
  radix_index_table<Torus> lut_idx_mid_in;
  /// @brief Xor to bit slots of the middle round's first key xor
  radix_index_table<Torus> lut_idx_xor_bits;
  /// @brief Inverse S-box bit slots leaving the middle round
  radix_index_table<Torus> lut_idx_mid_out;
  /// @brief Inverse S-box slots of each backward round, the last one emits u2
  radix_index_table<Torus> lut_idx_bw_sbox[5];
  /// @brief Parity slots of the forward rounds, weight from the bit position
  radix_index_table<Torus> lut_idx_par_fw;
  /// @brief Parity slots of the middle and backward rounds, weight from the
  /// term order
  radix_index_table<Torus> lut_idx_par_bw;

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

    // Parity slots, slot d scales the bit by 2^(3 - d) so a nibble is rebuilt
    // by a plain sum
    for (uint32_t d = 0; d < 4; ++d)
      push_slot([d](Torus x) -> Torus { return (x & 1) << (3 - d); });

    // Xor to bit slots, bit h of the xor of 4 * m + k, at weight 1 for the
    // 3-sum that follows
    const uint32_t xb_base = next_lut_id;
    for (uint32_t h = 0; h < 2; ++h)
      push_slot([h](Torus x) -> Torus {
        return ((((x & 3) ^ ((x >> 2) & 3)) >> (1 - h)) & 1);
      });

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

    // Same tables but emitting u2 in the high half, ready for a key xor
    std::map<const ZLut *, uint32_t> u2h_bases;
    auto u2h_table_base = [&](const ZLut *tbl) -> uint32_t {
      auto it = u2h_bases.find(tbl);
      if (it != u2h_bases.end())
        return it->second;
      uint32_t base = next_lut_id;
      u2h_bases[tbl] = base;
      for (uint32_t w = 0; w < NUM_WORDS; ++w)
        for (uint32_t b = 0; b < 2; ++b)
          push_slot([tbl, w, b](Torus x) -> Torus {
            return ((((*tbl)[w][x & 15] >> (2 - 2 * b)) & 3) << 2);
          });
      return base;
    };

    uint32_t fw_base[5], mid_in_base, mid_out_base, bw_base[5];
    for (uint32_t r = 0; r < 5; ++r)
      fw_base[r] = bit_table_base(tables.fw[r]);
    mid_in_base = u2h_table_base(tables.mid_in);
    mid_out_base = bit_table_base(tables.mid_out);
    for (uint32_t r = 0; r < 4; ++r)
      bw_base[r] = bit_table_base(tables.bw[r]);
    bw_base[4] = u2h_table_base(tables.bw[4]);
    this->num_gather_luts = next_lut_id;

    this->lut_flat32 = new int_radix_lut<Torus>(
        streams, params, 2, NUM_U2 * N, allocate_gpu_memory, size_tracker);
    this->lut_gather64 =
        new int_radix_lut<Torus>(streams, params, num_gather_luts, NUM_BITS * N,
                                 allocate_gpu_memory, size_tracker);

    // LUT fills are slow (host fill and a sync each) and don't count in the
    // size, so a size query skips them
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
    this->key_bits_mid = alloc_ct(NUM_BITS * N);

    // Word space maps, the same for every lane
    auto build_map =
        [&](radix_index_table<uint32_t> &map, uint32_t num_words,
            uint32_t num_terms,
            const std::function<uint32_t(uint32_t, uint32_t)> &word_source) {
          maps.create(streams, allocate_gpu_memory, size_tracker, map,
                      num_words, num_terms, N, N, word_source);
        };
    // Same but the source is shared by the whole batch, like a key
    auto build_tile_map =
        [&](radix_index_table<uint32_t> &map, uint32_t num_words,
            const std::function<uint32_t(uint32_t)> &word_source) {
          maps.create(streams, allocate_gpu_memory, size_tracker, map,
                      num_words, 1, N, 1,
                      [&](uint32_t w, uint32_t) { return word_source(w); });
        };
    // Block by block, only for the transposes since they cross lanes
    auto build_block_map =
        [&](radix_index_table<uint32_t> &map, uint32_t num_out_blocks,
            const std::function<uint32_t(uint32_t)> &block_source) {
          maps.create(streams, allocate_gpu_memory, size_tracker, map,
                      num_out_blocks, 1, 1, 1,
                      [&](uint32_t o, uint32_t) { return block_source(o); });
        };

    build_tile_map(map_key_tile, NUM_U2, [](uint32_t w) { return w; });
    build_tile_map(map_tile64, NUM_BITS, [](uint32_t w) { return w; });
    build_tile_map(map_tile64_mid, NUM_BITS,
                   [](uint32_t w) { return INV_FHE_M_PERM[w]; });
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
    build_map(map_stage_x2_bits, NUM_BITS, 1,
              [](uint32_t p, uint32_t) { return p >> 1; });
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
    build_capped_lut_indexes(lut_idx_mid_in, mid_in_base, NUM_U2);
    build_word_lut_indexes(lut_idx_xor_bits, NUM_BITS * N,
                           [xb_base](uint32_t p) { return xb_base + (p & 1); });
    build_capped_lut_indexes(lut_idx_mid_out, mid_out_base, NUM_BITS);
    for (uint32_t r = 0; r < 4; ++r)
      build_capped_lut_indexes(lut_idx_bw_sbox[r], bw_base[r], NUM_BITS);
    build_capped_lut_indexes(lut_idx_bw_sbox[4], bw_base[4], NUM_U2);
    build_word_lut_indexes(lut_idx_par_fw, NUM_BITS * N,
                           [](uint32_t i) { return i & 3; });
    build_word_lut_indexes(lut_idx_par_bw, NUM_BITS * N,
                           [](uint32_t m) { return (m >> 2) & 3; });
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
                     &kap_bw_first, &kap_bw_second, &key_bits_mid}) {
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
