#ifndef PRINCE_UTILITIES_H
#define PRINCE_UTILITIES_H

#include "../integer/integer_utilities.h"
#include <array>
#include <cstdint>
#include <cstring>
#include <map>
#include <vector>

/* PRINCEv2 [BEK+20] tables, ported from apps/princev2 [BJ26]. Round and
 * alpha-reflection constants are pre-fused so they cost no FHE operation. */
namespace prince_v2 {

constexpr uint32_t NUM_WORDS = 16; // 4-bit nibbles in the 64-bit state
constexpr uint32_t NUM_U2 = 32;    // 2-bit nibbles in the 64-bit state
constexpr uint32_t NUM_BITS = 64;  // bits in the state
constexpr uint32_t NUM_ROUNDS = 12;

using ZLut = std::array<std::array<uint8_t, 16>, 16>; // 16 per-word 4->4 LUTs
using U4Vec = std::array<uint8_t, 16>;

constexpr uint64_t RC_V2[NUM_ROUNDS] = {
    0x0000000000000000, 0x13198a2e03707344, 0xa4093822299f31d0,
    0x082efa98ec4e6c89, 0x452821e638d01377, 0xbe5466cf34e90c6c,
    0x7ef84f78fd955cb1, 0x7aacf4538d971a60, 0xc882d32f25323c54,
    0x9b8ded979cd838c7, 0xd3b5a399ca0c2399, 0x3f84d5b5b5470917,
};
// iM . iP (RC) [from sage script, via apps/princev2/src/pv2_lut.rs]
constexpr uint64_t RC_V2_IP_IM[NUM_ROUNDS] = {
    0x0000000000000000, 0x90ecdeb7cb7fc1ce, 0x81b2cb20a82a2928,
    0x480cdfa91d749037, 0xcb1a13467044d772, 0x9e8995b07a988c08,
    0xe70338c395311a6a, 0x60dc22bf6e681c08, 0x318672daf2dd0655,
    0x2a74fad9b606e252, 0xe96673c424d657ac, 0xabc631f91e2ccb7a,
};
// iM (RC_BETA) where RC_BETA = 0x3f84d5b5b5470917 [from sage script]
constexpr uint64_t RC_BETA_IM = 0x42f93b79daa0eea5;

// u64 -> [u4; 16], element 0 holds the 4 MSBs
constexpr U4Vec u64_to_vec_u4(uint64_t u) {
  U4Vec v{};
  for (uint32_t i = 0; i < NUM_WORDS; ++i)
    v[NUM_WORDS - i - 1] = (uint8_t)((u >> (4 * i)) & 0xf);
  return v;
}

constexpr uint8_t SBOX[16] = {0xb, 0xf, 0x3, 0x2, 0xa, 0xc, 0x9, 0x1,
                              0x6, 0x7, 0x8, 0x0, 0xe, 0x5, 0xd, 0x4};
constexpr uint8_t INV_SBOX[16] = {0xb, 0x7, 0x3, 0x2, 0xf, 0xd, 0x8, 0x9,
                                  0xa, 0x6, 0x4, 0x0, 0x5, 0xe, 0xc, 0x1};

// zlut[w][x] = sbox[x ^ inner[w]] ^ outer[w]
constexpr ZLut build_zlut_xsy(const uint8_t (&sbox)[16], U4Vec xor_inner,
                              U4Vec xor_outer) {
  ZLut z{};
  for (uint32_t w = 0; w < NUM_WORDS; ++w)
    for (uint32_t x = 0; x < 16; ++x)
      z[w][x] = (uint8_t)(sbox[(x ^ xor_inner[w]) & 0xf] ^ xor_outer[w]);
  return z;
}

constexpr U4Vec ZERO_NIBBLES{};

// Encryption tables
constexpr ZLut PV2_0_S_0 = build_zlut_xsy(SBOX, ZERO_NIBBLES, ZERO_NIBBLES);
constexpr ZLut PV2_1_S_2 = build_zlut_xsy(SBOX, u64_to_vec_u4(RC_V2[1]),
                                          u64_to_vec_u4(RC_V2_IP_IM[2]));
constexpr ZLut PV2_3_S_4 = build_zlut_xsy(SBOX, u64_to_vec_u4(RC_V2[3]),
                                          u64_to_vec_u4(RC_V2_IP_IM[4]));
constexpr ZLut PV2_5_S_M =
    build_zlut_xsy(SBOX, u64_to_vec_u4(RC_V2[5]), u64_to_vec_u4(RC_BETA_IM));
constexpr ZLut PV2_0_IS_0 =
    build_zlut_xsy(INV_SBOX, ZERO_NIBBLES, ZERO_NIBBLES);
constexpr ZLut PV2_6_IS_7 = build_zlut_xsy(
    INV_SBOX, u64_to_vec_u4(RC_V2_IP_IM[6]), u64_to_vec_u4(RC_V2[7]));
constexpr ZLut PV2_8_IS_9 = build_zlut_xsy(
    INV_SBOX, u64_to_vec_u4(RC_V2_IP_IM[8]), u64_to_vec_u4(RC_V2[9]));
constexpr ZLut PV2_A_IS_B = build_zlut_xsy(
    INV_SBOX, u64_to_vec_u4(RC_V2_IP_IM[10]), u64_to_vec_u4(RC_V2[11]));

// Additional tables for decryption (alpha-reflection at the table level)
constexpr ZLut PV2_B_S_A = build_zlut_xsy(SBOX, u64_to_vec_u4(RC_V2[11]),
                                          u64_to_vec_u4(RC_V2_IP_IM[10]));
constexpr ZLut PV2_9_S_8 = build_zlut_xsy(SBOX, u64_to_vec_u4(RC_V2[9]),
                                          u64_to_vec_u4(RC_V2_IP_IM[8]));
constexpr ZLut PV2_7_S_6 = build_zlut_xsy(SBOX, u64_to_vec_u4(RC_V2[7]),
                                          u64_to_vec_u4(RC_V2_IP_IM[6]));
constexpr ZLut PV2_M_IS_5 = build_zlut_xsy(INV_SBOX, u64_to_vec_u4(RC_BETA_IM),
                                           u64_to_vec_u4(RC_V2[5]));
constexpr ZLut PV2_4_IS_3 = build_zlut_xsy(
    INV_SBOX, u64_to_vec_u4(RC_V2_IP_IM[4]), u64_to_vec_u4(RC_V2[3]));
constexpr ZLut PV2_2_IS_1 = build_zlut_xsy(
    INV_SBOX, u64_to_vec_u4(RC_V2_IP_IM[2]), u64_to_vec_u4(RC_V2[1]));

constexpr uint32_t PERM[NUM_WORDS] = {0x0, 0x5, 0xa, 0xf, 0x4, 0x9, 0xe, 0x3,
                                      0x8, 0xd, 0x2, 0x7, 0xc, 0x1, 0x6, 0xb};
constexpr uint32_t IPERM[NUM_WORDS] = {0x0, 0xd, 0xa, 0x7, 0x4, 0x1, 0xe, 0xb,
                                       0x8, 0x5, 0x2, 0xf, 0xc, 0x9, 0x6, 0x3};

constexpr uint32_t FHE_M0_PERM[16] = {0x0, 0x5, 0xa, 0xf, 0x3, 0x4, 0x9, 0xe,
                                      0x2, 0x7, 0x8, 0xd, 0x1, 0x6, 0xb, 0xc};
constexpr uint32_t FHE_M1_PERM[16] = {0x3, 0x4, 0x9, 0xe, 0x2, 0x7, 0x8, 0xd,
                                      0x1, 0x6, 0xb, 0xc, 0x0, 0x5, 0xa, 0xf};

// Combined bit permutation for M' = diag(M0, M1, M1, M0)
constexpr std::array<uint32_t, NUM_BITS> build_fhe_m_perm() {
  std::array<uint32_t, NUM_BITS> m_perm{};
  for (uint32_t n = 0; n < 4; ++n)
    for (uint32_t p = 0; p < 16; ++p)
      m_perm[p + n * 16] =
          n * 16 + ((n == 0 || n == 3) ? FHE_M0_PERM[p] : FHE_M1_PERM[p]);
  return m_perm;
}
constexpr std::array<uint32_t, NUM_BITS> FHE_M_PERM = build_fhe_m_perm();

// M' permutation combined with the forward nibble permutation layer SR
constexpr std::array<uint32_t, NUM_BITS> build_fhe_mp_perm_fw() {
  std::array<uint32_t, NUM_BITS> m_perm{};
  for (uint32_t b = 0; b < NUM_BITS; ++b)
    m_perm[b] = FHE_M_PERM[(PERM[b >> 2] << 2) + (b & 0x3)];
  return m_perm;
}
constexpr std::array<uint32_t, NUM_BITS> FHE_MP_PERM_FW =
    build_fhe_mp_perm_fw();

// Table set per direction (pv2_encrypt / pv2_decrypt); the key order
// (first, second) is (k0, k1) for encrypt, (k1, k0) for decrypt
struct prince_table_set {
  const ZLut *fw[5];
  const ZLut *mid_in;
  const ZLut *mid_out;
  const ZLut *bw[5];
};

constexpr prince_table_set ENCRYPT_TABLES = {
    {&PV2_0_S_0, &PV2_1_S_2, &PV2_0_S_0, &PV2_3_S_4, &PV2_0_S_0},
    &PV2_5_S_M,
    &PV2_0_IS_0,
    {&PV2_6_IS_7, &PV2_0_IS_0, &PV2_8_IS_9, &PV2_0_IS_0, &PV2_A_IS_B}};

constexpr prince_table_set DECRYPT_TABLES = {
    {&PV2_B_S_A, &PV2_0_S_0, &PV2_9_S_8, &PV2_0_S_0, &PV2_7_S_6},
    &PV2_0_S_0,
    &PV2_M_IS_5,
    {&PV2_0_IS_0, &PV2_4_IS_3, &PV2_0_IS_0, &PV2_2_IS_1, &PV2_0_IS_0}};

// Compile-time checks against the apps/princev2 unit-test reference values
constexpr bool zlut_eq(const ZLut &a, const uint8_t (&b)[16][16]) {
  for (uint32_t w = 0; w < 16; ++w)
    for (uint32_t x = 0; x < 16; ++x)
      if (a[w][x] != b[w][x])
        return false;
  return true;
}
constexpr bool perm64_eq(const std::array<uint32_t, 64> &a,
                         const uint32_t (&b)[64]) {
  for (uint32_t i = 0; i < 64; ++i)
    if (a[i] != b[i])
      return false;
  return true;
}

constexpr uint8_t REF_ZLUT_1S2[16][16] = {
    {0x7, 0x3, 0xa, 0xb, 0x4, 0x2, 0x9, 0x1, 0xf, 0xe, 0x8, 0x0, 0xd, 0x6, 0xc,
     0x5},
    {0x3, 0x2, 0xe, 0xa, 0x0, 0x8, 0xd, 0xb, 0x1, 0x9, 0x6, 0x7, 0x5, 0xc, 0x4,
     0xf},
    {0x4, 0x0, 0x9, 0x8, 0x7, 0x1, 0xa, 0x2, 0xc, 0xd, 0xb, 0x3, 0xe, 0x5, 0xf,
     0x6},
    {0x5, 0x4, 0x2, 0xa, 0x7, 0xc, 0x6, 0xf, 0xd, 0x9, 0x0, 0x1, 0xe, 0x8, 0x3,
     0xb},
    {0xa, 0xb, 0x4, 0xc, 0x2, 0x9, 0x1, 0x8, 0x7, 0x3, 0xf, 0xe, 0x6, 0x0, 0x5,
     0xd},
    {0x3, 0xb, 0xd, 0xc, 0x6, 0xf, 0x5, 0xe, 0x8, 0x9, 0x0, 0x4, 0x2, 0xa, 0x1,
     0x7},
    {0x1, 0x0, 0x9, 0xd, 0xb, 0x3, 0x8, 0xe, 0xa, 0x2, 0x4, 0x5, 0xf, 0x6, 0xc,
     0x7},
    {0xd, 0x4, 0xe, 0x5, 0x8, 0x0, 0x6, 0x7, 0x9, 0x1, 0xa, 0xc, 0x3, 0x2, 0xb,
     0xf},
    {0x1, 0x5, 0x9, 0x8, 0x0, 0x6, 0x3, 0xb, 0xc, 0xd, 0x2, 0xa, 0x4, 0xf, 0x7,
     0xe},
    {0xa, 0xb, 0x7, 0x3, 0x9, 0x1, 0x4, 0x2, 0x8, 0x0, 0xf, 0xe, 0xc, 0x5, 0xd,
     0x6},
    {0x3, 0xb, 0xe, 0x8, 0x0, 0x1, 0xd, 0x9, 0x6, 0xf, 0x7, 0xc, 0x2, 0xa, 0x5,
     0x4},
    {0x1, 0x5, 0x9, 0x8, 0x0, 0x6, 0x3, 0xb, 0xc, 0xd, 0x2, 0xa, 0x4, 0xf, 0x7,
     0xe},
    {0x3, 0xb, 0xe, 0x8, 0x0, 0x1, 0xd, 0x9, 0x6, 0xf, 0x7, 0xc, 0x2, 0xa, 0x5,
     0x4},
    {0xb, 0xa, 0x6, 0x2, 0x8, 0x0, 0x5, 0x3, 0x9, 0x1, 0xe, 0xf, 0xd, 0x4, 0xc,
     0x7},
    {0x8, 0xe, 0xb, 0x3, 0x9, 0xd, 0x1, 0x0, 0xc, 0x7, 0xf, 0x6, 0x4, 0x5, 0xa,
     0x2},
    {0x2, 0x4, 0x1, 0x9, 0x3, 0x7, 0xb, 0xa, 0x6, 0xd, 0x5, 0xc, 0xe, 0xf, 0x0,
     0x8},
};
static_assert(zlut_eq(PV2_1_S_2, REF_ZLUT_1S2),
              "PV2_1_S_2 does not match the reference from pv2_lut.rs");

constexpr uint8_t REF_ZLUT_5SM[16][16] = {
    {0x4, 0xc, 0x3, 0x2, 0x0, 0x9, 0x1, 0xa, 0x6, 0x7, 0xb, 0xf, 0x5, 0xd, 0x8,
     0xe},
    {0xf, 0x6, 0xc, 0x7, 0xa, 0x2, 0x4, 0x5, 0xb, 0x3, 0x8, 0xe, 0x1, 0x0, 0x9,
     0xd},
    {0x3, 0x5, 0xe, 0x6, 0x0, 0x4, 0xd, 0xc, 0xa, 0x1, 0xb, 0x2, 0x8, 0x9, 0xf,
     0x7},
    {0x3, 0x5, 0x0, 0x8, 0x2, 0x6, 0xa, 0xb, 0x7, 0xc, 0x4, 0xd, 0xf, 0xe, 0x1,
     0x9},
    {0xa, 0x2, 0x9, 0xf, 0x0, 0x1, 0x8, 0xc, 0xe, 0x7, 0xd, 0x6, 0xb, 0x3, 0x5,
     0x4},
    {0x2, 0xa, 0x1, 0x7, 0x8, 0x9, 0x0, 0x4, 0x6, 0xf, 0x5, 0xe, 0x3, 0xb, 0xd,
     0xc},
    {0x9, 0x2, 0xa, 0x3, 0x1, 0x0, 0xf, 0x7, 0xd, 0xb, 0xe, 0x6, 0xc, 0x8, 0x4,
     0x5},
    {0xd, 0x4, 0xc, 0x7, 0x9, 0x1, 0xe, 0xf, 0x8, 0x0, 0x5, 0x3, 0xb, 0xa, 0x6,
     0x2},
    {0xf, 0xe, 0x2, 0x6, 0xc, 0x4, 0x1, 0x7, 0xd, 0x5, 0xa, 0xb, 0x9, 0x0, 0x8,
     0x3},
    {0x0, 0x6, 0x3, 0xb, 0x1, 0x5, 0x9, 0x8, 0x4, 0xf, 0x7, 0xe, 0xc, 0xd, 0x2,
     0xa},
    {0x7, 0xe, 0x4, 0xf, 0x2, 0xa, 0xc, 0xd, 0x3, 0xb, 0x0, 0x6, 0x9, 0x8, 0x1,
     0x5},
    {0x7, 0x6, 0x0, 0x8, 0x5, 0xe, 0x4, 0xd, 0xf, 0xb, 0x2, 0x3, 0xc, 0xa, 0x1,
     0x9},
    {0x5, 0x1, 0xd, 0xc, 0x4, 0x2, 0x7, 0xf, 0x8, 0x9, 0x6, 0xe, 0x0, 0xb, 0x3,
     0xa},
    {0x0, 0xb, 0x3, 0xa, 0x8, 0x9, 0x6, 0xe, 0x4, 0x2, 0x7, 0xf, 0x5, 0x1, 0xd,
     0xc},
    {0x3, 0xb, 0x0, 0x6, 0x9, 0x8, 0x1, 0x5, 0x7, 0xe, 0x4, 0xf, 0x2, 0xa, 0xc,
     0xd},
    {0xb, 0x0, 0x8, 0x1, 0x3, 0x2, 0xd, 0x5, 0xf, 0x9, 0xc, 0x4, 0xe, 0xa, 0x6,
     0x7},
};
static_assert(zlut_eq(PV2_5_S_M, REF_ZLUT_5SM),
              "PV2_5_S_M does not match the reference from pv2_lut.rs");

constexpr uint8_t REF_ZLUT_6IS7[16][16] = {
    {0xb, 0x6, 0x2, 0x9, 0x3, 0x7, 0xd, 0x1, 0xf, 0xe, 0x8, 0xa, 0x4, 0x5, 0xc,
     0x0},
    {0x3, 0x2, 0x7, 0x5, 0x8, 0x9, 0xd, 0x1, 0xb, 0x6, 0x4, 0xf, 0xa, 0xe, 0xc,
     0x0},
    {0x1, 0xd, 0x9, 0x8, 0x5, 0x7, 0x2, 0x3, 0x0, 0xc, 0xe, 0xa, 0xf, 0x4, 0x6,
     0xb},
    {0xe, 0xf, 0xb, 0x7, 0x5, 0x4, 0x1, 0x3, 0xc, 0x8, 0xa, 0x6, 0xd, 0x0, 0x2,
     0x9},
    {0xd, 0xc, 0x8, 0x4, 0x6, 0x7, 0x2, 0x0, 0xf, 0xb, 0x9, 0x5, 0xe, 0x3, 0x1,
     0xa},
    {0xe, 0x2, 0x0, 0x4, 0x1, 0xa, 0x8, 0x5, 0xf, 0x3, 0x7, 0x6, 0xb, 0x9, 0xc,
     0xd},
    {0x0, 0xb, 0x9, 0x4, 0xf, 0x3, 0x1, 0x5, 0xa, 0x8, 0xd, 0xc, 0xe, 0x2, 0x6,
     0x7},
    {0x1, 0x0, 0x4, 0x8, 0xa, 0xb, 0xe, 0xc, 0x3, 0x7, 0x5, 0x9, 0x2, 0xf, 0xd,
     0x6},
    {0xe, 0x2, 0x8, 0xc, 0x6, 0xd, 0x9, 0x4, 0xf, 0x3, 0xa, 0xb, 0x5, 0x7, 0x1,
     0x0},
    {0x0, 0x2, 0x4, 0x5, 0xa, 0x6, 0xf, 0xe, 0x3, 0x8, 0xc, 0x1, 0xb, 0x7, 0xd,
     0x9},
    {0xb, 0xa, 0xe, 0x2, 0x0, 0x1, 0x4, 0x6, 0x9, 0xd, 0xf, 0x3, 0x8, 0x5, 0x7,
     0xc},
    {0x0, 0xc, 0x5, 0x4, 0xa, 0x8, 0xe, 0xf, 0x1, 0xd, 0x7, 0x3, 0x9, 0x2, 0x6,
     0xb},
    {0x6, 0xa, 0x3, 0x2, 0xc, 0xe, 0x8, 0x9, 0x7, 0xb, 0x1, 0x5, 0xf, 0x4, 0x0,
     0xd},
    {0xe, 0xa, 0x0, 0xc, 0x6, 0xb, 0xf, 0x4, 0x9, 0x8, 0x1, 0xd, 0x2, 0x3, 0x5,
     0x7},
    {0xe, 0xf, 0x9, 0xb, 0x5, 0x4, 0xd, 0x1, 0xa, 0x7, 0x3, 0x8, 0x2, 0x6, 0xc,
     0x0},
    {0x4, 0x0, 0xa, 0x6, 0xc, 0x1, 0x5, 0xe, 0x3, 0x2, 0xb, 0x7, 0x8, 0x9, 0xf,
     0xd},
};
static_assert(zlut_eq(PV2_6_IS_7, REF_ZLUT_6IS7),
              "PV2_6_IS_7 does not match the reference from pv2_lut.rs");

constexpr uint32_t REF_FHE_MP_PERM_FW[64] = {
    0x00, 0x05, 0x0a, 0x0f, 0x12, 0x17, 0x18, 0x1d, 0x21, 0x26, 0x2b,
    0x2c, 0x31, 0x36, 0x3b, 0x3c, 0x13, 0x14, 0x19, 0x1e, 0x22, 0x27,
    0x28, 0x2d, 0x32, 0x37, 0x38, 0x3d, 0x01, 0x06, 0x0b, 0x0c, 0x23,
    0x24, 0x29, 0x2e, 0x33, 0x34, 0x39, 0x3e, 0x02, 0x07, 0x08, 0x0d,
    0x10, 0x15, 0x1a, 0x1f, 0x30, 0x35, 0x3a, 0x3f, 0x03, 0x04, 0x09,
    0x0e, 0x11, 0x16, 0x1b, 0x1c, 0x20, 0x25, 0x2a, 0x2f,
};
static_assert(perm64_eq(FHE_MP_PERM_FW, REF_FHE_MP_PERM_FW),
              "FHE_MP_PERM_FW does not match the reference from permute.rs");

} // namespace prince_v2

// Index arrays of the levelled layers, host copies for degree bookkeeping:
// a gather map sums num_terms source blocks per output block, a LUT pattern
// selects one accumulator per block
struct prince_gather_map {
  uint32_t *h = nullptr;
  uint32_t *d = nullptr;
  uint32_t num_terms = 0;
  uint32_t num_out_blocks = 0;
};
template <typename Torus> struct prince_lut_pattern {
  Torus *h = nullptr;
  Torus *d = nullptr;
};

inline void prince_build_map(
    CudaStreams streams, bool allocate_gpu_memory, uint64_t &size_tracker,
    prince_gather_map &map, uint32_t num_out_blocks, uint32_t num_terms,
    const std::function<uint32_t(uint32_t, uint32_t)> &block_source) {
  map.num_terms = num_terms;
  map.num_out_blocks = num_out_blocks;
  uint64_t map_bytes =
      safe_mul_sizeof<uint32_t>((size_t)num_out_blocks, (size_t)num_terms);
  map.h = (uint32_t *)malloc(map_bytes);
  PANIC_IF_FALSE(map.h != nullptr, "prince gather map: host allocation failed");
  for (uint32_t o = 0; o < num_out_blocks; ++o)
    for (uint32_t t = 0; t < num_terms; ++t)
      map.h[o * num_terms + t] = block_source(o, t);
  map.d = (uint32_t *)cuda_malloc_with_size_tracking_async(
      map_bytes, streams.stream(0), streams.gpu_index(0), size_tracker,
      allocate_gpu_memory);
  cuda_memcpy_with_size_tracking_async_to_gpu(
      map.d, map.h, map_bytes, streams.stream(0), streams.gpu_index(0),
      allocate_gpu_memory);
}

template <typename Torus>
void prince_build_pattern(CudaStreams streams, bool allocate_gpu_memory,
                          uint64_t &size_tracker,
                          prince_lut_pattern<Torus> &pat, uint32_t num_blocks,
                          const std::function<uint32_t(uint32_t)> &lut_id) {
  uint64_t pat_bytes = safe_mul_sizeof<Torus>((size_t)num_blocks);
  pat.h = (Torus *)malloc(pat_bytes);
  PANIC_IF_FALSE(pat.h != nullptr,
                 "prince LUT pattern: host allocation failed");
  for (uint32_t i = 0; i < num_blocks; ++i)
    pat.h[i] = lut_id(i);
  pat.d = (Torus *)cuda_malloc_with_size_tracking_async(
      pat_bytes, streams.stream(0), streams.gpu_index(0), size_tracker,
      allocate_gpu_memory);
  cuda_memcpy_with_size_tracking_async_to_gpu(
      pat.d, pat.h, pat_bytes, streams.stream(0), streams.gpu_index(0),
      allocate_gpu_memory);
}

inline void prince_release_map(CudaStreams streams, bool allocate_gpu_memory,
                               prince_gather_map &map) {
  if (map.d != nullptr && allocate_gpu_memory)
    cuda_drop_async(map.d, streams.stream(0), streams.gpu_index(0));
  map.d = nullptr;
}
template <typename Torus>
void prince_release_pattern(CudaStreams streams, bool allocate_gpu_memory,
                            prince_lut_pattern<Torus> &pat) {
  if (pat.d != nullptr && allocate_gpu_memory)
    cuda_drop_async(pat.d, streams.stream(0), streams.gpu_index(0));
  pat.d = nullptr;
}

// tt-th of the 3 e-xor input bits of output bit p = 4w' + b: bit w'%4 of
// word k != b of nibble group w'/4 (through IPERM for backward rounds)
constexpr uint32_t prince_sum3_source(uint32_t p, uint32_t tt, bool iperm) {
  uint32_t w = p >> 2, b = p & 3;
  uint32_t k = (tt >= b) ? tt + 1 : tt;
  uint32_t ws = iperm ? prince_v2::IPERM[4 * (w >> 2) + k] : 4 * (w >> 2) + k;
  return 4 * ws + (w & 3);
}

// Key preparation scratch: raw 32-block key half -> 64 key bits and 64
// three-bit key parities (kappa). Lane-free, so it serves any batch size.
template <typename Torus> struct int_prince_key_prep_buffer {
  int_radix_params params;
  bool allocate_gpu_memory;

  // slots: 0 = x & 1, serving both the low bit of a u2 block and the 3-bit
  // parity; 1 = the high bit
  int_radix_lut<Torus> *lut;
  CudaRadixCiphertextFFI *buf_a = nullptr; // 64 blocks
  CudaRadixCiphertextFFI *buf_b = nullptr; // 64 blocks

  prince_gather_map map_dup;      // 64 <- 32, K=1 (each u2 twice)
  prince_gather_map map_bw_sum3;  // 64 <- 64, K=3 (IPERM-addressed parity)
  prince_gather_map map_mid_sum3; // 64 <- 64, K=3 (direct parity)
  prince_lut_pattern<Torus> pat_keybit; // 64 entries, slots 1/0 alternating

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

    prince_build_map(streams, allocate_gpu_memory, size_tracker, map_dup,
                     NUM_BITS, 1, [](uint32_t o, uint32_t) { return o >> 1; });
    prince_build_map(streams, allocate_gpu_memory, size_tracker, map_bw_sum3,
                     NUM_BITS, 3, [](uint32_t m, uint32_t tt) {
                       return prince_sum3_source(m, tt, true);
                     });
    prince_build_map(streams, allocate_gpu_memory, size_tracker, map_mid_sum3,
                     NUM_BITS, 3, [](uint32_t m, uint32_t tt) {
                       return prince_sum3_source(m, tt, false);
                     });
    prince_build_pattern<Torus>(streams, allocate_gpu_memory, size_tracker,
                                pat_keybit, NUM_BITS,
                                [](uint32_t i) { return 1 - (i & 1); });
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
    for (auto *map : {&map_dup, &map_bw_sum3, &map_mid_sum3})
      prince_release_map(streams, allocate_gpu_memory, *map);
    prince_release_pattern<Torus>(streams, allocate_gpu_memory, pat_keybit);
    cuda_synchronize_stream(streams.stream(0), streams.gpu_index(0));
    for (auto *map : {&map_dup, &map_bw_sum3, &map_mid_sum3}) {
      free(map->h);
      map->h = nullptr;
    }
    free(pat_keybit.h);
    pat_keybit.h = nullptr;
  }
};

// Circuit scratch. State is word-major, lane-fast (block = word * N + lane)
// so LUT indexes and gather maps are constant across the batch. lut_gather64
// slots: [0, 4) parity by drift, then one group per distinct S-box table.
template <typename Torus> struct int_prince_buffer {
  int_radix_params params;
  bool allocate_gpu_memory;
  uint32_t num_inputs;
  bool is_decrypt;
  uint32_t num_gather_luts;

  // xor of a u2 state block with a u2 key block. Rests on the alternating
  // high/low slot pattern it is generated with; only the final layer departs
  // from it.
  int_radix_lut<Torus> *lut_flat32;
  int_radix_lut<Torus> *lut_gather64; // all per-word tables

  CudaRadixCiphertextFFI *buf_b = nullptr;   // 64 * num_inputs bits
  CudaRadixCiphertextFFI *buf_b2 = nullptr;  // 64 * num_inputs levelled sums
  CudaRadixCiphertextFFI *buf_u4 = nullptr;  // 16 * num_inputs 4-bit nibbles
  CudaRadixCiphertextFFI *buf_u2q = nullptr; // 32 * num_inputs 2-bit halves
  CudaRadixCiphertextFFI *buf_sum = nullptr; // 32 * num_inputs levelled sums
  CudaRadixCiphertextFFI *buf_k_first = nullptr;  // 32 * num_inputs tiled key
  CudaRadixCiphertextFFI *buf_k_second = nullptr; // 32 * num_inputs tiled key

  CudaRadixCiphertextFFI *key_bits_first = nullptr; // 64 * num_inputs, tiled
  CudaRadixCiphertextFFI *key_bits_second = nullptr;
  CudaRadixCiphertextFFI *kap_bw_first = nullptr;
  CudaRadixCiphertextFFI *kap_bw_second = nullptr;
  CudaRadixCiphertextFFI *kap_mid_first = nullptr;

  prince_gather_map map_key_tile; // 32N <- 32,  K=1 (broadcast over lanes)
  prince_gather_map map_tile64;   // 64N <- 64,  K=1 (broadcast over lanes)
  prince_gather_map
      map_transpose_in; // 32N <- 32N, K=1 (instance -> word major)
  prince_gather_map
      map_transpose_out;          // 32N <- 32N, K=1 (word -> instance major)
  prince_gather_map map_pair;     // 16N <- 32N, K=2 (hi/lo pair combine)
  prince_gather_map map_stage_x4; // 64N <- 16N, K=1 (replicate each word x4)
  prince_gather_map map_stage_x2; // 32N <- 16N, K=1 (replicate each word x2)
  prince_gather_map map_perm_pair_mid; // 32N <- 64N, K=2 (FHE_M_PERM + pair)
  prince_gather_map map_mperm_comb;    // 16N <- 64N, K=4 (FHE_M_PERM + comb)
  prince_gather_map map_fw_sum3;       // 64N <- 64N, K=3 (bridge+perm composed)
  prince_gather_map map_mid_sum3;      // 64N <- 64N, K=3 (bridge composed)
  prince_gather_map map_bw_sum3;       // 64N <- 64N, K=3 (IPERM composed)
  prince_gather_map map_comb4_id; // 16N <- 64N, K=4 (4 drifted bits -> nibble)

  prince_lut_pattern<Torus> pat_fw_sbox[5];
  prince_lut_pattern<Torus> pat_mid_in;
  prince_lut_pattern<Torus> pat_mid_out;
  prince_lut_pattern<Torus> pat_bw_sbox[5];
  prince_lut_pattern<Torus> pat_par_fw;
  prince_lut_pattern<Torus> pat_par_bw;
  prince_lut_pattern<Torus> pat_par_mid;

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
    this->is_decrypt = is_decrypt;

    const uint32_t N = num_inputs;
    const prince_table_set &tables =
        is_decrypt ? DECRYPT_TABLES : ENCRYPT_TABLES;

    uint32_t next_lut_id = 0;
    std::vector<std::function<Torus(Torus)>> lut_lambdas;
    auto push_slot = [&](std::function<Torus(Torus)> f) -> uint32_t {
      lut_lambdas.push_back(std::move(f));
      return next_lut_id++;
    };

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

    auto build_raw_map =
        [&](prince_gather_map &map, uint32_t num_out_blocks, uint32_t num_terms,
            const std::function<uint32_t(uint32_t, uint32_t)> &block_source) {
          prince_build_map(streams, allocate_gpu_memory, size_tracker, map,
                           num_out_blocks, num_terms, block_source);
        };
    auto build_map =
        [&](prince_gather_map &map, uint32_t num_out_blocks, uint32_t num_terms,
            const std::function<uint32_t(uint32_t, uint32_t)> &word_source) {
          build_raw_map(map, num_out_blocks, num_terms,
                        [&](uint32_t o, uint32_t t) {
                          uint32_t out_word = o / N, lane = o % N;
                          return word_source(out_word, t) * N + lane;
                        });
        };

    build_raw_map(map_key_tile, NUM_U2 * N, 1,
                  [&](uint32_t o, uint32_t) { return o / N; });
    build_raw_map(map_tile64, NUM_BITS * N, 1,
                  [&](uint32_t o, uint32_t) { return o / N; });
    build_raw_map(map_transpose_in, NUM_U2 * N, 1, [&](uint32_t o, uint32_t) {
      uint32_t w = o / N, lane = o % N;
      return lane * NUM_U2 + w;
    });
    build_raw_map(map_transpose_out, NUM_U2 * N, 1, [&](uint32_t o, uint32_t) {
      uint32_t lane = o / NUM_U2, w = o % NUM_U2;
      return w * N + lane;
    });
    build_map(map_pair, NUM_WORDS * N, 2,
              [](uint32_t w, uint32_t t) { return 2 * w + t; });
    build_map(map_stage_x4, NUM_BITS * N, 1,
              [](uint32_t idx, uint32_t) { return idx >> 2; });
    build_map(map_stage_x2, NUM_U2 * N, 1,
              [](uint32_t idx, uint32_t) { return idx >> 1; });
    build_map(map_perm_pair_mid, NUM_U2 * N, 2,
              [](uint32_t n, uint32_t t) { return FHE_M_PERM[2 * n + t]; });
    build_map(map_mperm_comb, NUM_WORDS * N, 4,
              [](uint32_t w, uint32_t t) { return FHE_M_PERM[4 * w + t]; });
    build_map(map_fw_sum3, NUM_BITS * N, 3, [](uint32_t i, uint32_t tt) {
      return prince_sum3_source(FHE_MP_PERM_FW[i], tt, false);
    });
    build_map(map_mid_sum3, NUM_BITS * N, 3, [](uint32_t m, uint32_t tt) {
      return prince_sum3_source(m, tt, false);
    });
    build_map(map_bw_sum3, NUM_BITS * N, 3, [](uint32_t m, uint32_t tt) {
      return prince_sum3_source(m, tt, true);
    });
    build_map(map_comb4_id, NUM_WORDS * N, 4,
              [](uint32_t w, uint32_t t) { return 4 * w + t; });

    auto build_word_pattern =
        [&](prince_lut_pattern<Torus> &pat, uint32_t num_blocks,
            const std::function<uint32_t(uint32_t)> &word_lut_id) {
          prince_build_pattern<Torus>(
              streams, allocate_gpu_memory, size_tracker, pat, num_blocks,
              [&](uint32_t i) { return word_lut_id(i / N); });
        };
    auto build_capped_pattern = [&](prince_lut_pattern<Torus> &pat,
                                    uint32_t base, uint32_t cap) {
      build_word_pattern(pat, NUM_BITS * N, [base, cap](uint32_t idx) {
        return idx < cap ? base + idx : 0;
      });
    };
    for (uint32_t r = 0; r < 5; ++r)
      build_capped_pattern(pat_fw_sbox[r], fw_base[r], NUM_BITS);
    build_capped_pattern(pat_mid_in, mid_in_base, NUM_BITS);
    build_capped_pattern(pat_mid_out, mid_out_base, NUM_BITS);
    for (uint32_t r = 0; r < 4; ++r)
      build_capped_pattern(pat_bw_sbox[r], bw_base[r], NUM_BITS);
    build_capped_pattern(pat_bw_sbox[4], bw_base[4], NUM_U2);
    build_word_pattern(pat_par_fw, NUM_BITS * N,
                       [](uint32_t i) { return i & 3; });
    build_word_pattern(pat_par_bw, NUM_BITS * N,
                       [](uint32_t m) { return (m >> 2) & 3; });
    build_word_pattern(pat_par_mid, NUM_BITS * N,
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

    auto all_maps = {&map_key_tile,      &map_tile64,        &map_transpose_in,
                     &map_transpose_out, &map_pair,          &map_stage_x4,
                     &map_stage_x2,      &map_perm_pair_mid, &map_mperm_comb,
                     &map_fw_sum3,       &map_mid_sum3,      &map_bw_sum3,
                     &map_comb4_id};
    for (auto *map : all_maps)
      prince_release_map(streams, allocate_gpu_memory, *map);

    auto all_patterns = {&pat_fw_sbox[0], &pat_fw_sbox[1], &pat_fw_sbox[2],
                         &pat_fw_sbox[3], &pat_fw_sbox[4], &pat_mid_in,
                         &pat_mid_out,    &pat_bw_sbox[0], &pat_bw_sbox[1],
                         &pat_bw_sbox[2], &pat_bw_sbox[3], &pat_bw_sbox[4],
                         &pat_par_fw,     &pat_par_bw,     &pat_par_mid};
    for (auto *pat : all_patterns)
      prince_release_pattern<Torus>(streams, allocate_gpu_memory, *pat);

    cuda_synchronize_stream(streams.stream(0), streams.gpu_index(0));

    for (auto *map : all_maps) {
      free(map->h);
      map->h = nullptr;
    }
    for (auto *pat : all_patterns) {
      free(pat->h);
      pat->h = nullptr;
    }
  }
};

#endif // PRINCE_UTILITIES_H
