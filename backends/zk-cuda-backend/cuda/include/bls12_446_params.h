#pragma once

#include "fp.h" // For LIMB_BITS_CONFIG

// ============================================================================
// BLS12-446 curve parameters
// ============================================================================
// Prime modulus p for BLS12-446 (Fq field)
// From tfhe-rs/tfhe-zk-pok/src/curve_446/mod.rs
// Modulus:
// 172824703542857155980071276579495962243492693522789898437834836356385656662277472896902502740297183690175962001546428467344062165330603
// This is a 446-bit prime
// Format: little-endian, limb[0] is least significant
// ============================================================================

#if LIMB_BITS_CONFIG == 64
// ============================================================================
// 64-bit limb constants (7 limbs for Fp, 5 limbs for scalar)
// ============================================================================

// Prime modulus p (7 limbs, little-endian)
#define BLS12_446_MODULUS_LIMBS                                                \
  {                                                                            \
    0x311c0026aab0aaabULL, 0x56ee4528c573b5ccULL, 0x824e6dc3e23acdeeULL,       \
        0x0f75a64bbac71602ULL, 0x0095a4b78a02fe32ULL, 0x200fc34965aad640ULL,   \
        0x3cdee0fb28c5e535ULL                                                  \
  }

// R^2 mod p for Montgomery conversion
// R = 2^448 (for 7 limbs of 64 bits)
#define BLS12_446_R2_LIMBS                                                     \
  {                                                                            \
    0x2AFF01DDDC752B45ULL, 0x92C772A7421CCF5BULL, 0x140EEF29C347DAD6ULL,       \
        0xF5A1400C22EA595EULL, 0x99D91C9FEC145218ULL, 0x3BB6537F90143D4BULL,   \
        0x3627854C9BE7974FULL                                                  \
  }

// R_INV mod p (R^-1 mod p)
#define BLS12_446_R_INV_LIMBS                                                  \
  {                                                                            \
    0xCE2560B51652D82FULL, 0xA0166C2F90C0838EULL, 0x6C2028836577CA52ULL,       \
        0x28BE97CD54A76C2CULL, 0x0C01F5F4B5806D69ULL, 0x498338A6A4F43367ULL,   \
        0x32E6A14BC7F5FA16ULL                                                  \
  }

// -p^-1 mod 2^64 (Montgomery reduction constant)
#define BLS12_446_P_PRIME 0xcd63fd900035fffdULL

// Scalar field modulus r (group order) for BLS12-446
// Modulus:
// 645383785691237230677916041525710377746967055506026847120930304831624105190538527824412673
// This is a 320-bit prime (5 limbs of 64 bits)
#define BLS12_446_SCALAR_MODULUS_LIMBS                                         \
  {                                                                            \
    0x0428001400040001ULL, 0x7bb9b0e8d8ca3461ULL, 0xd04c98ccc4c050bcULL,       \
        0x7995b34995830fa4ULL, 0x00000511b70539f2ULL                           \
  }

// Precomputed Montgomery form constants for Fp
// These are computed as: value * R mod p, where R = 2^448
#define BLS12_446_TWO_MONT_LIMBS                                               \
  {                                                                            \
    0x771FFECAAA7AAAA8ULL, 0x488DD6B9D462519EULL, 0xED8C91E0EE29908DULL,       \
        0x8452CDA229C74FEBULL, 0xFB52DA43AFE80E6FULL, 0xFF81E5B4D2A94DFFULL,   \
        0x1908F826B9D0D656ULL                                                  \
  }

#define BLS12_446_THREE_MONT_LIMBS                                             \
  {                                                                            \
    0xB2AFFE2FFFB7FFFCULL, 0xECD4C216BE937A6DULL, 0xE452DAD1653E58D3ULL,       \
        0x467C34733EAAF7E1ULL, 0xF8FC476587DC15A7ULL, 0x7F42D88F3BFDF4FFULL,   \
        0x258D743A16B94182ULL                                                  \
  }

#define BLS12_446_FOUR_MONT_LIMBS                                              \
  {                                                                            \
    0xEE3FFD9554F55550ULL, 0x911BAD73A8C4A33CULL, 0xDB1923C1DC53211AULL,       \
        0x08A59B44538E9FD7ULL, 0xF6A5B4875FD01CDFULL, 0xFF03CB69A5529BFFULL,   \
        0x3211F04D73A1ACADULL                                                  \
  }

#define BLS12_446_EIGHT_MONT_LIMBS                                             \
  {                                                                            \
    0xAB63FB03FF39FFF5ULL, 0xCB4915BE8C1590ADULL, 0x33E3D9BFD66B7446ULL,       \
        0x01D5903CEC5629ADULL, 0xECB5C457359D3B8CULL, 0xDDF7D389E4FA61BFULL,   \
        0x2744FF9FBE7D7426ULL                                                  \
  }

#elif LIMB_BITS_CONFIG == 32
// ============================================================================
// 32-bit limb constants (14 limbs for Fp, 10 limbs for scalar)
// Each 64-bit limb 0xHHHHHHHHLLLLLLLL splits into: 0xLLLLLLLL, 0xHHHHHHHH
// ============================================================================

// Prime modulus p (14 limbs, little-endian)
#define BLS12_446_MODULUS_LIMBS                                                \
  {                                                                            \
    0xaab0aaabU, 0x311c0026U, 0xc573b5ccU, 0x56ee4528U, 0xe23acdeeU,           \
        0x824e6dc3U, 0xbac71602U, 0x0f75a64bU, 0x8a02fe32U, 0x0095a4b7U,       \
        0x65aad640U, 0x200fc349U, 0x28c5e535U, 0x3cdee0fbU                     \
  }

// R^2 mod p for Montgomery conversion
// R = 2^448 (same for both 32-bit and 64-bit, just different representation)
#define BLS12_446_R2_LIMBS                                                     \
  {                                                                            \
    0xDC752B45U, 0x2AFF01DDU, 0x421CCF5BU, 0x92C772A7U, 0xC347DAD6U,           \
        0x140EEF29U, 0x22EA595EU, 0xF5A1400CU, 0xEC145218U, 0x99D91C9FU,       \
        0x90143D4BU, 0x3BB6537FU, 0x9BE7974FU, 0x3627854CU                     \
  }

// R_INV mod p (R^-1 mod p)
#define BLS12_446_R_INV_LIMBS                                                  \
  {                                                                            \
    0x1652D82FU, 0xCE2560B5U, 0x90C0838EU, 0xA0166C2FU, 0x6577CA52U,           \
        0x6C202883U, 0x54A76C2CU, 0x28BE97CDU, 0xB5806D69U, 0x0C01F5F4U,       \
        0xA4F43367U, 0x498338A6U, 0xC7F5FA16U, 0x32E6A14BU                     \
  }

// -p^-1 mod 2^32 (Montgomery reduction constant)
#define BLS12_446_P_PRIME 0x0035fffdU

// Scalar field modulus r (group order) for BLS12-446 (10 limbs of 32 bits)
#define BLS12_446_SCALAR_MODULUS_LIMBS                                         \
  {                                                                            \
    0x00040001U, 0x04280014U, 0xd8ca3461U, 0x7bb9b0e8U, 0xc4c050bcU,           \
        0xd04c98ccU, 0x95830fa4U, 0x7995b349U, 0xb70539f2U, 0x00000511U        \
  }

// Precomputed Montgomery form constants for Fp
// These are computed as: value * R mod p, where R = 2^448
#define BLS12_446_TWO_MONT_LIMBS                                               \
  {                                                                            \
    0xAA7AAAA8U, 0x771FFECAU, 0xD462519EU, 0x488DD6B9U, 0xEE29908DU,           \
        0xED8C91E0U, 0x29C74FEBU, 0x8452CDA2U, 0xAFE80E6FU, 0xFB52DA43U,       \
        0xD2A94DFFU, 0xFF81E5B4U, 0xB9D0D656U, 0x1908F826U                     \
  }

#define BLS12_446_THREE_MONT_LIMBS                                             \
  {                                                                            \
    0xFFB7FFFCU, 0xB2AFFE2FU, 0xBE937A6DU, 0xECD4C216U, 0x653E58D3U,           \
        0xE452DAD1U, 0x3EAAF7E1U, 0x467C3473U, 0x87DC15A7U, 0xF8FC4765U,       \
        0x3BFDF4FFU, 0x7F42D88FU, 0x16B94182U, 0x258D743AU                     \
  }

#define BLS12_446_FOUR_MONT_LIMBS                                              \
  {                                                                            \
    0x54F55550U, 0xEE3FFD95U, 0xA8C4A33CU, 0x911BAD73U, 0xDC53211AU,           \
        0xDB1923C1U, 0x538E9FD7U, 0x08A59B44U, 0x5FD01CDFU, 0xF6A5B487U,       \
        0xA5529BFFU, 0xFF03CB69U, 0x73A1ACADU, 0x3211F04DU                     \
  }

#define BLS12_446_EIGHT_MONT_LIMBS                                             \
  {                                                                            \
    0xFF39FFF5U, 0xAB63FB03U, 0x8C1590ADU, 0xCB4915BEU, 0xD66B7446U,           \
        0x33E3D9BFU, 0xEC5629ADU, 0x01D5903CU, 0x359D3B8CU, 0xECB5C457U,       \
        0xE4FA61BFU, 0xDDF7D389U, 0xBE7D7426U, 0x2744FF9FU                     \
  }

#endif // LIMB_BITS_CONFIG
