#ifndef CUDA_INTEGER_PRF_SEEDING_CUH
#define CUDA_INTEGER_PRF_SEEDING_CUH
#include "integer.h"

#ifdef CUPQC_ENABLED

#include <cupqc/hash.hpp>

namespace {
using SHAKE_256_WARP = decltype(cupqc::SHAKE_256() + cupqc::Warp());
} // namespace

// One block per mask, 32 threads per block (warp-mode SHAKE256).
// Output layout: num_masks rows of (lwe_dim + 1) u64 values.
//   row[0..lwe_dim)  = mask values shifted to MSB position
//   row[lwe_dim]     = body = 0
__global__ void
generate_lwe_masks_shake256_kernel(uint64_t *__restrict__ d_out,
                                   const uint8_t *__restrict__ d_seed,
                                   uint32_t seed_len, uint32_t lwe_dim,
                                   uint32_t num_masks, uint32_t log_modulus) {
  const uint32_t mask_idx = blockIdx.x;
  if (mask_idx >= num_masks)
    return;

  SHAKE_256_WARP shake{};
  shake.reset();
  // Domain separator matching the CPU reference function (8 bytes, no NUL)
  shake.update(reinterpret_cast<const uint8_t *>("TFHE_PRF"), 8);
  shake.update(d_seed, seed_len);
  // Per-mask counter as little-endian u32 (matches CPU: i as u32 to_le_bytes)
  shake.update(reinterpret_cast<const uint8_t *>(&mask_idx), 4);
  shake.finalize();

  uint64_t *row = d_out + static_cast<uint64_t>(mask_idx) * (lwe_dim + 1);

  // Squeeze lwe_dim u64s (8 bytes each) directly into the row.
  // digest() buffer must be 8-byte aligned — row qualifies.
  shake.digest(reinterpret_cast<uint8_t *>(row),
               static_cast<size_t>(lwe_dim) * sizeof(uint64_t));

  // Apply power-of-2 mask then left-shift to MSB position.
  // Matches raw_seeded_msed_to_lwe: value << (64 - log_modulus).
  const uint64_t mod_mask = (1ULL << log_modulus) - 1ULL;
  const uint32_t shift = 64u - log_modulus;
  for (uint32_t i = threadIdx.x; i < lwe_dim; i += 32)
    row[i] = (row[i] & mod_mask) << shift;

  __syncwarp();

  // Body = 0 (seeded LWE encrypts zero)
  if (threadIdx.x == 0)
    row[lwe_dim] = 0ULL;
}
#endif // CUPQC_ENABLED

#endif // CUDA_INTEGER_PRF_SEEDING_CUH
