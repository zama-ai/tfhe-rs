#include "device.h"
#include "integer/prf_seeding.cuh"

void cuda_generate_lwe_masks_shake256_async(CudaStreamsFFI streams_ffi,
                                            uint64_t *d_out,
                                            const uint8_t *d_seed,
                                            uint32_t seed_len, uint32_t lwe_dim,
                                            uint32_t num_masks,
                                            uint32_t log_modulus) {
#ifdef CUPQC_ENABLED
  CudaStreams streams(streams_ffi);
  cudaStream_t stream = streams.stream(0);
  // One warp (32 threads) per mask
  generate_lwe_masks_shake256_kernel<<<num_masks, 32, 0, stream>>>(
      d_out, d_seed, seed_len, lwe_dim, num_masks, log_modulus);
#else
  (void)streams_ffi;
  (void)d_out;
  (void)d_seed;
  (void)seed_len;
  (void)lwe_dim;
  (void)num_masks;
  (void)log_modulus;
#endif
}
