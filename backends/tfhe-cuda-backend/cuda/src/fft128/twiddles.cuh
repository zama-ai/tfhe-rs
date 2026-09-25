#ifndef CUDA_FFT128_TWIDDLES_CUH
#define CUDA_FFT128_TWIDDLES_CUH

#include <cstdint>
#include <cuda_runtime.h>

constexpr uint32_t NEG_TWIDDLES_COUNT = 4096;

/*
 * 'negtwiddles' are stored in device memory to profit caching
 */
extern __device__ double neg_twiddles_re_hi[NEG_TWIDDLES_COUNT];
extern __device__ double neg_twiddles_re_lo[NEG_TWIDDLES_COUNT];
extern __device__ double neg_twiddles_im_hi[NEG_TWIDDLES_COUNT];
extern __device__ double neg_twiddles_im_lo[NEG_TWIDDLES_COUNT];

/*
 * Array-of-structures (AoS) view of the plane arrays above: twiddle i
 * occupies double2 entries 2*i (re) and 2*i+1 (im), so a butterfly reads it
 * with two 16-byte loads instead of four 8-byte ones. Filled at runtime by
 * host_build_neg_twiddles_aos, which the scratch function of every PBS
 * variant reading the table calls before launch.
 */
extern __device__ double2 neg_twiddles_aos[2 * NEG_TWIDDLES_COUNT];

void host_build_neg_twiddles_aos(cudaStream_t stream, uint32_t gpu_index);
#endif
