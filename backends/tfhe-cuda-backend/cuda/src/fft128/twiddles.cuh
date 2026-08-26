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
 * Array-of-structures (AoS) view of the four plane arrays above: twiddle i
 * occupies the two consecutive double2 entries 2*i (re_hi, re_lo) and 2*i+1
 * (im_hi, im_lo), so a butterfly reads a full twiddle with two 16-byte loads
 * instead of four 8-byte loads. The table is filled at runtime, so a kernel
 * reading it may only be launched on a GPU for which
 * host_build_neg_twiddles_aos has already returned. Today that is arranged by
 * scratch_programmable_bootstrap_128, the scratch of the only PBS variant whose
 * kernels read the table.
 */
extern __device__ double2 neg_twiddles_aos[2 * NEG_TWIDDLES_COUNT];

void host_build_neg_twiddles_aos(cudaStream_t stream, uint32_t gpu_index);
#endif
