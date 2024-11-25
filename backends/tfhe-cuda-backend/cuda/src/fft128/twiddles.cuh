#ifndef CUDA_FFT128_TWIDDLES_CUH
#define CUDA_FFT128_TWIDDLES_CUH

/*
 * 'negtwiddles' are stored in device memory to profit caching
 */
extern __device__ double neg_twiddles_re_hi[4096];
extern __device__ double neg_twiddles_re_lo[4096];
extern __device__ double neg_twiddles_im_hi[4096];
extern __device__ double neg_twiddles_im_lo[4096];
#endif
