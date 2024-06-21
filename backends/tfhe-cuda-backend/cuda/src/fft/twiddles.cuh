#ifndef GPU_BOOTSTRAP_TWIDDLES_CUH
#define GPU_BOOTSTRAP_TWIDDLES_CUH

/*
 * 'negtwiddles' are stored in device memory to profit caching
 */
extern __device__ double2 negtwiddles[8192];
#endif
