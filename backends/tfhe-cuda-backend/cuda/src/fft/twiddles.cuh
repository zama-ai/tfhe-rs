#ifndef GPU_BOOTSTRAP_TWIDDLES_CUH
#define GPU_BOOTSTRAP_TWIDDLES_CUH

/*
 * 'negtwiddles' are stored in constant memory for faster access times
 * because of it's limited size, only twiddles for up to 2^12 polynomial size
 * can be stored there, twiddles for 2^13 are stored in device memory
 * 'negtwiddles13'
 */

extern __constant__ double2 negtwiddles[4096];
extern __device__ double2 negtwiddles13[4096];
#endif
