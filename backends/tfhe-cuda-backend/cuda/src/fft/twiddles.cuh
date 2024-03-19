#ifndef GPU_BOOTSTRAP_TWIDDLES_CUH
#define GPU_BOOTSTRAP_TWIDDLES_CUH

extern __device__ cufftdx::detail::complex<double> neg_twist_128[128];
extern __device__ cufftdx::detail::complex<double> neg_twist_256[256];
extern __device__ cufftdx::detail::complex<double> neg_twist_512[512];
extern __device__ cufftdx::detail::complex<double> neg_twist_1024[1024];
extern __device__ cufftdx::detail::complex<double> neg_twist_2048[2048];
extern __device__ cufftdx::detail::complex<double> neg_twist_4096[4096];

#endif
