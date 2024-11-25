#include "fft128.cuh"

void fourier_transform_forward_f128(void *stream, uint32_t gpu_index, void *re0,
                                    void *re1, void *im0, void *im1,
                                    void const *standard, uint32_t const N) {
  switch (N) {
  case 256:
    host_fourier_transform_forward_f128_split_input<Degree<256>>(
        static_cast<cudaStream_t>(stream), gpu_index, (double *)re0,
        (double *)re1, (double *)im1, (double *)im1,
        (__uint128_t const *)standard, N);
    break;
  case 512:
    host_fourier_transform_forward_f128_split_input<Degree<512>>(
        static_cast<cudaStream_t>(stream), gpu_index, (double *)re0,
        (double *)re1, (double *)im1, (double *)im1,
        (__uint128_t const *)standard, N);
    break;
  case 1024:
    host_fourier_transform_forward_f128_split_input<Degree<1024>>(
        static_cast<cudaStream_t>(stream), gpu_index, (double *)re0,
        (double *)re1, (double *)im1, (double *)im1,
        (__uint128_t const *)standard, N);
    break;
  case 2048:
    host_fourier_transform_forward_f128_split_input<Degree<2048>>(
        static_cast<cudaStream_t>(stream), gpu_index, (double *)re0,
        (double *)re1, (double *)im1, (double *)im1,
        (__uint128_t const *)standard, N);
    break;
  case 4096:
    host_fourier_transform_forward_f128_split_input<Degree<4096>>(
        static_cast<cudaStream_t>(stream), gpu_index, (double *)re0,
        (double *)re1, (double *)im1, (double *)im1,
        (__uint128_t const *)standard, N);
    break;
  default:
    PANIC("Cuda error (f128 fft): unsupported polynomial size. Supported "
          "N's are powers of two"
          " in the interval [256..4096].")
  }
}