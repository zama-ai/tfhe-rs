#include "fft128.cuh"

void cuda_fourier_transform_forward_as_integer_f128_async(
    void *stream, uint32_t gpu_index, void *re0, void *re1, void *im0,
    void *im1, void const *standard, const uint32_t N,
    const uint32_t number_of_samples) {
  switch (N) {
  case 64:
    host_fourier_transform_forward_as_integer_f128<AmortizedDegree<64>>(
        static_cast<cudaStream_t>(stream), gpu_index, (double *)re0,
        (double *)re1, (double *)im0, (double *)im1,
        (__uint128_t const *)standard, N, number_of_samples);
    break;
  case 128:
    host_fourier_transform_forward_as_integer_f128<AmortizedDegree<128>>(
        static_cast<cudaStream_t>(stream), gpu_index, (double *)re0,
        (double *)re1, (double *)im0, (double *)im1,
        (__uint128_t const *)standard, N, number_of_samples);
    break;
  case 256:
    host_fourier_transform_forward_as_integer_f128<AmortizedDegree<256>>(
        static_cast<cudaStream_t>(stream), gpu_index, (double *)re0,
        (double *)re1, (double *)im0, (double *)im1,
        (__uint128_t const *)standard, N, number_of_samples);
    break;
  case 512:
    host_fourier_transform_forward_as_integer_f128<AmortizedDegree<512>>(
        static_cast<cudaStream_t>(stream), gpu_index, (double *)re0,
        (double *)re1, (double *)im0, (double *)im1,
        (__uint128_t const *)standard, N, number_of_samples);
    break;
  case 1024:
    host_fourier_transform_forward_as_integer_f128<AmortizedDegree<1024>>(
        static_cast<cudaStream_t>(stream), gpu_index, (double *)re0,
        (double *)re1, (double *)im0, (double *)im1,
        (__uint128_t const *)standard, N, number_of_samples);
    break;
  case 2048:
    host_fourier_transform_forward_as_integer_f128<AmortizedDegree<2048>>(
        static_cast<cudaStream_t>(stream), gpu_index, (double *)re0,
        (double *)re1, (double *)im0, (double *)im1,
        (__uint128_t const *)standard, N, number_of_samples);
    break;
  case 4096:
    host_fourier_transform_forward_as_integer_f128<AmortizedDegree<4096>>(
        static_cast<cudaStream_t>(stream), gpu_index, (double *)re0,
        (double *)re1, (double *)im0, (double *)im1,
        (__uint128_t const *)standard, N, number_of_samples);
    break;
  default:
    PANIC("Cuda error (f128 fft): unsupported polynomial size. Supported "
          "N's are powers of two"
          " in the interval [64..4096].")
  }
}

void cuda_fourier_transform_forward_as_torus_f128_async(
    void *stream, uint32_t gpu_index, void *re0, void *re1, void *im0,
    void *im1, void const *standard, const uint32_t N,
    const uint32_t number_of_samples) {
  switch (N) {
  case 64:
    host_fourier_transform_forward_as_torus_f128<AmortizedDegree<64>>(
        static_cast<cudaStream_t>(stream), gpu_index, (double *)re0,
        (double *)re1, (double *)im0, (double *)im1,
        (__uint128_t const *)standard, N, number_of_samples);
    break;
  case 128:
    host_fourier_transform_forward_as_torus_f128<AmortizedDegree<128>>(
        static_cast<cudaStream_t>(stream), gpu_index, (double *)re0,
        (double *)re1, (double *)im0, (double *)im1,
        (__uint128_t const *)standard, N, number_of_samples);
    break;
  case 256:
    host_fourier_transform_forward_as_torus_f128<AmortizedDegree<256>>(
        static_cast<cudaStream_t>(stream), gpu_index, (double *)re0,
        (double *)re1, (double *)im0, (double *)im1,
        (__uint128_t const *)standard, N, number_of_samples);
    break;
  case 512:
    host_fourier_transform_forward_as_torus_f128<AmortizedDegree<512>>(
        static_cast<cudaStream_t>(stream), gpu_index, (double *)re0,
        (double *)re1, (double *)im0, (double *)im1,
        (__uint128_t const *)standard, N, number_of_samples);
    break;
  case 1024:
    host_fourier_transform_forward_as_torus_f128<AmortizedDegree<1024>>(
        static_cast<cudaStream_t>(stream), gpu_index, (double *)re0,
        (double *)re1, (double *)im0, (double *)im1,
        (__uint128_t const *)standard, N, number_of_samples);
    break;
  case 2048:
    host_fourier_transform_forward_as_torus_f128<AmortizedDegree<2048>>(
        static_cast<cudaStream_t>(stream), gpu_index, (double *)re0,
        (double *)re1, (double *)im0, (double *)im1,
        (__uint128_t const *)standard, N, number_of_samples);
    break;
  case 4096:
    host_fourier_transform_forward_as_torus_f128<AmortizedDegree<4096>>(
        static_cast<cudaStream_t>(stream), gpu_index, (double *)re0,
        (double *)re1, (double *)im0, (double *)im1,
        (__uint128_t const *)standard, N, number_of_samples);
    break;
  default:
    PANIC("Cuda error (f128 fft): unsupported polynomial size. Supported "
          "N's are powers of two"
          " in the interval [64..4096].")
  }
}

void cuda_fourier_transform_backward_as_torus_f128_async(
    void *stream, uint32_t gpu_index, void *standard, void const *re0,
    void const *re1, void const *im0, void const *im1, const uint32_t N,
    const uint32_t number_of_samples) {
  switch (N) {
  case 64:
    host_fourier_transform_backward_as_torus_f128<AmortizedDegree<64>>(
        static_cast<cudaStream_t>(stream), gpu_index, (__uint128_t *)standard,
        (double const *)re0, (double const *)re1, (double const *)im0,
        (double const *)im1, N, number_of_samples);
    break;
  case 128:
    host_fourier_transform_backward_as_torus_f128<AmortizedDegree<128>>(
        static_cast<cudaStream_t>(stream), gpu_index, (__uint128_t *)standard,
        (double const *)re0, (double const *)re1, (double const *)im0,
        (double const *)im1, N, number_of_samples);
    break;
  case 256:
    host_fourier_transform_backward_as_torus_f128<AmortizedDegree<256>>(
        static_cast<cudaStream_t>(stream), gpu_index, (__uint128_t *)standard,
        (double const *)re0, (double const *)re1, (double const *)im0,
        (double const *)im1, N, number_of_samples);
    break;
  case 512:
    host_fourier_transform_backward_as_torus_f128<AmortizedDegree<512>>(
        static_cast<cudaStream_t>(stream), gpu_index, (__uint128_t *)standard,
        (double const *)re0, (double const *)re1, (double const *)im0,
        (double const *)im1, N, number_of_samples);
    break;
  case 1024:
    host_fourier_transform_backward_as_torus_f128<AmortizedDegree<1024>>(
        static_cast<cudaStream_t>(stream), gpu_index, (__uint128_t *)standard,
        (double const *)re0, (double const *)re1, (double const *)im0,
        (double const *)im1, N, number_of_samples);
    break;
  case 2048:
    host_fourier_transform_backward_as_torus_f128<AmortizedDegree<2048>>(
        static_cast<cudaStream_t>(stream), gpu_index, (__uint128_t *)standard,
        (double const *)re0, (double const *)re1, (double const *)im0,
        (double const *)im1, N, number_of_samples);
    break;
  case 4096:
    host_fourier_transform_backward_as_torus_f128<AmortizedDegree<4096>>(
        static_cast<cudaStream_t>(stream), gpu_index, (__uint128_t *)standard,
        (double const *)re0, (double const *)re1, (double const *)im0,
        (double const *)im1, N, number_of_samples);
    break;
  default:
    PANIC("Cuda error (f128 ifft): unsupported polynomial size. Supported "
          "N's are powers of two"
          " in the interval [64..4096].")
  }
}
