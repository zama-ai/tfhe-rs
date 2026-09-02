#include "fft128.cuh"
#include "polynomial/dispatch.cuh"

void cuda_fourier_transform_forward_as_torus_f128_async(
    void *stream, uint32_t gpu_index, void *re0, void *re1, void *im0,
    void *im1, void const *standard, const uint32_t N,
    const uint32_t number_of_samples) {
  DISPATCH_POLY_SIZE(N, AmortizedDegreePolicyFFT128,
                     host_fourier_transform_forward_as_torus_f128_async<Params>(
                         static_cast<cudaStream_t>(stream), gpu_index,
                         (double *)re0, (double *)re1, (double *)im0,
                         (double *)im1, (__uint128_t const *)standard, N,
                         number_of_samples));
}

void cuda_fourier_transform_backward_as_torus_f128_async(
    void *stream, uint32_t gpu_index, void *standard, void const *re0,
    void const *re1, void const *im0, void const *im1, const uint32_t N,
    const uint32_t number_of_samples) {
  DISPATCH_POLY_SIZE(N, AmortizedDegreePolicyFFT128,
                     host_fourier_transform_backward_as_torus_f128_async<Params>(
                         static_cast<cudaStream_t>(stream), gpu_index,
                         (__uint128_t *)standard, (double const *)re0,
                         (double const *)re1, (double const *)im0,
                         (double const *)im1, N, number_of_samples));
}
