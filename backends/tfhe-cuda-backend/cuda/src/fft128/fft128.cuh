#ifndef TFHE_RS_BACKENDS_TFHE_CUDA_BACKEND_CUDA_SRC_FFT128_FFT128_CUH_
#define TFHE_RS_BACKENDS_TFHE_CUDA_BACKEND_CUDA_SRC_FFT128_FFT128_CUH_

#include "polynomial/functions.cuh"
#include "polynomial/parameters.cuh"
#include "twiddles.cuh"
#include "types/complex/operations.cuh"
#include "pbs/fft.h"
#include <iostream>

using Index = unsigned;

// zl - left part of butterfly operation
// zr - right part of butterfly operation
// re - real part
// im - imaginary part
// hi - high bits
// lo - low bits
// dt - list
// cf - single coefficient

template <class params>
__device__ void negacyclic_forward_fft_f128(
    double *dt_re_hi,
    double *dt_re_lo,
    double *dt_im_hi,
    double *dt_im_lo){

  __syncthreads();
  constexpr Index BUTTERFLY_DEPTH = params::opt >> 1;
  constexpr Index LOG2_DEGREE = params::log2_degree;
  constexpr Index HALF_DEGREE = params::degree >> 1;
  constexpr Index STRIDE = params::degree / params::opt;

  double cf_zl_re_hi[BUTTERFLY_DEPTH], cf_zr_re_hi[BUTTERFLY_DEPTH];
  double cf_zl_re_lo[BUTTERFLY_DEPTH], cf_zr_re_lo[BUTTERFLY_DEPTH];
  double cf_zl_im_hi[BUTTERFLY_DEPTH], cf_zr_im_hi[BUTTERFLY_DEPTH];
  double cf_zl_im_lo[BUTTERFLY_DEPTH], cf_zr_im_lo[BUTTERFLY_DEPTH];


  Index tid = threadIdx.x;

  // load into registers
#pragma unroll
  for (Index i = 0; i < BUTTERFLY_DEPTH; ++i) {
    cf_zl_re_hi[i] = dt_re_hi[tid]; cf_zr_re_hi[i] = dt_re_hi[tid + HALF_DEGREE];
    cf_zl_re_lo[i] = dt_re_lo[tid]; cf_zr_re_lo[i] = dt_re_lo[tid + HALF_DEGREE];
    cf_zl_im_hi[i] = dt_im_hi[tid]; cf_zr_im_hi[i] = dt_im_hi[tid + HALF_DEGREE];
    cf_zl_im_lo[i] = dt_im_lo[tid]; cf_zr_im_lo[i] = dt_im_lo[tid + HALF_DEGREE];

    tid += STRIDE;
  }

  // level 1
  // we don't make actual complex multiplication on level1 since we have only
  // one twiddle, it's real and image parts are equal, so we can multiply
  // it with simpler operations
  // TODO first we need to generate twiddles to implement first iteration

//#pragma unroll
//  for (Index i = 0; i < BUTTERFLY_DEPTH; ++i) {
//    w = v[i] * (double2){0.707106781186547461715008466854,
//                         0.707106781186547461715008466854};
//    v[i] = u[i] - w;
//    u[i] = u[i] + w;
//  }

}

void print_uint128_bits(__uint128_t value) {
  char buffer[129]; // 128 bits + null terminator
  buffer[128] = '\0'; // Null-terminate the string

  for (int i = 127; i >= 0; --i) {
    buffer[i] = (value & 1) ? '1' : '0'; // Extract the least significant bit
    value >>= 1; // Shift right by 1 bit
  }

  printf("%s\n", buffer);
}

template <class params>
__host__ void host_fourier_transform_forward_f128_split_input(
    cudaStream_t stream, uint32_t gpu_index,
    double *re0, double *re1,
    double *im0, double *im1,
    __uint128_t const *standard, uint32_t const N) {


  printf("cpp_poly_host\n");
  for (int i = 0; i < N; i++) {
    print_uint128_bits(standard[i]);
  }
  printf("check #1\n");

  double *d_re0, *d_re1, *d_im0, *d_im1;
  __uint128_t *d_standard;

  check_cuda_error(cudaMalloc((void**)&d_re0, N * sizeof(double)));
  check_cuda_error(cudaMalloc((void**)&d_re1, N * sizeof(double)));
  check_cuda_error(cudaMalloc((void**)&d_im0, N * sizeof(double)));
  check_cuda_error(cudaMalloc((void**)&d_im1, N * sizeof(double)));

  check_cuda_error(cudaMalloc((void**)&d_standard, N * sizeof(__uint128_t)));

  check_cuda_error(cudaFree(d_re0));
  check_cuda_error(cudaFree(d_re1));
  check_cuda_error(cudaFree(d_im0));
  check_cuda_error(cudaFree(d_im1));

  cudaFree(d_standard);


}

#endif //TFHE_RS_BACKENDS_TFHE_CUDA_BACKEND_CUDA_SRC_FFT128_FFT128_CUH_
