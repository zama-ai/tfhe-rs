#ifndef TFHE_RS_BACKENDS_TFHE_CUDA_BACKEND_CUDA_SRC_FFT128_FFT128_CUH_
#define TFHE_RS_BACKENDS_TFHE_CUDA_BACKEND_CUDA_SRC_FFT128_FFT128_CUH_

#include "polynomial/functions.cuh"
#include "polynomial/parameters.cuh"
#include "twiddles.cuh"
#include "types/complex/operations.cuh"
#include "pbs/fft.h"
#include <iostream>

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
