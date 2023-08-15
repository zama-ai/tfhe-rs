#ifndef HELPER_CUH
#define HELPER_CUH

#include <stdio.h>

template <typename T> __global__ void print_debug_kernel(T *src, int N) {
  for (int i = 0; i < N; i++) {
    printf("%lu, ", src[i]);
  }
}

template <typename T> void print_debug(const char *name, T *src, int N) {
  printf("%s: ", name);
  cudaDeviceSynchronize();
  print_debug_kernel<<<1, 1>>>(src, N);
  cudaDeviceSynchronize();
  printf("\n");
}

template <typename T>
__global__ void print_body_kernel(T *src, int N, int lwe_dimension) {
  for (int i = 0; i < N; i++) {
    printf("%lu, ", src[i * (lwe_dimension + 1) + lwe_dimension]);
  }
}

template <typename T>
void print_body(const char *name, T *src, int n, int lwe_dimension) {
  printf("%s: ", name);
  cudaDeviceSynchronize();
  print_body_kernel<<<1, 1>>>(src, n, lwe_dimension);
  cudaDeviceSynchronize();
  printf("\n");
}

#endif
