#ifndef HELPER_CUH
#define HELPER_CUH

#include <cstdint>
#include <stdio.h>
#include <type_traits>

template <typename T> inline __device__ const char *get_format();

template <> inline __device__ const char *get_format<int>() { return "%d, "; }

template <> inline __device__ const char *get_format<unsigned int>() {
  return "%u, ";
}

template <> inline __device__ const char *get_format<uint64_t>() {
  return "%lu, ";
}

template <typename T> __global__ void print_debug_kernel(const T *src, int N) {
  for (int i = 0; i < N; i++) {
    printf(get_format<T>(), src[i]);
  }
}

template <>
__global__ inline void print_debug_kernel(const double2 *src, int N) {
  for (int i = 0; i < N; i++) {
    printf("(%lf, %lf), ", src[i].x, src[i].y);
  }
}
template <typename T> void print_debug(const char *name, const T *src, int N) {
  printf("%s: ", name);
  cudaDeviceSynchronize();
  print_debug_kernel<<<1, 1>>>(src, N);
  cudaDeviceSynchronize();
  printf("\n");
}

template <typename T>
__global__ void print_body_kernel(T *src, int N, int lwe_dimension, T delta) {
  for (int i = 0; i < N; i++) {
    T body = src[i * (lwe_dimension + 1) + lwe_dimension];
    T clear = body / delta;
    printf("(%lu, %lu), ", body, clear);
  }
}

template <typename T>
void print_body(const char *name, T *src, int n, int lwe_dimension, T delta) {
  printf("%s: ", name);
  cudaDeviceSynchronize();
  print_body_kernel<<<1, 1>>>(src, n, lwe_dimension, delta);
  cudaDeviceSynchronize();
  printf("\n");
}

#endif
