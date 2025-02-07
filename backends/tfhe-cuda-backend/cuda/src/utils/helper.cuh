#ifndef HELPER_CUH
#define HELPER_CUH

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

template <typename T> __global__ void print_debug_kernel(T *src, int N) {
  for (int i = 0; i < N; i++) {
    printf(get_format<T>(), src[i]);
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

void print_uint128_bits(__uint128_t value) {
  char buffer[129];   // 128 bits + null terminator
  buffer[128] = '\0'; // Null-terminate the string

  for (int i = 127; i >= 0; --i) {
    buffer[i] = (value & 1) ? '1' : '0'; // Extract the least significant bit
    value >>= 1;                         // Shift right by 1 bit
  }

  printf("%s\n", buffer);
}

#endif
