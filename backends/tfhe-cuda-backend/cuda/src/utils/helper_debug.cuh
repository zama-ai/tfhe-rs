#ifndef HELPER_DEBUG_CUH
#define HELPER_DEBUG_CUH

#include "checked_arithmetic.h"
#include "cuComplex.h"
#include "thrust/complex.h"
#include <cstdint>
#include <iostream>
#include <sstream>
#include <stdio.h>
#include <string>
#include <type_traits>

#define PRINT_VARS
#ifdef PRINT_VARS
#define PRINT_DEBUG_5(var, begin, end, step, cond)                             \
  _print_debug(var, #var, begin, end, step, cond, "", false)
#define PRINT_DEBUG_6(var, begin, end, step, cond, text)                       \
  _print_debug(var, #var, begin, end, step, cond, text, true)
#define CAT(A, B) A##B
#define PRINT_SELECT(NAME, NUM) CAT(NAME##_, NUM)
#define GET_COUNT(_1, _2, _3, _4, _5, _6, COUNT, ...) COUNT
#define VA_SIZE(...) GET_COUNT(__VA_ARGS__, 6, 5, 4, 3, 2, 1)
#define PRINT_DEBUG(...)                                                       \
  PRINT_SELECT(PRINT_DEBUG, VA_SIZE(__VA_ARGS__))(__VA_ARGS__)
#else
#define PRINT_DEBUG(...)
#endif

template <typename T>
__device__ typename std::enable_if<std::is_unsigned<T>::value, void>::type
_print_debug(T *var, const char *var_name, int start, int end, int step,
             bool cond, const char *text, bool has_text) {
  __syncthreads();
  if (cond) {
    if (has_text)
      printf("%s\n", text);
    for (int i = start; i < end; i += step) {
      printf("%s[%u]: %u\n", var_name, i, var[i]);
    }
  }
  __syncthreads();
}

template <typename T>
__device__ typename std::enable_if<std::is_signed<T>::value, void>::type
_print_debug(T *var, const char *var_name, int start, int end, int step,
             bool cond, const char *text, bool has_text) {
  __syncthreads();
  if (cond) {
    if (has_text)
      printf("%s\n", text);
    for (int i = start; i < end; i += step) {
      printf("%s[%u]: %d\n", var_name, i, var[i]);
    }
  }
  __syncthreads();
}

template <typename T>
__device__ typename std::enable_if<std::is_floating_point<T>::value, void>::type
_print_debug(T *var, const char *var_name, int start, int end, int step,
             bool cond, const char *text, bool has_text) {
  __syncthreads();
  if (cond) {
    if (has_text)
      printf("%s\n", text);
    for (int i = start; i < end; i += step) {
      printf("%s[%u]: %.15f\n", var_name, i, var[i]);
    }
  }
  __syncthreads();
}

template <typename T>
__device__
    typename std::enable_if<std::is_same<T, thrust::complex<double>>::value,
                            void>::type
    _print_debug(T *var, const char *var_name, int start, int end, int step,
                 bool cond, const char *text, bool has_text) {
  __syncthreads();
  if (cond) {
    if (has_text)
      printf("%s\n", text);
    for (int i = start; i < end; i += step) {
      printf("%s[%u]: %.15f , %.15f\n", var_name, i, var[i].real(),
             var[i].imag());
    }
  }
  __syncthreads();
}

template <typename T>
__device__
    typename std::enable_if<std::is_same<T, cuDoubleComplex>::value, void>::type
    _print_debug(T *var, const char *var_name, int start, int end, int step,
                 bool cond, const char *text, bool has_text) {
  __syncthreads();
  if (cond) {
    if (has_text)
      printf("%s\n", text);
    for (int i = start; i < end; i += step) {
      printf("%s[%u]: %.15f , %.15f\n", var_name, i, var[i].x, var[i].y);
    }
  }
  __syncthreads();
}

template <typename T> __device__ inline const char *get_format();

template <> __device__ inline const char *get_format<int>() { return "%d, "; }

template <> __device__ inline const char *get_format<unsigned int>() {
  return "%u, ";
}

template <> __device__ inline const char *get_format<uint64_t>() {
  return "%lu, ";
}

template <typename T> __global__ void print_debug_kernel(const T *src, int N) {
  for (int i = 0; i < N; i++) {
    printf(get_format<T>(), src[i]);
  }
}

template <>
__global__ inline void print_debug_kernel(const __uint128_t *src, int N) {
  for (int i = 0; i < N; i++) {
    uint64_t low = static_cast<uint64_t>(src[i]);
    uint64_t high = static_cast<uint64_t>(src[i] >> 64);
    printf("(%llu, %llu), ", high, low);
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
  check_cuda_error(cudaDeviceSynchronize());
  print_debug_kernel<<<1, 1>>>(src, N);
  check_cuda_error(cudaDeviceSynchronize());
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
  check_cuda_error(cudaDeviceSynchronize());
  print_body_kernel<<<1, 1>>>(src, n, lwe_dimension, delta);
  check_cuda_error(cudaDeviceSynchronize());
  printf("\n");
}

template <typename Torus>
void print_2d_csv_to_file(const std::vector<Torus> &v, int col_size,
                          const char *fname) {
  FILE *fp = fopen(fname, "wt");
  for (int i = 0; i < v.size() / col_size; ++i) {
    for (int j = 0; j < col_size; ++j) {
      fprintf(fp, "%lu%c", v[i * col_size + j],
              (j == col_size - 1) ? '\n' : ',');
    }
  }
  fclose(fp);
}

template <typename Torus>
__host__ void dump_2d_gpu_to_file(const Torus *ptr, int row_size, int col_size,
                                  const char *fname_prefix, int rand_prefix,
                                  cudaStream_t stream, uint32_t gpu_index) {
  // #ifndef NDEBUG
  std::vector<Torus> buf_cpu(row_size * col_size);

  char fname[4096];
  snprintf(fname, 4096, "%s_%d_%d_%d.csv", fname_prefix, row_size, col_size,
           rand_prefix);

  cuda_memcpy_async_to_cpu((void *)&buf_cpu[0], ptr,
                           safe_mul_sizeof<Torus>(buf_cpu.size()), stream,
                           gpu_index);
  cuda_synchronize_device(gpu_index);
  print_2d_csv_to_file(buf_cpu, col_size, fname);
  // #endif
}

template <typename Torus>
__host__ void compare_2d_arrays(const Torus *ptr1, const Torus *ptr2,
                                int row_size, int col_size, cudaStream_t stream,
                                uint32_t gpu_index) {
  // #ifndef NDEBUG
  std::vector<Torus> buf_cpu1(row_size * col_size),
      buf_cpu2(row_size * col_size);
  ;
  cuda_memcpy_async_to_cpu((void *)&buf_cpu1[0], ptr1,
                           safe_mul_sizeof<Torus>(buf_cpu1.size()), stream,
                           gpu_index);
  cuda_memcpy_async_to_cpu((void *)&buf_cpu2[0], ptr2,
                           safe_mul_sizeof<Torus>(buf_cpu2.size()), stream,
                           gpu_index);
  cuda_synchronize_device(gpu_index);

  std::vector<uint32_t> non_matching_indexes;
  for (int i = 0; i < buf_cpu1.size(); ++i) {
    if (buf_cpu1[i] != buf_cpu2[i]) {
      non_matching_indexes.push_back(i);
    }
  }

  if (!non_matching_indexes.empty()) {
    std::stringstream ss;
    for (int i = 0; i < std::min(non_matching_indexes.size(), (size_t)10);
         ++i) {
      ss << "    difference at " << non_matching_indexes[i] << ": "
         << buf_cpu1[non_matching_indexes[i]] << " vs "
         << buf_cpu2[non_matching_indexes[i]] << " at index "
         << non_matching_indexes[i] << "\n";
    }
    GPU_ASSERT(non_matching_indexes.empty(),
               "Correctness error for matrices %d x %d: \n%s", row_size,
               col_size, ss.str().c_str());
  }
}

#endif
