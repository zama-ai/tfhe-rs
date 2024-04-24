#include "cuComplex.h"
#include "thrust/complex.h"
#include <iostream>
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
