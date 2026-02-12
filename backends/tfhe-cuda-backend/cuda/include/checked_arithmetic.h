#pragma once

#include <cstddef>
#include <cstdio>

#include "device.h"

// Variadic checked multiplication of size_t values.
// Folds left-to-right using __builtin_mul_overflow, returning true on overflow.
// On overflow the value written to *out is unspecified.
template <typename... Args>
inline bool checked_mul(size_t *out, size_t first, Args... rest) {
  size_t result = first;
  for (size_t value : {static_cast<size_t>(rest)...}) {
    if (__builtin_mul_overflow(result, value, &result))
      return true;
  }
  *out = result;
  return false;
}

// Variadic safe multiplication: computes the product and panics on overflow.
template <typename... Args> inline size_t safe_mul(size_t first, Args... rest) {
  size_t result;
  bool overflow = checked_mul(&result, first, rest...);
  PANIC_IF_FALSE(!overflow, "multiplication overflow wraps size_t");
  return result;
}

// Variadic safe multiplication with an appended sizeof(T) factor.
// Computes (args... * sizeof(T)) with overflow checking.
template <typename T, typename... Args>
inline size_t safe_mul_sizeof(Args... args) {
  return safe_mul(args..., sizeof(T));
}
