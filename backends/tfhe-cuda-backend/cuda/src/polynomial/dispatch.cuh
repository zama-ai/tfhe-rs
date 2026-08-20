#ifndef CUDA_POLYNOMIAL_DISPATCH_CUH
#define CUDA_POLYNOMIAL_DISPATCH_CUH

#include "parameters.cuh"
#include <type_traits>

// Degree policies map a polynomial size N to the appropriate Degree or
// AmortizedDegree type. `supported` controls which sizes are valid;
// unsupported sizes PANIC at runtime and are not instantiated at compile time
// (via if constexpr).

// Standard policy: AmortizedDegree for sizes 256-16384
// (64-bit PBS CG, integer ops, FFT, keyswitch, sample extract)
template <uint32_t N> struct AmortizedDegreePolicy {
  static constexpr bool supported = (N >= 256 && N <= 16384);
  using type = AmortizedDegree<N>;
};

// FFT128 policy: AmortizedDegree for sizes 64-4096
template <uint32_t N> struct AmortizedDegreePolicyFFT128 {
  static constexpr bool supported = (N >= 64 && N <= 4096);
  using type = AmortizedDegree<N>;
};

// 128-bit policy: AmortizedDegree for sizes 256-4096
// (128-bit sample extract, BSK 128 conversion)
template <uint32_t N> struct AmortizedDegreePolicy128 {
  static constexpr bool supported = (N >= 256 && N <= 4096);
  using type = AmortizedDegree<N>;
};

// Classic PBS policy: Degree<2048> for N=2048 (measured to outperform
// AmortizedDegree there), AmortizedDegree for all other sizes 256-16384.
// Used by non-CG classic PBS and TBC classic PBS.
template <uint32_t N> struct ClassicPBSDegreePolicy {
  static constexpr bool supported = (N >= 256 && N <= 16384);
  using type = std::conditional_t<(N == 2048), Degree<N>, AmortizedDegree<N>>;
};

// Multibit 128-bit PBS policy: Degree for sizes 256-2048, AmortizedDegree
// for 4096 (avoids register exhaustion at that size).
template <uint32_t N> struct Multibit128DegreePolicy {
  static constexpr bool supported = (N >= 256 && N <= 4096);
  using type = std::conditional_t<(N <= 2048), Degree<N>, AmortizedDegree<N>>;
};

// Dispatch helper: expands a single case arm, injecting a `Params` type alias.
// The body uses `Params` as a template argument. Unsupported sizes PANIC.
#define DISPATCH_POLY_SIZE_CASE(N, Policy, ...)                                \
  case N:                                                                      \
    if constexpr (Policy<N>::supported) {                                      \
      using Params = typename Policy<N>::type;                                 \
      __VA_ARGS__;                                                             \
    } else {                                                                   \
      PANIC("Unsupported polynomial size: %u", static_cast<unsigned>(N));      \
    }                                                                          \
    break;

// Dispatches a runtime polynomial size to the correct compile-time Degree
// or AmortizedDegree instantiation.
//
// Usage:
//   DISPATCH_POLY_SIZE(polynomial_size, AmortizedDegreePolicy,
//       host_some_function<Torus, Params>(stream, gpu_index, ...));
//
//   DISPATCH_POLY_SIZE(polynomial_size, Multibit128DegreePolicy,
//       return scratch_function<InputTorus, Params>(stream, ...));
#define DISPATCH_POLY_SIZE(poly_size, Policy, ...)                             \
  do {                                                                         \
    switch (poly_size) {                                                       \
      DISPATCH_POLY_SIZE_CASE(64, Policy, __VA_ARGS__)                         \
      DISPATCH_POLY_SIZE_CASE(128, Policy, __VA_ARGS__)                        \
      DISPATCH_POLY_SIZE_CASE(256, Policy, __VA_ARGS__)                        \
      DISPATCH_POLY_SIZE_CASE(512, Policy, __VA_ARGS__)                        \
      DISPATCH_POLY_SIZE_CASE(1024, Policy, __VA_ARGS__)                       \
      DISPATCH_POLY_SIZE_CASE(2048, Policy, __VA_ARGS__)                       \
      DISPATCH_POLY_SIZE_CASE(4096, Policy, __VA_ARGS__)                       \
      DISPATCH_POLY_SIZE_CASE(8192, Policy, __VA_ARGS__)                       \
      DISPATCH_POLY_SIZE_CASE(16384, Policy, __VA_ARGS__)                      \
    default:                                                                   \
      PANIC("Unsupported polynomial size: %u",                                 \
            static_cast<unsigned>(poly_size));                                 \
    }                                                                          \
  } while (0)

#endif // CUDA_POLYNOMIAL_DISPATCH_CUH
