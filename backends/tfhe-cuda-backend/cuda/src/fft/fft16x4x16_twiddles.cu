// Single instantiation point for the FFT16x4x16 constant-memory twiddle
// tables. Defining FFT16X4X16_TWIDDLES_INSTANTIATE before including the
// header switches its declarations from `extern __device__ __constant__`
// to actual definitions so the symbols live in exactly one translation unit.
#define FFT16X4X16_TWIDDLES_INSTANTIATE
#include "fft/fft16x4x16_twiddles.cuh"
