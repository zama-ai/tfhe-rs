// Single instantiation of the FFT16x16x4 constant-memory twiddle tables: the
// macro turns the header's extern declarations into definitions in this TU.
#define FFT16X16X4_TWIDDLES_INSTANTIATE
#include "fft/fft16x16x4_twiddles.cuh"
