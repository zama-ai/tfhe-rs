#include "checked_arithmetic.h"
#include "device.h"
#include "pbs/programmable_bootstrap.h"
#include "utils.h"
#include "gtest/gtest.h"
#include <cmath>
#include <cstdint>
#include <cuda_runtime.h>
#include <setup_and_teardown.h>

// Test for the forward pass of the throughput-oriented FFT16x4x16 used by the
// specialized 2_2_params PBS. Instead of validating a full negacyclic
// polynomial multiplication (see test_fft16x4x16.cpp), this test checks the
// forward transform in isolation: for a random 1024-element complex input it
// compares the FFT16x4x16 forward spectrum against the "classic" NSMFFT_direct
// forward spectrum (the FFT used everywhere else in the backend). Both compute
// the same negacyclic DFT, so — once the two output orderings are lined up —
// they must agree to within floating-point rounding.
//
// Ordering / bit-reversal
// ───────────────────────
//   * cuda_forward_fft16x4x16_async writes its spectrum in NATURAL frequency
//     order: out16[f] is the coefficient at frequency f (f = 0..1023).
//   * cuda_forward_fft_classic_async leaves the spectrum in NSMFFT_direct's
//     native (bit-reversed) order.
//
//   Empirically (and structurally), natural frequency f maps to the classic
//   native index:
//
//       classic_index(f) = bitreverse_10( (1024 - f) mod 1024 )
//
//   i.e. the classic order is a 10-bit bit-reversal of the negated frequency.
//   The comparison below applies this permutation so both spectra are read at
//   the same physical frequency.
//
// The FFT16x4x16 path is specialized for N = 2048 and needs the named-barrier /
// mbarrier primitives introduced with sm_90, so it runs on compute capability
// 9.x and above (H100, Blackwell, ...). Both constraints are enforced below
// (single param set + runtime device-capability skip).

typedef struct {
  size_t polynomial_size;
  int samples;
} ForwardFFT16x4x16TestParams;

// 10-bit bit-reversal (1024 = 2^10 complex coefficients for N = 2048).
static inline size_t bitreverse_10(size_t x) {
  size_t r = 0;
  for (int i = 0; i < 10; i++) {
    r = (r << 1) | ((x >> i) & 1u);
  }
  return r;
}

class ForwardFFT16x4x16TestPrimitives_u64
    : public ::testing::TestWithParam<ForwardFFT16x4x16TestParams> {
protected:
  size_t polynomial_size;
  int samples;
  cudaStream_t stream;
  uint32_t gpu_index = 0;

  double *poly1;
  double *poly2;
  double2 *h_cpoly1;
  double2 *h_cpoly2;
  double2 *d_cpoly1; // random complex input
  double2 *d_cpoly2; // unused here (allocated by fft_setup)

  double2 *d_out_fft16;   // FFT16x4x16 forward spectrum (natural order)
  double2 *d_out_classic; // classic forward spectrum (native order)

public:
  void SetUp() {
    // The FFT16x4x16 core needs the mbarrier / named-barrier primitives
    // introduced with sm_90 (H100), so it runs on compute capability 9.x and
    // above (Hopper, Blackwell, ...). Skip on anything older so the suite stays
    // green on other GPUs in CI.
    cudaDeviceProp prop;
    cudaError_t err = cudaGetDeviceProperties(&prop, gpu_index);
    if (err != cudaSuccess || prop.major < 9) {
      GTEST_SKIP() << "FFT16x4x16 requires compute capability 9.x or above "
                   << "(H100 or newer); detected "
                   << (err == cudaSuccess ? prop.major : -1) << "."
                   << (err == cudaSuccess ? prop.minor : -1);
    }

    stream = cuda_create_stream(gpu_index);

    polynomial_size = (int)GetParam().polynomial_size;
    samples = (int)GetParam().samples;

    // Random real polynomials compressed into polynomial_size/2 complex
    // coefficients (the same encoding the forward FFTs consume).
    fft_setup(stream, gpu_index, &poly1, &poly2, &h_cpoly1, &h_cpoly2,
              &d_cpoly1, &d_cpoly2, polynomial_size, samples);

    d_out_fft16 = (double2 *)cuda_malloc_async(
        safe_mul_sizeof<double2>(polynomial_size / 2, (size_t)samples), stream,
        gpu_index);
    d_out_classic = (double2 *)cuda_malloc_async(
        safe_mul_sizeof<double2>(polynomial_size / 2, (size_t)samples), stream,
        gpu_index);
  }

  void TearDown() {
    if (IsSkipped())
      return;
    cuda_drop_async(d_out_fft16, stream, gpu_index);
    cuda_drop_async(d_out_classic, stream, gpu_index);
    fft_teardown(stream, gpu_index, poly1, poly2, h_cpoly1, h_cpoly2, d_cpoly1,
                 d_cpoly2);
  }
};

TEST_P(ForwardFFT16x4x16TestPrimitives_u64, forward_matches_classic_fft) {
  size_t half = polynomial_size / 2;

  // Forward FFT16x4x16 (natural frequency order) and classic forward FFT
  // (native bit-reversed order) on the same random input.
  cuda_forward_fft16x4x16_async(stream, gpu_index, d_cpoly1, d_out_fft16,
                                polynomial_size, samples);
  cuda_forward_fft_classic_async(stream, gpu_index, d_cpoly1, d_out_classic,
                                 polynomial_size, samples);

  auto h_fft16 =
      (double2 *)malloc(safe_mul_sizeof<double2>(half, (size_t)samples));
  auto h_classic =
      (double2 *)malloc(safe_mul_sizeof<double2>(half, (size_t)samples));

  cuda_memcpy_async_to_cpu(h_fft16, d_out_fft16,
                           safe_mul_sizeof<double2>(half, (size_t)samples),
                           stream, gpu_index);
  cuda_memcpy_async_to_cpu(h_classic, d_out_classic,
                           safe_mul_sizeof<double2>(half, (size_t)samples),
                           stream, gpu_index);
  cuda_synchronize_stream(stream, gpu_index);

  // Same negacyclic transform, so the two spectra must agree to within
  // double-precision rounding once the ordering permutation is applied.
  const double tol = std::pow(2.0, -20);
  for (int p = 0; p < samples; p++) {
    const double2 *sample_fft16 = &h_fft16[(size_t)p * half];
    const double2 *sample_classic = &h_classic[(size_t)p * half];
    for (size_t f = 0; f < half; f++) {
      size_t classic_idx = bitreverse_10((half - f) % half);
      EXPECT_NEAR(sample_fft16[f].x, sample_classic[classic_idx].x, tol)
          << "sample " << p << " frequency " << f << " (real)";
      EXPECT_NEAR(sample_fft16[f].y, sample_classic[classic_idx].y, tol)
          << "sample " << p << " frequency " << f << " (imag)";
    }
  }

  free(h_fft16);
  free(h_classic);
}

// FFT16x4x16 is specialized for N = 2048 only.
::testing::internal::ParamGenerator<ForwardFFT16x4x16TestParams>
    forward_fft16x4x16_params_u64 =
        ::testing::Values((ForwardFFT16x4x16TestParams){2048, 100});

std::string printForwardParamName16x4x16(
    ::testing::TestParamInfo<ForwardFFT16x4x16TestParams> p) {
  ForwardFFT16x4x16TestParams params = p.param;
  return "N_" + std::to_string(params.polynomial_size) + "_samples_" +
         std::to_string(params.samples);
}

INSTANTIATE_TEST_CASE_P(forwardFft16x4x16Instantiation,
                        ForwardFFT16x4x16TestPrimitives_u64,
                        forward_fft16x4x16_params_u64,
                        printForwardParamName16x4x16);
