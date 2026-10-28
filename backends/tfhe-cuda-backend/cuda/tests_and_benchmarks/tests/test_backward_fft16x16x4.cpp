#include "checked_arithmetic.h"
#include "device.h"
#include "pbs/programmable_bootstrap.h"
#include "utils.h"
#include "gtest/gtest.h"
#include <cmath>
#include <cstdint>
#include <cuda_runtime.h>
#include <setup_and_teardown.h>

// Forward then inverse paired FFT16x16x4 must return the input; the test
// transforms carry no 1/N, so the roundtrip is N/2 = 1024 times the input.

typedef struct {
  size_t polynomial_size;
  int samples;
} BackwardFFT16x16x4TestParams;

class BackwardFFT16x16x4TestPrimitives_u64
    : public ::testing::TestWithParam<BackwardFFT16x16x4TestParams> {
protected:
  size_t polynomial_size;
  int samples;
  cudaStream_t stream;
  uint32_t gpu_index = 0;

  double *poly1;
  double *poly2;
  double2 *h_cpoly1; // random complex input (host copy)
  double2 *h_cpoly2;
  double2 *d_cpoly1; // random complex input
  double2 *d_cpoly2; // unused here (allocated by fft_setup)

  double2 *d_spectrum;  // FFT16x16x4 forward spectrum (natural order)
  double2 *d_roundtrip; // inverse of the spectrum, back in time domain

public:
  void SetUp() {
    // The FFT16x16x4 cores are validated on compute capability 8.x and above
    // (Ampere, Ada, Hopper, ...). Skip on anything older so the suite stays
    // green on other GPUs in CI.
    cudaDeviceProp prop;
    cudaError_t err = cudaGetDeviceProperties(&prop, gpu_index);
    if (err != cudaSuccess || prop.major < 8) {
      GTEST_SKIP() << "FFT16x16x4 requires compute capability 8.x or above "
                   << "(Ampere or newer); detected "
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

    d_spectrum = (double2 *)cuda_malloc_async(
        safe_mul_sizeof<double2>(polynomial_size / 2, (size_t)samples), stream,
        gpu_index);
    d_roundtrip = (double2 *)cuda_malloc_async(
        safe_mul_sizeof<double2>(polynomial_size / 2, (size_t)samples), stream,
        gpu_index);
  }

  void TearDown() {
    if (IsSkipped())
      return;
    cuda_drop_async(d_spectrum, stream, gpu_index);
    cuda_drop_async(d_roundtrip, stream, gpu_index);
    fft_teardown(stream, gpu_index, poly1, poly2, h_cpoly1, h_cpoly2, d_cpoly1,
                 d_cpoly2);
  }
};

TEST_P(BackwardFFT16x16x4TestPrimitives_u64, roundtrip_matches_input) {
  size_t half = polynomial_size / 2;

  cuda_forward_fft16x16x4_async(stream, gpu_index, d_cpoly1, d_spectrum,
                                polynomial_size, samples);
  cuda_backward_fft16x16x4_async(stream, gpu_index, d_spectrum, d_roundtrip,
                                 polynomial_size, samples);

  auto h_roundtrip =
      (double2 *)malloc(safe_mul_sizeof<double2>(half, (size_t)samples));
  cuda_memcpy_async_to_cpu(h_roundtrip, d_roundtrip,
                           safe_mul_sizeof<double2>(half, (size_t)samples),
                           stream, gpu_index);
  cuda_synchronize_stream(stream, gpu_index);

  // Inputs are uniform in [-1, 1); after undoing the missing 1/(N/2) the
  // roundtrip error is a handful of double-precision ulps.
  const double scale = 1.0 / (double)half;
  const double tol = 1e-9;
  for (int p = 0; p < samples; p++) {
    const double2 *expected = &h_cpoly1[(size_t)p * half];
    const double2 *actual = &h_roundtrip[(size_t)p * half];
    for (size_t i = 0; i < half; i++) {
      EXPECT_NEAR(actual[i].x * scale, expected[i].x, tol)
          << "sample " << p << " coefficient " << i << " (real)";
      EXPECT_NEAR(actual[i].y * scale, expected[i].y, tol)
          << "sample " << p << " coefficient " << i << " (imag)";
    }
  }

  free(h_roundtrip);
}

// FFT16x16x4 is specialized for N = 2048 only and needs an even sample count.
::testing::internal::ParamGenerator<BackwardFFT16x16x4TestParams>
    backward_fft16x16x4_params_u64 =
        ::testing::Values((BackwardFFT16x16x4TestParams){2048, 100});

std::string printBackwardParamName16x16x4(
    ::testing::TestParamInfo<BackwardFFT16x16x4TestParams> p) {
  BackwardFFT16x16x4TestParams params = p.param;
  return "N_" + std::to_string(params.polynomial_size) + "_samples_" +
         std::to_string(params.samples);
}

INSTANTIATE_TEST_CASE_P(backwardFft16x16x4Instantiation,
                        BackwardFFT16x16x4TestPrimitives_u64,
                        backward_fft16x16x4_params_u64,
                        printBackwardParamName16x16x4);
