#include "checked_arithmetic.h"
#include "device.h"
#include "pbs/pbs_utilities.h"
#include "pbs/programmable_bootstrap.h"
#include "utils.h"
#include "gtest/gtest.h"
#include <cstdint>
#include <cuda_runtime.h>
#include <functional>
#include <random>
#include <setup_and_teardown.h>
#include <stdio.h>
#include <stdlib.h>

// Test for the throughput-oriented FFT16x4x16 used by the specialized
// 2_2_params PBS. It mirrors test_fft.cpp (negacyclic polynomial
// multiplication checked against a schoolbook reference) but routes the
// transform through cuda_fourier_polynomial_mul_fft16x4x16_async, which uses
// the FFT16x4x16_{fwd,inv}_optimized_for_pbs cores.
//
// The FFT16x4x16 path is specialized for N = 2048 and requires an H100 (sm_90):
// its forward/inverse cores rely on named-barrier / mbarrier primitives only
// available there. Both constraints are enforced below (single param set +
// runtime device-capability skip).

typedef struct {
  size_t polynomial_size;
  int samples;
} FourierTransform16x4x16TestParams;

class FourierTransform16x4x16TestPrimitives_u64
    : public ::testing::TestWithParam<FourierTransform16x4x16TestParams> {
protected:
  size_t polynomial_size;
  int samples;
  cudaStream_t stream;
  uint32_t gpu_index = 0;

  double *poly1;
  double *poly2; // will be used as extracted result for cuda mult
  double *poly_exp_result;
  double2 *h_cpoly1;
  double2 *h_cpoly2; // will be used as a result poly
  double2 *d_cpoly1;
  double2 *d_cpoly2; // will be used as a result poly

public:
  void SetUp() {
    // The FFT16x4x16 cores are H100-only (sm_90). Skip on anything else so the
    // suite stays green on other GPUs in CI.
    cudaDeviceProp prop;
    cudaError_t err = cudaGetDeviceProperties(&prop, gpu_index);
    if (err != cudaSuccess || prop.major != 9) {
      GTEST_SKIP() << "FFT16x4x16 requires an H100 (compute capability 9.x); "
                   << "detected " << (err == cudaSuccess ? prop.major : -1)
                   << "." << (err == cudaSuccess ? prop.minor : -1);
    }

    stream = cuda_create_stream(gpu_index);

    // get src params
    polynomial_size = (int)GetParam().polynomial_size;
    samples = (int)GetParam().samples;

    fft_setup(stream, gpu_index, &poly1, &poly2, &h_cpoly1, &h_cpoly2,
              &d_cpoly1, &d_cpoly2, polynomial_size, samples);

    // allocate memory
    size_t poly_exp_size =
        safe_mul_sizeof<double>(polynomial_size, (size_t)2, (size_t)samples);
    poly_exp_result = (double *)malloc(poly_exp_size);
    memset(poly_exp_result, 0., poly_exp_size);

    // execute school book multiplication
    for (size_t p = 0; p < (size_t)samples; p++) {
      auto left = &poly1[p * polynomial_size];
      auto right = &poly2[p * polynomial_size];
      auto res = &poly_exp_result[p * polynomial_size * 2];

      // multiplication
      for (std::size_t i = 0; i < polynomial_size; ++i) {
        for (std::size_t j = 0; j < polynomial_size; ++j) {
          res[i + j] += left[i] * right[j];
        }
      }

      // make result negacyclic
      for (size_t i = 0; i < polynomial_size; i++) {
        res[i] = res[i] - res[i + polynomial_size];
      }
    }
  }

  void TearDown() {
    if (IsSkipped())
      return;
    fft_teardown(stream, gpu_index, poly1, poly2, h_cpoly1, h_cpoly2, d_cpoly1,
                 d_cpoly2);
    free(poly_exp_result);
  }
};

TEST_P(FourierTransform16x4x16TestPrimitives_u64, cuda_fft16x4x16_mult) {

  int r = 0;
  auto cur_input1 = &d_cpoly1[r * polynomial_size / 2 * samples];
  auto cur_input2 = &d_cpoly2[r * polynomial_size / 2 * samples];
  auto cur_h_c_res = &h_cpoly2[r * polynomial_size / 2 * samples];
  auto cur_poly2 = &poly2[r * polynomial_size * samples];
  auto cur_expected = &poly_exp_result[r * polynomial_size * 2 * samples];

  cuda_fourier_polynomial_mul_fft16x4x16_async(stream, gpu_index, cur_input1,
                                               cur_input2, cur_input2,
                                               polynomial_size, samples);

  cuda_memcpy_async_to_cpu(
      cur_h_c_res, cur_input2,
      safe_mul_sizeof<double2>(polynomial_size / 2, (size_t)samples), stream,
      gpu_index);
  cuda_synchronize_stream(stream, gpu_index);

  for (int p = 0; p < samples; p++) {
    for (size_t i = 0; i < (size_t)polynomial_size / 2; i++) {
      cur_poly2[p * polynomial_size + i] =
          cur_h_c_res[p * polynomial_size / 2 + i].x;
      cur_poly2[p * polynomial_size + i + polynomial_size / 2] =
          cur_h_c_res[p * polynomial_size / 2 + i].y;
    }
  }

  for (size_t p = 0; p < (size_t)samples; p++) {
    for (size_t i = 0; i < (size_t)polynomial_size; i++) {
      EXPECT_NEAR(cur_poly2[p * polynomial_size + i],
                  cur_expected[p * 2 * polynomial_size + i], 1e-6);
    }
  }
}

// FFT16x4x16 is specialized for N = 2048 only.
::testing::internal::ParamGenerator<FourierTransform16x4x16TestParams>
    fft16x4x16_params_u64 =
        ::testing::Values((FourierTransform16x4x16TestParams){2048, 10000});

std::string printParamName16x4x16(
    ::testing::TestParamInfo<FourierTransform16x4x16TestParams> p) {
  FourierTransform16x4x16TestParams params = p.param;

  return "N_" + std::to_string(params.polynomial_size) + "_samples_" +
         std::to_string(params.samples);
}

INSTANTIATE_TEST_CASE_P(fft16x4x16Instantiation,
                        FourierTransform16x4x16TestPrimitives_u64,
                        fft16x4x16_params_u64, printParamName16x4x16);
