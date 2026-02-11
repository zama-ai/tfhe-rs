#include "checked_arithmetic.h"
#include "device.h"
#include "pbs/pbs_utilities.h"
#include "pbs/programmable_bootstrap.h"
#include "utils.h"
#include "gtest/gtest.h"
#include <cstdint>
#include <functional>
#include <random>
#include <setup_and_teardown.h>
#include <stdio.h>
#include <stdlib.h>

typedef struct {
  size_t polynomial_size;
  int samples;
} FourierTransformTestParams;

class FourierTransformTestPrimitives_u64
    : public ::testing::TestWithParam<FourierTransformTestParams> {
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
    fft_teardown(stream, gpu_index, poly1, poly2, h_cpoly1, h_cpoly2, d_cpoly1,
                 d_cpoly2);
    free(poly_exp_result);
  }
};

TEST_P(FourierTransformTestPrimitives_u64, cuda_fft_mult) {

  int r = 0;
  auto cur_input1 = &d_cpoly1[r * polynomial_size / 2 * samples];
  auto cur_input2 = &d_cpoly2[r * polynomial_size / 2 * samples];
  auto cur_h_c_res = &h_cpoly2[r * polynomial_size / 2 * samples];
  auto cur_poly2 = &poly2[r * polynomial_size * samples];
  auto cur_expected = &poly_exp_result[r * polynomial_size * 2 * samples];

  cuda_fourier_polynomial_mul_async(stream, gpu_index, cur_input1, cur_input2,
                                    cur_input2, polynomial_size, samples);

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
                  cur_expected[p * 2 * polynomial_size + i], 1e-9);
    }
  }
}

::testing::internal::ParamGenerator<FourierTransformTestParams> fft_params_u64 =
    ::testing::Values((FourierTransformTestParams){256, 100},
                      (FourierTransformTestParams){512, 100},
                      (FourierTransformTestParams){1024, 100},
                      (FourierTransformTestParams){2048, 100},
                      (FourierTransformTestParams){4096, 100},
                      (FourierTransformTestParams){8192, 50},
                      (FourierTransformTestParams){16384, 10});

std::string
printParamName(::testing::TestParamInfo<FourierTransformTestParams> p) {
  FourierTransformTestParams params = p.param;

  return "N_" + std::to_string(params.polynomial_size) + "_samples_" +
         std::to_string(params.samples);
}

INSTANTIATE_TEST_CASE_P(fftInstantiation, FourierTransformTestPrimitives_u64,
                        fft_params_u64, printParamName);
