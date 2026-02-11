#include "pbs/pbs_utilities.h"
#include <benchmark/benchmark.h>
#include <cstdint>
#include <setup_and_teardown.h>
#include <stdio.h>
#include <stdlib.h>

typedef struct {
  size_t polynomial_size;
  int samples;
} FourierTransformTestParams;

class FourierTransformTestPrimitives_u64 : public benchmark::Fixture {
protected:
  size_t polynomial_size;
  int num_samples;
  cudaStream_t stream;
  uint32_t gpu_index = 0;

  double *poly1;
  double *poly2; // will be used as extracted result for cuda mult
  double2 *h_cpoly1;
  double2 *h_cpoly2; // will be used as a result poly
  double2 *d_cpoly1;
  double2 *d_cpoly2; // will be used as a result poly

public:
  void SetUp(const ::benchmark::State &state) {
    stream = cuda_create_stream(0);

    // get test params
    polynomial_size = state.range(0);
    num_samples = state.range(1);

    fft_setup(stream, gpu_index, &poly1, &poly2, &h_cpoly1, &h_cpoly2,
              &d_cpoly1, &d_cpoly2, polynomial_size, num_samples);
  }

  void TearDown(const ::benchmark::State &state) {
    (void)state;
    fft_teardown(stream, gpu_index, poly1, poly2, h_cpoly1, h_cpoly2, d_cpoly1,
                 d_cpoly2);
  }
};

BENCHMARK_DEFINE_F(FourierTransformTestPrimitives_u64, cuda_fft_mult)
(benchmark::State &st) {

  for (auto _ : st) {
    cuda_fourier_polynomial_mul_async(stream, gpu_index, d_cpoly1, d_cpoly2,
                                      d_cpoly2, polynomial_size, num_samples);
    cuda_synchronize_stream(stream, gpu_index);
  }
}

static void FFTBenchmarkGenerateParams(benchmark::internal::Benchmark *b) {
  // Define the parameters to benchmark
  // n, input_lwe_ciphertext_count
  std::vector<FourierTransformTestParams> params = {
      (FourierTransformTestParams){256, 100},
      (FourierTransformTestParams){512, 100},
      (FourierTransformTestParams){1024, 100},
      (FourierTransformTestParams){2048, 100},
      (FourierTransformTestParams){4096, 100},
      (FourierTransformTestParams){8192, 100},
      (FourierTransformTestParams){16384, 100},
  };

  // Add to the list of parameters to benchmark
  for (auto x : params)
    b->Args({static_cast<long>(x.polynomial_size), x.samples});
}

BENCHMARK_REGISTER_F(FourierTransformTestPrimitives_u64, cuda_fft_mult)
    ->Apply(FFTBenchmarkGenerateParams)
    ->ArgNames({"polynomial_size", "samples"});
