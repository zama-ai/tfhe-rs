#include "../tests/primitives/fp2_helpers.h" // Include test-only batch operations
#include "device.h"
#include "fp.h"
#include "fp2.h"
#include <benchmark/benchmark.h>
#include <cstdint>
#include <cuda_runtime.h>
#include <random>

// Helper to get modulus (use fp_modulus() from the library)
static Fp get_modulus() { return fp_modulus(); }

// Global stream and gpu_index for benchmarks
static cudaStream_t g_benchmark_stream = nullptr;
static uint32_t g_gpu_index = 0;

// Number of warm-up iterations before measuring
static constexpr int WARMUP_ITERATIONS = 3;

// Initialize device modulus and create stream
static void init_benchmark() {
  static bool initialized = false;
  if (!initialized) {
    g_gpu_index = 0;

    // Create a CUDA stream using library function
    g_benchmark_stream = cuda_create_stream(g_gpu_index);

    initialized = true;
  }
}

// Helper to generate random Fp value
static Fp random_fp_value(std::mt19937_64 &rng) {
  Fp result;
  Fp p = get_modulus();

  // Generate random limbs
  for (int i = 0; i < FP_LIMBS; i++) {
    result.limb[i] = static_cast<UNSIGNED_LIMB>(rng());
  }

  // Reduce if needed
  while (fp_cmp(result, p) != ComparisonType::Less) {
    Fp reduced;
    fp_sub_raw(reduced, result, p);
    fp_copy(result, reduced);
  }

  return result;
}

// Helper to generate random Fp2 value
static Fp2 random_fp2_value(std::mt19937_64 &rng) {
  Fp2 result;
  result.c0 = random_fp_value(rng);
  result.c1 = random_fp_value(rng);
  return result;
}

// Benchmark scalar addition
static void BM_Fp2_ScalarAdd(benchmark::State &state) {
  init_benchmark();

  std::mt19937_64 rng(42);
  Fp2 a = random_fp2_value(rng);
  Fp2 b = random_fp2_value(rng);
  Fp2 result;

  // Warm-up iterations
  for (int i = 0; i < WARMUP_ITERATIONS; i++) {
    result = a + b;
    benchmark::DoNotOptimize(result);
  }

  for (auto _ : state) {
    result = a + b;
    benchmark::DoNotOptimize(result);
  }

  state.SetItemsProcessed(state.iterations());
}

// Benchmark scalar subtraction
static void BM_Fp2_ScalarSub(benchmark::State &state) {
  init_benchmark();

  std::mt19937_64 rng(42);
  Fp2 a = random_fp2_value(rng);
  Fp2 b = random_fp2_value(rng);
  Fp2 result;

  // Warm-up iterations
  for (int i = 0; i < WARMUP_ITERATIONS; i++) {
    result = a - b;
    benchmark::DoNotOptimize(result);
  }

  for (auto _ : state) {
    result = a - b;
    benchmark::DoNotOptimize(result);
  }

  state.SetItemsProcessed(state.iterations());
}

// Benchmark scalar multiplication
static void BM_Fp2_ScalarMul(benchmark::State &state) {
  init_benchmark();

  std::mt19937_64 rng(42);
  Fp2 a = random_fp2_value(rng);
  Fp2 b = random_fp2_value(rng);
  Fp2 result;

  // Warm-up iterations
  for (int i = 0; i < WARMUP_ITERATIONS; i++) {
    result = a * b;
    benchmark::DoNotOptimize(result);
  }

  for (auto _ : state) {
    result = a * b;
    benchmark::DoNotOptimize(result);
  }

  state.SetItemsProcessed(state.iterations());
}

// Benchmark scalar squaring
static void BM_Fp2_ScalarSquare(benchmark::State &state) {
  init_benchmark();

  std::mt19937_64 rng(42);
  Fp2 a = random_fp2_value(rng);
  Fp2 result;

  // Warm-up iterations
  for (int i = 0; i < WARMUP_ITERATIONS; i++) {
    fp2_square(result, a);
    benchmark::DoNotOptimize(result);
  }

  for (auto _ : state) {
    fp2_square(result, a);
    benchmark::DoNotOptimize(result);
  }

  state.SetItemsProcessed(state.iterations());
}

// Benchmark scalar inversion
static void BM_Fp2_ScalarInv(benchmark::State &state) {
  init_benchmark();

  std::mt19937_64 rng(42);
  Fp2 a = random_fp2_value(rng);
  // Ensure a is not zero
  while (fp2_is_zero(a)) {
    a = random_fp2_value(rng);
  }
  Fp2 result;

  // Warm-up iterations
  for (int i = 0; i < WARMUP_ITERATIONS; i++) {
    fp2_inv(result, a);
    benchmark::DoNotOptimize(result);
  }

  for (auto _ : state) {
    fp2_inv(result, a);
    benchmark::DoNotOptimize(result);
  }

  state.SetItemsProcessed(state.iterations());
}

// Benchmark scalar conjugation
static void BM_Fp2_ScalarConjugate(benchmark::State &state) {
  init_benchmark();

  std::mt19937_64 rng(42);
  Fp2 a = random_fp2_value(rng);
  Fp2 result;

  // Warm-up iterations
  for (int i = 0; i < WARMUP_ITERATIONS; i++) {
    fp2_conjugate(result, a);
    benchmark::DoNotOptimize(result);
  }

  for (auto _ : state) {
    fp2_conjugate(result, a);
    benchmark::DoNotOptimize(result);
  }

  state.SetItemsProcessed(state.iterations());
}

// Benchmark scalar negation
static void BM_Fp2_ScalarNeg(benchmark::State &state) {
  init_benchmark();

  std::mt19937_64 rng(42);
  Fp2 a = random_fp2_value(rng);
  Fp2 result;

  // Warm-up iterations
  for (int i = 0; i < WARMUP_ITERATIONS; i++) {
    result = -a;
    benchmark::DoNotOptimize(result);
  }

  for (auto _ : state) {
    result = -a;
    benchmark::DoNotOptimize(result);
  }

  state.SetItemsProcessed(state.iterations());
}

// Benchmark scalar multiply by i
static void BM_Fp2_ScalarMulByI(benchmark::State &state) {
  init_benchmark();

  std::mt19937_64 rng(42);
  Fp2 a = random_fp2_value(rng);
  Fp2 result;

  // Warm-up iterations
  for (int i = 0; i < WARMUP_ITERATIONS; i++) {
    fp2_mul_by_i(result, a);
    benchmark::DoNotOptimize(result);
  }

  for (auto _ : state) {
    fp2_mul_by_i(result, a);
    benchmark::DoNotOptimize(result);
  }

  state.SetItemsProcessed(state.iterations());
}

// Benchmark GPU kernel: array addition
static void BM_Fp2_GPU_ArrayAdd(benchmark::State &state) {
  init_benchmark();

  const int n = static_cast<int>(state.range(0));
  std::mt19937_64 rng(42);

  // Allocate host arrays
  Fp2 *h_a = new Fp2[n];
  Fp2 *h_b = new Fp2[n];
  Fp2 *h_c = new Fp2[n];

  // Initialize with random values
  for (int i = 0; i < n; i++) {
    h_a[i] = random_fp2_value(rng);
    h_b[i] = random_fp2_value(rng);
  }

  // Warm-up iterations
  for (int i = 0; i < WARMUP_ITERATIONS; i++) {
    fp2_add_batch_on_host(g_benchmark_stream, g_gpu_index, h_c, h_a, h_b, n);
  }

  for (auto _ : state) {
    fp2_add_batch_on_host(g_benchmark_stream, g_gpu_index, h_c, h_a, h_b, n);
    benchmark::DoNotOptimize(h_c);
  }

  state.SetItemsProcessed(state.iterations() * n);
  state.SetBytesProcessed(state.iterations() * n * sizeof(Fp2) * 3); // a, b, c

  delete[] h_a;
  delete[] h_b;
  delete[] h_c;
}

// Benchmark GPU kernel: array multiplication
static void BM_Fp2_GPU_ArrayMul(benchmark::State &state) {
  init_benchmark();

  const int n = static_cast<int>(state.range(0));
  std::mt19937_64 rng(42);

  // Allocate host arrays
  Fp2 *h_a = new Fp2[n];
  Fp2 *h_b = new Fp2[n];
  Fp2 *h_c = new Fp2[n];

  // Initialize with random values
  for (int i = 0; i < n; i++) {
    h_a[i] = random_fp2_value(rng);
    h_b[i] = random_fp2_value(rng);
  }

  // Warm-up iterations
  for (int i = 0; i < WARMUP_ITERATIONS; i++) {
    fp2_mul_batch_on_host(g_benchmark_stream, g_gpu_index, h_c, h_a, h_b, n);
  }

  for (auto _ : state) {
    fp2_mul_batch_on_host(g_benchmark_stream, g_gpu_index, h_c, h_a, h_b, n);
    benchmark::DoNotOptimize(h_c);
  }

  state.SetItemsProcessed(state.iterations() * n);
  state.SetBytesProcessed(state.iterations() * n * sizeof(Fp2) * 3); // a, b, c

  delete[] h_a;
  delete[] h_b;
  delete[] h_c;
}

// Register scalar benchmarks
BENCHMARK(BM_Fp2_ScalarAdd);
BENCHMARK(BM_Fp2_ScalarSub);
BENCHMARK(BM_Fp2_ScalarMul);
BENCHMARK(BM_Fp2_ScalarSquare);
BENCHMARK(BM_Fp2_ScalarNeg);
BENCHMARK(BM_Fp2_ScalarConjugate);
BENCHMARK(BM_Fp2_ScalarMulByI);
BENCHMARK(BM_Fp2_ScalarInv); // Inversion is expensive, so it's last

// GPU kernel benchmarks with different array sizes
BENCHMARK(BM_Fp2_GPU_ArrayAdd)
    ->Range(1024, 1024 * 1024)
    ->Unit(benchmark::kMicrosecond);
BENCHMARK(BM_Fp2_GPU_ArrayMul)
    ->Range(1024, 1024 * 1024)
    ->Unit(benchmark::kMicrosecond);

// Run benchmarks
BENCHMARK_MAIN();
