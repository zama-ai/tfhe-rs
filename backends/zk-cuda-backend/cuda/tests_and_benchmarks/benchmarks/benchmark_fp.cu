#include "../tests/primitives/fp_helpers.h" // Include test-only batch operations
#include "fp.h"
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

    // Create a CUDA stream
    cudaError_t err = cudaStreamCreate(&g_benchmark_stream);
    if (err != cudaSuccess) {
      fprintf(stderr, "Failed to create CUDA stream: %s\n",
              cudaGetErrorString(err));
      g_benchmark_stream = nullptr;
    }

    // Device modulus is now hardcoded at compile time, no initialization needed
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

// Benchmark scalar addition
static void BM_ScalarAdd(benchmark::State &state) {
  uint64_t size_tracker = 0;
  init_benchmark();

  std::mt19937_64 rng(42);
  Fp a = random_fp_value(rng);
  Fp b = random_fp_value(rng);
  Fp result;

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

// Benchmark scalar multiplication
static void BM_ScalarMul(benchmark::State &state) {
  uint64_t size_tracker = 0;
  init_benchmark();

  std::mt19937_64 rng(42);
  Fp a = random_fp_value(rng);
  Fp b = random_fp_value(rng);
  Fp result;

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

// Benchmark GPU kernel: array addition
static void BM_GPU_ArrayAdd(benchmark::State &state) {
  uint64_t size_tracker = 0;
  init_benchmark();

  const int n = static_cast<int>(state.range(0));
  std::mt19937_64 rng(42);

  // Allocate host arrays
  Fp *h_a = new Fp[n];
  Fp *h_b = new Fp[n];
  Fp *h_c = new Fp[n];

  // Initialize with random values
  for (int i = 0; i < n; i++) {
    h_a[i] = random_fp_value(rng);
    h_b[i] = random_fp_value(rng);
  }

  // Warm-up iterations
  for (int i = 0; i < WARMUP_ITERATIONS; i++) {
    fp_add_batch_on_host(g_benchmark_stream, g_gpu_index, h_c, h_a, h_b, n);
  }

  for (auto _ : state) {
    fp_add_batch_on_host(g_benchmark_stream, g_gpu_index, h_c, h_a, h_b, n);
    benchmark::DoNotOptimize(h_c);
  }

  state.SetItemsProcessed(state.iterations() * n);
  state.SetBytesProcessed(state.iterations() * n * sizeof(Fp) * 3); // a, b, c

  delete[] h_a;
  delete[] h_b;
  delete[] h_c;
}

// Benchmark GPU kernel: array multiplication
static void BM_GPU_ArrayMul(benchmark::State &state) {
  uint64_t size_tracker = 0;
  init_benchmark();

  const int n = static_cast<int>(state.range(0));
  std::mt19937_64 rng(42);

  // Allocate host arrays
  Fp *h_a = new Fp[n];
  Fp *h_b = new Fp[n];
  Fp *h_c = new Fp[n];

  // Initialize with random values
  for (int i = 0; i < n; i++) {
    h_a[i] = random_fp_value(rng);
    h_b[i] = random_fp_value(rng);
  }

  // Warm-up iterations
  for (int i = 0; i < WARMUP_ITERATIONS; i++) {
    fp_mul_batch_on_host(g_benchmark_stream, g_gpu_index, h_c, h_a, h_b, n);
  }

  for (auto _ : state) {
    fp_mul_batch_on_host(g_benchmark_stream, g_gpu_index, h_c, h_a, h_b, n);
    benchmark::DoNotOptimize(h_c);
  }

  state.SetItemsProcessed(state.iterations() * n);
  state.SetBytesProcessed(state.iterations() * n * sizeof(Fp) * 3); // a, b, c

  delete[] h_a;
  delete[] h_b;
  delete[] h_c;
}

// Register benchmarks
BENCHMARK(BM_ScalarAdd);
BENCHMARK(BM_ScalarMul);

// GPU kernel benchmarks with different array sizes
BENCHMARK(BM_GPU_ArrayAdd)
    ->Range(1024, 1024 * 1024)
    ->Unit(benchmark::kMicrosecond);
BENCHMARK(BM_GPU_ArrayMul)
    ->Range(1024, 1024 * 1024)
    ->Unit(benchmark::kMicrosecond);

// Run benchmarks
BENCHMARK_MAIN();
