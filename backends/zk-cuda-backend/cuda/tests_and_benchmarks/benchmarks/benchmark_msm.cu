#include "curve.h"
#include "device.h"
#include "fp.h"
#include "fp2.h"
#include "msm.h"
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

// Initialize device modulus, curve, and generators
static void init_benchmark() {
  static bool initialized = false;
  if (!initialized) {
    g_gpu_index = 0;

    // Create a CUDA stream using library function
    g_benchmark_stream = cuda_create_stream(g_gpu_index);

    // Device generators are now hardcoded at compile time, no initialization
    // needed

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
    result = reduced;
  }

  return result;
}

// Helper to generate random G1 point (not necessarily on curve, but valid
// coordinates)
static G1Affine random_g1_point(std::mt19937_64 &rng) {
  G1Affine point;
  point.infinity = false;
  point.x = random_fp_value(rng);
  point.y = random_fp_value(rng);
  return point;
}

// Helper to generate random G2 point
static G2Affine random_g2_point(std::mt19937_64 &rng) {
  G2Affine point;
  point.infinity = false;
  point.x.c0 = random_fp_value(rng);
  point.x.c1 = random_fp_value(rng);
  point.y.c0 = random_fp_value(rng);
  point.y.c1 = random_fp_value(rng);
  return point;
}

// Helper to generate random BigInt scalar (320 bits)
static Scalar random_scalar_bigint(std::mt19937_64 &rng) {
  Scalar result;
  for (int i = 0; i < 5; i++) {
    result.limb[i] = rng();
  }
  return result;
}

// Benchmark G1 MSM with random points and 320-bit scalars
static void BM_G1_MSM(benchmark::State &state) {
  uint64_t size_tracker = 0;
  init_benchmark();

  const auto n = static_cast<int>(state.range(0));
  std::mt19937_64 rng(42);

  // Calculate required scratch space
  const int threadsPerBlock =
      get_msm_threads_per_block<G1Affine>(n); // Must match MSM implementation
  const auto num_blocks = CEIL_DIV(n, threadsPerBlock);
  const auto scratch_size =
      (num_blocks + 1) * MSM_G1_BUCKET_COUNT * sizeof(G1Projective);

  // Allocate device memory
  auto *d_points = static_cast<G1Affine *>(cuda_malloc_with_size_tracking_async(
      n * sizeof(G1Affine), g_benchmark_stream, g_gpu_index, size_tracker,
      true));
  auto *d_scalars = static_cast<Scalar *>(cuda_malloc_with_size_tracking_async(
      n * sizeof(Scalar), g_benchmark_stream, g_gpu_index, size_tracker, true));
  auto *d_result =
      static_cast<G1Projective *>(cuda_malloc_with_size_tracking_async(
          sizeof(G1Projective), g_benchmark_stream, g_gpu_index, size_tracker,
          true));
  auto *d_scratch =
      static_cast<G1Projective *>(cuda_malloc_with_size_tracking_async(
          scratch_size, g_benchmark_stream, g_gpu_index, size_tracker, true));

  // Prepare host data
  auto *h_points = new G1Affine[n];
  auto *h_scalars = new Scalar[n];

  // Initialize with random values
  for (int i = 0; i < n; i++) {
    h_points[i] = random_g1_point(rng);
    h_scalars[i] = random_scalar_bigint(rng);
  }

  // Copy to device (once, before benchmark loop)
  cuda_memcpy_with_size_tracking_async_to_gpu(
      d_points, h_points, n * sizeof(G1Affine), g_benchmark_stream, g_gpu_index,
      true);
  cuda_memcpy_with_size_tracking_async_to_gpu(
      d_scalars, h_scalars, n * sizeof(Scalar), g_benchmark_stream, g_gpu_index,
      true);

  // Convert points to Montgomery form (required for performance - all
  // operations use Montgomery)
  point_to_montgomery_batch<G1Affine>(g_benchmark_stream, g_gpu_index, d_points,
                                      n);
  check_cuda_error(cudaGetLastError());

  // Initialize result and scratch memory to zero (once, before benchmark loop)
  cuda_memset_with_size_tracking_async(d_result, 0, sizeof(G1Projective),
                                       g_benchmark_stream, g_gpu_index, true);
  cuda_memset_with_size_tracking_async(d_scratch, 0, scratch_size,
                                       g_benchmark_stream, g_gpu_index, true);

  // Synchronize once before benchmark loop to ensure all setup is complete
  cuda_synchronize_stream(g_benchmark_stream, g_gpu_index);

  // Warm-up iterations
  for (int i = 0; i < WARMUP_ITERATIONS; i++) {
    point_msm_async_g1(g_benchmark_stream, g_gpu_index, d_result, d_points,
                       d_scalars, d_scratch, n, size_tracker);
  }
  cuda_synchronize_stream(g_benchmark_stream, g_gpu_index);

  // Benchmark loop: only measure the MSM computation, no memory operations
  for (auto _ : state) {
    point_msm_async_g1(g_benchmark_stream, g_gpu_index, d_result, d_points,
                       d_scalars, d_scratch, n, size_tracker);
    benchmark::ClobberMemory();
  }

  // Synchronize once after benchmark loop to ensure all iterations complete
  cuda_synchronize_stream(g_benchmark_stream, g_gpu_index);
  state.SetItemsProcessed(state.iterations() * n);
  state.SetBytesProcessed(state.iterations() * n *
                          (sizeof(G1Affine) + sizeof(Scalar)));

  delete[] h_points;
  delete[] h_scalars;
  cuda_drop_with_size_tracking_async(d_points, g_benchmark_stream, g_gpu_index,
                                     true);
  cuda_drop_with_size_tracking_async(d_scalars, g_benchmark_stream, g_gpu_index,
                                     true);
  cuda_drop_with_size_tracking_async(d_result, g_benchmark_stream, g_gpu_index,
                                     true);
  cuda_drop_with_size_tracking_async(d_scratch, g_benchmark_stream, g_gpu_index,
                                     true);
}

// Benchmark G2 MSM with random points and 320-bit scalars
static void BM_G2_MSM(benchmark::State &state) {
  uint64_t size_tracker = 0;
  init_benchmark();

  const auto n = static_cast<int>(state.range(0));
  std::mt19937_64 rng(42);

  // Calculate required scratch space
  const int threadsPerBlock =
      get_msm_threads_per_block<G2Affine>(n); // Must match MSM implementation
  const auto num_blocks = CEIL_DIV(n, threadsPerBlock);
  const auto scratch_size =
      (num_blocks + 1) * MSM_G2_BUCKET_COUNT * sizeof(G2Projective);

  // Allocate device memory
  auto *d_points = static_cast<G2Affine *>(cuda_malloc_with_size_tracking_async(
      n * sizeof(G2Affine), g_benchmark_stream, g_gpu_index, size_tracker,
      true));
  auto *d_scalars = static_cast<Scalar *>(cuda_malloc_with_size_tracking_async(
      n * sizeof(Scalar), g_benchmark_stream, g_gpu_index, size_tracker, true));
  auto *d_result =
      static_cast<G2Projective *>(cuda_malloc_with_size_tracking_async(
          sizeof(G2Projective), g_benchmark_stream, g_gpu_index, size_tracker,
          true));
  auto *d_scratch =
      static_cast<G2Projective *>(cuda_malloc_with_size_tracking_async(
          scratch_size, g_benchmark_stream, g_gpu_index, size_tracker, true));

  // Prepare host data
  auto *h_points = new G2Affine[n];
  auto *h_scalars = new Scalar[n];

  // Initialize with random values
  for (int i = 0; i < n; i++) {
    h_points[i] = random_g2_point(rng);
    h_scalars[i] = random_scalar_bigint(rng);
  }

  // Copy to device (once, before benchmark loop)
  cuda_memcpy_with_size_tracking_async_to_gpu(
      d_points, h_points, n * sizeof(G2Affine), g_benchmark_stream, g_gpu_index,
      true);
  cuda_memcpy_with_size_tracking_async_to_gpu(
      d_scalars, h_scalars, n * sizeof(Scalar), g_benchmark_stream, g_gpu_index,
      true);

  // Convert points to Montgomery form (required for performance - all
  // operations use Montgomery)
  point_to_montgomery_batch<G2Affine>(g_benchmark_stream, g_gpu_index, d_points,
                                      n);
  check_cuda_error(cudaGetLastError());

  // Initialize result and scratch memory to zero (once, before benchmark loop)
  cuda_memset_with_size_tracking_async(d_result, 0, sizeof(G2Projective),
                                       g_benchmark_stream, g_gpu_index, true);
  cuda_memset_with_size_tracking_async(d_scratch, 0, scratch_size,
                                       g_benchmark_stream, g_gpu_index, true);

  // Synchronize once before benchmark loop to ensure all setup is complete
  cuda_synchronize_stream(g_benchmark_stream, g_gpu_index);

  // Warm-up iterations
  for (int i = 0; i < WARMUP_ITERATIONS; i++) {
    point_msm_async_g2(g_benchmark_stream, g_gpu_index, d_result, d_points,
                       d_scalars, d_scratch, n, size_tracker);
  }
  cuda_synchronize_stream(g_benchmark_stream, g_gpu_index);

  // Benchmark loop: only measure the MSM computation, no memory operations
  for (auto _ : state) {
    point_msm_async_g2(g_benchmark_stream, g_gpu_index, d_result, d_points,
                       d_scalars, d_scratch, n, size_tracker);
    benchmark::ClobberMemory();
  }

  // Synchronize once after benchmark loop to ensure all iterations complete
  cuda_synchronize_stream(g_benchmark_stream, g_gpu_index);
  state.SetItemsProcessed(state.iterations() * n);
  state.SetBytesProcessed(state.iterations() * n *
                          (sizeof(G2Affine) + sizeof(Scalar)));

  delete[] h_points;
  delete[] h_scalars;
  cuda_drop_with_size_tracking_async(d_points, g_benchmark_stream, g_gpu_index,
                                     true);
  cuda_drop_with_size_tracking_async(d_scalars, g_benchmark_stream, g_gpu_index,
                                     true);
  cuda_drop_with_size_tracking_async(d_result, g_benchmark_stream, g_gpu_index,
                                     true);
  cuda_drop_with_size_tracking_async(d_scratch, g_benchmark_stream, g_gpu_index,
                                     true);
}

// Register MSM benchmarks with sizes matching the Rust Criterion benchmarks
BENCHMARK(BM_G1_MSM)
    ->Args({100})
    ->Args({1000})
    ->Args({2048})
    ->Args({4096})
    ->Args({10000})
    ->Unit(benchmark::kMillisecond)
    ->Name("zk::cuda::msm::bls12_446::G1");
BENCHMARK(BM_G2_MSM)
    ->Args({100})
    ->Args({1000})
    ->Args({2048})
    ->Args({4096})
    ->Args({10000})
    ->Unit(benchmark::kMillisecond)
    ->Name("zk::cuda::msm::bls12_446::G2");

// Run benchmarks
BENCHMARK_MAIN();
