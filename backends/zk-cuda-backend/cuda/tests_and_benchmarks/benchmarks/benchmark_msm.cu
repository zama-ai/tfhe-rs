#include "curve.h"
#include "device.h"
#include "fp.h"
#include "fp2.h"
#include "msm.h"
#include <benchmark/benchmark.h>
#include <cstdint>
#include <cuda_runtime.h>
#include <random>

// Helper to get modulus (duplicated from test utilities)
static Fp get_modulus() {
  Fp p;
  p.limb[0] = 0x311c0026aab0aaabULL;
  p.limb[1] = 0x56ee4528c573b5ccULL;
  p.limb[2] = 0x824e6dc3e23acdeeULL;
  p.limb[3] = 0x0f75a64bbac71602ULL;
  p.limb[4] = 0x0095a4b78a02fe32ULL;
  p.limb[5] = 0x200fc34965aad640ULL;
  p.limb[6] = 0x3cdee0fb28c5e535ULL;
  // Note: Value is in normal form
  return p;
}

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
    result.limb[i] = rng();
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

// Helper to generate random 64-bit scalar
static uint64_t random_scalar_u64(std::mt19937_64 &rng) { return rng(); }

// Helper to generate random BigInt scalar (320 bits)
static Scalar random_scalar_bigint(std::mt19937_64 &rng) {
  Scalar result;
  for (int i = 0; i < 5; i++) {
    result.limb[i] = rng();
  }
  return result;
}

// Benchmark G1 scalar multiplication (single point)
static void BM_G1_ScalarMul(benchmark::State &state) {
  uint64_t size_tracker = 0;
  init_benchmark();

  std::mt19937_64 rng(42);
  auto h_point = random_g1_point(rng);
  auto scalar = random_scalar_u64(rng);

  // Allocate device memory
  auto *d_point = static_cast<G1Affine *>(cuda_malloc_with_size_tracking_async(
      sizeof(G1Affine), g_benchmark_stream, g_gpu_index, size_tracker, true));
  auto *d_result = static_cast<G1Affine *>(cuda_malloc_with_size_tracking_async(
      sizeof(G1Affine), g_benchmark_stream, g_gpu_index, size_tracker, true));

  // Copy point to device
  cuda_memcpy_with_size_tracking_async_to_gpu(
      d_point, &h_point, sizeof(G1Affine), g_benchmark_stream, g_gpu_index,
      true);
  cuda_synchronize_stream(g_benchmark_stream, g_gpu_index);

  // Warm-up iterations
  for (int i = 0; i < WARMUP_ITERATIONS; i++) {
    point_scalar_mul_u64<G1Affine>(g_benchmark_stream, g_gpu_index, d_result,
                                   d_point, scalar);
  }
  cuda_synchronize_stream(g_benchmark_stream, g_gpu_index);

  for (auto _ : state) {
    point_scalar_mul_u64<G1Affine>(g_benchmark_stream, g_gpu_index, d_result,
                                   d_point, scalar);
    benchmark::ClobberMemory();
  }

  cuda_synchronize_stream(g_benchmark_stream, g_gpu_index);
  state.SetItemsProcessed(state.iterations());

  cuda_drop_with_size_tracking_async(d_point, g_benchmark_stream, g_gpu_index,
                                     true);
  cuda_drop_with_size_tracking_async(d_result, g_benchmark_stream, g_gpu_index,
                                     true);
}

// Benchmark G2 scalar multiplication (single point)
static void BM_G2_ScalarMul(benchmark::State &state) {
  uint64_t size_tracker = 0;
  init_benchmark();

  std::mt19937_64 rng(42);
  auto h_point = random_g2_point(rng);
  auto scalar = random_scalar_u64(rng);

  // Allocate device memory
  auto *d_point = static_cast<G2Affine *>(cuda_malloc_with_size_tracking_async(
      sizeof(G2Affine), g_benchmark_stream, g_gpu_index, size_tracker, true));
  auto *d_result = static_cast<G2Affine *>(cuda_malloc_with_size_tracking_async(
      sizeof(G2Affine), g_benchmark_stream, g_gpu_index, size_tracker, true));

  // Copy point to device
  cuda_memcpy_with_size_tracking_async_to_gpu(
      d_point, &h_point, sizeof(G2Affine), g_benchmark_stream, g_gpu_index,
      true);
  cuda_synchronize_stream(g_benchmark_stream, g_gpu_index);

  // Warm-up iterations
  for (int i = 0; i < WARMUP_ITERATIONS; i++) {
    point_scalar_mul_u64<G2Affine>(g_benchmark_stream, g_gpu_index, d_result,
                                   d_point, scalar);
  }
  cuda_synchronize_stream(g_benchmark_stream, g_gpu_index);

  for (auto _ : state) {
    point_scalar_mul_u64<G2Affine>(g_benchmark_stream, g_gpu_index, d_result,
                                   d_point, scalar);
    benchmark::ClobberMemory();
  }

  cuda_synchronize_stream(g_benchmark_stream, g_gpu_index);
  state.SetItemsProcessed(state.iterations());

  cuda_drop_with_size_tracking_async(d_point, g_benchmark_stream, g_gpu_index,
                                     true);
  cuda_drop_with_size_tracking_async(d_result, g_benchmark_stream, g_gpu_index,
                                     true);
}

// Benchmark G1 MSM with generator point (common use case)
static void BM_G1_MSM_Generator(benchmark::State &state) {
  uint64_t size_tracker = 0;
  init_benchmark();

  const auto n = static_cast<int>(state.range(0));
  std::mt19937_64 rng(42);

  // Get generator point
  const G1Affine &G = g1_generator();

  // Calculate required scratch space: (num_blocks + 1) * MSM_G1_BUCKET_COUNT
  // (projective points)
  const int threadsPerBlock = 128; // Reduced for projective points
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

  // Prepare host data - all points are the generator
  auto *h_points = new G1Affine[n];
  auto *h_scalars = new Scalar[n];

  // Initialize: all points are generator, random scalars
  for (int i = 0; i < n; i++) {
    h_points[i] = G;
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
                       d_scalars, d_scratch, n);
  }
  cuda_synchronize_stream(g_benchmark_stream, g_gpu_index);

  // Benchmark loop: only measure the MSM computation, no memory operations
  for (auto _ : state) {
    point_msm_async_g1(g_benchmark_stream, g_gpu_index, d_result, d_points,
                       d_scalars, d_scratch, n);
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

// Benchmark G2 MSM with generator point (common use case)
static void BM_G2_MSM_Generator(benchmark::State &state) {
  uint64_t size_tracker = 0;
  init_benchmark();

  const auto n = static_cast<int>(state.range(0));
  std::mt19937_64 rng(42);

  // Get generator point
  const G2Affine &G = g2_generator();

  // Calculate required scratch space: (num_blocks + 1) * MSM_G1_BUCKET_COUNT
  // (projective points)
  const int threadsPerBlock = 64; // Reduced for G2 projective points
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

  // Prepare host data - all points are the generator
  auto *h_points = new G2Affine[n];
  auto *h_scalars = new Scalar[n];

  // Initialize: all points are generator, random scalars
  for (int i = 0; i < n; i++) {
    h_points[i] = G;
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
  cuda_memset_with_size_tracking_async(d_result, 0, sizeof(G2Affine),
                                       g_benchmark_stream, g_gpu_index, true);
  cuda_memset_with_size_tracking_async(d_scratch, 0, scratch_size,
                                       g_benchmark_stream, g_gpu_index, true);

  // Synchronize once before benchmark loop to ensure all setup is complete
  cuda_synchronize_stream(g_benchmark_stream, g_gpu_index);

  // Warm-up iterations
  for (int i = 0; i < WARMUP_ITERATIONS; i++) {
    point_msm_async_g2(g_benchmark_stream, g_gpu_index, d_result, d_points,
                       d_scalars, d_scratch, n);
  }
  cuda_synchronize_stream(g_benchmark_stream, g_gpu_index);

  // Benchmark loop: only measure the MSM computation, no memory operations
  for (auto _ : state) {
    point_msm_async_g2(g_benchmark_stream, g_gpu_index, d_result, d_points,
                       d_scalars, d_scratch, n);
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

// Benchmark G1 MSM with BigInt scalars (320-bit scalars)
static void BM_G1_MSM_BigInt(benchmark::State &state) {
  uint64_t size_tracker = 0;
  init_benchmark();

  const auto n = static_cast<int>(state.range(0));
  std::mt19937_64 rng(42);

  // Calculate required scratch space: (num_blocks + 1) * MSM_G1_BUCKET_COUNT
  // (projective points)
  const int threadsPerBlock = 128; // Same as u64 version
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
                       d_scalars, d_scratch, n);
  }
  cuda_synchronize_stream(g_benchmark_stream, g_gpu_index);

  // Benchmark loop: only measure the MSM computation, no memory operations
  for (auto _ : state) {
    point_msm_async_g1(g_benchmark_stream, g_gpu_index, d_result, d_points,
                       d_scalars, d_scratch, n);
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

// Benchmark G2 MSM with BigInt scalars (320-bit scalars)
static void BM_G2_MSM_BigInt(benchmark::State &state) {
  uint64_t size_tracker = 0;
  init_benchmark();

  const auto n = static_cast<int>(state.range(0));
  std::mt19937_64 rng(42);

  // Calculate required scratch space: (num_blocks + 1) * MSM_G1_BUCKET_COUNT
  // (projective points)
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
                       d_scalars, d_scratch, n);
  }
  cuda_synchronize_stream(g_benchmark_stream, g_gpu_index);

  // Benchmark loop: only measure the MSM computation, no memory operations
  for (auto _ : state) {
    point_msm_async_g2(g_benchmark_stream, g_gpu_index, d_result, d_points,
                       d_scalars, d_scratch, n);
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

// Benchmark G1 MSM with BigInt scalars using generator point
static void BM_G1_MSM_BigInt_Generator(benchmark::State &state) {
  uint64_t size_tracker = 0;
  init_benchmark();

  const auto n = static_cast<int>(state.range(0));
  std::mt19937_64 rng(42);

  // Get generator point
  const G1Affine &G = g1_generator();

  // Calculate required scratch space: (num_blocks + 1) * MSM_G1_BUCKET_COUNT
  // (projective points)
  const int threadsPerBlock = 128;
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

  // Prepare host data - all points are the generator
  auto *h_points = new G1Affine[n];
  auto *h_scalars = new Scalar[n];

  // Initialize: all points are generator, random BigInt scalars
  for (int i = 0; i < n; i++) {
    h_points[i] = G;
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
                       d_scalars, d_scratch, n);
  }
  cuda_synchronize_stream(g_benchmark_stream, g_gpu_index);

  // Benchmark loop: only measure the MSM computation, no memory operations
  for (auto _ : state) {
    point_msm_async_g1(g_benchmark_stream, g_gpu_index, d_result, d_points,
                       d_scalars, d_scratch, n);
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

// Benchmark G2 MSM with BigInt scalars using generator point
static void BM_G2_MSM_BigInt_Generator(benchmark::State &state) {
  uint64_t size_tracker = 0;
  init_benchmark();

  const auto n = static_cast<int>(state.range(0));
  std::mt19937_64 rng(42);

  // Get generator point
  const G2Affine &G = g2_generator();

  // Calculate required scratch space: (num_blocks + 1) * MSM_G1_BUCKET_COUNT
  // (projective points)
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

  // Prepare host data - all points are the generator
  auto *h_points = new G2Affine[n];
  auto *h_scalars = new Scalar[n];

  // Initialize: all points are generator, random BigInt scalars
  for (int i = 0; i < n; i++) {
    h_points[i] = G;
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
                       d_scalars, d_scratch, n);
  }
  cuda_synchronize_stream(g_benchmark_stream, g_gpu_index);

  // Benchmark loop: only measure the MSM computation, no memory operations
  for (auto _ : state) {
    point_msm_async_g2(g_benchmark_stream, g_gpu_index, d_result, d_points,
                       d_scalars, d_scratch, n);
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

// Register scalar multiplication benchmarks
BENCHMARK(BM_G1_ScalarMul);
BENCHMARK(BM_G2_ScalarMul);

// Register MSM benchmarks with different sizes
// Range from 10 to 10,000 points

// MSM with generator (common use case)
BENCHMARK(BM_G1_MSM_Generator)
    ->Range(100, 10000)
    ->Unit(benchmark::kMillisecond);
BENCHMARK(BM_G2_MSM_Generator)
    ->Range(100, 10000)
    ->Unit(benchmark::kMillisecond);

// MSM with BigInt scalars (320-bit scalars)
BENCHMARK(BM_G1_MSM_BigInt)->Range(100, 10000)->Unit(benchmark::kMillisecond);
BENCHMARK(BM_G2_MSM_BigInt)->Range(100, 10000)->Unit(benchmark::kMillisecond);

// MSM with BigInt scalars and generator (common use case)
BENCHMARK(BM_G1_MSM_BigInt_Generator)
    ->Range(100, 10000)
    ->Unit(benchmark::kMillisecond);
BENCHMARK(BM_G2_MSM_BigInt_Generator)
    ->Range(100, 10000)
    ->Unit(benchmark::kMillisecond);

// Run benchmarks
BENCHMARK_MAIN();
