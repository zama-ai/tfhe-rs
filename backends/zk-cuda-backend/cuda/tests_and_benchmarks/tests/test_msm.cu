#include "curve.h"
#include "device.h"
#include "fp.h"
#include "fp2.h"
#include "msm.h"
#include <cstdint>
#include <cstring>
#include <cuda_runtime.h>
#include <gtest/gtest.h>
#include <iomanip>
#include <iostream>
#include <string>

#include "checked_arithmetic.h"

// Convenience wrappers that allocate scratch, run MSM, and free scratch.
// Tests use these to avoid repeating scratch management at every call site.
static void test_point_msm_g1(cudaStream_t stream, uint32_t gpu_index,
                              G1Projective *d_result, const G1Affine *d_points,
                              const Scalar *d_scalars, uint32_t n,
                              uint64_t &size_tracker) {
  size_t scratch_bytes = pippenger_scratch_size_g1(n, gpu_index);
  void *d_scratch = cuda_malloc_with_size_tracking_async(
      scratch_bytes, stream, gpu_index, size_tracker, true);
  point_msm_g1(stream, gpu_index, d_result, d_points, d_scalars, n, d_scratch,
               size_tracker, true);
  cuda_drop_with_size_tracking_async(d_scratch, stream, gpu_index, true);
}

static void test_point_msm_g2(cudaStream_t stream, uint32_t gpu_index,
                              G2Projective *d_result, const G2Affine *d_points,
                              const Scalar *d_scalars, uint32_t n,
                              uint64_t &size_tracker) {
  size_t scratch_bytes = pippenger_scratch_size_g2(n, gpu_index);
  void *d_scratch = cuda_malloc_with_size_tracking_async(
      scratch_bytes, stream, gpu_index, size_tracker, true);
  point_msm_g2(stream, gpu_index, d_result, d_points, d_scalars, n, d_scratch,
               size_tracker, true);
  cuda_drop_with_size_tracking_async(d_scratch, stream, gpu_index, true);
}

// Test fixture for MSM tests
class MSMTest : public ::testing::Test {
protected:
  void SetUp() override {
    // Initialize CUDA
    if (!cuda_is_available()) {
      GTEST_SKIP() << "CUDA not available";
    }

    gpu_index = 0;
    stream = cuda_create_stream(gpu_index);

    // Device generators are now hardcoded at compile time, no initialization
    // needed
  }

  void TearDown() override {
    if (stream != nullptr) {
      cuda_destroy_stream(stream, gpu_index);
    }
  }

  uint32_t gpu_index;
  cudaStream_t stream;
};

// Helper function to compute N * (N+1) / 2
uint64_t triangular_number(uint64_t N) {
  if (N % 2 == 0) {
    return (N / 2) * (N + 1);
  } else {
    return N * ((N + 1) / 2);
  }
}

// Helper function to convert Fp to decimal string
// Converts from Montgomery form to normal form, then to decimal string
std::string fp_to_decimal_string(const Fp &val_montgomery) {
  // Convert from Montgomery form to normal form
  Fp val_normal;
  fp_from_montgomery(val_normal, val_montgomery);

  // Convert big integer to decimal string using repeated division by 10
  std::string result;
  if (fp_is_zero(val_normal)) {
    return "0";
  }

  // Create a working copy as an array of limbs for easier manipulation
  UNSIGNED_LIMB limbs[FP_LIMBS];
  std::memcpy(limbs, val_normal.limb, sizeof(limbs));

  // Repeatedly divide by 10 and collect remainders
  while (true) {
    // Check if all limbs are zero
    bool all_zero = true;
    for (int i = 0; i < FP_LIMBS; i++) {
      if (limbs[i] != 0) {
        all_zero = false;
        break;
      }
    }
    if (all_zero) {
      break;
    }

#if LIMB_BITS_CONFIG == 64
    // 64-bit limbs: use 128-bit intermediate for division
    uint64_t remainder = 0;
    for (int i = FP_LIMBS - 1; i >= 0; i--) {
      __uint128_t value =
          (static_cast<__uint128_t>(remainder) << 64) | limbs[i];
      limbs[i] = value / 10;
      remainder = value % 10;
    }
#elif LIMB_BITS_CONFIG == 32
    // 32-bit limbs: use 64-bit intermediate for division
    uint32_t remainder = 0;
    for (int i = FP_LIMBS - 1; i >= 0; i--) {
      uint64_t value = (static_cast<uint64_t>(remainder) << 32) | limbs[i];
      limbs[i] = static_cast<uint32_t>(value / 10);
      remainder = static_cast<uint32_t>(value % 10);
    }
#endif

    // The remainder is our digit
    result = std::to_string(remainder) + result;
  }

  return result.empty() ? "0" : result;
}

std::string scalar_to_decimal_string(const Scalar &scalar) {
  std::string result;
  // Create a working copy as an array of limbs for easier manipulation
  UNSIGNED_LIMB limbs[ZP_LIMBS];
  std::memcpy(limbs, scalar.limb, sizeof(limbs));

  // Repeatedly divide by 10 and collect remainders
  while (true) {
    // Check if all limbs are zero
    bool all_zero = true;
    for (int i = 0; i < ZP_LIMBS; i++) {
      if (limbs[i] != 0) {
        all_zero = false;
        break;
      }
    }
    if (all_zero) {
      break;
    }

#if LIMB_BITS_CONFIG == 64
    // 64-bit limbs: use 128-bit intermediate for division
    uint64_t remainder = 0;
    for (int i = ZP_LIMBS - 1; i >= 0; i--) {
      __uint128_t value =
          (static_cast<__uint128_t>(remainder) << 64) | limbs[i];
      limbs[i] = value / 10;
      remainder = value % 10;
    }
#elif LIMB_BITS_CONFIG == 32
    // 32-bit limbs: use 64-bit intermediate for division
    uint32_t remainder = 0;
    for (int i = ZP_LIMBS - 1; i >= 0; i--) {
      uint64_t value = (static_cast<uint64_t>(remainder) << 32) | limbs[i];
      limbs[i] = static_cast<uint32_t>(value / 10);
      remainder = static_cast<uint32_t>(value % 10);
    }
#endif

    // The remainder is our digit
    result = std::to_string(remainder) + result;
  }

  return result.empty() ? "0" : result;
}

// Helper function to print Fp value as decimal scalar
void print_fp(const char *label, const Fp &val) {
  std::string decimal = fp_to_decimal_string(val);
  std::cout << label << ": " << decimal << std::endl;
}

// Helper function to print G1Point
void print_labelled_g1_point(const char *label, const G1Affine &point) {
  std::cout << label << ":" << std::endl;
  if (point.infinity) {
    std::cout << "  Infinity: true" << std::endl;
  } else {
    std::cout << "  Infinity: false" << std::endl;
    print_fp("  X", point.x);
    print_fp("  Y", point.y);
  }
}

// Helper function to print G1Point
void print_g1_affine(const G1Affine &point) {
  const std::string x = fp_to_decimal_string(point.x);
  const std::string y = fp_to_decimal_string(point.y);
  std::cout << "x: " << x << ", y: " << y << ", infinity: " << point.infinity
            << std::endl;
}

void print_scalar(const Scalar &scalar) {
  std::string decimal = scalar_to_decimal_string(scalar);
  std::cout << decimal << std::endl;
}

// Test G1 MSM with generator point
// For N points, scalars are [1, 2, 3, ..., N]
// Expected result: G * (1 + 2 + ... + N) = G * N * (N+1) / 2
TEST_F(MSMTest, G1MSMWithGenerator) {
  const uint32_t N = 10; // Test with 10 points

  // Get generator point
  const G1Affine &G = g1_generator();
  G1Affine G_mont = G;
  point_to_montgomery_inplace(G_mont);

  // Check that generator is not at infinity (should be set from tfhe-rs)
  if (g1_is_infinity(G)) {
    GTEST_SKIP() << "G1 generator not set - please provide generator points "
                    "from tfhe-rs";
  }

  // Scratch is allocated and freed by the test_point_msm_g1/g2 helpers

  uint64_t size_tracker = 0;

  // Allocate device memory for points and scalars
  auto *d_points = static_cast<G1Affine *>(cuda_malloc_with_size_tracking_async(
      safe_mul_sizeof<G1Affine>(static_cast<size_t>(N)), stream, gpu_index,
      size_tracker, true));
  auto *d_scalars = static_cast<Scalar *>(cuda_malloc_with_size_tracking_async(
      safe_mul_sizeof<Scalar>(static_cast<size_t>(N)), stream, gpu_index,
      size_tracker, true));
  auto *d_result =
      static_cast<G1Projective *>(cuda_malloc_with_size_tracking_async(
          sizeof(G1Projective), stream, gpu_index, size_tracker, true));
  // Scratch is managed by the test helper wrappers
  auto *d_expected =
      static_cast<G1Affine *>(cuda_malloc_with_size_tracking_async(
          sizeof(G1Affine), stream, gpu_index, size_tracker, true));
  auto *d_G = static_cast<G1Affine *>(cuda_malloc_with_size_tracking_async(
      sizeof(G1Affine), stream, gpu_index, size_tracker, true));

  // Initialize allocated memory to zero to avoid uninitialized access warnings
  cuda_memset_with_size_tracking_async(d_result, 0, sizeof(G1Projective),
                                       stream, gpu_index, true);
  cuda_memset_with_size_tracking_async(d_expected, 0, sizeof(G1Affine), stream,
                                       gpu_index, true);
  cuda_memset_with_size_tracking_async(d_G, 0, sizeof(G1Affine), stream,
                                       gpu_index, true);

  // Prepare host data (generator provided in standard form)
  auto *h_points = static_cast<G1Affine *>(
      malloc(safe_mul_sizeof<G1Affine>(static_cast<size_t>(N))));
  for (uint64_t i = 0; i < N; i++) {
    h_points[i] = G;
  }

  auto *h_scalars = static_cast<Scalar *>(
      malloc(safe_mul_sizeof<Scalar>(static_cast<size_t>(N))));
  for (uint64_t i = 0; i < N; i++) {
    // Convert uint64_t to BigInt5 (put value in first limb, zeros in rest)
    h_scalars[i].limb[0] = i + 1;
    // Use memset to zero the remaining limbs
    memset(&h_scalars[i].limb[1], 0, (ZP_LIMBS - 1) * sizeof(UNSIGNED_LIMB));
  }

  // Copy to device
  cuda_memcpy_with_size_tracking_async_to_gpu(
      d_points, h_points, safe_mul_sizeof<G1Affine>(static_cast<size_t>(N)),
      stream, gpu_index, true);
  cuda_memcpy_with_size_tracking_async_to_gpu(
      d_scalars, h_scalars, safe_mul_sizeof<Scalar>(static_cast<size_t>(N)),
      stream, gpu_index, true);

  // Convert points to Montgomery form (required for performance)
  point_to_montgomery_batch<G1Affine>(stream, gpu_index, d_points, N);
  check_cuda_error(cudaGetLastError());

  // Copy generator (converted to Montgomery) to device for scalar
  // multiplication
  cuda_memcpy_with_size_tracking_async_to_gpu(d_G, &G_mont, sizeof(G1Affine),
                                              stream, gpu_index, true);

  // Compute MSM on device (returns projective point)
  test_point_msm_g1(stream, gpu_index, d_result, d_points, d_scalars, N,
                    size_tracker);

  // Compute expected result on device: G * (N * (N+1) / 2)
  UNSIGNED_LIMB expected_scalar =
      static_cast<UNSIGNED_LIMB>(triangular_number(N));
  single_point_scalar_mul<G1Affine>(stream, gpu_index, d_expected, d_G,
                                    expected_scalar);

  // Copy results to host and compare on CPU (avoids GPU->CPU->GPU round-trip)
  cuda_synchronize_stream(stream, gpu_index);
  G1Projective h_result_proj;
  G1Affine expected_result;
  cuda_memcpy_async_to_cpu(&h_result_proj, d_result, sizeof(G1Projective),
                           stream, gpu_index);
  cuda_memcpy_async_to_cpu(&expected_result, d_expected, sizeof(G1Affine),
                           stream, gpu_index);
  cuda_synchronize_stream(stream, gpu_index);

  // Convert projective->affine first (uses Montgomery arithmetic internally),
  // then convert both results from Montgomery to standard form
  G1Affine msm_result;
  projective_to_affine_g1(msm_result, h_result_proj);
  fp_from_montgomery(msm_result.x, msm_result.x);
  fp_from_montgomery(msm_result.y, msm_result.y);
  fp_from_montgomery(expected_result.x, expected_result.x);
  fp_from_montgomery(expected_result.y, expected_result.y);

  // Compare results
  EXPECT_EQ(msm_result.infinity, expected_result.infinity);
  if (!msm_result.infinity && !expected_result.infinity) {
    EXPECT_EQ(fp_cmp(msm_result.x, expected_result.x), ComparisonType::Equal)
        << "MSM x-coordinate mismatch";
    EXPECT_EQ(fp_cmp(msm_result.y, expected_result.y), ComparisonType::Equal)
        << "MSM y-coordinate mismatch";
  }

  // Cleanup
  free(h_points);
  free(h_scalars);
  cuda_drop_with_size_tracking_async(d_points, stream, gpu_index, true);
  cuda_drop_with_size_tracking_async(d_scalars, stream, gpu_index, true);
  cuda_drop_with_size_tracking_async(d_result, stream, gpu_index, true);
  // Scratch freed by test helper
  cuda_drop_with_size_tracking_async(d_expected, stream, gpu_index, true);
  cuda_drop_with_size_tracking_async(d_G, stream, gpu_index, true);
}

// Test G2 MSM with generator point
TEST_F(MSMTest, G2MSMWithGenerator) {
  const uint32_t N = 10; // Test with 10 points

  // Get generator point
  const G2Affine &G = g2_generator();
  G2Affine G_mont = G;
  point_to_montgomery_inplace(G_mont);

  // Check that generator is not at infinity (should be set from tfhe-rs)
  if (g2_is_infinity(G)) {
    GTEST_SKIP() << "G2 generator not set - please provide generator points "
                    "from tfhe-rs";
  }

  // Scratch is allocated and freed by the test_point_msm_g1/g2 helpers

  uint64_t size_tracker = 0;

  // Allocate device memory
  auto *d_points = static_cast<G2Affine *>(cuda_malloc_with_size_tracking_async(
      safe_mul_sizeof<G2Affine>(static_cast<size_t>(N)), stream, gpu_index,
      size_tracker, true));
  auto *d_scalars = static_cast<Scalar *>(cuda_malloc_with_size_tracking_async(
      safe_mul_sizeof<Scalar>(static_cast<size_t>(N)), stream, gpu_index,
      size_tracker, true));
  auto *d_result =
      static_cast<G2Projective *>(cuda_malloc_with_size_tracking_async(
          sizeof(G2Projective), stream, gpu_index, size_tracker, true));
  // Scratch is managed by the test helper wrappers
  auto *d_expected =
      static_cast<G2Affine *>(cuda_malloc_with_size_tracking_async(
          sizeof(G2Affine), stream, gpu_index, size_tracker, true));
  auto *d_G = static_cast<G2Affine *>(cuda_malloc_with_size_tracking_async(
      sizeof(G2Affine), stream, gpu_index, size_tracker, true));

  // Initialize allocated memory to zero to avoid uninitialized access warnings
  cuda_memset_with_size_tracking_async(d_result, 0, sizeof(G2Projective),
                                       stream, gpu_index, true);
  cuda_memset_with_size_tracking_async(d_expected, 0, sizeof(G2Affine), stream,
                                       gpu_index, true);
  cuda_memset_with_size_tracking_async(d_G, 0, sizeof(G2Affine), stream,
                                       gpu_index, true);

  // Prepare host data (generator already in standard form)

  auto *h_points = static_cast<G2Affine *>(
      malloc(safe_mul_sizeof<G2Affine>(static_cast<size_t>(N))));
  for (uint64_t i = 0; i < N; i++) {
    h_points[i] = G;
  }

  auto *h_scalars = static_cast<Scalar *>(
      malloc(safe_mul_sizeof<Scalar>(static_cast<size_t>(N))));
  for (uint64_t i = 0; i < N; i++) {
    // Convert uint64_t to BigInt5 (put value in first limb, zeros in rest)
    h_scalars[i].limb[0] = i + 1;
    // Use memset to zero the remaining limbs
    memset(&h_scalars[i].limb[1], 0, (ZP_LIMBS - 1) * sizeof(UNSIGNED_LIMB));
  }

  // Copy to device
  cuda_memcpy_with_size_tracking_async_to_gpu(
      d_points, h_points, safe_mul_sizeof<G2Affine>(static_cast<size_t>(N)),
      stream, gpu_index, true);
  cuda_memcpy_with_size_tracking_async_to_gpu(
      d_scalars, h_scalars, safe_mul_sizeof<Scalar>(static_cast<size_t>(N)),
      stream, gpu_index, true);

  // Convert points to Montgomery form (required for performance)
  point_to_montgomery_batch<G2Affine>(stream, gpu_index, d_points, N);
  check_cuda_error(cudaGetLastError());

  // Copy generator (converted to Montgomery) to device
  cuda_memcpy_with_size_tracking_async_to_gpu(d_G, &G_mont, sizeof(G2Affine),
                                              stream, gpu_index, true);

  // Compute MSM on device (returns projective point)
  test_point_msm_g2(stream, gpu_index, d_result, d_points, d_scalars, N,
                    size_tracker);

  // Compute expected result on device: G * (N * (N+1) / 2)
  UNSIGNED_LIMB expected_scalar =
      static_cast<UNSIGNED_LIMB>(triangular_number(N));
  single_point_scalar_mul<G2Affine>(stream, gpu_index, d_expected, d_G,
                                    expected_scalar);

  // Copy results to host and compare on CPU (avoids GPU->CPU->GPU round-trip)
  cuda_synchronize_stream(stream, gpu_index);
  G2Projective h_result_proj;
  G2Affine expected_result;
  cuda_memcpy_async_to_cpu(&h_result_proj, d_result, sizeof(G2Projective),
                           stream, gpu_index);
  cuda_memcpy_async_to_cpu(&expected_result, d_expected, sizeof(G2Affine),
                           stream, gpu_index);
  cuda_synchronize_stream(stream, gpu_index);

  // Convert projective->affine first (uses Montgomery arithmetic internally),
  // then convert both results from Montgomery to standard form
  G2Affine msm_result;
  projective_to_affine_g2(msm_result, h_result_proj);
  fp_from_montgomery(msm_result.x.c0, msm_result.x.c0);
  fp_from_montgomery(msm_result.x.c1, msm_result.x.c1);
  fp_from_montgomery(msm_result.y.c0, msm_result.y.c0);
  fp_from_montgomery(msm_result.y.c1, msm_result.y.c1);
  fp_from_montgomery(expected_result.x.c0, expected_result.x.c0);
  fp_from_montgomery(expected_result.x.c1, expected_result.x.c1);
  fp_from_montgomery(expected_result.y.c0, expected_result.y.c0);
  fp_from_montgomery(expected_result.y.c1, expected_result.y.c1);

  // Compare results
  EXPECT_EQ(msm_result.infinity, expected_result.infinity);
  if (!msm_result.infinity && !expected_result.infinity) {
    EXPECT_EQ(fp2_cmp(msm_result.x, expected_result.x), ComparisonType::Equal)
        << "MSM x-coordinate mismatch";
    EXPECT_EQ(fp2_cmp(msm_result.y, expected_result.y), ComparisonType::Equal)
        << "MSM y-coordinate mismatch";
  }

  // Cleanup
  free(h_points);
  free(h_scalars);
  cuda_drop_with_size_tracking_async(d_points, stream, gpu_index, true);
  cuda_drop_with_size_tracking_async(d_scalars, stream, gpu_index, true);
  cuda_drop_with_size_tracking_async(d_result, stream, gpu_index, true);
  // Scratch freed by test helper
  cuda_drop_with_size_tracking_async(d_expected, stream, gpu_index, true);
  cuda_drop_with_size_tracking_async(d_G, stream, gpu_index, true);
}

// Test with larger N to verify correctness
TEST_F(MSMTest, G1MSMLargeN) {
  constexpr uint32_t MAX_N = 100;

  const G1Affine &G = g1_generator();
  if (g1_is_infinity(G)) {
    GTEST_SKIP() << "G1 generator not set";
  }
  G1Affine G_mont = G;
  point_to_montgomery_inplace(G_mont);

  uint64_t size_tracker = 0;

  // Pre-allocate device buffers for max N to avoid per-iteration alloc/free
  auto *d_points = static_cast<G1Affine *>(cuda_malloc_with_size_tracking_async(
      safe_mul_sizeof<G1Affine>(static_cast<size_t>(MAX_N)), stream, gpu_index,
      size_tracker, true));
  auto *d_scalars = static_cast<Scalar *>(cuda_malloc_with_size_tracking_async(
      safe_mul_sizeof<Scalar>(static_cast<size_t>(MAX_N)), stream, gpu_index,
      size_tracker, true));
  auto *d_result =
      static_cast<G1Projective *>(cuda_malloc_with_size_tracking_async(
          sizeof(G1Projective), stream, gpu_index, size_tracker, true));
  auto *d_expected =
      static_cast<G1Affine *>(cuda_malloc_with_size_tracking_async(
          sizeof(G1Affine), stream, gpu_index, size_tracker, true));
  auto *d_G = static_cast<G1Affine *>(cuda_malloc_with_size_tracking_async(
      sizeof(G1Affine), stream, gpu_index, size_tracker, true));

  // Prepare host points (all copies of generator) and upload once for max N
  auto *h_points = static_cast<G1Affine *>(
      malloc(safe_mul_sizeof<G1Affine>(static_cast<size_t>(MAX_N))));
  auto *h_scalars = static_cast<Scalar *>(
      malloc(safe_mul_sizeof<Scalar>(static_cast<size_t>(MAX_N))));
  for (uint32_t i = 0; i < MAX_N; i++) {
    h_points[i] = G;
    h_scalars[i].limb[0] = i + 1;
    memset(&h_scalars[i].limb[1], 0, (ZP_LIMBS - 1) * sizeof(UNSIGNED_LIMB));
  }

  cuda_memcpy_with_size_tracking_async_to_gpu(
      d_points, h_points, safe_mul_sizeof<G1Affine>(static_cast<size_t>(MAX_N)),
      stream, gpu_index, true);
  point_to_montgomery_batch<G1Affine>(stream, gpu_index, d_points, MAX_N);
  check_cuda_error(cudaGetLastError());

  cuda_memcpy_with_size_tracking_async_to_gpu(d_G, &G_mont, sizeof(G1Affine),
                                              stream, gpu_index, true);

  for (uint32_t N = 1; N <= MAX_N; N++) {
    // Upload only the first N scalars each iteration
    cuda_memcpy_with_size_tracking_async_to_gpu(
        d_scalars, h_scalars, safe_mul_sizeof<Scalar>(static_cast<size_t>(N)),
        stream, gpu_index, true);

    cuda_memset_with_size_tracking_async(d_result, 0, sizeof(G1Projective),
                                         stream, gpu_index, true);

    test_point_msm_g1(stream, gpu_index, d_result, d_points, d_scalars, N,
                      size_tracker);

    UNSIGNED_LIMB expected_scalar =
        static_cast<UNSIGNED_LIMB>(triangular_number(N));
    single_point_scalar_mul<G1Affine>(stream, gpu_index, d_expected, d_G,
                                      expected_scalar);

    // Copy results to host and compare on CPU
    cuda_synchronize_stream(stream, gpu_index);
    G1Projective h_result_proj;
    G1Affine expected_result;
    cuda_memcpy_async_to_cpu(&h_result_proj, d_result, sizeof(G1Projective),
                             stream, gpu_index);
    cuda_memcpy_async_to_cpu(&expected_result, d_expected, sizeof(G1Affine),
                             stream, gpu_index);
    cuda_synchronize_stream(stream, gpu_index);

    // Convert projective->affine first (uses Montgomery arithmetic internally),
    // then convert both results from Montgomery to standard form
    G1Affine msm_result;
    projective_to_affine_g1(msm_result, h_result_proj);
    fp_from_montgomery(msm_result.x, msm_result.x);
    fp_from_montgomery(msm_result.y, msm_result.y);
    fp_from_montgomery(expected_result.x, expected_result.x);
    fp_from_montgomery(expected_result.y, expected_result.y);

    EXPECT_EQ(msm_result.infinity, expected_result.infinity) << "N=" << N;
    if (!msm_result.infinity && !expected_result.infinity) {
      ComparisonType x_cmp = fp_cmp(msm_result.x, expected_result.x);
      ComparisonType y_cmp = fp_cmp(msm_result.y, expected_result.y);
      if (x_cmp != ComparisonType::Equal || y_cmp != ComparisonType::Equal) {
        printf("G1MSMLargeN FAILED: N=%u, expected_scalar=%lu\n", N,
               triangular_number(N));
        printf("MSM result: ");
        print_g1_affine(msm_result);
        printf("Expected result: ");
        print_g1_affine(expected_result);
      }

      EXPECT_EQ(x_cmp, ComparisonType::Equal)
          << "N=" << N << " x-coordinate mismatch";
      EXPECT_EQ(y_cmp, ComparisonType::Equal)
          << "N=" << N << " y-coordinate mismatch";
    }
  }

  free(h_points);
  free(h_scalars);
  cuda_drop_with_size_tracking_async(d_points, stream, gpu_index, true);
  cuda_drop_with_size_tracking_async(d_scalars, stream, gpu_index, true);
  cuda_drop_with_size_tracking_async(d_result, stream, gpu_index, true);
  cuda_drop_with_size_tracking_async(d_expected, stream, gpu_index, true);
  cuda_drop_with_size_tracking_async(d_G, stream, gpu_index, true);
}

// Test G2 MSM with larger N to verify correctness (compare with G1MSMLargeN)
TEST_F(MSMTest, G2MSMLargeN) {
  constexpr uint32_t MAX_N = 100;

  const G2Affine &G = g2_generator();
  if (g2_is_infinity(G)) {
    GTEST_SKIP() << "G2 generator not set";
  }
  G2Affine G_mont = G;
  point_to_montgomery_inplace(G_mont);

  uint64_t size_tracker = 0;

  // Pre-allocate device buffers for max N to avoid per-iteration alloc/free
  auto *d_points = static_cast<G2Affine *>(cuda_malloc_with_size_tracking_async(
      safe_mul_sizeof<G2Affine>(static_cast<size_t>(MAX_N)), stream, gpu_index,
      size_tracker, true));
  auto *d_scalars = static_cast<Scalar *>(cuda_malloc_with_size_tracking_async(
      safe_mul_sizeof<Scalar>(static_cast<size_t>(MAX_N)), stream, gpu_index,
      size_tracker, true));
  auto *d_result =
      static_cast<G2Projective *>(cuda_malloc_with_size_tracking_async(
          sizeof(G2Projective), stream, gpu_index, size_tracker, true));
  auto *d_expected =
      static_cast<G2Affine *>(cuda_malloc_with_size_tracking_async(
          sizeof(G2Affine), stream, gpu_index, size_tracker, true));
  auto *d_G = static_cast<G2Affine *>(cuda_malloc_with_size_tracking_async(
      sizeof(G2Affine), stream, gpu_index, size_tracker, true));

  // Prepare host points (all copies of generator) and upload once for max N
  auto *h_points = static_cast<G2Affine *>(
      malloc(safe_mul_sizeof<G2Affine>(static_cast<size_t>(MAX_N))));
  auto *h_scalars = static_cast<Scalar *>(
      malloc(safe_mul_sizeof<Scalar>(static_cast<size_t>(MAX_N))));
  for (uint32_t i = 0; i < MAX_N; i++) {
    h_points[i] = G;
    h_scalars[i].limb[0] = i + 1;
    memset(&h_scalars[i].limb[1], 0, (ZP_LIMBS - 1) * sizeof(UNSIGNED_LIMB));
  }

  cuda_memcpy_with_size_tracking_async_to_gpu(
      d_points, h_points, safe_mul_sizeof<G2Affine>(static_cast<size_t>(MAX_N)),
      stream, gpu_index, true);
  point_to_montgomery_batch<G2Affine>(stream, gpu_index, d_points, MAX_N);
  check_cuda_error(cudaGetLastError());

  cuda_memcpy_with_size_tracking_async_to_gpu(d_G, &G_mont, sizeof(G2Affine),
                                              stream, gpu_index, true);

  for (uint32_t N = 1; N <= MAX_N; N++) {
    // Upload only the first N scalars each iteration
    cuda_memcpy_with_size_tracking_async_to_gpu(
        d_scalars, h_scalars, safe_mul_sizeof<Scalar>(static_cast<size_t>(N)),
        stream, gpu_index, true);

    cuda_memset_with_size_tracking_async(d_result, 0, sizeof(G2Projective),
                                         stream, gpu_index, true);

    test_point_msm_g2(stream, gpu_index, d_result, d_points, d_scalars, N,
                      size_tracker);

    UNSIGNED_LIMB expected_scalar =
        static_cast<UNSIGNED_LIMB>(triangular_number(N));
    single_point_scalar_mul<G2Affine>(stream, gpu_index, d_expected, d_G,
                                      expected_scalar);

    // Copy results to host and compare on CPU
    cuda_synchronize_stream(stream, gpu_index);
    G2Projective h_result_proj;
    G2Affine expected_result;
    cuda_memcpy_async_to_cpu(&h_result_proj, d_result, sizeof(G2Projective),
                             stream, gpu_index);
    cuda_memcpy_async_to_cpu(&expected_result, d_expected, sizeof(G2Affine),
                             stream, gpu_index);
    cuda_synchronize_stream(stream, gpu_index);

    // Convert projective->affine first (uses Montgomery arithmetic internally),
    // then convert both results from Montgomery to standard form
    G2Affine msm_result;
    projective_to_affine_g2(msm_result, h_result_proj);
    fp_from_montgomery(msm_result.x.c0, msm_result.x.c0);
    fp_from_montgomery(msm_result.x.c1, msm_result.x.c1);
    fp_from_montgomery(msm_result.y.c0, msm_result.y.c0);
    fp_from_montgomery(msm_result.y.c1, msm_result.y.c1);
    fp_from_montgomery(expected_result.x.c0, expected_result.x.c0);
    fp_from_montgomery(expected_result.x.c1, expected_result.x.c1);
    fp_from_montgomery(expected_result.y.c0, expected_result.y.c0);
    fp_from_montgomery(expected_result.y.c1, expected_result.y.c1);

    EXPECT_EQ(msm_result.infinity, expected_result.infinity) << "N=" << N;
    if (!msm_result.infinity && !expected_result.infinity) {
      ComparisonType x_cmp = fp2_cmp(msm_result.x, expected_result.x);
      ComparisonType y_cmp = fp2_cmp(msm_result.y, expected_result.y);
      if (x_cmp != ComparisonType::Equal || y_cmp != ComparisonType::Equal) {
        printf("G2MSMLargeN FAILED: N=%u, expected_scalar=%lu\n", N,
               triangular_number(N));
      }

      EXPECT_EQ(x_cmp, ComparisonType::Equal)
          << "N=" << N << " x-coordinate mismatch";
      EXPECT_EQ(y_cmp, ComparisonType::Equal)
          << "N=" << N << " y-coordinate mismatch";
    }
  }

  free(h_points);
  free(h_scalars);
  cuda_drop_with_size_tracking_async(d_points, stream, gpu_index, true);
  cuda_drop_with_size_tracking_async(d_scalars, stream, gpu_index, true);
  cuda_drop_with_size_tracking_async(d_result, stream, gpu_index, true);
  cuda_drop_with_size_tracking_async(d_expected, stream, gpu_index, true);
  cuda_drop_with_size_tracking_async(d_G, stream, gpu_index, true);
}

// u64_to_scalar hardcodes 5 limbs which matches only LIMB_BITS_CONFIG == 64
// (ZP_LIMBS == 5). Guard it and its callers to prevent uninitialized limbs
// or implicit narrowing when LIMB_BITS_CONFIG == 32.
#if LIMB_BITS_CONFIG == 64

// Helper function to convert uint64_t to Scalar (put value in first limb, zeros
// in rest)
Scalar u64_to_scalar(uint64_t val) {
  Scalar result;
  result.limb[0] = val;
  result.limb[1] = 0;
  result.limb[2] = 0;
  result.limb[3] = 0;
  result.limb[4] = 0;
  return result;
}

// Test G1 MSM with bigint scalars
TEST_F(MSMTest, G1MSMWithBigIntScalars) {
  const uint32_t N = 10;

  const G1Affine &G = g1_generator();
  G1Affine G_mont = G;
  point_to_montgomery_inplace(G_mont);

  if (g1_is_infinity(G)) {
    GTEST_SKIP() << "G1 generator not set";
  }

  // Scratch is allocated and freed by the test_point_msm_g1/g2 helpers

  uint64_t size_tracker = 0;

  auto *d_points = static_cast<G1Affine *>(cuda_malloc_with_size_tracking_async(
      safe_mul_sizeof<G1Affine>(static_cast<size_t>(N)), stream, gpu_index,
      size_tracker, true));
  auto *d_scalars = static_cast<Scalar *>(cuda_malloc_with_size_tracking_async(
      safe_mul_sizeof<Scalar>(static_cast<size_t>(N)), stream, gpu_index,
      size_tracker, true));
  auto *d_result =
      static_cast<G1Projective *>(cuda_malloc_with_size_tracking_async(
          sizeof(G1Projective), stream, gpu_index, size_tracker, true));
  // Scratch is managed by the test helper wrappers
  auto *d_expected =
      static_cast<G1Affine *>(cuda_malloc_with_size_tracking_async(
          sizeof(G1Affine), stream, gpu_index, size_tracker, true));
  auto *d_G = static_cast<G1Affine *>(cuda_malloc_with_size_tracking_async(
      sizeof(G1Affine), stream, gpu_index, size_tracker, true));

  cuda_memset_with_size_tracking_async(d_result, 0, sizeof(G1Projective),
                                       stream, gpu_index, true);
  cuda_memset_with_size_tracking_async(d_expected, 0, sizeof(G1Affine), stream,
                                       gpu_index, true);
  cuda_memset_with_size_tracking_async(d_G, 0, sizeof(G1Affine), stream,
                                       gpu_index, true);

  auto *h_points = static_cast<G1Affine *>(
      malloc(safe_mul_sizeof<G1Affine>(static_cast<size_t>(N))));
  for (uint64_t i = 0; i < N; i++) {
    h_points[i] = G;
  }

  auto *h_scalars = static_cast<Scalar *>(
      malloc(safe_mul_sizeof<Scalar>(static_cast<size_t>(N))));
  for (uint64_t i = 0; i < N; i++) {
    h_scalars[i] = u64_to_scalar(i + 1);
  }

  cuda_memcpy_with_size_tracking_async_to_gpu(
      d_points, h_points, safe_mul_sizeof<G1Affine>(static_cast<size_t>(N)),
      stream, gpu_index, true);
  cuda_memcpy_with_size_tracking_async_to_gpu(
      d_scalars, h_scalars, safe_mul_sizeof<Scalar>(static_cast<size_t>(N)),
      stream, gpu_index, true);

  point_to_montgomery_batch<G1Affine>(stream, gpu_index, d_points, N);
  check_cuda_error(cudaGetLastError());

  cuda_memcpy_with_size_tracking_async_to_gpu(d_G, &G_mont, sizeof(G1Affine),
                                              stream, gpu_index, true);

  test_point_msm_g1(stream, gpu_index, d_result, d_points, d_scalars, N,
                    size_tracker);

  UNSIGNED_LIMB expected_scalar =
      static_cast<UNSIGNED_LIMB>(triangular_number(N));
  single_point_scalar_mul<G1Affine>(stream, gpu_index, d_expected, d_G,
                                    expected_scalar);

  // Copy results to host and compare on CPU (avoids GPU->CPU->GPU round-trip)
  cuda_synchronize_stream(stream, gpu_index);
  G1Projective h_result_proj;
  G1Affine expected_result;
  cuda_memcpy_async_to_cpu(&h_result_proj, d_result, sizeof(G1Projective),
                           stream, gpu_index);
  cuda_memcpy_async_to_cpu(&expected_result, d_expected, sizeof(G1Affine),
                           stream, gpu_index);
  cuda_synchronize_stream(stream, gpu_index);

  // Convert projective->affine first (uses Montgomery arithmetic internally),
  // then convert both results from Montgomery to standard form
  G1Affine msm_result;
  projective_to_affine_g1(msm_result, h_result_proj);
  fp_from_montgomery(msm_result.x, msm_result.x);
  fp_from_montgomery(msm_result.y, msm_result.y);
  fp_from_montgomery(expected_result.x, expected_result.x);
  fp_from_montgomery(expected_result.y, expected_result.y);

  EXPECT_EQ(msm_result.infinity, expected_result.infinity);
  if (!msm_result.infinity && !expected_result.infinity) {
    EXPECT_EQ(fp_cmp(msm_result.x, expected_result.x), ComparisonType::Equal)
        << "MSM x-coordinate mismatch";
    EXPECT_EQ(fp_cmp(msm_result.y, expected_result.y), ComparisonType::Equal)
        << "MSM y-coordinate mismatch";
  }

  free(h_points);
  free(h_scalars);
  cuda_drop_with_size_tracking_async(d_points, stream, gpu_index, true);
  cuda_drop_with_size_tracking_async(d_scalars, stream, gpu_index, true);
  cuda_drop_with_size_tracking_async(d_result, stream, gpu_index, true);
  // Scratch freed by test helper
  cuda_drop_with_size_tracking_async(d_expected, stream, gpu_index, true);
  cuda_drop_with_size_tracking_async(d_G, stream, gpu_index, true);
}

// Test G2 MSM with bigint scalars
TEST_F(MSMTest, G2MSMWithBigIntScalars) {
  const uint32_t N = 2;

  const G2Affine &G = g2_generator();
  G2Affine G_mont = G;
  point_to_montgomery_inplace(G_mont);

  if (g2_is_infinity(G)) {
    GTEST_SKIP() << "G2 generator not set";
  }

  // Scratch is allocated and freed by the test_point_msm_g1/g2 helpers

  uint64_t size_tracker = 0;

  auto *d_points = static_cast<G2Affine *>(cuda_malloc_with_size_tracking_async(
      safe_mul_sizeof<G2Affine>(static_cast<size_t>(N)), stream, gpu_index,
      size_tracker, true));
  auto *d_scalars = static_cast<Scalar *>(cuda_malloc_with_size_tracking_async(
      safe_mul_sizeof<Scalar>(static_cast<size_t>(N)), stream, gpu_index,
      size_tracker, true));
  auto *d_result =
      static_cast<G2Projective *>(cuda_malloc_with_size_tracking_async(
          sizeof(G2Projective), stream, gpu_index, size_tracker, true));
  // Scratch is managed by the test helper wrappers
  auto *d_expected =
      static_cast<G2Affine *>(cuda_malloc_with_size_tracking_async(
          sizeof(G2Affine), stream, gpu_index, size_tracker, true));
  auto *d_G = static_cast<G2Affine *>(cuda_malloc_with_size_tracking_async(
      sizeof(G2Affine), stream, gpu_index, size_tracker, true));

  cuda_memset_with_size_tracking_async(d_result, 0, sizeof(G2Projective),
                                       stream, gpu_index, true);
  cuda_memset_with_size_tracking_async(d_expected, 0, sizeof(G2Affine), stream,
                                       gpu_index, true);
  cuda_memset_with_size_tracking_async(d_G, 0, sizeof(G2Affine), stream,
                                       gpu_index, true);

  auto *h_points = static_cast<G2Affine *>(
      malloc(safe_mul_sizeof<G2Affine>(static_cast<size_t>(N))));
  for (uint64_t i = 0; i < N; i++) {
    h_points[i] = G;
  }

  auto *h_scalars = static_cast<Scalar *>(
      malloc(safe_mul_sizeof<Scalar>(static_cast<size_t>(N))));
  for (uint64_t i = 0; i < N; i++) {
    h_scalars[i] = u64_to_scalar(i + 1);
  }

  cuda_memcpy_with_size_tracking_async_to_gpu(
      d_points, h_points, safe_mul_sizeof<G2Affine>(static_cast<size_t>(N)),
      stream, gpu_index, true);
  cuda_memcpy_with_size_tracking_async_to_gpu(
      d_scalars, h_scalars, safe_mul_sizeof<Scalar>(static_cast<size_t>(N)),
      stream, gpu_index, true);

  point_to_montgomery_batch<G2Affine>(stream, gpu_index, d_points, N);
  check_cuda_error(cudaGetLastError());

  cuda_memcpy_with_size_tracking_async_to_gpu(d_G, &G_mont, sizeof(G2Affine),
                                              stream, gpu_index, true);

  test_point_msm_g2(stream, gpu_index, d_result, d_points, d_scalars, N,
                    size_tracker);

  UNSIGNED_LIMB expected_scalar =
      static_cast<UNSIGNED_LIMB>(triangular_number(N));
  single_point_scalar_mul<G2Affine>(stream, gpu_index, d_expected, d_G,
                                    expected_scalar);

  // Copy results to host and compare on CPU (avoids GPU->CPU->GPU round-trip)
  cuda_synchronize_stream(stream, gpu_index);
  G2Projective h_result_proj;
  G2Affine expected_result;
  cuda_memcpy_async_to_cpu(&h_result_proj, d_result, sizeof(G2Projective),
                           stream, gpu_index);
  cuda_memcpy_async_to_cpu(&expected_result, d_expected, sizeof(G2Affine),
                           stream, gpu_index);
  cuda_synchronize_stream(stream, gpu_index);

  // Convert projective->affine first (uses Montgomery arithmetic internally),
  // then convert both results from Montgomery to standard form
  G2Affine msm_result;
  projective_to_affine_g2(msm_result, h_result_proj);
  fp_from_montgomery(msm_result.x.c0, msm_result.x.c0);
  fp_from_montgomery(msm_result.x.c1, msm_result.x.c1);
  fp_from_montgomery(msm_result.y.c0, msm_result.y.c0);
  fp_from_montgomery(msm_result.y.c1, msm_result.y.c1);
  fp_from_montgomery(expected_result.x.c0, expected_result.x.c0);
  fp_from_montgomery(expected_result.x.c1, expected_result.x.c1);
  fp_from_montgomery(expected_result.y.c0, expected_result.y.c0);
  fp_from_montgomery(expected_result.y.c1, expected_result.y.c1);

  EXPECT_EQ(msm_result.infinity, expected_result.infinity);
  if (!msm_result.infinity && !expected_result.infinity) {
    EXPECT_EQ(fp2_cmp(msm_result.x, expected_result.x), ComparisonType::Equal)
        << "MSM x-coordinate mismatch";
    EXPECT_EQ(fp2_cmp(msm_result.y, expected_result.y), ComparisonType::Equal)
        << "MSM y-coordinate mismatch";
  }

  free(h_points);
  free(h_scalars);
  cuda_drop_with_size_tracking_async(d_points, stream, gpu_index, true);
  cuda_drop_with_size_tracking_async(d_scalars, stream, gpu_index, true);
  cuda_drop_with_size_tracking_async(d_result, stream, gpu_index, true);
  // Scratch freed by test helper
  cuda_drop_with_size_tracking_async(d_expected, stream, gpu_index, true);
  cuda_drop_with_size_tracking_async(d_G, stream, gpu_index, true);
}

#endif // LIMB_BITS_CONFIG == 64 (u64_to_scalar and callers)

// ============================================================================
// 64-bit limb specific helper and tests
// These use hardcoded 64-bit limb values and are only valid when
// LIMB_BITS_CONFIG == 64 (ZP_LIMBS == 5)
// ============================================================================
#if LIMB_BITS_CONFIG == 64

// Helper function to create Scalar from multiple 64-bit limbs
Scalar scalar_from_limbs(uint64_t l0, uint64_t l1, uint64_t l2, uint64_t l3,
                         uint64_t l4) {
  Scalar result;
  result.limb[0] = l0;
  result.limb[1] = l1;
  result.limb[2] = l2;
  result.limb[3] = l3;
  result.limb[4] = l4;
  return result;
}

// Test G1 MSM with BigInt scalar using 2-limb value (2^64)
// This verifies that multi-limb scalars work correctly
TEST_F(MSMTest, G1MSMWithBigIntTwoLimbScalar) {
  const uint32_t N = 1; // Single point test

  const G1Affine &G = g1_generator();
  G1Affine G_mont = G;
  point_to_montgomery_inplace(G_mont);

  if (g1_is_infinity(G)) {
    GTEST_SKIP() << "G1 generator not set";
  }

  // Scratch is allocated and freed by the test_point_msm_g1/g2 helpers

  uint64_t size_tracker = 0;

  auto *d_points = static_cast<G1Affine *>(cuda_malloc_with_size_tracking_async(
      safe_mul_sizeof<G1Affine>(static_cast<size_t>(N)), stream, gpu_index,
      size_tracker, true));
  auto *d_scalars = static_cast<Scalar *>(cuda_malloc_with_size_tracking_async(
      safe_mul_sizeof<Scalar>(static_cast<size_t>(N)), stream, gpu_index,
      size_tracker, true));
  auto *d_result =
      static_cast<G1Projective *>(cuda_malloc_with_size_tracking_async(
          sizeof(G1Projective), stream, gpu_index, size_tracker, true));
  // Scratch is managed by the test helper wrappers
  auto *d_expected =
      static_cast<G1Affine *>(cuda_malloc_with_size_tracking_async(
          sizeof(G1Affine), stream, gpu_index, size_tracker, true));
  auto *d_G = static_cast<G1Affine *>(cuda_malloc_with_size_tracking_async(
      sizeof(G1Affine), stream, gpu_index, size_tracker, true));

  cuda_memset_with_size_tracking_async(d_result, 0, sizeof(G1Projective),
                                       stream, gpu_index, true);
  cuda_memset_with_size_tracking_async(d_expected, 0, sizeof(G1Affine), stream,
                                       gpu_index, true);
  cuda_memset_with_size_tracking_async(d_G, 0, sizeof(G1Affine), stream,
                                       gpu_index, true);

  auto *h_points = static_cast<G1Affine *>(
      malloc(safe_mul_sizeof<G1Affine>(static_cast<size_t>(N))));
  h_points[0] = G;

  // Create Scalar scalar = 2^64 (requires 2 limbs: limb[0]=0, limb[1]=1)
  auto *h_scalars = static_cast<Scalar *>(
      malloc(safe_mul_sizeof<Scalar>(static_cast<size_t>(N))));
  h_scalars[0] = scalar_from_limbs(0ULL, 1ULL, 0ULL, 0ULL, 0ULL);

  cuda_memcpy_with_size_tracking_async_to_gpu(
      d_points, h_points, safe_mul_sizeof<G1Affine>(static_cast<size_t>(N)),
      stream, gpu_index, true);
  cuda_memcpy_with_size_tracking_async_to_gpu(
      d_scalars, h_scalars, safe_mul_sizeof<Scalar>(static_cast<size_t>(N)),
      stream, gpu_index, true);

  point_to_montgomery_batch<G1Affine>(stream, gpu_index, d_points, N);
  check_cuda_error(cudaGetLastError());

  cuda_memcpy_with_size_tracking_async_to_gpu(d_G, &G_mont, sizeof(G1Affine),
                                              stream, gpu_index, true);

  // Compute MSM
  test_point_msm_g1(stream, gpu_index, d_result, d_points, d_scalars, N,
                    size_tracker);

  // Compute expected: G * 2^64 using multi-limb scalar multiplication
  auto *d_scalar_temp =
      static_cast<UNSIGNED_LIMB *>(cuda_malloc_with_size_tracking_async(
          ZP_LIMBS * sizeof(UNSIGNED_LIMB), stream, gpu_index, size_tracker,
          true));
  cuda_memcpy_with_size_tracking_async_to_gpu(d_scalar_temp, h_scalars[0].limb,
                                              ZP_LIMBS * sizeof(UNSIGNED_LIMB),
                                              stream, gpu_index, true);
  cuda_synchronize_stream(stream, gpu_index);
  point_scalar_mul<G1Affine>(stream, gpu_index, d_expected, d_G, d_scalar_temp,
                             ZP_LIMBS);
  cuda_drop_with_size_tracking_async(d_scalar_temp, stream, gpu_index, true);

  // Convert results for comparison
  // Copy results to host and compare on CPU (avoids GPU->CPU->GPU round-trip)
  cuda_synchronize_stream(stream, gpu_index);
  G1Projective h_result_proj;
  G1Affine expected_result;
  cuda_memcpy_async_to_cpu(&h_result_proj, d_result, sizeof(G1Projective),
                           stream, gpu_index);
  cuda_memcpy_async_to_cpu(&expected_result, d_expected, sizeof(G1Affine),
                           stream, gpu_index);
  cuda_synchronize_stream(stream, gpu_index);

  // Convert projective->affine first (uses Montgomery arithmetic internally),
  // then convert both results from Montgomery to standard form
  G1Affine msm_result;
  projective_to_affine_g1(msm_result, h_result_proj);
  fp_from_montgomery(msm_result.x, msm_result.x);
  fp_from_montgomery(msm_result.y, msm_result.y);
  fp_from_montgomery(expected_result.x, expected_result.x);
  fp_from_montgomery(expected_result.y, expected_result.y);

  EXPECT_EQ(msm_result.infinity, expected_result.infinity);
  if (!msm_result.infinity && !expected_result.infinity) {
    EXPECT_EQ(fp_cmp(msm_result.x, expected_result.x), ComparisonType::Equal)
        << "MSM x-coordinate mismatch";
    EXPECT_EQ(fp_cmp(msm_result.y, expected_result.y), ComparisonType::Equal)
        << "MSM y-coordinate mismatch";
  }

  free(h_points);
  free(h_scalars);
  cuda_drop_with_size_tracking_async(d_points, stream, gpu_index, true);
  cuda_drop_with_size_tracking_async(d_scalars, stream, gpu_index, true);
  cuda_drop_with_size_tracking_async(d_result, stream, gpu_index, true);
  // Scratch freed by test helper
  cuda_drop_with_size_tracking_async(d_expected, stream, gpu_index, true);
  cuda_drop_with_size_tracking_async(d_G, stream, gpu_index, true);
}

// Test G1 MSM with bigint scalars using multi-limb values (> 64 bits)
TEST_F(MSMTest, G1MSMWithBigIntMultiLimbScalars) {
  const uint32_t N = 5;

  const G1Affine &G = g1_generator();
  G1Affine G_mont = G;
  point_to_montgomery_inplace(G_mont);

  if (g1_is_infinity(G)) {
    GTEST_SKIP() << "G1 generator not set";
  }

  // Scratch is allocated and freed by the test_point_msm_g1/g2 helpers

  uint64_t size_tracker = 0;

  auto *d_points = static_cast<G1Affine *>(cuda_malloc_with_size_tracking_async(
      safe_mul_sizeof<G1Affine>(static_cast<size_t>(N)), stream, gpu_index,
      size_tracker, true));
  auto *d_scalars = static_cast<Scalar *>(cuda_malloc_with_size_tracking_async(
      safe_mul_sizeof<Scalar>(static_cast<size_t>(N)), stream, gpu_index,
      size_tracker, true));
  auto *d_result =
      static_cast<G1Projective *>(cuda_malloc_with_size_tracking_async(
          sizeof(G1Projective), stream, gpu_index, size_tracker, true));
  // Scratch is managed by the test helper wrappers
  auto *d_expected =
      static_cast<G1Affine *>(cuda_malloc_with_size_tracking_async(
          sizeof(G1Affine), stream, gpu_index, size_tracker, true));
  auto *d_G = static_cast<G1Affine *>(cuda_malloc_with_size_tracking_async(
      sizeof(G1Affine), stream, gpu_index, size_tracker, true));

  cuda_memset_with_size_tracking_async(d_result, 0, sizeof(G1Projective),
                                       stream, gpu_index, true);
  cuda_memset_with_size_tracking_async(d_expected, 0, sizeof(G1Affine), stream,
                                       gpu_index, true);
  cuda_memset_with_size_tracking_async(d_G, 0, sizeof(G1Affine), stream,
                                       gpu_index, true);

  auto *h_points = static_cast<G1Affine *>(
      malloc(safe_mul_sizeof<G1Affine>(static_cast<size_t>(N))));
  for (uint64_t i = 0; i < N; i++) {
    h_points[i] = G;
  }

  // Create BigInt5 scalars that use multiple limbs (values > 2^64)
  auto *h_scalars = static_cast<Scalar *>(
      malloc(safe_mul_sizeof<Scalar>(static_cast<size_t>(N))));
  h_scalars[0] = scalar_from_limbs(0ULL, 1ULL, 0ULL, 0ULL, 0ULL); // 2^64
  h_scalars[1] = scalar_from_limbs(1ULL, 1ULL, 0ULL, 0ULL, 0ULL); // 2^64 + 1
  h_scalars[2] = scalar_from_limbs(0ULL, 0ULL, 1ULL, 0ULL, 0ULL); // 2^128
  h_scalars[3] =
      scalar_from_limbs(0ULL, 1ULL, 1ULL, 0ULL, 0ULL); // 2^128 + 2^64
  h_scalars[4] = scalar_from_limbs(0ULL, 0ULL, 0ULL, 1ULL, 0ULL); // 2^192

  cuda_memcpy_with_size_tracking_async_to_gpu(
      d_points, h_points, safe_mul_sizeof<G1Affine>(static_cast<size_t>(N)),
      stream, gpu_index, true);
  cuda_memcpy_with_size_tracking_async_to_gpu(
      d_scalars, h_scalars, safe_mul_sizeof<Scalar>(static_cast<size_t>(N)),
      stream, gpu_index, true);

  point_to_montgomery_batch<G1Affine>(stream, gpu_index, d_points, N);
  check_cuda_error(cudaGetLastError());

  cuda_memcpy_with_size_tracking_async_to_gpu(d_G, &G_mont, sizeof(G1Affine),
                                              stream, gpu_index, true);

  test_point_msm_g1(stream, gpu_index, d_result, d_points, d_scalars, N,
                    size_tracker);

  // Compute expected result by summing individual scalar multiplications
  // Each point is multiplied by its corresponding scalar
  auto *d_scalar_temp =
      static_cast<UNSIGNED_LIMB *>(cuda_malloc_with_size_tracking_async(
          ZP_LIMBS * sizeof(UNSIGNED_LIMB), stream, gpu_index, size_tracker,
          true));
  auto *d_individual_results =
      static_cast<G1Affine *>(cuda_malloc_with_size_tracking_async(
          safe_mul_sizeof<G1Affine>(static_cast<size_t>(N)), stream, gpu_index,
          size_tracker, true));

  // Compute each scalar[i] * points[i] separately
  for (auto i = 0ULL; i < N; i++) {
    cuda_memcpy_with_size_tracking_async_to_gpu(
        d_scalar_temp, h_scalars[i].limb, ZP_LIMBS * sizeof(UNSIGNED_LIMB),
        stream, gpu_index, true);
    // point_scalar_mul syncs internally; no extra sync needed between
    // same-stream operations
    point_scalar_mul<G1Affine>(stream, gpu_index, d_individual_results + i,
                               d_points + i, d_scalar_temp, ZP_LIMBS);
  }

  // Sum all individual results
  auto *d_sum = static_cast<G1Affine *>(cuda_malloc_with_size_tracking_async(
      sizeof(G1Affine), stream, gpu_index, size_tracker, true));
  point_at_infinity<G1Affine>(stream, gpu_index, d_sum);

  for (auto i = 0ULL; i < N; i++) {
    auto *d_new_sum =
        static_cast<G1Affine *>(cuda_malloc_with_size_tracking_async(
            sizeof(G1Affine), stream, gpu_index, size_tracker, true));
    point_add<G1Affine>(stream, gpu_index, d_new_sum, d_sum,
                        d_individual_results + i);
    cuda_drop_with_size_tracking_async(d_sum, stream, gpu_index, true);
    d_sum = d_new_sum;
  }
  cuda_memcpy_with_size_tracking_async_gpu_to_gpu(
      d_expected, d_sum, sizeof(G1Affine), stream, gpu_index, true);
  cuda_drop_with_size_tracking_async(d_scalar_temp, stream, gpu_index, true);
  cuda_drop_with_size_tracking_async(d_individual_results, stream, gpu_index,
                                     true);
  cuda_drop_with_size_tracking_async(d_sum, stream, gpu_index, true);

  // Copy results to host and compare on CPU (avoids GPU->CPU->GPU round-trip)
  cuda_synchronize_stream(stream, gpu_index);
  G1Projective h_result_proj;
  G1Affine expected_result;
  cuda_memcpy_async_to_cpu(&h_result_proj, d_result, sizeof(G1Projective),
                           stream, gpu_index);
  cuda_memcpy_async_to_cpu(&expected_result, d_expected, sizeof(G1Affine),
                           stream, gpu_index);
  cuda_synchronize_stream(stream, gpu_index);

  // Convert projective->affine first (uses Montgomery arithmetic internally),
  // then convert both results from Montgomery to standard form
  G1Affine msm_result;
  projective_to_affine_g1(msm_result, h_result_proj);
  fp_from_montgomery(msm_result.x, msm_result.x);
  fp_from_montgomery(msm_result.y, msm_result.y);
  fp_from_montgomery(expected_result.x, expected_result.x);
  fp_from_montgomery(expected_result.y, expected_result.y);

  EXPECT_EQ(msm_result.infinity, expected_result.infinity);
  if (!msm_result.infinity && !expected_result.infinity) {
    EXPECT_EQ(fp_cmp(msm_result.x, expected_result.x), ComparisonType::Equal)
        << "MSM x-coordinate mismatch";
    EXPECT_EQ(fp_cmp(msm_result.y, expected_result.y), ComparisonType::Equal)
        << "MSM y-coordinate mismatch";
  }

  free(h_points);
  free(h_scalars);
  cuda_drop_with_size_tracking_async(d_points, stream, gpu_index, true);
  cuda_drop_with_size_tracking_async(d_scalars, stream, gpu_index, true);
  cuda_drop_with_size_tracking_async(d_result, stream, gpu_index, true);
  // Scratch freed by test helper
  cuda_drop_with_size_tracking_async(d_expected, stream, gpu_index, true);
  cuda_drop_with_size_tracking_async(d_G, stream, gpu_index, true);
}

// Test G1 MSM with BigInt5 scalars using maximum values (all 5 limbs)
TEST_F(MSMTest, G1MSMWithBigInt5MaxValueScalars) {
  const uint32_t N = 3;

  const G1Affine &G = g1_generator();
  G1Affine G_mont = G;
  point_to_montgomery_inplace(G_mont);

  if (g1_is_infinity(G)) {
    GTEST_SKIP() << "G1 generator not set";
  }

  // Scratch is allocated and freed by the test_point_msm_g1/g2 helpers

  uint64_t size_tracker = 0;

  auto *d_points = static_cast<G1Affine *>(cuda_malloc_with_size_tracking_async(
      safe_mul_sizeof<G1Affine>(static_cast<size_t>(N)), stream, gpu_index,
      size_tracker, true));
  auto *d_scalars = static_cast<Scalar *>(cuda_malloc_with_size_tracking_async(
      safe_mul_sizeof<Scalar>(static_cast<size_t>(N)), stream, gpu_index,
      size_tracker, true));
  auto *d_result =
      static_cast<G1Projective *>(cuda_malloc_with_size_tracking_async(
          sizeof(G1Projective), stream, gpu_index, size_tracker, true));
  // Scratch is managed by the test helper wrappers
  auto *d_expected =
      static_cast<G1Affine *>(cuda_malloc_with_size_tracking_async(
          sizeof(G1Affine), stream, gpu_index, size_tracker, true));
  auto *d_G = static_cast<G1Affine *>(cuda_malloc_with_size_tracking_async(
      sizeof(G1Affine), stream, gpu_index, size_tracker, true));

  cuda_memset_with_size_tracking_async(d_result, 0, sizeof(G1Projective),
                                       stream, gpu_index, true);
  cuda_memset_with_size_tracking_async(d_expected, 0, sizeof(G1Affine), stream,
                                       gpu_index, true);
  cuda_memset_with_size_tracking_async(d_G, 0, sizeof(G1Affine), stream,
                                       gpu_index, true);

  auto *h_points = static_cast<G1Affine *>(
      malloc(safe_mul_sizeof<G1Affine>(static_cast<size_t>(N))));
  for (uint64_t i = 0; i < N; i++) {
    h_points[i] = G;
  }

  // Create BigInt5 scalars that use all 5 limbs (near maximum 320-bit values)
  auto *h_scalars = static_cast<Scalar *>(
      malloc(safe_mul_sizeof<Scalar>(static_cast<size_t>(N))));
  h_scalars[0] = scalar_from_limbs(0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL,
                                   0ULL, 0ULL, 0ULL); // 2^128 - 1
  h_scalars[1] =
      scalar_from_limbs(0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL,
                        0xFFFFFFFFFFFFFFFFULL, 0ULL, 0ULL); // 2^192 - 1
  h_scalars[2] = scalar_from_limbs(0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL,
                                   0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL,
                                   0ULL); // 2^256 - 1

  cuda_memcpy_with_size_tracking_async_to_gpu(
      d_points, h_points, safe_mul_sizeof<G1Affine>(static_cast<size_t>(N)),
      stream, gpu_index, true);
  cuda_memcpy_with_size_tracking_async_to_gpu(
      d_scalars, h_scalars, safe_mul_sizeof<Scalar>(static_cast<size_t>(N)),
      stream, gpu_index, true);

  point_to_montgomery_batch<G1Affine>(stream, gpu_index, d_points, N);
  check_cuda_error(cudaGetLastError());

  cuda_memcpy_with_size_tracking_async_to_gpu(d_G, &G_mont, sizeof(G1Affine),
                                              stream, gpu_index, true);

  test_point_msm_g1(stream, gpu_index, d_result, d_points, d_scalars, N,
                    size_tracker);

  // Compute expected result by summing individual scalar multiplications
  // Each point is multiplied by its corresponding scalar
  auto *d_scalar_temp =
      static_cast<UNSIGNED_LIMB *>(cuda_malloc_with_size_tracking_async(
          ZP_LIMBS * sizeof(UNSIGNED_LIMB), stream, gpu_index, size_tracker,
          true));
  auto *d_sum = static_cast<G1Affine *>(cuda_malloc_with_size_tracking_async(
      sizeof(G1Affine), stream, gpu_index, size_tracker, true));
  auto *d_temp = static_cast<G1Affine *>(cuda_malloc_with_size_tracking_async(
      sizeof(G1Affine), stream, gpu_index, size_tracker, true));
  auto *d_new_sum =
      static_cast<G1Affine *>(cuda_malloc_with_size_tracking_async(
          sizeof(G1Affine), stream, gpu_index, size_tracker, true));

  point_at_infinity<G1Affine>(stream, gpu_index, d_sum);

  // All non-async operations sync internally; no extra syncs needed
  for (auto i = 0ULL; i < N; i++) {
    cuda_memcpy_with_size_tracking_async_to_gpu(
        d_scalar_temp, h_scalars[i].limb, ZP_LIMBS * sizeof(UNSIGNED_LIMB),
        stream, gpu_index, true);
    point_scalar_mul<G1Affine>(stream, gpu_index, d_temp, d_points + i,
                               d_scalar_temp, ZP_LIMBS);
    point_add<G1Affine>(stream, gpu_index, d_new_sum, d_sum, d_temp);
    // Swap d_sum and d_new_sum for next iteration
    G1Affine *tmp = d_sum;
    d_sum = d_new_sum;
    d_new_sum = tmp;
  }
  cuda_memcpy_with_size_tracking_async_gpu_to_gpu(
      d_expected, d_sum, sizeof(G1Affine), stream, gpu_index, true);
  cuda_drop_with_size_tracking_async(d_scalar_temp, stream, gpu_index, true);
  cuda_drop_with_size_tracking_async(d_sum, stream, gpu_index, true);
  cuda_drop_with_size_tracking_async(d_temp, stream, gpu_index, true);
  cuda_drop_with_size_tracking_async(d_new_sum, stream, gpu_index, true);

  // Copy results to host and compare on CPU (avoids GPU->CPU->GPU round-trip)
  cuda_synchronize_stream(stream, gpu_index);
  G1Projective h_result_proj;
  G1Affine expected_result;
  cuda_memcpy_async_to_cpu(&h_result_proj, d_result, sizeof(G1Projective),
                           stream, gpu_index);
  cuda_memcpy_async_to_cpu(&expected_result, d_expected, sizeof(G1Affine),
                           stream, gpu_index);
  cuda_synchronize_stream(stream, gpu_index);

  // Convert projective->affine first (uses Montgomery arithmetic internally),
  // then convert both results from Montgomery to standard form
  G1Affine msm_result;
  projective_to_affine_g1(msm_result, h_result_proj);
  fp_from_montgomery(msm_result.x, msm_result.x);
  fp_from_montgomery(msm_result.y, msm_result.y);
  fp_from_montgomery(expected_result.x, expected_result.x);
  fp_from_montgomery(expected_result.y, expected_result.y);

  EXPECT_EQ(msm_result.infinity, expected_result.infinity);
  if (!msm_result.infinity && !expected_result.infinity) {
    EXPECT_EQ(fp_cmp(msm_result.x, expected_result.x), ComparisonType::Equal)
        << "MSM x-coordinate mismatch";
    EXPECT_EQ(fp_cmp(msm_result.y, expected_result.y), ComparisonType::Equal)
        << "MSM y-coordinate mismatch";
  }

  free(h_points);
  free(h_scalars);
  cuda_drop_with_size_tracking_async(d_points, stream, gpu_index, true);
  cuda_drop_with_size_tracking_async(d_scalars, stream, gpu_index, true);
  cuda_drop_with_size_tracking_async(d_result, stream, gpu_index, true);
  // Scratch freed by test helper
  cuda_drop_with_size_tracking_async(d_expected, stream, gpu_index, true);
  cuda_drop_with_size_tracking_async(d_G, stream, gpu_index, true);
}

// Test G2 MSM with BigInt5 scalars using multi-limb values (> 64 bits)
TEST_F(MSMTest, G2MSMWithBigInt5MultiLimbScalars) {
  const uint32_t N = 5;

  const G2Affine &G = g2_generator();
  G2Affine G_mont = G;
  point_to_montgomery_inplace(G_mont);

  if (g2_is_infinity(G)) {
    GTEST_SKIP() << "G2 generator not set";
  }

  // Scratch is allocated and freed by the test_point_msm_g1/g2 helpers

  uint64_t size_tracker = 0;

  auto *d_points = static_cast<G2Affine *>(cuda_malloc_with_size_tracking_async(
      safe_mul_sizeof<G2Affine>(static_cast<size_t>(N)), stream, gpu_index,
      size_tracker, true));
  auto *d_scalars = static_cast<Scalar *>(cuda_malloc_with_size_tracking_async(
      safe_mul_sizeof<Scalar>(static_cast<size_t>(N)), stream, gpu_index,
      size_tracker, true));
  auto *d_result =
      static_cast<G2Projective *>(cuda_malloc_with_size_tracking_async(
          sizeof(G2Projective), stream, gpu_index, size_tracker, true));
  // Scratch is managed by the test helper wrappers
  auto *d_expected =
      static_cast<G2Affine *>(cuda_malloc_with_size_tracking_async(
          sizeof(G2Affine), stream, gpu_index, size_tracker, true));
  auto *d_G = static_cast<G2Affine *>(cuda_malloc_with_size_tracking_async(
      sizeof(G2Affine), stream, gpu_index, size_tracker, true));

  cuda_memset_with_size_tracking_async(d_result, 0, sizeof(G2Projective),
                                       stream, gpu_index, true);
  cuda_memset_with_size_tracking_async(d_expected, 0, sizeof(G2Affine), stream,
                                       gpu_index, true);
  cuda_memset_with_size_tracking_async(d_G, 0, sizeof(G2Affine), stream,
                                       gpu_index, true);

  auto *h_points = static_cast<G2Affine *>(
      malloc(safe_mul_sizeof<G2Affine>(static_cast<size_t>(N))));
  for (uint64_t i = 0; i < N; i++) {
    h_points[i] = G;
  }

  // Create BigInt5 scalars that use multiple limbs
  auto *h_scalars = static_cast<Scalar *>(
      malloc(safe_mul_sizeof<Scalar>(static_cast<size_t>(N))));
  h_scalars[0] = scalar_from_limbs(0ULL, 1ULL, 0ULL, 0ULL, 0ULL); // 2^64
  h_scalars[1] = scalar_from_limbs(1ULL, 1ULL, 0ULL, 0ULL, 0ULL); // 2^64 + 1
  h_scalars[2] = scalar_from_limbs(0ULL, 0ULL, 1ULL, 0ULL, 0ULL); // 2^128
  h_scalars[3] =
      scalar_from_limbs(0ULL, 1ULL, 1ULL, 0ULL, 0ULL); // 2^128 + 2^64
  h_scalars[4] = scalar_from_limbs(0ULL, 0ULL, 0ULL, 1ULL, 0ULL); // 2^192

  cuda_memcpy_with_size_tracking_async_to_gpu(
      d_points, h_points, safe_mul_sizeof<G2Affine>(static_cast<size_t>(N)),
      stream, gpu_index, true);
  cuda_memcpy_with_size_tracking_async_to_gpu(
      d_scalars, h_scalars, safe_mul_sizeof<Scalar>(static_cast<size_t>(N)),
      stream, gpu_index, true);

  point_to_montgomery_batch<G2Affine>(stream, gpu_index, d_points, N);
  check_cuda_error(cudaGetLastError());

  cuda_memcpy_with_size_tracking_async_to_gpu(d_G, &G_mont, sizeof(G2Affine),
                                              stream, gpu_index, true);

  test_point_msm_g2(stream, gpu_index, d_result, d_points, d_scalars, N,
                    size_tracker);

  // Compute expected result by summing individual scalar multiplications
  // Each point is multiplied by its corresponding scalar
  auto *d_scalar_temp =
      static_cast<UNSIGNED_LIMB *>(cuda_malloc_with_size_tracking_async(
          ZP_LIMBS * sizeof(UNSIGNED_LIMB), stream, gpu_index, size_tracker,
          true));
  auto *d_sum = static_cast<G2Affine *>(cuda_malloc_with_size_tracking_async(
      sizeof(G2Affine), stream, gpu_index, size_tracker, true));
  auto *d_temp = static_cast<G2Affine *>(cuda_malloc_with_size_tracking_async(
      sizeof(G2Affine), stream, gpu_index, size_tracker, true));
  auto *d_new_sum =
      static_cast<G2Affine *>(cuda_malloc_with_size_tracking_async(
          sizeof(G2Affine), stream, gpu_index, size_tracker, true));

  point_at_infinity<G2Affine>(stream, gpu_index, d_sum);

  // All non-async operations sync internally; no extra syncs needed
  for (auto i = 0ULL; i < N; i++) {
    cuda_memcpy_with_size_tracking_async_to_gpu(
        d_scalar_temp, h_scalars[i].limb, ZP_LIMBS * sizeof(UNSIGNED_LIMB),
        stream, gpu_index, true);
    point_scalar_mul<G2Affine>(stream, gpu_index, d_temp, d_points + i,
                               d_scalar_temp, ZP_LIMBS);
    point_add<G2Affine>(stream, gpu_index, d_new_sum, d_sum, d_temp);
    // Swap d_sum and d_new_sum for next iteration
    G2Affine *tmp = d_sum;
    d_sum = d_new_sum;
    d_new_sum = tmp;
  }
  cuda_memcpy_with_size_tracking_async_gpu_to_gpu(
      d_expected, d_sum, sizeof(G2Affine), stream, gpu_index, true);
  cuda_drop_with_size_tracking_async(d_scalar_temp, stream, gpu_index, true);
  cuda_drop_with_size_tracking_async(d_sum, stream, gpu_index, true);
  cuda_drop_with_size_tracking_async(d_temp, stream, gpu_index, true);
  cuda_drop_with_size_tracking_async(d_new_sum, stream, gpu_index, true);

  // Copy results to host and compare on CPU (avoids GPU->CPU->GPU round-trip)
  cuda_synchronize_stream(stream, gpu_index);
  G2Projective h_result_proj;
  G2Affine expected_result;
  cuda_memcpy_async_to_cpu(&h_result_proj, d_result, sizeof(G2Projective),
                           stream, gpu_index);
  cuda_memcpy_async_to_cpu(&expected_result, d_expected, sizeof(G2Affine),
                           stream, gpu_index);
  cuda_synchronize_stream(stream, gpu_index);

  // Convert projective->affine first (uses Montgomery arithmetic internally),
  // then convert both results from Montgomery to standard form
  G2Affine msm_result;
  projective_to_affine_g2(msm_result, h_result_proj);
  fp_from_montgomery(msm_result.x.c0, msm_result.x.c0);
  fp_from_montgomery(msm_result.x.c1, msm_result.x.c1);
  fp_from_montgomery(msm_result.y.c0, msm_result.y.c0);
  fp_from_montgomery(msm_result.y.c1, msm_result.y.c1);
  fp_from_montgomery(expected_result.x.c0, expected_result.x.c0);
  fp_from_montgomery(expected_result.x.c1, expected_result.x.c1);
  fp_from_montgomery(expected_result.y.c0, expected_result.y.c0);
  fp_from_montgomery(expected_result.y.c1, expected_result.y.c1);

  EXPECT_EQ(msm_result.infinity, expected_result.infinity);
  if (!msm_result.infinity && !expected_result.infinity) {
    EXPECT_EQ(fp2_cmp(msm_result.x, expected_result.x), ComparisonType::Equal)
        << "MSM x-coordinate mismatch";
    EXPECT_EQ(fp2_cmp(msm_result.y, expected_result.y), ComparisonType::Equal)
        << "MSM y-coordinate mismatch";
  }

  free(h_points);
  free(h_scalars);
  cuda_drop_with_size_tracking_async(d_points, stream, gpu_index, true);
  cuda_drop_with_size_tracking_async(d_scalars, stream, gpu_index, true);
  cuda_drop_with_size_tracking_async(d_result, stream, gpu_index, true);
  // Scratch freed by test helper
  cuda_drop_with_size_tracking_async(d_expected, stream, gpu_index, true);
  cuda_drop_with_size_tracking_async(d_G, stream, gpu_index, true);
}

// Test G1 MSM with BigInt5 scalar using 3-limb value (2^128)
TEST_F(MSMTest, G1MSMWithBigInt5ThreeLimbScalar) {
  const uint32_t N = 1;

  const G1Affine &G = g1_generator();
  G1Affine G_mont = G;
  point_to_montgomery_inplace(G_mont);

  if (g1_is_infinity(G)) {
    GTEST_SKIP() << "G1 generator not set";
  }

  // Scratch is allocated and freed by the test_point_msm_g1/g2 helpers

  uint64_t size_tracker = 0;

  auto *d_points = static_cast<G1Affine *>(cuda_malloc_with_size_tracking_async(
      safe_mul_sizeof<G1Affine>(static_cast<size_t>(N)), stream, gpu_index,
      size_tracker, true));
  auto *d_scalars = static_cast<Scalar *>(cuda_malloc_with_size_tracking_async(
      safe_mul_sizeof<Scalar>(static_cast<size_t>(N)), stream, gpu_index,
      size_tracker, true));
  auto *d_result =
      static_cast<G1Projective *>(cuda_malloc_with_size_tracking_async(
          sizeof(G1Projective), stream, gpu_index, size_tracker, true));
  // Scratch is managed by the test helper wrappers
  auto *d_expected =
      static_cast<G1Affine *>(cuda_malloc_with_size_tracking_async(
          sizeof(G1Affine), stream, gpu_index, size_tracker, true));
  auto *d_G = static_cast<G1Affine *>(cuda_malloc_with_size_tracking_async(
      sizeof(G1Affine), stream, gpu_index, size_tracker, true));

  cuda_memset_with_size_tracking_async(d_result, 0, sizeof(G1Projective),
                                       stream, gpu_index, true);
  cuda_memset_with_size_tracking_async(d_expected, 0, sizeof(G1Affine), stream,
                                       gpu_index, true);
  cuda_memset_with_size_tracking_async(d_G, 0, sizeof(G1Affine), stream,
                                       gpu_index, true);

  auto *h_points = static_cast<G1Affine *>(
      malloc(safe_mul_sizeof<G1Affine>(static_cast<size_t>(N))));
  h_points[0] = G;

  // Create BigInt5 scalar = 2^128 (requires 3 limbs)
  auto *h_scalars = static_cast<Scalar *>(
      malloc(safe_mul_sizeof<Scalar>(static_cast<size_t>(N))));
  h_scalars[0] = scalar_from_limbs(0ULL, 0ULL, 1ULL, 0ULL, 0ULL);

  cuda_memcpy_with_size_tracking_async_to_gpu(
      d_points, h_points, safe_mul_sizeof<G1Affine>(static_cast<size_t>(N)),
      stream, gpu_index, true);
  cuda_memcpy_with_size_tracking_async_to_gpu(
      d_scalars, h_scalars, safe_mul_sizeof<Scalar>(static_cast<size_t>(N)),
      stream, gpu_index, true);

  point_to_montgomery_batch<G1Affine>(stream, gpu_index, d_points, N);
  check_cuda_error(cudaGetLastError());

  cuda_memcpy_with_size_tracking_async_to_gpu(d_G, &G_mont, sizeof(G1Affine),
                                              stream, gpu_index, true);

  test_point_msm_g1(stream, gpu_index, d_result, d_points, d_scalars, N,
                    size_tracker);

  auto *d_scalar_temp =
      static_cast<UNSIGNED_LIMB *>(cuda_malloc_with_size_tracking_async(
          ZP_LIMBS * sizeof(UNSIGNED_LIMB), stream, gpu_index, size_tracker,
          true));
  cuda_memcpy_with_size_tracking_async_to_gpu(d_scalar_temp, h_scalars[0].limb,
                                              ZP_LIMBS * sizeof(UNSIGNED_LIMB),
                                              stream, gpu_index, true);
  cuda_synchronize_stream(stream, gpu_index);
  point_scalar_mul<G1Affine>(stream, gpu_index, d_expected, d_G, d_scalar_temp,
                             ZP_LIMBS);
  cuda_drop_with_size_tracking_async(d_scalar_temp, stream, gpu_index, true);

  // Copy results to host and compare on CPU (avoids GPU->CPU->GPU round-trip)
  cuda_synchronize_stream(stream, gpu_index);
  G1Projective h_result_proj;
  G1Affine expected_result;
  cuda_memcpy_async_to_cpu(&h_result_proj, d_result, sizeof(G1Projective),
                           stream, gpu_index);
  cuda_memcpy_async_to_cpu(&expected_result, d_expected, sizeof(G1Affine),
                           stream, gpu_index);
  cuda_synchronize_stream(stream, gpu_index);

  // Convert projective->affine first (uses Montgomery arithmetic internally),
  // then convert both results from Montgomery to standard form
  G1Affine msm_result;
  projective_to_affine_g1(msm_result, h_result_proj);
  fp_from_montgomery(msm_result.x, msm_result.x);
  fp_from_montgomery(msm_result.y, msm_result.y);
  fp_from_montgomery(expected_result.x, expected_result.x);
  fp_from_montgomery(expected_result.y, expected_result.y);

  EXPECT_EQ(msm_result.infinity, expected_result.infinity);
  if (!msm_result.infinity && !expected_result.infinity) {
    EXPECT_EQ(fp_cmp(msm_result.x, expected_result.x), ComparisonType::Equal)
        << "MSM x-coordinate mismatch";
    EXPECT_EQ(fp_cmp(msm_result.y, expected_result.y), ComparisonType::Equal)
        << "MSM y-coordinate mismatch";
  }

  free(h_points);
  free(h_scalars);
  cuda_drop_with_size_tracking_async(d_points, stream, gpu_index, true);
  cuda_drop_with_size_tracking_async(d_scalars, stream, gpu_index, true);
  cuda_drop_with_size_tracking_async(d_result, stream, gpu_index, true);
  // Scratch freed by test helper
  cuda_drop_with_size_tracking_async(d_expected, stream, gpu_index, true);
  cuda_drop_with_size_tracking_async(d_G, stream, gpu_index, true);
}

// Test G1 MSM with BigInt5 scalar using 4-limb value (2^192)
TEST_F(MSMTest, G1MSMWithBigInt5FourLimbScalar) {
  const uint32_t N = 1;

  const G1Affine &G = g1_generator();
  G1Affine G_mont = G;
  point_to_montgomery_inplace(G_mont);

  if (g1_is_infinity(G)) {
    GTEST_SKIP() << "G1 generator not set";
  }

  // Scratch is allocated and freed by the test_point_msm_g1/g2 helpers

  uint64_t size_tracker = 0;

  auto *d_points = static_cast<G1Affine *>(cuda_malloc_with_size_tracking_async(
      safe_mul_sizeof<G1Affine>(static_cast<size_t>(N)), stream, gpu_index,
      size_tracker, true));
  auto *d_scalars = static_cast<Scalar *>(cuda_malloc_with_size_tracking_async(
      safe_mul_sizeof<Scalar>(static_cast<size_t>(N)), stream, gpu_index,
      size_tracker, true));
  auto *d_result =
      static_cast<G1Projective *>(cuda_malloc_with_size_tracking_async(
          sizeof(G1Projective), stream, gpu_index, size_tracker, true));
  // Scratch is managed by the test helper wrappers
  auto *d_expected =
      static_cast<G1Affine *>(cuda_malloc_with_size_tracking_async(
          sizeof(G1Affine), stream, gpu_index, size_tracker, true));
  auto *d_G = static_cast<G1Affine *>(cuda_malloc_with_size_tracking_async(
      sizeof(G1Affine), stream, gpu_index, size_tracker, true));

  cuda_memset_with_size_tracking_async(d_result, 0, sizeof(G1Projective),
                                       stream, gpu_index, true);
  cuda_memset_with_size_tracking_async(d_expected, 0, sizeof(G1Affine), stream,
                                       gpu_index, true);
  cuda_memset_with_size_tracking_async(d_G, 0, sizeof(G1Affine), stream,
                                       gpu_index, true);

  auto *h_points = static_cast<G1Affine *>(
      malloc(safe_mul_sizeof<G1Affine>(static_cast<size_t>(N))));
  h_points[0] = G;

  // Create BigInt5 scalar = 2^192 (requires 4 limbs)
  auto *h_scalars = static_cast<Scalar *>(
      malloc(safe_mul_sizeof<Scalar>(static_cast<size_t>(N))));
  h_scalars[0] = scalar_from_limbs(0ULL, 0ULL, 0ULL, 1ULL, 0ULL);

  cuda_memcpy_with_size_tracking_async_to_gpu(
      d_points, h_points, safe_mul_sizeof<G1Affine>(static_cast<size_t>(N)),
      stream, gpu_index, true);
  cuda_memcpy_with_size_tracking_async_to_gpu(
      d_scalars, h_scalars, safe_mul_sizeof<Scalar>(static_cast<size_t>(N)),
      stream, gpu_index, true);

  point_to_montgomery_batch<G1Affine>(stream, gpu_index, d_points, N);
  check_cuda_error(cudaGetLastError());

  cuda_memcpy_with_size_tracking_async_to_gpu(d_G, &G_mont, sizeof(G1Affine),
                                              stream, gpu_index, true);

  test_point_msm_g1(stream, gpu_index, d_result, d_points, d_scalars, N,
                    size_tracker);

  auto *d_scalar_temp =
      static_cast<UNSIGNED_LIMB *>(cuda_malloc_with_size_tracking_async(
          ZP_LIMBS * sizeof(UNSIGNED_LIMB), stream, gpu_index, size_tracker,
          true));
  cuda_memcpy_with_size_tracking_async_to_gpu(d_scalar_temp, h_scalars[0].limb,
                                              ZP_LIMBS * sizeof(UNSIGNED_LIMB),
                                              stream, gpu_index, true);
  cuda_synchronize_stream(stream, gpu_index);
  point_scalar_mul<G1Affine>(stream, gpu_index, d_expected, d_G, d_scalar_temp,
                             ZP_LIMBS);
  cuda_drop_with_size_tracking_async(d_scalar_temp, stream, gpu_index, true);

  // Copy results to host and compare on CPU (avoids GPU->CPU->GPU round-trip)
  cuda_synchronize_stream(stream, gpu_index);
  G1Projective h_result_proj;
  G1Affine expected_result;
  cuda_memcpy_async_to_cpu(&h_result_proj, d_result, sizeof(G1Projective),
                           stream, gpu_index);
  cuda_memcpy_async_to_cpu(&expected_result, d_expected, sizeof(G1Affine),
                           stream, gpu_index);
  cuda_synchronize_stream(stream, gpu_index);

  // Convert projective->affine first (uses Montgomery arithmetic internally),
  // then convert both results from Montgomery to standard form
  G1Affine msm_result;
  projective_to_affine_g1(msm_result, h_result_proj);
  fp_from_montgomery(msm_result.x, msm_result.x);
  fp_from_montgomery(msm_result.y, msm_result.y);
  fp_from_montgomery(expected_result.x, expected_result.x);
  fp_from_montgomery(expected_result.y, expected_result.y);

  EXPECT_EQ(msm_result.infinity, expected_result.infinity);
  if (!msm_result.infinity && !expected_result.infinity) {
    EXPECT_EQ(fp_cmp(msm_result.x, expected_result.x), ComparisonType::Equal)
        << "MSM x-coordinate mismatch";
    EXPECT_EQ(fp_cmp(msm_result.y, expected_result.y), ComparisonType::Equal)
        << "MSM y-coordinate mismatch";
  }

  free(h_points);
  free(h_scalars);
  cuda_drop_with_size_tracking_async(d_points, stream, gpu_index, true);
  cuda_drop_with_size_tracking_async(d_scalars, stream, gpu_index, true);
  cuda_drop_with_size_tracking_async(d_result, stream, gpu_index, true);
  // Scratch freed by test helper
  cuda_drop_with_size_tracking_async(d_expected, stream, gpu_index, true);
  cuda_drop_with_size_tracking_async(d_G, stream, gpu_index, true);
}

// Test G1 MSM with BigInt5 scalar using 5-limb value (2^256) - near maximum
TEST_F(MSMTest, G1MSMWithBigInt5FiveLimbScalar) {
  const uint32_t N = 1;

  const G1Affine &G = g1_generator();
  G1Affine G_mont = G;
  point_to_montgomery_inplace(G_mont);

  if (g1_is_infinity(G)) {
    GTEST_SKIP() << "G1 generator not set";
  }

  // Scratch is allocated and freed by the test_point_msm_g1/g2 helpers

  uint64_t size_tracker = 0;

  auto *d_points = static_cast<G1Affine *>(cuda_malloc_with_size_tracking_async(
      safe_mul_sizeof<G1Affine>(static_cast<size_t>(N)), stream, gpu_index,
      size_tracker, true));
  auto *d_scalars = static_cast<Scalar *>(cuda_malloc_with_size_tracking_async(
      safe_mul_sizeof<Scalar>(static_cast<size_t>(N)), stream, gpu_index,
      size_tracker, true));
  auto *d_result =
      static_cast<G1Projective *>(cuda_malloc_with_size_tracking_async(
          sizeof(G1Projective), stream, gpu_index, size_tracker, true));
  // Scratch is managed by the test helper wrappers
  auto *d_expected =
      static_cast<G1Affine *>(cuda_malloc_with_size_tracking_async(
          sizeof(G1Affine), stream, gpu_index, size_tracker, true));
  auto *d_G = static_cast<G1Affine *>(cuda_malloc_with_size_tracking_async(
      sizeof(G1Affine), stream, gpu_index, size_tracker, true));

  cuda_memset_with_size_tracking_async(d_result, 0, sizeof(G1Projective),
                                       stream, gpu_index, true);
  cuda_memset_with_size_tracking_async(d_expected, 0, sizeof(G1Affine), stream,
                                       gpu_index, true);
  cuda_memset_with_size_tracking_async(d_G, 0, sizeof(G1Affine), stream,
                                       gpu_index, true);

  auto *h_points = static_cast<G1Affine *>(
      malloc(safe_mul_sizeof<G1Affine>(static_cast<size_t>(N))));
  h_points[0] = G;

  // Create BigInt5 scalar = 2^256 (requires 5 limbs, uses highest limb)
  auto *h_scalars = static_cast<Scalar *>(
      malloc(safe_mul_sizeof<Scalar>(static_cast<size_t>(N))));
  h_scalars[0] = scalar_from_limbs(0ULL, 0ULL, 0ULL, 0ULL, 1ULL);

  cuda_memcpy_with_size_tracking_async_to_gpu(
      d_points, h_points, safe_mul_sizeof<G1Affine>(static_cast<size_t>(N)),
      stream, gpu_index, true);
  cuda_memcpy_with_size_tracking_async_to_gpu(
      d_scalars, h_scalars, safe_mul_sizeof<Scalar>(static_cast<size_t>(N)),
      stream, gpu_index, true);

  point_to_montgomery_batch<G1Affine>(stream, gpu_index, d_points, N);
  check_cuda_error(cudaGetLastError());

  cuda_memcpy_with_size_tracking_async_to_gpu(d_G, &G_mont, sizeof(G1Affine),
                                              stream, gpu_index, true);

  test_point_msm_g1(stream, gpu_index, d_result, d_points, d_scalars, N,
                    size_tracker);

  auto *d_scalar_temp =
      static_cast<UNSIGNED_LIMB *>(cuda_malloc_with_size_tracking_async(
          ZP_LIMBS * sizeof(UNSIGNED_LIMB), stream, gpu_index, size_tracker,
          true));
  cuda_memcpy_with_size_tracking_async_to_gpu(d_scalar_temp, h_scalars[0].limb,
                                              ZP_LIMBS * sizeof(UNSIGNED_LIMB),
                                              stream, gpu_index, true);
  cuda_synchronize_stream(stream, gpu_index);
  point_scalar_mul<G1Affine>(stream, gpu_index, d_expected, d_G, d_scalar_temp,
                             ZP_LIMBS);
  cuda_drop_with_size_tracking_async(d_scalar_temp, stream, gpu_index, true);

  // Copy results to host and compare on CPU (avoids GPU->CPU->GPU round-trip)
  cuda_synchronize_stream(stream, gpu_index);
  G1Projective h_result_proj;
  G1Affine expected_result;
  cuda_memcpy_async_to_cpu(&h_result_proj, d_result, sizeof(G1Projective),
                           stream, gpu_index);
  cuda_memcpy_async_to_cpu(&expected_result, d_expected, sizeof(G1Affine),
                           stream, gpu_index);
  cuda_synchronize_stream(stream, gpu_index);

  // Convert projective->affine first (uses Montgomery arithmetic internally),
  // then convert both results from Montgomery to standard form
  G1Affine msm_result;
  projective_to_affine_g1(msm_result, h_result_proj);
  fp_from_montgomery(msm_result.x, msm_result.x);
  fp_from_montgomery(msm_result.y, msm_result.y);
  fp_from_montgomery(expected_result.x, expected_result.x);
  fp_from_montgomery(expected_result.y, expected_result.y);

  EXPECT_EQ(msm_result.infinity, expected_result.infinity);
  if (!msm_result.infinity && !expected_result.infinity) {
    EXPECT_EQ(fp_cmp(msm_result.x, expected_result.x), ComparisonType::Equal)
        << "MSM x-coordinate mismatch";
    EXPECT_EQ(fp_cmp(msm_result.y, expected_result.y), ComparisonType::Equal)
        << "MSM y-coordinate mismatch";
  }

  free(h_points);
  free(h_scalars);
  cuda_drop_with_size_tracking_async(d_points, stream, gpu_index, true);
  cuda_drop_with_size_tracking_async(d_scalars, stream, gpu_index, true);
  cuda_drop_with_size_tracking_async(d_result, stream, gpu_index, true);
  // Scratch freed by test helper
  cuda_drop_with_size_tracking_async(d_expected, stream, gpu_index, true);
  cuda_drop_with_size_tracking_async(d_G, stream, gpu_index, true);
}

// Test G1 MSM with BigInt5 scalar using near-maximum 320-bit value (all limbs
// set)
TEST_F(MSMTest, G1MSMWithBigInt5Max320BitScalar) {
  const uint32_t N = 1;

  const G1Affine &G = g1_generator();
  G1Affine G_mont = G;
  point_to_montgomery_inplace(G_mont);

  if (g1_is_infinity(G)) {
    GTEST_SKIP() << "G1 generator not set";
  }

  // Scratch is allocated and freed by the test_point_msm_g1/g2 helpers

  uint64_t size_tracker = 0;

  auto *d_points = static_cast<G1Affine *>(cuda_malloc_with_size_tracking_async(
      safe_mul_sizeof<G1Affine>(static_cast<size_t>(N)), stream, gpu_index,
      size_tracker, true));
  auto *d_scalars = static_cast<Scalar *>(cuda_malloc_with_size_tracking_async(
      safe_mul_sizeof<Scalar>(static_cast<size_t>(N)), stream, gpu_index,
      size_tracker, true));
  auto *d_result =
      static_cast<G1Projective *>(cuda_malloc_with_size_tracking_async(
          sizeof(G1Projective), stream, gpu_index, size_tracker, true));
  // Scratch is managed by the test helper wrappers
  auto *d_expected =
      static_cast<G1Affine *>(cuda_malloc_with_size_tracking_async(
          sizeof(G1Affine), stream, gpu_index, size_tracker, true));
  auto *d_G = static_cast<G1Affine *>(cuda_malloc_with_size_tracking_async(
      sizeof(G1Affine), stream, gpu_index, size_tracker, true));

  cuda_memset_with_size_tracking_async(d_result, 0, sizeof(G1Projective),
                                       stream, gpu_index, true);
  cuda_memset_with_size_tracking_async(d_expected, 0, sizeof(G1Affine), stream,
                                       gpu_index, true);
  cuda_memset_with_size_tracking_async(d_G, 0, sizeof(G1Affine), stream,
                                       gpu_index, true);

  auto *h_points = static_cast<G1Affine *>(
      malloc(safe_mul_sizeof<G1Affine>(static_cast<size_t>(N))));
  h_points[0] = G;

  // Create BigInt5 scalar with all 5 limbs set (near maximum 320-bit value)
  // Using 0xFFFFFFFFFFFFFFFF for all limbs would be 2^320 - 1, but we'll use a
  // smaller value to avoid potential issues: 2^256 - 1 (uses 4 limbs fully, 5th
  // limb = 0)
  auto *h_scalars = static_cast<Scalar *>(
      malloc(safe_mul_sizeof<Scalar>(static_cast<size_t>(N))));
  h_scalars[0] =
      scalar_from_limbs(0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL,
                        0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL, 0ULL);

  cuda_memcpy_with_size_tracking_async_to_gpu(
      d_points, h_points, safe_mul_sizeof<G1Affine>(static_cast<size_t>(N)),
      stream, gpu_index, true);
  cuda_memcpy_with_size_tracking_async_to_gpu(
      d_scalars, h_scalars, safe_mul_sizeof<Scalar>(static_cast<size_t>(N)),
      stream, gpu_index, true);

  point_to_montgomery_batch<G1Affine>(stream, gpu_index, d_points, N);
  check_cuda_error(cudaGetLastError());

  cuda_memcpy_with_size_tracking_async_to_gpu(d_G, &G_mont, sizeof(G1Affine),
                                              stream, gpu_index, true);

  test_point_msm_g1(stream, gpu_index, d_result, d_points, d_scalars, N,
                    size_tracker);

  auto *d_scalar_temp =
      static_cast<UNSIGNED_LIMB *>(cuda_malloc_with_size_tracking_async(
          ZP_LIMBS * sizeof(UNSIGNED_LIMB), stream, gpu_index, size_tracker,
          true));
  cuda_memcpy_with_size_tracking_async_to_gpu(d_scalar_temp, h_scalars[0].limb,
                                              ZP_LIMBS * sizeof(UNSIGNED_LIMB),
                                              stream, gpu_index, true);
  cuda_synchronize_stream(stream, gpu_index);
  point_scalar_mul<G1Affine>(stream, gpu_index, d_expected, d_G, d_scalar_temp,
                             ZP_LIMBS);
  cuda_drop_with_size_tracking_async(d_scalar_temp, stream, gpu_index, true);

  // Copy results to host and compare on CPU (avoids GPU->CPU->GPU round-trip)
  cuda_synchronize_stream(stream, gpu_index);
  G1Projective h_result_proj;
  G1Affine expected_result;
  cuda_memcpy_async_to_cpu(&h_result_proj, d_result, sizeof(G1Projective),
                           stream, gpu_index);
  cuda_memcpy_async_to_cpu(&expected_result, d_expected, sizeof(G1Affine),
                           stream, gpu_index);
  cuda_synchronize_stream(stream, gpu_index);

  // Convert projective->affine first (uses Montgomery arithmetic internally),
  // then convert both results from Montgomery to standard form
  G1Affine msm_result;
  projective_to_affine_g1(msm_result, h_result_proj);
  fp_from_montgomery(msm_result.x, msm_result.x);
  fp_from_montgomery(msm_result.y, msm_result.y);
  fp_from_montgomery(expected_result.x, expected_result.x);
  fp_from_montgomery(expected_result.y, expected_result.y);

  EXPECT_EQ(msm_result.infinity, expected_result.infinity);
  if (!msm_result.infinity && !expected_result.infinity) {
    EXPECT_EQ(fp_cmp(msm_result.x, expected_result.x), ComparisonType::Equal)
        << "MSM x-coordinate mismatch";
    EXPECT_EQ(fp_cmp(msm_result.y, expected_result.y), ComparisonType::Equal)
        << "MSM y-coordinate mismatch";
  }

  free(h_points);
  free(h_scalars);
  cuda_drop_with_size_tracking_async(d_points, stream, gpu_index, true);
  cuda_drop_with_size_tracking_async(d_scalars, stream, gpu_index, true);
  cuda_drop_with_size_tracking_async(d_result, stream, gpu_index, true);
  // Scratch freed by test helper
  cuda_drop_with_size_tracking_async(d_expected, stream, gpu_index, true);
  cuda_drop_with_size_tracking_async(d_G, stream, gpu_index, true);
}

// ============================================================================
// Edge-case tests: zero scalars, canceling scalars, infinity-point inputs
// ============================================================================

// All-zero scalars should produce the identity (infinity) in projective form,
// i.e. the Z coordinate must be zero.
TEST_F(MSMTest, G1MSMZeroScalarsReturnsInfinity) {
  constexpr uint64_t N = 5;

  const G1Affine &G = g1_generator();
  if (g1_is_infinity(G)) {
    GTEST_SKIP() << "G1 generator not set";
  }

  uint64_t size_tracker = 0;

  auto *d_points = static_cast<G1Affine *>(cuda_malloc_with_size_tracking_async(
      safe_mul_sizeof<G1Affine>(static_cast<size_t>(N)), stream, gpu_index,
      size_tracker, true));
  auto *d_scalars = static_cast<Scalar *>(cuda_malloc_with_size_tracking_async(
      safe_mul_sizeof<Scalar>(static_cast<size_t>(N)), stream, gpu_index,
      size_tracker, true));
  auto *d_result =
      static_cast<G1Projective *>(cuda_malloc_with_size_tracking_async(
          sizeof(G1Projective), stream, gpu_index, size_tracker, true));

  cuda_memset_with_size_tracking_async(d_result, 0, sizeof(G1Projective),
                                       stream, gpu_index, true);

  // N copies of the generator, all scalars zero
  auto *h_points = static_cast<G1Affine *>(
      malloc(safe_mul_sizeof<G1Affine>(static_cast<size_t>(N))));
  auto *h_scalars = static_cast<Scalar *>(
      malloc(safe_mul_sizeof<Scalar>(static_cast<size_t>(N))));
  for (uint64_t i = 0; i < N; i++) {
    h_points[i] = G;
    h_scalars[i] = scalar_from_limbs(0, 0, 0, 0, 0);
  }

  cuda_memcpy_with_size_tracking_async_to_gpu(
      d_points, h_points, safe_mul_sizeof<G1Affine>(static_cast<size_t>(N)),
      stream, gpu_index, true);
  cuda_memcpy_with_size_tracking_async_to_gpu(
      d_scalars, h_scalars, safe_mul_sizeof<Scalar>(static_cast<size_t>(N)),
      stream, gpu_index, true);

  point_to_montgomery_batch<G1Affine>(stream, gpu_index, d_points, N);
  check_cuda_error(cudaGetLastError());

  test_point_msm_g1(stream, gpu_index, d_result, d_points, d_scalars, N,
                    size_tracker);

  cuda_synchronize_stream(stream, gpu_index);
  G1Projective h_result;
  cuda_memcpy_async_to_cpu(&h_result, d_result, sizeof(G1Projective), stream,
                           gpu_index);
  cuda_synchronize_stream(stream, gpu_index);

  EXPECT_TRUE(fp_is_zero(h_result.Z))
      << "0*G + 0*G + ... should be the identity (Z == 0)";

  free(h_points);
  free(h_scalars);
  cuda_drop_with_size_tracking_async(d_points, stream, gpu_index, true);
  cuda_drop_with_size_tracking_async(d_scalars, stream, gpu_index, true);
  cuda_drop_with_size_tracking_async(d_result, stream, gpu_index, true);
}

TEST_F(MSMTest, G2MSMZeroScalarsReturnsInfinity) {
  constexpr uint64_t N = 5;

  const G2Affine &G = g2_generator();
  if (g2_is_infinity(G)) {
    GTEST_SKIP() << "G2 generator not set";
  }

  uint64_t size_tracker = 0;

  auto *d_points = static_cast<G2Affine *>(cuda_malloc_with_size_tracking_async(
      safe_mul_sizeof<G2Affine>(static_cast<size_t>(N)), stream, gpu_index,
      size_tracker, true));
  auto *d_scalars = static_cast<Scalar *>(cuda_malloc_with_size_tracking_async(
      safe_mul_sizeof<Scalar>(static_cast<size_t>(N)), stream, gpu_index,
      size_tracker, true));
  auto *d_result =
      static_cast<G2Projective *>(cuda_malloc_with_size_tracking_async(
          sizeof(G2Projective), stream, gpu_index, size_tracker, true));

  cuda_memset_with_size_tracking_async(d_result, 0, sizeof(G2Projective),
                                       stream, gpu_index, true);

  auto *h_points = static_cast<G2Affine *>(
      malloc(safe_mul_sizeof<G2Affine>(static_cast<size_t>(N))));
  auto *h_scalars = static_cast<Scalar *>(
      malloc(safe_mul_sizeof<Scalar>(static_cast<size_t>(N))));
  for (uint64_t i = 0; i < N; i++) {
    h_points[i] = G;
    h_scalars[i] = scalar_from_limbs(0, 0, 0, 0, 0);
  }

  cuda_memcpy_with_size_tracking_async_to_gpu(
      d_points, h_points, safe_mul_sizeof<G2Affine>(static_cast<size_t>(N)),
      stream, gpu_index, true);
  cuda_memcpy_with_size_tracking_async_to_gpu(
      d_scalars, h_scalars, safe_mul_sizeof<Scalar>(static_cast<size_t>(N)),
      stream, gpu_index, true);

  point_to_montgomery_batch<G2Affine>(stream, gpu_index, d_points, N);
  check_cuda_error(cudaGetLastError());

  test_point_msm_g2(stream, gpu_index, d_result, d_points, d_scalars, N,
                    size_tracker);

  cuda_synchronize_stream(stream, gpu_index);
  G2Projective h_result;
  cuda_memcpy_async_to_cpu(&h_result, d_result, sizeof(G2Projective), stream,
                           gpu_index);
  cuda_synchronize_stream(stream, gpu_index);

  EXPECT_TRUE(fp2_is_zero(h_result.Z))
      << "0*G + 0*G + ... should be the identity (Z.c0 == 0 && Z.c1 == 0)";

  free(h_points);
  free(h_scalars);
  cuda_drop_with_size_tracking_async(d_points, stream, gpu_index, true);
  cuda_drop_with_size_tracking_async(d_scalars, stream, gpu_index, true);
  cuda_drop_with_size_tracking_async(d_result, stream, gpu_index, true);
}

// Scalars [1, r-1] on two copies of G cancel: 1*G + (r-1)*G = r*G = O.
// r-1 in little-endian 64-bit limbs (the scalar-field order minus one).
TEST_F(MSMTest, G1MSMCancelingScalarsReturnsInfinity) {
  constexpr uint64_t N = 2;

  const G1Affine &G = g1_generator();
  if (g1_is_infinity(G)) {
    GTEST_SKIP() << "G1 generator not set";
  }

  uint64_t size_tracker = 0;

  auto *d_points = static_cast<G1Affine *>(cuda_malloc_with_size_tracking_async(
      safe_mul_sizeof<G1Affine>(static_cast<size_t>(N)), stream, gpu_index,
      size_tracker, true));
  auto *d_scalars = static_cast<Scalar *>(cuda_malloc_with_size_tracking_async(
      safe_mul_sizeof<Scalar>(static_cast<size_t>(N)), stream, gpu_index,
      size_tracker, true));
  auto *d_result =
      static_cast<G1Projective *>(cuda_malloc_with_size_tracking_async(
          sizeof(G1Projective), stream, gpu_index, size_tracker, true));

  cuda_memset_with_size_tracking_async(d_result, 0, sizeof(G1Projective),
                                       stream, gpu_index, true);

  G1Affine h_points[N] = {G, G};
  Scalar h_scalars[N];
  h_scalars[0] = scalar_from_limbs(1, 0, 0, 0, 0);
  h_scalars[1] = scalar_from_limbs(0x0428001400040000ULL, 0x7bb9b0e8d8ca3461ULL,
                                   0xd04c98ccc4c050bcULL, 0x7995b34995830fa4ULL,
                                   0x00000511b70539f2ULL);

  cuda_memcpy_with_size_tracking_async_to_gpu(
      d_points, h_points, safe_mul_sizeof<G1Affine>(static_cast<size_t>(N)),
      stream, gpu_index, true);
  cuda_memcpy_with_size_tracking_async_to_gpu(
      d_scalars, h_scalars, safe_mul_sizeof<Scalar>(static_cast<size_t>(N)),
      stream, gpu_index, true);

  point_to_montgomery_batch<G1Affine>(stream, gpu_index, d_points, N);
  check_cuda_error(cudaGetLastError());

  test_point_msm_g1(stream, gpu_index, d_result, d_points, d_scalars, N,
                    size_tracker);

  cuda_synchronize_stream(stream, gpu_index);
  G1Projective h_result;
  cuda_memcpy_async_to_cpu(&h_result, d_result, sizeof(G1Projective), stream,
                           gpu_index);
  cuda_synchronize_stream(stream, gpu_index);

  EXPECT_TRUE(fp_is_zero(h_result.Z))
      << "1*G + (r-1)*G should be the identity (Z == 0)";

  cuda_drop_with_size_tracking_async(d_points, stream, gpu_index, true);
  cuda_drop_with_size_tracking_async(d_scalars, stream, gpu_index, true);
  cuda_drop_with_size_tracking_async(d_result, stream, gpu_index, true);
}

TEST_F(MSMTest, G2MSMCancelingScalarsReturnsInfinity) {
  constexpr uint64_t N = 2;

  const G2Affine &G = g2_generator();
  if (g2_is_infinity(G)) {
    GTEST_SKIP() << "G2 generator not set";
  }

  uint64_t size_tracker = 0;

  auto *d_points = static_cast<G2Affine *>(cuda_malloc_with_size_tracking_async(
      safe_mul_sizeof<G2Affine>(static_cast<size_t>(N)), stream, gpu_index,
      size_tracker, true));
  auto *d_scalars = static_cast<Scalar *>(cuda_malloc_with_size_tracking_async(
      safe_mul_sizeof<Scalar>(static_cast<size_t>(N)), stream, gpu_index,
      size_tracker, true));
  auto *d_result =
      static_cast<G2Projective *>(cuda_malloc_with_size_tracking_async(
          sizeof(G2Projective), stream, gpu_index, size_tracker, true));

  cuda_memset_with_size_tracking_async(d_result, 0, sizeof(G2Projective),
                                       stream, gpu_index, true);

  G2Affine h_points[N] = {G, G};
  Scalar h_scalars[N];
  h_scalars[0] = scalar_from_limbs(1, 0, 0, 0, 0);
  h_scalars[1] = scalar_from_limbs(0x0428001400040000ULL, 0x7bb9b0e8d8ca3461ULL,
                                   0xd04c98ccc4c050bcULL, 0x7995b34995830fa4ULL,
                                   0x00000511b70539f2ULL);

  cuda_memcpy_with_size_tracking_async_to_gpu(
      d_points, h_points, safe_mul_sizeof<G2Affine>(static_cast<size_t>(N)),
      stream, gpu_index, true);
  cuda_memcpy_with_size_tracking_async_to_gpu(
      d_scalars, h_scalars, safe_mul_sizeof<Scalar>(static_cast<size_t>(N)),
      stream, gpu_index, true);

  point_to_montgomery_batch<G2Affine>(stream, gpu_index, d_points, N);
  check_cuda_error(cudaGetLastError());

  test_point_msm_g2(stream, gpu_index, d_result, d_points, d_scalars, N,
                    size_tracker);

  cuda_synchronize_stream(stream, gpu_index);
  G2Projective h_result;
  cuda_memcpy_async_to_cpu(&h_result, d_result, sizeof(G2Projective), stream,
                           gpu_index);
  cuda_synchronize_stream(stream, gpu_index);

  EXPECT_TRUE(fp2_is_zero(h_result.Z))
      << "1*G + (r-1)*G should be the identity (Z.c0 == 0 && Z.c1 == 0)";

  cuda_drop_with_size_tracking_async(d_points, stream, gpu_index, true);
  cuda_drop_with_size_tracking_async(d_scalars, stream, gpu_index, true);
  cuda_drop_with_size_tracking_async(d_result, stream, gpu_index, true);
}

// Points [O, G, O] with scalars [5, 3, 7]. Infinity inputs contribute nothing,
// so the expected result is 3*G.
TEST_F(MSMTest, G1MSMInfinityPointInput) {
  constexpr uint64_t N = 3;

  const G1Affine &G = g1_generator();
  if (g1_is_infinity(G)) {
    GTEST_SKIP() << "G1 generator not set";
  }

  G1Affine G_mont = G;
  point_to_montgomery_inplace(G_mont);

  uint64_t size_tracker = 0;

  auto *d_points = static_cast<G1Affine *>(cuda_malloc_with_size_tracking_async(
      safe_mul_sizeof<G1Affine>(static_cast<size_t>(N)), stream, gpu_index,
      size_tracker, true));
  auto *d_scalars = static_cast<Scalar *>(cuda_malloc_with_size_tracking_async(
      safe_mul_sizeof<Scalar>(static_cast<size_t>(N)), stream, gpu_index,
      size_tracker, true));
  auto *d_result =
      static_cast<G1Projective *>(cuda_malloc_with_size_tracking_async(
          sizeof(G1Projective), stream, gpu_index, size_tracker, true));
  auto *d_expected =
      static_cast<G1Affine *>(cuda_malloc_with_size_tracking_async(
          sizeof(G1Affine), stream, gpu_index, size_tracker, true));
  auto *d_G = static_cast<G1Affine *>(cuda_malloc_with_size_tracking_async(
      sizeof(G1Affine), stream, gpu_index, size_tracker, true));

  cuda_memset_with_size_tracking_async(d_result, 0, sizeof(G1Projective),
                                       stream, gpu_index, true);
  cuda_memset_with_size_tracking_async(d_expected, 0, sizeof(G1Affine), stream,
                                       gpu_index, true);
  cuda_memset_with_size_tracking_async(d_G, 0, sizeof(G1Affine), stream,
                                       gpu_index, true);

  // Build host arrays: [O, G, O] with scalars [5, 3, 7]
  G1Affine inf;
  g1_point_at_infinity(inf);

  G1Affine h_points[N] = {inf, G, inf};
  Scalar h_scalars[N] = {scalar_from_limbs(5, 0, 0, 0, 0),
                         scalar_from_limbs(3, 0, 0, 0, 0),
                         scalar_from_limbs(7, 0, 0, 0, 0)};

  cuda_memcpy_with_size_tracking_async_to_gpu(
      d_points, h_points, safe_mul_sizeof<G1Affine>(static_cast<size_t>(N)),
      stream, gpu_index, true);
  cuda_memcpy_with_size_tracking_async_to_gpu(
      d_scalars, h_scalars, safe_mul_sizeof<Scalar>(static_cast<size_t>(N)),
      stream, gpu_index, true);

  point_to_montgomery_batch<G1Affine>(stream, gpu_index, d_points, N);
  check_cuda_error(cudaGetLastError());

  // Copy Montgomery-form generator for the reference computation
  cuda_memcpy_with_size_tracking_async_to_gpu(d_G, &G_mont, sizeof(G1Affine),
                                              stream, gpu_index, true);

  test_point_msm_g1(stream, gpu_index, d_result, d_points, d_scalars, N,
                    size_tracker);

  // Expected: 3 * G
  single_point_scalar_mul<G1Affine>(stream, gpu_index, d_expected, d_G,
                                    static_cast<UNSIGNED_LIMB>(3));

  // Convert MSM projective result to affine
  cuda_synchronize_stream(stream, gpu_index);
  G1Projective h_result_proj;
  cuda_memcpy_async_to_cpu(&h_result_proj, d_result, sizeof(G1Projective),
                           stream, gpu_index);
  cuda_synchronize_stream(stream, gpu_index);

  auto *d_result_affine =
      static_cast<G1Affine *>(cuda_malloc_with_size_tracking_async(
          sizeof(G1Affine), stream, gpu_index, size_tracker, true));
  auto *d_expected_normal =
      static_cast<G1Affine *>(cuda_malloc_with_size_tracking_async(
          sizeof(G1Affine), stream, gpu_index, size_tracker, true));

  G1Affine h_result_affine;
  projective_to_affine_g1(h_result_affine, h_result_proj);
  cuda_memcpy_with_size_tracking_async_to_gpu(d_result_affine, &h_result_affine,
                                              sizeof(G1Affine), stream,
                                              gpu_index, true);

  point_from_montgomery<G1Affine>(stream, gpu_index, d_result_affine,
                                  d_result_affine);
  point_from_montgomery<G1Affine>(stream, gpu_index, d_expected_normal,
                                  d_expected);

  cuda_synchronize_stream(stream, gpu_index);
  G1Affine msm_result;
  G1Affine expected_result;
  cuda_memcpy_async_to_cpu(&msm_result, d_result_affine, sizeof(G1Affine),
                           stream, gpu_index);
  cuda_memcpy_async_to_cpu(&expected_result, d_expected_normal,
                           sizeof(G1Affine), stream, gpu_index);
  cuda_synchronize_stream(stream, gpu_index);

  cuda_drop_with_size_tracking_async(d_result_affine, stream, gpu_index, true);
  cuda_drop_with_size_tracking_async(d_expected_normal, stream, gpu_index,
                                     true);

  EXPECT_EQ(msm_result.infinity, expected_result.infinity);
  if (!msm_result.infinity && !expected_result.infinity) {
    EXPECT_EQ(fp_cmp(msm_result.x, expected_result.x), ComparisonType::Equal)
        << "x-coordinate mismatch (expected 3*G)";
    EXPECT_EQ(fp_cmp(msm_result.y, expected_result.y), ComparisonType::Equal)
        << "y-coordinate mismatch (expected 3*G)";
  }

  cuda_drop_with_size_tracking_async(d_points, stream, gpu_index, true);
  cuda_drop_with_size_tracking_async(d_scalars, stream, gpu_index, true);
  cuda_drop_with_size_tracking_async(d_result, stream, gpu_index, true);
  cuda_drop_with_size_tracking_async(d_expected, stream, gpu_index, true);
  cuda_drop_with_size_tracking_async(d_G, stream, gpu_index, true);
}

TEST_F(MSMTest, G2MSMInfinityPointInput) {
  constexpr uint64_t N = 3;

  const G2Affine &G = g2_generator();
  if (g2_is_infinity(G)) {
    GTEST_SKIP() << "G2 generator not set";
  }

  G2Affine G_mont = G;
  point_to_montgomery_inplace(G_mont);

  uint64_t size_tracker = 0;

  auto *d_points = static_cast<G2Affine *>(cuda_malloc_with_size_tracking_async(
      safe_mul_sizeof<G2Affine>(static_cast<size_t>(N)), stream, gpu_index,
      size_tracker, true));
  auto *d_scalars = static_cast<Scalar *>(cuda_malloc_with_size_tracking_async(
      safe_mul_sizeof<Scalar>(static_cast<size_t>(N)), stream, gpu_index,
      size_tracker, true));
  auto *d_result =
      static_cast<G2Projective *>(cuda_malloc_with_size_tracking_async(
          sizeof(G2Projective), stream, gpu_index, size_tracker, true));
  auto *d_expected =
      static_cast<G2Affine *>(cuda_malloc_with_size_tracking_async(
          sizeof(G2Affine), stream, gpu_index, size_tracker, true));
  auto *d_G = static_cast<G2Affine *>(cuda_malloc_with_size_tracking_async(
      sizeof(G2Affine), stream, gpu_index, size_tracker, true));

  cuda_memset_with_size_tracking_async(d_result, 0, sizeof(G2Projective),
                                       stream, gpu_index, true);
  cuda_memset_with_size_tracking_async(d_expected, 0, sizeof(G2Affine), stream,
                                       gpu_index, true);
  cuda_memset_with_size_tracking_async(d_G, 0, sizeof(G2Affine), stream,
                                       gpu_index, true);

  // Build host arrays: [O, G, O] with scalars [5, 3, 7]
  G2Affine inf;
  g2_point_at_infinity(inf);

  G2Affine h_points[N] = {inf, G, inf};
  Scalar h_scalars[N] = {scalar_from_limbs(5, 0, 0, 0, 0),
                         scalar_from_limbs(3, 0, 0, 0, 0),
                         scalar_from_limbs(7, 0, 0, 0, 0)};

  cuda_memcpy_with_size_tracking_async_to_gpu(
      d_points, h_points, safe_mul_sizeof<G2Affine>(static_cast<size_t>(N)),
      stream, gpu_index, true);
  cuda_memcpy_with_size_tracking_async_to_gpu(
      d_scalars, h_scalars, safe_mul_sizeof<Scalar>(static_cast<size_t>(N)),
      stream, gpu_index, true);

  point_to_montgomery_batch<G2Affine>(stream, gpu_index, d_points, N);
  check_cuda_error(cudaGetLastError());

  cuda_memcpy_with_size_tracking_async_to_gpu(d_G, &G_mont, sizeof(G2Affine),
                                              stream, gpu_index, true);

  test_point_msm_g2(stream, gpu_index, d_result, d_points, d_scalars, N,
                    size_tracker);

  // Expected: 3 * G
  single_point_scalar_mul<G2Affine>(stream, gpu_index, d_expected, d_G,
                                    static_cast<UNSIGNED_LIMB>(3));

  // Convert MSM projective result to affine
  cuda_synchronize_stream(stream, gpu_index);
  G2Projective h_result_proj;
  cuda_memcpy_async_to_cpu(&h_result_proj, d_result, sizeof(G2Projective),
                           stream, gpu_index);
  cuda_synchronize_stream(stream, gpu_index);

  auto *d_result_affine =
      static_cast<G2Affine *>(cuda_malloc_with_size_tracking_async(
          sizeof(G2Affine), stream, gpu_index, size_tracker, true));
  auto *d_expected_normal =
      static_cast<G2Affine *>(cuda_malloc_with_size_tracking_async(
          sizeof(G2Affine), stream, gpu_index, size_tracker, true));

  G2Affine h_result_affine;
  projective_to_affine_g2(h_result_affine, h_result_proj);
  cuda_memcpy_with_size_tracking_async_to_gpu(d_result_affine, &h_result_affine,
                                              sizeof(G2Affine), stream,
                                              gpu_index, true);

  point_from_montgomery<G2Affine>(stream, gpu_index, d_result_affine,
                                  d_result_affine);
  point_from_montgomery<G2Affine>(stream, gpu_index, d_expected_normal,
                                  d_expected);

  cuda_synchronize_stream(stream, gpu_index);
  G2Affine msm_result;
  G2Affine expected_result;
  cuda_memcpy_async_to_cpu(&msm_result, d_result_affine, sizeof(G2Affine),
                           stream, gpu_index);
  cuda_memcpy_async_to_cpu(&expected_result, d_expected_normal,
                           sizeof(G2Affine), stream, gpu_index);
  cuda_synchronize_stream(stream, gpu_index);

  cuda_drop_with_size_tracking_async(d_result_affine, stream, gpu_index, true);
  cuda_drop_with_size_tracking_async(d_expected_normal, stream, gpu_index,
                                     true);

  EXPECT_EQ(msm_result.infinity, expected_result.infinity);
  if (!msm_result.infinity && !expected_result.infinity) {
    EXPECT_EQ(fp2_cmp(msm_result.x, expected_result.x), ComparisonType::Equal)
        << "x-coordinate mismatch (expected 3*G)";
    EXPECT_EQ(fp2_cmp(msm_result.y, expected_result.y), ComparisonType::Equal)
        << "y-coordinate mismatch (expected 3*G)";
  }

  cuda_drop_with_size_tracking_async(d_points, stream, gpu_index, true);
  cuda_drop_with_size_tracking_async(d_scalars, stream, gpu_index, true);
  cuda_drop_with_size_tracking_async(d_result, stream, gpu_index, true);
  cuda_drop_with_size_tracking_async(d_expected, stream, gpu_index, true);
  cuda_drop_with_size_tracking_async(d_G, stream, gpu_index, true);
}

#endif // LIMB_BITS_CONFIG == 64
