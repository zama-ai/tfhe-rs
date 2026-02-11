#include "curve.h"
#include "device.h"
#include "fp.h"
#include "fp2.h"
#include <cstdint>
#include <cstring>
#include <cuda_runtime.h>
#include <gtest/gtest.h>

// Test fixture for scalar multiplication tests
class ScalarMulTest : public ::testing::Test {
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

// Test scalar multiplication by using MSM with a single point
// This tests the building block projective_scalar_mul indirectly
// MSM with n=1 calls projective_scalar_mul internally

// Test G1 scalar multiplication: scalar = 1 (should return point itself)
TEST_F(ScalarMulTest, G1ScalarMulOne) {
  uint64_t size_tracker = 0;
  // Get generator point
  const G1Affine &G = g1_generator();
  if (g1_is_infinity(G)) {
    GTEST_SKIP() << "G1 generator not set";
  }

  // Convert to Montgomery form
  G1Affine G_mont = G;
  point_to_montgomery_inplace(G_mont);
  G_mont.infinity = false;

  // Create scalar = 1
  Scalar scalar_one;
  scalar_one.limb[0] = 1;
  for (int i = 1; i < 5; i++) {
    scalar_one.limb[i] = 0;
  }

  // Allocate device memory
  auto *d_point = static_cast<G1Affine *>(cuda_malloc_with_size_tracking_async(
      sizeof(G1Affine), stream, gpu_index, size_tracker, true));
  auto *d_scalar = static_cast<Scalar *>(cuda_malloc_with_size_tracking_async(
      sizeof(Scalar), stream, gpu_index, size_tracker, true));
  auto *d_result =
      static_cast<G1Projective *>(cuda_malloc_with_size_tracking_async(
          sizeof(G1Projective), stream, gpu_index, size_tracker, true));

  // Copy to device
  cuda_memcpy_with_size_tracking_async_to_gpu(
      d_point, &G_mont, sizeof(G1Affine), stream, gpu_index, true);
  cuda_memcpy_with_size_tracking_async_to_gpu(
      d_scalar, &scalar_one, sizeof(Scalar), stream, gpu_index, true);

  // Test scalar multiplication using MSM with single point (tests
  // projective_scalar_mul)
  int threadsPerBlock = 256;
  int num_blocks = 1;
  size_t scratch_size =
      (num_blocks + 1) * MSM_G1_BUCKET_COUNT * sizeof(G1Projective);
  auto *d_scratch =
      static_cast<G1Projective *>(cuda_malloc_with_size_tracking_async(
          scratch_size, stream, gpu_index, size_tracker, true));

  point_msm_g1(stream, gpu_index, d_result, d_point, d_scalar, d_scratch, 1, size_tracker);
  check_cuda_error(cudaGetLastError());

  cuda_drop_with_size_tracking_async(d_scratch, stream, gpu_index, true);

  // Copy result back
  G1Projective h_result;
  cuda_memcpy_async_to_cpu(&h_result, d_result, sizeof(G1Projective), stream,
                           gpu_index);
  cuda_synchronize_stream(stream, gpu_index);

  // Convert projective to affine
  G1Affine result_affine;
  projective_to_affine_g1(result_affine, h_result);

  // Convert from Montgomery to normal form
  G1Affine result_normal;
  fp_from_montgomery(result_normal.x, result_affine.x);
  fp_from_montgomery(result_normal.y, result_affine.y);
  result_normal.infinity = result_affine.infinity;

  // Check: result should be the same as input (scalar = 1)
  EXPECT_FALSE(result_normal.infinity)
      << "Result should not be at infinity for scalar=1";
  EXPECT_EQ(fp_cmp(result_normal.x, G.x), FpComparison::Equal)
      << "x-coordinate should match input point";
  EXPECT_EQ(fp_cmp(result_normal.y, G.y), FpComparison::Equal)
      << "y-coordinate should match input point";

  // Cleanup
  cuda_drop_with_size_tracking_async(d_point, stream, gpu_index, true);
  cuda_drop_with_size_tracking_async(d_scalar, stream, gpu_index, true);
  cuda_drop_with_size_tracking_async(d_result, stream, gpu_index, true);
}

// Test G1 scalar multiplication: scalar = 0 (should return infinity)
TEST_F(ScalarMulTest, G1ScalarMulZero) {
  uint64_t size_tracker = 0;
  // Get generator point
  const G1Affine &G = g1_generator();
  if (g1_is_infinity(G)) {
    GTEST_SKIP() << "G1 generator not set";
  }

  // Convert to Montgomery form
  G1Affine G_mont = G;
  point_to_montgomery_inplace(G_mont);

  // Create scalar = 0
  Scalar scalar_zero;
  std::memset(scalar_zero.limb, 0, sizeof(scalar_zero.limb));

  // Allocate device memory
  auto *d_point = static_cast<G1Affine *>(cuda_malloc_with_size_tracking_async(
      sizeof(G1Affine), stream, gpu_index, size_tracker, true));
  auto *d_scalar = static_cast<Scalar *>(cuda_malloc_with_size_tracking_async(
      sizeof(Scalar), stream, gpu_index, size_tracker, true));
  auto *d_result =
      static_cast<G1Projective *>(cuda_malloc_with_size_tracking_async(
          sizeof(G1Projective), stream, gpu_index, size_tracker, true));

  // Copy to device
  cuda_memcpy_with_size_tracking_async_to_gpu(
      d_point, &G_mont, sizeof(G1Affine), stream, gpu_index, true);
  cuda_memcpy_with_size_tracking_async_to_gpu(
      d_scalar, &scalar_zero, sizeof(Scalar), stream, gpu_index, true);

  // Test scalar multiplication using MSM with single point (tests
  // projective_scalar_mul)
  int threadsPerBlock = 256;
  int num_blocks = 1;
  size_t scratch_size =
      (num_blocks + 1) * MSM_G1_BUCKET_COUNT * sizeof(G1Projective);
  auto *d_scratch =
      static_cast<G1Projective *>(cuda_malloc_with_size_tracking_async(
          scratch_size, stream, gpu_index, size_tracker, true));

  point_msm_g1(stream, gpu_index, d_result, d_point, d_scalar, d_scratch, 1, size_tracker);
  check_cuda_error(cudaGetLastError());

  cuda_drop_with_size_tracking_async(d_scratch, stream, gpu_index, true);

  // Copy result back
  G1Projective h_result;
  cuda_memcpy_async_to_cpu(&h_result, d_result, sizeof(G1Projective), stream,
                           gpu_index);
  cuda_synchronize_stream(stream, gpu_index);

  // Check: result should be at infinity (Z = 0)
  EXPECT_TRUE(fp_is_zero(h_result.Z))
      << "Result should be at infinity for scalar=0";

  // Cleanup
  cuda_drop_with_size_tracking_async(d_point, stream, gpu_index, true);
  cuda_drop_with_size_tracking_async(d_scalar, stream, gpu_index, true);
  cuda_drop_with_size_tracking_async(d_result, stream, gpu_index, true);
}

// Test G1 scalar multiplication: scalar = 2 (should return 2*point)
TEST_F(ScalarMulTest, G1ScalarMulTwo) {
  uint64_t size_tracker = 0;
  // Get generator point
  const G1Affine &G = g1_generator();
  if (g1_is_infinity(G)) {
    GTEST_SKIP() << "G1 generator not set";
  }

  // Convert to Montgomery form
  G1Affine G_mont = G;
  point_to_montgomery_inplace(G_mont);

  // Create scalar = 2
  Scalar scalar_two;
  scalar_two.limb[0] = 2;
  for (int i = 1; i < 5; i++) {
    scalar_two.limb[i] = 0;
  }

  // Allocate device memory
  auto *d_point = static_cast<G1Affine *>(cuda_malloc_with_size_tracking_async(
      sizeof(G1Affine), stream, gpu_index, size_tracker, true));
  auto *d_scalar = static_cast<Scalar *>(cuda_malloc_with_size_tracking_async(
      sizeof(Scalar), stream, gpu_index, size_tracker, true));
  auto *d_result =
      static_cast<G1Projective *>(cuda_malloc_with_size_tracking_async(
          sizeof(G1Projective), stream, gpu_index, size_tracker, true));
  auto *d_expected =
      static_cast<G1Affine *>(cuda_malloc_with_size_tracking_async(
          sizeof(G1Affine), stream, gpu_index, size_tracker, true));

  // Copy to device
  cuda_memcpy_with_size_tracking_async_to_gpu(
      d_point, &G_mont, sizeof(G1Affine), stream, gpu_index, true);
  cuda_memcpy_with_size_tracking_async_to_gpu(
      d_scalar, &scalar_two, sizeof(Scalar), stream, gpu_index, true);

  // Test scalar multiplication using MSM with single point (tests
  // projective_scalar_mul)
  int threadsPerBlock = 256;
  int num_blocks = 1;
  size_t scratch_size =
      (num_blocks + 1) * MSM_G1_BUCKET_COUNT * sizeof(G1Projective);
  auto *d_scratch =
      static_cast<G1Projective *>(cuda_malloc_with_size_tracking_async(
          scratch_size, stream, gpu_index, size_tracker, true));

  point_msm_g1(stream, gpu_index, d_result, d_point, d_scalar, d_scratch, 1, size_tracker);
  check_cuda_error(cudaGetLastError());

  cuda_drop_with_size_tracking_async(d_scratch, stream, gpu_index, true);

  // Compute expected result: 2*G using point doubling
  single_point_scalar_mul<G1Affine>(stream, gpu_index, d_expected, d_point, 2);

  // Synchronize and copy results back
  cuda_synchronize_stream(stream, gpu_index);
  G1Projective h_result;
  cuda_memcpy_async_to_cpu(&h_result, d_result, sizeof(G1Projective), stream,
                           gpu_index);
  G1Affine h_expected;
  cuda_memcpy_async_to_cpu(&h_expected, d_expected, sizeof(G1Affine), stream,
                           gpu_index);
  cuda_synchronize_stream(stream, gpu_index);

  // Convert projective result to affine
  G1Affine result_affine;
  projective_to_affine_g1(result_affine, h_result);

  // Convert from Montgomery to normal form
  G1Affine result_normal, expected_normal;
  fp_from_montgomery(result_normal.x, result_affine.x);
  fp_from_montgomery(result_normal.y, result_affine.y);
  result_normal.infinity = result_affine.infinity;
  fp_from_montgomery(expected_normal.x, h_expected.x);
  fp_from_montgomery(expected_normal.y, h_expected.y);
  expected_normal.infinity = h_expected.infinity;

  // Check: result should match expected (2*G)
  EXPECT_EQ(result_normal.infinity, expected_normal.infinity)
      << "Infinity flag should match";
  if (!result_normal.infinity && !expected_normal.infinity) {
    EXPECT_EQ(fp_cmp(result_normal.x, expected_normal.x), FpComparison::Equal)
        << "x-coordinate should match 2*G";
    EXPECT_EQ(fp_cmp(result_normal.y, expected_normal.y), FpComparison::Equal)
        << "y-coordinate should match 2*G";
  }

  // Cleanup
  cuda_drop_with_size_tracking_async(d_point, stream, gpu_index, true);
  cuda_drop_with_size_tracking_async(d_scalar, stream, gpu_index, true);
  cuda_drop_with_size_tracking_async(d_result, stream, gpu_index, true);
  cuda_drop_with_size_tracking_async(d_expected, stream, gpu_index, true);
}

// Test G1 scalar multiplication: scalar = 3 (should return 3*point = point +
// 2*point)
TEST_F(ScalarMulTest, G1ScalarMulThree) {
  uint64_t size_tracker = 0;
  // Get generator point
  const G1Affine &G = g1_generator();
  if (g1_is_infinity(G)) {
    GTEST_SKIP() << "G1 generator not set";
  }

  // Convert to Montgomery form
  G1Affine G_mont = G;
  point_to_montgomery_inplace(G_mont);

  // Create scalar = 3
  Scalar scalar_three;
  scalar_three.limb[0] = 3;
  for (int i = 1; i < 5; i++) {
    scalar_three.limb[i] = 0;
  }

  // Allocate device memory
  auto *d_point = static_cast<G1Affine *>(cuda_malloc_with_size_tracking_async(
      sizeof(G1Affine), stream, gpu_index, size_tracker, true));
  auto *d_scalar = static_cast<Scalar *>(cuda_malloc_with_size_tracking_async(
      sizeof(Scalar), stream, gpu_index, size_tracker, true));
  auto *d_result =
      static_cast<G1Projective *>(cuda_malloc_with_size_tracking_async(
          sizeof(G1Projective), stream, gpu_index, size_tracker, true));
  auto *d_expected =
      static_cast<G1Affine *>(cuda_malloc_with_size_tracking_async(
          sizeof(G1Affine), stream, gpu_index, size_tracker, true));

  // Copy to device
  cuda_memcpy_with_size_tracking_async_to_gpu(
      d_point, &G_mont, sizeof(G1Affine), stream, gpu_index, true);
  cuda_memcpy_with_size_tracking_async_to_gpu(
      d_scalar, &scalar_three, sizeof(Scalar), stream, gpu_index, true);

  // Test scalar multiplication using MSM with single point (tests
  // projective_scalar_mul)
  int threadsPerBlock = 256;
  int num_blocks = 1;
  size_t scratch_size =
      (num_blocks + 1) * MSM_G1_BUCKET_COUNT * sizeof(G1Projective);
  auto *d_scratch =
      static_cast<G1Projective *>(cuda_malloc_with_size_tracking_async(
          scratch_size, stream, gpu_index, size_tracker, true));

  point_msm_g1(stream, gpu_index, d_result, d_point, d_scalar, d_scratch, 1, size_tracker);
  check_cuda_error(cudaGetLastError());

  cuda_drop_with_size_tracking_async(d_scratch, stream, gpu_index, true);

  // Compute expected result: 3*G using u64 scalar multiplication
  single_point_scalar_mul<G1Affine>(stream, gpu_index, d_expected, d_point, 3);

  // Synchronize and copy results back
  cuda_synchronize_stream(stream, gpu_index);
  G1Projective h_result;
  cuda_memcpy_async_to_cpu(&h_result, d_result, sizeof(G1Projective), stream,
                           gpu_index);
  G1Affine h_expected;
  cuda_memcpy_async_to_cpu(&h_expected, d_expected, sizeof(G1Affine), stream,
                           gpu_index);
  cuda_synchronize_stream(stream, gpu_index);

  // Convert projective result to affine
  G1Affine result_affine;
  projective_to_affine_g1(result_affine, h_result);

  // Convert from Montgomery to normal form
  G1Affine result_normal, expected_normal;
  fp_from_montgomery(result_normal.x, result_affine.x);
  fp_from_montgomery(result_normal.y, result_affine.y);
  result_normal.infinity = result_affine.infinity;
  fp_from_montgomery(expected_normal.x, h_expected.x);
  fp_from_montgomery(expected_normal.y, h_expected.y);
  expected_normal.infinity = h_expected.infinity;

  // Check: result should match expected (3*G)
  EXPECT_EQ(result_normal.infinity, expected_normal.infinity)
      << "Infinity flag should match";
  if (!result_normal.infinity && !expected_normal.infinity) {
    EXPECT_EQ(fp_cmp(result_normal.x, expected_normal.x), FpComparison::Equal)
        << "x-coordinate should match 3*G";
    EXPECT_EQ(fp_cmp(result_normal.y, expected_normal.y), FpComparison::Equal)
        << "y-coordinate should match 3*G";
  }

  // Cleanup
  cuda_drop_with_size_tracking_async(d_point, stream, gpu_index, true);
  cuda_drop_with_size_tracking_async(d_scalar, stream, gpu_index, true);
  cuda_drop_with_size_tracking_async(d_result, stream, gpu_index, true);
  cuda_drop_with_size_tracking_async(d_expected, stream, gpu_index, true);
}
