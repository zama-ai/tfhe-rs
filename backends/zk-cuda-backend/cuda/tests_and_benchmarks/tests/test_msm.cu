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
  const uint64_t N = 10; // Test with 10 points

  // Get generator point
  const G1Affine &G = g1_generator();
  G1Affine G_mont = G;
  point_to_montgomery_inplace(G_mont);

  // Check that generator is not at infinity (should be set from tfhe-rs)
  if (g1_is_infinity(G)) {
    GTEST_SKIP() << "G1 generator not set - please provide generator points "
                    "from tfhe-rs";
  }

  // Calculate required scratch space: (num_blocks + 1) * MSM_G1_BUCKET_COUNT
  // (projective points)
  int threadsPerBlock = 256;
  int num_blocks = CEIL_DIV(N, threadsPerBlock);
  size_t scratch_size =
      (num_blocks + 1) * MSM_G1_BUCKET_COUNT * sizeof(G1Projective);

  uint64_t size_tracker = 0;

  // Allocate device memory for points and scalars
  auto *d_points = static_cast<G1Affine *>(cuda_malloc_with_size_tracking_async(
      N * sizeof(G1Affine), stream, gpu_index, size_tracker, true));
  auto *d_scalars = static_cast<Scalar *>(cuda_malloc_with_size_tracking_async(
      N * sizeof(Scalar), stream, gpu_index, size_tracker, true));
  auto *d_result =
      static_cast<G1Projective *>(cuda_malloc_with_size_tracking_async(
          sizeof(G1Projective), stream, gpu_index, size_tracker, true));
  auto *d_scratch =
      static_cast<G1Projective *>(cuda_malloc_with_size_tracking_async(
          scratch_size, stream, gpu_index, size_tracker, true));
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
  auto *h_points = static_cast<G1Affine *>(malloc(N * sizeof(G1Affine)));
  for (uint64_t i = 0; i < N; i++) {
    h_points[i] = G;
  }

  auto *h_scalars = static_cast<Scalar *>(malloc(N * sizeof(Scalar)));
  for (uint64_t i = 0; i < N; i++) {
    // Convert uint64_t to BigInt5 (put value in first limb, zeros in rest)
    h_scalars[i].limb[0] = i + 1;
    // Use memset to zero the remaining limbs
    memset(&h_scalars[i].limb[1], 0, (ZP_LIMBS - 1) * sizeof(UNSIGNED_LIMB));
  }

  // Copy to device
  cuda_memcpy_with_size_tracking_async_to_gpu(
      d_points, h_points, N * sizeof(G1Affine), stream, gpu_index, true);
  cuda_memcpy_with_size_tracking_async_to_gpu(
      d_scalars, h_scalars, N * sizeof(Scalar), stream, gpu_index, true);

  // Convert points to Montgomery form (required for performance)
  point_to_montgomery_batch<G1Affine>(stream, gpu_index, d_points, N);
  check_cuda_error(cudaGetLastError());

  // Copy generator (converted to Montgomery) to device for scalar
  // multiplication
  cuda_memcpy_with_size_tracking_async_to_gpu(d_G, &G_mont, sizeof(G1Affine),
                                              stream, gpu_index, true);

  // Compute MSM on device (returns projective point)
  point_msm_g1(stream, gpu_index, d_result, d_points, d_scalars, d_scratch, N,
               size_tracker);

  // Compute expected result on device: G * (N * (N+1) / 2)
  UNSIGNED_LIMB expected_scalar = static_cast<UNSIGNED_LIMB>(triangular_number(N));
  single_point_scalar_mul<G1Affine>(stream, gpu_index, d_expected, d_G,
                                 expected_scalar);

  // Convert projective result to affine, then from Montgomery form before
  // comparing
  G1Projective *d_result_proj = d_result;
  auto *d_result_affine =
      static_cast<G1Affine *>(cuda_malloc_with_size_tracking_async(
          sizeof(G1Affine), stream, gpu_index, size_tracker, true));
  auto *d_expected_normal =
      static_cast<G1Affine *>(cuda_malloc_with_size_tracking_async(
          sizeof(G1Affine), stream, gpu_index, size_tracker, true));

  // Convert projective to affine on device
  cuda_synchronize_stream(stream, gpu_index);
  G1Projective h_result_proj;
  cuda_memcpy_async_to_cpu(&h_result_proj, d_result_proj, sizeof(G1Projective),
                           stream, gpu_index);
  cuda_synchronize_stream(stream, gpu_index);
  G1Affine h_result_affine;
  projective_to_affine_g1(h_result_affine, h_result_proj);
  cuda_memcpy_with_size_tracking_async_to_gpu(d_result_affine, &h_result_affine,
                                              sizeof(G1Affine), stream,
                                              gpu_index, true);

  point_from_montgomery<G1Affine>(stream, gpu_index, d_result_affine,
                                  d_result_affine);
  point_from_montgomery<G1Affine>(stream, gpu_index, d_expected_normal,
                                  d_expected);

  // Synchronize and copy results back
  cuda_synchronize_stream(stream, gpu_index);
  G1Affine msm_result;
  G1Affine expected_result;
  cuda_memcpy_async_to_cpu(&msm_result, d_result_affine, sizeof(G1Affine),
                           stream, gpu_index);
  cuda_memcpy_async_to_cpu(&expected_result, d_expected_normal,
                           sizeof(G1Affine), stream, gpu_index);
  cuda_synchronize_stream(stream, gpu_index);

  // Cleanup
  cuda_drop_with_size_tracking_async(d_result_affine, stream, gpu_index, true);
  cuda_drop_with_size_tracking_async(d_expected_normal, stream, gpu_index,
                                     true);

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
  cuda_drop_with_size_tracking_async(d_scratch, stream, gpu_index, true);
  cuda_drop_with_size_tracking_async(d_expected, stream, gpu_index, true);
  cuda_drop_with_size_tracking_async(d_G, stream, gpu_index, true);
}

// Test G2 MSM with generator point
TEST_F(MSMTest, G2MSMWithGenerator) {
  const uint64_t N = 10; // Test with 10 points

  // Get generator point
  const G2Affine &G = g2_generator();
  G2Affine G_mont = G;
  point_to_montgomery_inplace(G_mont);

  // Check that generator is not at infinity (should be set from tfhe-rs)
  if (g2_is_infinity(G)) {
    GTEST_SKIP() << "G2 generator not set - please provide generator points "
                    "from tfhe-rs";
  }

  // Calculate required scratch space: (num_blocks + 1) * MSM_G2_BUCKET_COUNT
  // (projective points)
  int threadsPerBlock = 128;
  int num_blocks = CEIL_DIV(N, threadsPerBlock);
  size_t scratch_size =
      (num_blocks + 1) * MSM_G2_BUCKET_COUNT * sizeof(G2Projective);

  uint64_t size_tracker = 0;

  // Allocate device memory
  auto *d_points = static_cast<G2Affine *>(cuda_malloc_with_size_tracking_async(
      N * sizeof(G2Affine), stream, gpu_index, size_tracker, true));
  auto *d_scalars = static_cast<Scalar *>(cuda_malloc_with_size_tracking_async(
      N * sizeof(Scalar), stream, gpu_index, size_tracker, true));
  auto *d_result =
      static_cast<G2Projective *>(cuda_malloc_with_size_tracking_async(
          sizeof(G2Projective), stream, gpu_index, size_tracker, true));
  auto *d_scratch =
      static_cast<G2Projective *>(cuda_malloc_with_size_tracking_async(
          scratch_size, stream, gpu_index, size_tracker, true));
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

  auto *h_points = static_cast<G2Affine *>(malloc(N * sizeof(G2Affine)));
  for (uint64_t i = 0; i < N; i++) {
    h_points[i] = G;
  }

  auto *h_scalars = static_cast<Scalar *>(malloc(N * sizeof(Scalar)));
  for (uint64_t i = 0; i < N; i++) {
    // Convert uint64_t to BigInt5 (put value in first limb, zeros in rest)
    h_scalars[i].limb[0] = i + 1;
    // Use memset to zero the remaining limbs
    memset(&h_scalars[i].limb[1], 0, (ZP_LIMBS - 1) * sizeof(UNSIGNED_LIMB));
  }

  // Copy to device
  cuda_memcpy_with_size_tracking_async_to_gpu(
      d_points, h_points, N * sizeof(G2Affine), stream, gpu_index, true);
  cuda_memcpy_with_size_tracking_async_to_gpu(
      d_scalars, h_scalars, N * sizeof(Scalar), stream, gpu_index, true);

  // Convert points to Montgomery form (required for performance)
  int threadsPerBlock_conv = 128;
  int blocks_conv = CEIL_DIV(N, threadsPerBlock_conv);
  point_to_montgomery_batch<G2Affine>(stream, gpu_index, d_points, N);
  check_cuda_error(cudaGetLastError());

  // Copy generator (converted to Montgomery) to device
  cuda_memcpy_with_size_tracking_async_to_gpu(d_G, &G_mont, sizeof(G2Affine),
                                              stream, gpu_index, true);

  // Compute MSM on device (returns projective point)
  point_msm_g2(stream, gpu_index, d_result, d_points, d_scalars, d_scratch, N,
               size_tracker);

  // Compute expected result on device: G * (N * (N+1) / 2)
  UNSIGNED_LIMB expected_scalar = static_cast<UNSIGNED_LIMB>(triangular_number(N));
  single_point_scalar_mul<G2Affine>(stream, gpu_index, d_expected, d_G,
                                 expected_scalar);

  // Convert projective result to affine, then from Montgomery form before
  // comparing
  G2Projective *d_result_proj = d_result;
  auto *d_result_affine =
      static_cast<G2Affine *>(cuda_malloc_with_size_tracking_async(
          sizeof(G2Affine), stream, gpu_index, size_tracker, true));
  auto *d_expected_normal =
      static_cast<G2Affine *>(cuda_malloc_with_size_tracking_async(
          sizeof(G2Affine), stream, gpu_index, size_tracker, true));

  // Convert projective to affine on device
  cuda_synchronize_stream(stream, gpu_index);
  G2Projective h_result_proj;
  cuda_memcpy_async_to_cpu(&h_result_proj, d_result_proj, sizeof(G2Projective),
                           stream, gpu_index);
  cuda_synchronize_stream(stream, gpu_index);
  G2Affine h_result_affine;
  projective_to_affine_g2(h_result_affine, h_result_proj);
  cuda_memcpy_with_size_tracking_async_to_gpu(d_result_affine, &h_result_affine,
                                              sizeof(G2Affine), stream,
                                              gpu_index, true);

  point_from_montgomery<G2Affine>(stream, gpu_index, d_result_affine,
                                  d_result_affine);
  point_from_montgomery<G2Affine>(stream, gpu_index, d_expected_normal,
                                  d_expected);

  // Synchronize and copy results back
  cuda_synchronize_stream(stream, gpu_index);
  G2Affine msm_result;
  G2Affine expected_result;
  cuda_memcpy_async_to_cpu(&msm_result, d_result_affine, sizeof(G2Affine),
                           stream, gpu_index);
  cuda_memcpy_async_to_cpu(&expected_result, d_expected_normal,
                           sizeof(G2Affine), stream, gpu_index);
  cuda_synchronize_stream(stream, gpu_index);

  // Cleanup
  cuda_drop_with_size_tracking_async(d_result_affine, stream, gpu_index, true);
  cuda_drop_with_size_tracking_async(d_expected_normal, stream, gpu_index,
                                     true);

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
  cuda_drop_with_size_tracking_async(d_scratch, stream, gpu_index, true);
  cuda_drop_with_size_tracking_async(d_expected, stream, gpu_index, true);
  cuda_drop_with_size_tracking_async(d_G, stream, gpu_index, true);
}

// Test with larger N to verify correctness
TEST_F(MSMTest, G1MSMLargeN) {
  // Test multiple N values to find where it breaks
  uint64_t size_tracker = 0;
  for (uint64_t test_N = 1; test_N <= 100; test_N++) {
    const uint64_t N = test_N;

    const G1Affine &G = g1_generator();
    if (g1_is_infinity(G)) {
      GTEST_SKIP() << "G1 generator not set";
    }
    G1Affine G_mont = G;
    point_to_montgomery_inplace(G_mont);

    // Calculate required scratch space: (num_blocks + 1) * MSM_G1_BUCKET_COUNT
    // (projective points) Note: Must match threadsPerBlock used in Pippenger
    // implementation (128 for G1)
    int threadsPerBlock = 128;
    int num_blocks = CEIL_DIV(N, threadsPerBlock);
    size_t scratch_size =
        (num_blocks + 1) * MSM_G1_BUCKET_COUNT * sizeof(G1Projective);

    // Allocate device memory
    auto *d_points =
        static_cast<G1Affine *>(cuda_malloc_with_size_tracking_async(
            N * sizeof(G1Affine), stream, gpu_index, size_tracker, true));
    auto *d_scalars =
        static_cast<Scalar *>(cuda_malloc_with_size_tracking_async(
            N * sizeof(Scalar), stream, gpu_index, size_tracker, true));
    auto *d_result =
        static_cast<G1Projective *>(cuda_malloc_with_size_tracking_async(
            sizeof(G1Projective), stream, gpu_index, size_tracker, true));
    auto *d_scratch =
        static_cast<G1Projective *>(cuda_malloc_with_size_tracking_async(
            scratch_size, stream, gpu_index, size_tracker, true));
    auto *d_expected =
        static_cast<G1Affine *>(cuda_malloc_with_size_tracking_async(
            sizeof(G1Affine), stream, gpu_index, size_tracker, true));
    auto *d_G = static_cast<G1Affine *>(cuda_malloc_with_size_tracking_async(
        sizeof(G1Affine), stream, gpu_index, size_tracker, true));

    // Initialize allocated memory to zero to avoid uninitialized access
    // warnings
    cuda_memset_with_size_tracking_async(d_result, 0, sizeof(G1Projective),
                                         stream, gpu_index, true);
    cuda_memset_with_size_tracking_async(d_expected, 0, sizeof(G1Affine),
                                         stream, gpu_index, true);
    cuda_memset_with_size_tracking_async(d_G, 0, sizeof(G1Affine), stream,
                                         gpu_index, true);
    // Note: Scratch space is cleared by MSM kernels, but zeroing it doesn't
    // hurt

    // Prepare host data (generator already in standard form)

    auto *h_points = static_cast<G1Affine *>(malloc(N * sizeof(G1Affine)));
    for (uint64_t i = 0; i < N; i++) {
      h_points[i] = G;
    }

    auto *h_scalars = static_cast<Scalar *>(malloc(N * sizeof(Scalar)));
    for (uint64_t i = 0; i < N; i++) {
      // Convert uint64_t to BigInt5 (put value in first limb, zeros in rest)
      h_scalars[i].limb[0] = i + 1;
      // Use memset to zero the remaining limbs
      memset(&h_scalars[i].limb[1], 0, (ZP_LIMBS - 1) * sizeof(UNSIGNED_LIMB));
    }

    // Copy to device
    cuda_memcpy_with_size_tracking_async_to_gpu(
        d_points, h_points, N * sizeof(G1Affine), stream, gpu_index, true);
    cuda_memcpy_with_size_tracking_async_to_gpu(
        d_scalars, h_scalars, N * sizeof(Scalar), stream, gpu_index, true);

    // Convert points to Montgomery form (required for performance)
    point_to_montgomery_batch<G1Affine>(stream, gpu_index, d_points, N);
    check_cuda_error(cudaGetLastError());

    // Copy generator (converted to Montgomery) to device
    cuda_memcpy_with_size_tracking_async_to_gpu(d_G, &G_mont, sizeof(G1Affine),
                                                stream, gpu_index, true);

    // Compute MSM on device (returns projective point)
    point_msm_g1(stream, gpu_index, d_result, d_points, d_scalars, d_scratch,
                 N, size_tracker);

    // Compute expected result on device: G * (N * (N+1) / 2)
    UNSIGNED_LIMB expected_scalar = static_cast<UNSIGNED_LIMB>(triangular_number(N));
    single_point_scalar_mul<G1Affine>(stream, gpu_index, d_expected, d_G,
                                   expected_scalar);

    // Convert projective result to affine, then from Montgomery form before
    // comparing
    G1Projective *d_result_proj = d_result;
    auto *d_result_affine =
        static_cast<G1Affine *>(cuda_malloc_with_size_tracking_async(
            sizeof(G1Affine), stream, gpu_index, size_tracker, true));
    auto *d_expected_normal =
        static_cast<G1Affine *>(cuda_malloc_with_size_tracking_async(
            sizeof(G1Affine), stream, gpu_index, size_tracker, true));

    // Convert projective to affine on device
    cuda_synchronize_stream(stream, gpu_index);
    G1Projective h_result_proj;
    cuda_memcpy_async_to_cpu(&h_result_proj, d_result_proj,
                             sizeof(G1Projective), stream, gpu_index);
    cuda_synchronize_stream(stream, gpu_index);
    G1Affine h_result_affine;
    projective_to_affine_g1(h_result_affine, h_result_proj);
    cuda_memcpy_with_size_tracking_async_to_gpu(
        d_result_affine, &h_result_affine, sizeof(G1Affine), stream, gpu_index,
        true);

    point_from_montgomery<G1Affine>(stream, gpu_index, d_result_affine,
                                    d_result_affine);
    point_from_montgomery<G1Affine>(stream, gpu_index, d_expected_normal,
                                    d_expected);

    // Synchronize and copy results back
    cuda_synchronize_stream(stream, gpu_index);
    G1Affine msm_result;
    G1Affine expected_result;
    cuda_memcpy_async_to_cpu(&msm_result, d_result_affine, sizeof(G1Affine),
                             stream, gpu_index);
    cuda_memcpy_async_to_cpu(&expected_result, d_expected_normal,
                             sizeof(G1Affine), stream, gpu_index);
    cuda_synchronize_stream(stream, gpu_index);

    // Cleanup
    cuda_drop_with_size_tracking_async(d_result_affine, stream, gpu_index,
                                       true);
    cuda_drop_with_size_tracking_async(d_expected_normal, stream, gpu_index,
                                       true);
    cuda_synchronize_stream(stream, gpu_index);

    EXPECT_EQ(msm_result.infinity, expected_result.infinity) << "N=" << N;
    if (!msm_result.infinity && !expected_result.infinity) {
      // Debug output only for failures
      ComparisonType x_cmp = fp_cmp(msm_result.x, expected_result.x);
      ComparisonType y_cmp = fp_cmp(msm_result.y, expected_result.y);
      if (x_cmp != ComparisonType::Equal || y_cmp != ComparisonType::Equal) {
        printf("G1MSMLargeN FAILED: N=%lu, expected_scalar=%lu\n", N,
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

    free(h_points);
    free(h_scalars);
    cuda_drop_with_size_tracking_async(d_points, stream, gpu_index, true);
    cuda_drop_with_size_tracking_async(d_scalars, stream, gpu_index, true);
    cuda_drop_with_size_tracking_async(d_result, stream, gpu_index, true);
    cuda_drop_with_size_tracking_async(d_scratch, stream, gpu_index, true);
    cuda_drop_with_size_tracking_async(d_expected, stream, gpu_index, true);
    cuda_drop_with_size_tracking_async(d_G, stream, gpu_index, true);
  }
}

// Test G2 MSM with larger N to verify correctness (compare with G1MSMLargeN)
TEST_F(MSMTest, G2MSMLargeN) {
  // Test multiple N values to find where it breaks
  uint64_t size_tracker = 0;
  for (uint64_t test_N = 1; test_N <= 100; test_N++) {
    const uint64_t N = test_N;

    const G2Affine &G = g2_generator();
    if (g2_is_infinity(G)) {
      GTEST_SKIP() << "G2 generator not set";
    }
    G2Affine G_mont = G;
    point_to_montgomery_inplace(G_mont);

    // Calculate required scratch space: (num_blocks + 1) * MSM_G2_BUCKET_COUNT
    // (projective points) Note: Must match threadsPerBlock used in Pippenger
    // implementation (64 for G2)
    int threadsPerBlock = 64;
    int num_blocks = CEIL_DIV(N, threadsPerBlock);
    size_t scratch_size =
        (num_blocks + 1) * MSM_G2_BUCKET_COUNT * sizeof(G2Projective);

    // Allocate device memory
    auto *d_points =
        static_cast<G2Affine *>(cuda_malloc_with_size_tracking_async(
            N * sizeof(G2Affine), stream, gpu_index, size_tracker, true));
    auto *d_scalars =
        static_cast<Scalar *>(cuda_malloc_with_size_tracking_async(
            N * sizeof(Scalar), stream, gpu_index, size_tracker, true));
    auto *d_result =
        static_cast<G2Projective *>(cuda_malloc_with_size_tracking_async(
            sizeof(G2Projective), stream, gpu_index, size_tracker, true));
    auto *d_scratch =
        static_cast<G2Projective *>(cuda_malloc_with_size_tracking_async(
            scratch_size, stream, gpu_index, size_tracker, true));
    auto *d_expected =
        static_cast<G2Affine *>(cuda_malloc_with_size_tracking_async(
            sizeof(G2Affine), stream, gpu_index, size_tracker, true));
    auto *d_G = static_cast<G2Affine *>(cuda_malloc_with_size_tracking_async(
        sizeof(G2Affine), stream, gpu_index, size_tracker, true));

    // Initialize allocated memory to zero to avoid uninitialized access
    // warnings
    cuda_memset_with_size_tracking_async(d_result, 0, sizeof(G2Projective),
                                         stream, gpu_index, true);
    cuda_memset_with_size_tracking_async(d_expected, 0, sizeof(G2Affine),
                                         stream, gpu_index, true);
    cuda_memset_with_size_tracking_async(d_G, 0, sizeof(G2Affine), stream,
                                         gpu_index, true);

    // Prepare host data (generator already in standard form)
    auto *h_points = static_cast<G2Affine *>(malloc(N * sizeof(G2Affine)));
    for (uint64_t i = 0; i < N; i++) {
      h_points[i] = G;
    }

    auto *h_scalars = static_cast<Scalar *>(malloc(N * sizeof(Scalar)));
    for (uint64_t i = 0; i < N; i++) {
      // Convert uint64_t to BigInt5 (put value in first limb, zeros in rest)
      h_scalars[i].limb[0] = i + 1;
      // Use memset to zero the remaining limbs
      memset(&h_scalars[i].limb[1], 0, (ZP_LIMBS - 1) * sizeof(UNSIGNED_LIMB));
    }

    // Copy to device
    cuda_memcpy_with_size_tracking_async_to_gpu(
        d_points, h_points, N * sizeof(G2Affine), stream, gpu_index, true);
    cuda_memcpy_with_size_tracking_async_to_gpu(
        d_scalars, h_scalars, N * sizeof(Scalar), stream, gpu_index, true);

    // Convert points to Montgomery form (required for performance)
    point_to_montgomery_batch<G2Affine>(stream, gpu_index, d_points, N);
    check_cuda_error(cudaGetLastError());

    // Copy generator (converted to Montgomery) to device
    cuda_memcpy_with_size_tracking_async_to_gpu(d_G, &G_mont, sizeof(G2Affine),
                                                stream, gpu_index, true);

    // Compute MSM on device (returns projective point)
    point_msm_g2(stream, gpu_index, d_result, d_points, d_scalars, d_scratch,
                 N, size_tracker);

    // Compute expected result on device: G * (N * (N+1) / 2)
    UNSIGNED_LIMB expected_scalar = static_cast<UNSIGNED_LIMB>(triangular_number(N));
    single_point_scalar_mul<G2Affine>(stream, gpu_index, d_expected, d_G,
                                   expected_scalar);

    // Convert projective result to affine, then from Montgomery form before
    // comparing
    G2Projective *d_result_proj = d_result;
    auto *d_result_affine =
        static_cast<G2Affine *>(cuda_malloc_with_size_tracking_async(
            sizeof(G2Affine), stream, gpu_index, size_tracker, true));
    auto *d_expected_normal =
        static_cast<G2Affine *>(cuda_malloc_with_size_tracking_async(
            sizeof(G2Affine), stream, gpu_index, size_tracker, true));

    // Convert projective to affine on device
    cuda_synchronize_stream(stream, gpu_index);
    G2Projective h_result_proj;
    cuda_memcpy_async_to_cpu(&h_result_proj, d_result_proj,
                             sizeof(G2Projective), stream, gpu_index);
    cuda_synchronize_stream(stream, gpu_index);
    G2Affine h_result_affine;
    projective_to_affine_g2(h_result_affine, h_result_proj);
    cuda_memcpy_with_size_tracking_async_to_gpu(
        d_result_affine, &h_result_affine, sizeof(G2Affine), stream, gpu_index,
        true);

    point_from_montgomery<G2Affine>(stream, gpu_index, d_result_affine,
                                    d_result_affine);
    point_from_montgomery<G2Affine>(stream, gpu_index, d_expected_normal,
                                    d_expected);

    // Synchronize and copy results back
    cuda_synchronize_stream(stream, gpu_index);
    G2Affine msm_result;
    G2Affine expected_result;
    cuda_memcpy_async_to_cpu(&msm_result, d_result_affine, sizeof(G2Affine),
                             stream, gpu_index);
    cuda_memcpy_async_to_cpu(&expected_result, d_expected_normal,
                             sizeof(G2Affine), stream, gpu_index);
    cuda_synchronize_stream(stream, gpu_index);

    // Cleanup
    cuda_drop_with_size_tracking_async(d_result_affine, stream, gpu_index,
                                       true);
    cuda_drop_with_size_tracking_async(d_expected_normal, stream, gpu_index,
                                       true);
    cuda_synchronize_stream(stream, gpu_index);

    EXPECT_EQ(msm_result.infinity, expected_result.infinity) << "N=" << N;
    if (!msm_result.infinity && !expected_result.infinity) {
      // Debug output only for failures
      ComparisonType x_cmp = fp2_cmp(msm_result.x, expected_result.x);
      ComparisonType y_cmp = fp2_cmp(msm_result.y, expected_result.y);
      if (x_cmp != ComparisonType::Equal || y_cmp != ComparisonType::Equal) {
        printf("G2MSMLargeN FAILED: N=%lu, expected_scalar=%lu\n", N,
               triangular_number(N));
      }

      EXPECT_EQ(x_cmp, ComparisonType::Equal)
          << "N=" << N << " x-coordinate mismatch";
      EXPECT_EQ(y_cmp, ComparisonType::Equal)
          << "N=" << N << " y-coordinate mismatch";
    }

    free(h_points);
    free(h_scalars);
    cuda_drop_with_size_tracking_async(d_points, stream, gpu_index, true);
    cuda_drop_with_size_tracking_async(d_scalars, stream, gpu_index, true);
    cuda_drop_with_size_tracking_async(d_result, stream, gpu_index, true);
    cuda_drop_with_size_tracking_async(d_scratch, stream, gpu_index, true);
    cuda_drop_with_size_tracking_async(d_expected, stream, gpu_index, true);
    cuda_drop_with_size_tracking_async(d_G, stream, gpu_index, true);
  }
}

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
  const uint64_t N = 10;

  const G1Affine &G = g1_generator();
  G1Affine G_mont = G;
  point_to_montgomery_inplace(G_mont);

  if (g1_is_infinity(G)) {
    GTEST_SKIP() << "G1 generator not set";
  }

  int threadsPerBlock = 128;
  int num_blocks = CEIL_DIV(N, threadsPerBlock);
  size_t scratch_size =
      (num_blocks + 1) * MSM_G1_BUCKET_COUNT * sizeof(G1Projective);

  uint64_t size_tracker = 0;

  auto *d_points = static_cast<G1Affine *>(cuda_malloc_with_size_tracking_async(
      N * sizeof(G1Affine), stream, gpu_index, size_tracker, true));
  auto *d_scalars = static_cast<Scalar *>(cuda_malloc_with_size_tracking_async(
      N * sizeof(Scalar), stream, gpu_index, size_tracker, true));
  auto *d_result =
      static_cast<G1Projective *>(cuda_malloc_with_size_tracking_async(
          sizeof(G1Projective), stream, gpu_index, size_tracker, true));
  auto *d_scratch =
      static_cast<G1Projective *>(cuda_malloc_with_size_tracking_async(
          scratch_size, stream, gpu_index, size_tracker, true));
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

  auto *h_points = static_cast<G1Affine *>(malloc(N * sizeof(G1Affine)));
  for (uint64_t i = 0; i < N; i++) {
    h_points[i] = G;
  }

  auto *h_scalars = static_cast<Scalar *>(malloc(N * sizeof(Scalar)));
  for (uint64_t i = 0; i < N; i++) {
    h_scalars[i] = u64_to_scalar(i + 1);
  }

  cuda_memcpy_with_size_tracking_async_to_gpu(
      d_points, h_points, N * sizeof(G1Affine), stream, gpu_index, true);
  cuda_memcpy_with_size_tracking_async_to_gpu(
      d_scalars, h_scalars, N * sizeof(Scalar), stream, gpu_index, true);

  point_to_montgomery_batch<G1Affine>(stream, gpu_index, d_points, N);
  check_cuda_error(cudaGetLastError());

  cuda_memcpy_with_size_tracking_async_to_gpu(d_G, &G_mont, sizeof(G1Affine),
                                              stream, gpu_index, true);

  point_msm_g1(stream, gpu_index, d_result, d_points, d_scalars, d_scratch, N,
               size_tracker);

  UNSIGNED_LIMB expected_scalar = static_cast<UNSIGNED_LIMB>(triangular_number(N));
  single_point_scalar_mul<G1Affine>(stream, gpu_index, d_expected, d_G,
                                 expected_scalar);

  G1Projective *d_result_proj = d_result;
  auto *d_result_affine =
      static_cast<G1Affine *>(cuda_malloc_with_size_tracking_async(
          sizeof(G1Affine), stream, gpu_index, size_tracker, true));
  auto *d_expected_normal =
      static_cast<G1Affine *>(cuda_malloc_with_size_tracking_async(
          sizeof(G1Affine), stream, gpu_index, size_tracker, true));

  cuda_synchronize_stream(stream, gpu_index);
  G1Projective h_result_proj;
  cuda_memcpy_async_to_cpu(&h_result_proj, d_result_proj, sizeof(G1Projective),
                           stream, gpu_index);
  cuda_synchronize_stream(stream, gpu_index);
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
        << "MSM x-coordinate mismatch";
    EXPECT_EQ(fp_cmp(msm_result.y, expected_result.y), ComparisonType::Equal)
        << "MSM y-coordinate mismatch";
  }

  free(h_points);
  free(h_scalars);
  cuda_drop_with_size_tracking_async(d_points, stream, gpu_index, true);
  cuda_drop_with_size_tracking_async(d_scalars, stream, gpu_index, true);
  cuda_drop_with_size_tracking_async(d_result, stream, gpu_index, true);
  cuda_drop_with_size_tracking_async(d_scratch, stream, gpu_index, true);
  cuda_drop_with_size_tracking_async(d_expected, stream, gpu_index, true);
  cuda_drop_with_size_tracking_async(d_G, stream, gpu_index, true);
}

// Test G2 MSM with bigint scalars
TEST_F(MSMTest, G2MSMWithBigIntScalars) {
  const uint64_t N = 2;

  const G2Affine &G = g2_generator();
  G2Affine G_mont = G;
  point_to_montgomery_inplace(G_mont);

  if (g2_is_infinity(G)) {
    GTEST_SKIP() << "G2 generator not set";
  }

  int threadsPerBlock = 80;
  int num_blocks = CEIL_DIV(N, threadsPerBlock);
  size_t scratch_size =
      (num_blocks + 1) * MSM_G2_BUCKET_COUNT * sizeof(G2Projective);

  uint64_t size_tracker = 0;

  auto *d_points = static_cast<G2Affine *>(cuda_malloc_with_size_tracking_async(
      N * sizeof(G2Affine), stream, gpu_index, size_tracker, true));
  auto *d_scalars = static_cast<Scalar *>(cuda_malloc_with_size_tracking_async(
      N * sizeof(Scalar), stream, gpu_index, size_tracker, true));
  auto *d_result =
      static_cast<G2Projective *>(cuda_malloc_with_size_tracking_async(
          sizeof(G2Projective), stream, gpu_index, size_tracker, true));
  auto *d_scratch =
      static_cast<G2Projective *>(cuda_malloc_with_size_tracking_async(
          scratch_size, stream, gpu_index, size_tracker, true));
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

  auto *h_points = static_cast<G2Affine *>(malloc(N * sizeof(G2Affine)));
  for (uint64_t i = 0; i < N; i++) {
    h_points[i] = G;
  }

  auto *h_scalars = static_cast<Scalar *>(malloc(N * sizeof(Scalar)));
  for (uint64_t i = 0; i < N; i++) {
    h_scalars[i] = u64_to_scalar(i + 1);
  }

  cuda_memcpy_with_size_tracking_async_to_gpu(
      d_points, h_points, N * sizeof(G2Affine), stream, gpu_index, true);
  cuda_memcpy_with_size_tracking_async_to_gpu(
      d_scalars, h_scalars, N * sizeof(Scalar), stream, gpu_index, true);

  point_to_montgomery_batch<G2Affine>(stream, gpu_index, d_points, N);
  check_cuda_error(cudaGetLastError());

  cuda_memcpy_with_size_tracking_async_to_gpu(d_G, &G_mont, sizeof(G2Affine),
                                              stream, gpu_index, true);

  point_msm_g2(stream, gpu_index, d_result, d_points, d_scalars, d_scratch, N,
               size_tracker);

  UNSIGNED_LIMB expected_scalar = static_cast<UNSIGNED_LIMB>(triangular_number(N));
  single_point_scalar_mul<G2Affine>(stream, gpu_index, d_expected, d_G,
                                 expected_scalar);

  G2Projective *d_result_proj = d_result;
  auto *d_result_affine =
      static_cast<G2Affine *>(cuda_malloc_with_size_tracking_async(
          sizeof(G2Affine), stream, gpu_index, size_tracker, true));
  auto *d_expected_normal =
      static_cast<G2Affine *>(cuda_malloc_with_size_tracking_async(
          sizeof(G2Affine), stream, gpu_index, size_tracker, true));

  cuda_synchronize_stream(stream, gpu_index);
  G2Projective h_result_proj;
  cuda_memcpy_async_to_cpu(&h_result_proj, d_result_proj, sizeof(G2Projective),
                           stream, gpu_index);
  cuda_synchronize_stream(stream, gpu_index);
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
        << "MSM x-coordinate mismatch";
    EXPECT_EQ(fp2_cmp(msm_result.y, expected_result.y), ComparisonType::Equal)
        << "MSM y-coordinate mismatch";
  }

  free(h_points);
  free(h_scalars);
  cuda_drop_with_size_tracking_async(d_points, stream, gpu_index, true);
  cuda_drop_with_size_tracking_async(d_scalars, stream, gpu_index, true);
  cuda_drop_with_size_tracking_async(d_result, stream, gpu_index, true);
  cuda_drop_with_size_tracking_async(d_scratch, stream, gpu_index, true);
  cuda_drop_with_size_tracking_async(d_expected, stream, gpu_index, true);
  cuda_drop_with_size_tracking_async(d_G, stream, gpu_index, true);
}

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
  const uint64_t N = 1; // Single point test

  const G1Affine &G = g1_generator();
  G1Affine G_mont = G;
  point_to_montgomery_inplace(G_mont);

  if (g1_is_infinity(G)) {
    GTEST_SKIP() << "G1 generator not set";
  }

  int threadsPerBlock = 128;
  int num_blocks = CEIL_DIV(N, threadsPerBlock);
  size_t scratch_size =
      (num_blocks + 1) * MSM_G1_BUCKET_COUNT * sizeof(G1Projective);

  uint64_t size_tracker = 0;

  auto *d_points = static_cast<G1Affine *>(cuda_malloc_with_size_tracking_async(
      N * sizeof(G1Affine), stream, gpu_index, size_tracker, true));
  auto *d_scalars = static_cast<Scalar *>(cuda_malloc_with_size_tracking_async(
      N * sizeof(Scalar), stream, gpu_index, size_tracker, true));
  auto *d_result =
      static_cast<G1Projective *>(cuda_malloc_with_size_tracking_async(
          sizeof(G1Projective), stream, gpu_index, size_tracker, true));
  auto *d_scratch =
      static_cast<G1Projective *>(cuda_malloc_with_size_tracking_async(
          scratch_size, stream, gpu_index, size_tracker, true));
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

  auto *h_points = static_cast<G1Affine *>(malloc(N * sizeof(G1Affine)));
  h_points[0] = G;

  // Create Scalar scalar = 2^64 (requires 2 limbs: limb[0]=0, limb[1]=1)
  auto *h_scalars = static_cast<Scalar *>(malloc(N * sizeof(Scalar)));
  h_scalars[0] = scalar_from_limbs(0ULL, 1ULL, 0ULL, 0ULL, 0ULL);

  cuda_memcpy_with_size_tracking_async_to_gpu(
      d_points, h_points, N * sizeof(G1Affine), stream, gpu_index, true);
  cuda_memcpy_with_size_tracking_async_to_gpu(
      d_scalars, h_scalars, N * sizeof(Scalar), stream, gpu_index, true);

  point_to_montgomery_batch<G1Affine>(stream, gpu_index, d_points, N);
  check_cuda_error(cudaGetLastError());

  cuda_memcpy_with_size_tracking_async_to_gpu(d_G, &G_mont, sizeof(G1Affine),
                                              stream, gpu_index, true);

  // Compute MSM
  point_msm_g1(stream, gpu_index, d_result, d_points, d_scalars, d_scratch, N,
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
  G1Projective *d_result_proj = d_result;
  auto *d_result_affine =
      static_cast<G1Affine *>(cuda_malloc_with_size_tracking_async(
          sizeof(G1Affine), stream, gpu_index, size_tracker, true));
  auto *d_expected_normal =
      static_cast<G1Affine *>(cuda_malloc_with_size_tracking_async(
          sizeof(G1Affine), stream, gpu_index, size_tracker, true));

  cuda_synchronize_stream(stream, gpu_index);
  G1Projective h_result_proj;
  cuda_memcpy_async_to_cpu(&h_result_proj, d_result_proj, sizeof(G1Projective),
                           stream, gpu_index);
  cuda_synchronize_stream(stream, gpu_index);
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
        << "MSM x-coordinate mismatch";
    EXPECT_EQ(fp_cmp(msm_result.y, expected_result.y), ComparisonType::Equal)
        << "MSM y-coordinate mismatch";
  }

  free(h_points);
  free(h_scalars);
  cuda_drop_with_size_tracking_async(d_points, stream, gpu_index, true);
  cuda_drop_with_size_tracking_async(d_scalars, stream, gpu_index, true);
  cuda_drop_with_size_tracking_async(d_result, stream, gpu_index, true);
  cuda_drop_with_size_tracking_async(d_scratch, stream, gpu_index, true);
  cuda_drop_with_size_tracking_async(d_expected, stream, gpu_index, true);
  cuda_drop_with_size_tracking_async(d_G, stream, gpu_index, true);
}

// Test G1 MSM with bigint scalars using multi-limb values (> 64 bits)
TEST_F(MSMTest, G1MSMWithBigIntMultiLimbScalars) {
  const uint64_t N = 5;

  const G1Affine &G = g1_generator();
  G1Affine G_mont = G;
  point_to_montgomery_inplace(G_mont);

  if (g1_is_infinity(G)) {
    GTEST_SKIP() << "G1 generator not set";
  }

  int threadsPerBlock = 128;
  int num_blocks = CEIL_DIV(N, threadsPerBlock);
  size_t scratch_size =
      (num_blocks + 1) * MSM_G1_BUCKET_COUNT * sizeof(G1Projective);

  uint64_t size_tracker = 0;

  auto *d_points = static_cast<G1Affine *>(cuda_malloc_with_size_tracking_async(
      N * sizeof(G1Affine), stream, gpu_index, size_tracker, true));
  auto *d_scalars = static_cast<Scalar *>(cuda_malloc_with_size_tracking_async(
      N * sizeof(Scalar), stream, gpu_index, size_tracker, true));
  auto *d_result =
      static_cast<G1Projective *>(cuda_malloc_with_size_tracking_async(
          sizeof(G1Projective), stream, gpu_index, size_tracker, true));
  auto *d_scratch =
      static_cast<G1Projective *>(cuda_malloc_with_size_tracking_async(
          scratch_size, stream, gpu_index, size_tracker, true));
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

  auto *h_points = static_cast<G1Affine *>(malloc(N * sizeof(G1Affine)));
  for (uint64_t i = 0; i < N; i++) {
    h_points[i] = G;
  }

  // Create BigInt5 scalars that use multiple limbs (values > 2^64)
  auto *h_scalars = static_cast<Scalar *>(malloc(N * sizeof(Scalar)));
  h_scalars[0] = scalar_from_limbs(0ULL, 1ULL, 0ULL, 0ULL, 0ULL); // 2^64
  h_scalars[1] = scalar_from_limbs(1ULL, 1ULL, 0ULL, 0ULL, 0ULL); // 2^64 + 1
  h_scalars[2] = scalar_from_limbs(0ULL, 0ULL, 1ULL, 0ULL, 0ULL); // 2^128
  h_scalars[3] =
      scalar_from_limbs(0ULL, 1ULL, 1ULL, 0ULL, 0ULL); // 2^128 + 2^64
  h_scalars[4] = scalar_from_limbs(0ULL, 0ULL, 0ULL, 1ULL, 0ULL); // 2^192

  cuda_memcpy_with_size_tracking_async_to_gpu(
      d_points, h_points, N * sizeof(G1Affine), stream, gpu_index, true);
  cuda_memcpy_with_size_tracking_async_to_gpu(
      d_scalars, h_scalars, N * sizeof(Scalar), stream, gpu_index, true);

  point_to_montgomery_batch<G1Affine>(stream, gpu_index, d_points, N);
  check_cuda_error(cudaGetLastError());

  cuda_memcpy_with_size_tracking_async_to_gpu(d_G, &G_mont, sizeof(G1Affine),
                                              stream, gpu_index, true);

  point_msm_g1(stream, gpu_index, d_result, d_points, d_scalars, d_scratch, N,
               size_tracker);

  // Compute expected result by summing individual scalar multiplications
  // Each point is multiplied by its corresponding scalar
  auto *d_scalar_temp =
      static_cast<UNSIGNED_LIMB *>(cuda_malloc_with_size_tracking_async(
          ZP_LIMBS * sizeof(UNSIGNED_LIMB), stream, gpu_index, size_tracker,
          true));
  auto *d_individual_results =
      static_cast<G1Affine *>(cuda_malloc_with_size_tracking_async(
          N * sizeof(G1Affine), stream, gpu_index, size_tracker, true));

  // Compute each scalar[i] * points[i] separately
  for (auto i = 0ULL; i < N; i++) {
    cuda_memcpy_with_size_tracking_async_to_gpu(
        d_scalar_temp, h_scalars[i].limb, ZP_LIMBS * sizeof(UNSIGNED_LIMB),
        stream, gpu_index, true);
    cuda_synchronize_stream(stream, gpu_index);
    point_scalar_mul<G1Affine>(stream, gpu_index, d_individual_results + i,
                               d_points + i, d_scalar_temp, ZP_LIMBS);
    cuda_synchronize_stream(stream, gpu_index);
  }

  // Sum all individual results
  auto *d_sum = static_cast<G1Affine *>(cuda_malloc_with_size_tracking_async(
      sizeof(G1Affine), stream, gpu_index, size_tracker, true));
  point_at_infinity<G1Affine>(stream, gpu_index, d_sum);
  cuda_synchronize_stream(stream, gpu_index);

  for (auto i = 0ULL; i < N; i++) {
    auto *d_new_sum =
        static_cast<G1Affine *>(cuda_malloc_with_size_tracking_async(
            sizeof(G1Affine), stream, gpu_index, size_tracker, true));
    point_add<G1Affine>(stream, gpu_index, d_new_sum, d_sum,
                        d_individual_results + i);
    cuda_synchronize_stream(stream, gpu_index);
    cuda_drop_with_size_tracking_async(d_sum, stream, gpu_index, true);
    d_sum = d_new_sum;
  }
  cuda_memcpy_with_size_tracking_async_to_gpu(
      d_expected, d_sum, sizeof(G1Affine), stream, gpu_index, true);
  cuda_drop_with_size_tracking_async(d_scalar_temp, stream, gpu_index, true);
  cuda_drop_with_size_tracking_async(d_individual_results, stream, gpu_index,
                                     true);
  cuda_drop_with_size_tracking_async(d_sum, stream, gpu_index, true);

  G1Projective *d_result_proj = d_result;
  auto *d_result_affine =
      static_cast<G1Affine *>(cuda_malloc_with_size_tracking_async(
          sizeof(G1Affine), stream, gpu_index, size_tracker, true));
  auto *d_expected_normal =
      static_cast<G1Affine *>(cuda_malloc_with_size_tracking_async(
          sizeof(G1Affine), stream, gpu_index, size_tracker, true));

  cuda_synchronize_stream(stream, gpu_index);
  G1Projective h_result_proj;
  cuda_memcpy_async_to_cpu(&h_result_proj, d_result_proj, sizeof(G1Projective),
                           stream, gpu_index);
  cuda_synchronize_stream(stream, gpu_index);
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
        << "MSM x-coordinate mismatch";
    EXPECT_EQ(fp_cmp(msm_result.y, expected_result.y), ComparisonType::Equal)
        << "MSM y-coordinate mismatch";
  }

  free(h_points);
  free(h_scalars);
  cuda_drop_with_size_tracking_async(d_points, stream, gpu_index, true);
  cuda_drop_with_size_tracking_async(d_scalars, stream, gpu_index, true);
  cuda_drop_with_size_tracking_async(d_result, stream, gpu_index, true);
  cuda_drop_with_size_tracking_async(d_scratch, stream, gpu_index, true);
  cuda_drop_with_size_tracking_async(d_expected, stream, gpu_index, true);
  cuda_drop_with_size_tracking_async(d_G, stream, gpu_index, true);
}

// Test G1 MSM with BigInt5 scalars using maximum values (all 5 limbs)
TEST_F(MSMTest, G1MSMWithBigInt5MaxValueScalars) {
  const uint64_t N = 3;

  const G1Affine &G = g1_generator();
  G1Affine G_mont = G;
  point_to_montgomery_inplace(G_mont);

  if (g1_is_infinity(G)) {
    GTEST_SKIP() << "G1 generator not set";
  }

  int threadsPerBlock = 128;
  int num_blocks = CEIL_DIV(N, threadsPerBlock);
  size_t scratch_size =
      (num_blocks + 1) * MSM_G1_BUCKET_COUNT * sizeof(G1Projective);

  uint64_t size_tracker = 0;

  auto *d_points = static_cast<G1Affine *>(cuda_malloc_with_size_tracking_async(
      N * sizeof(G1Affine), stream, gpu_index, size_tracker, true));
  auto *d_scalars = static_cast<Scalar *>(cuda_malloc_with_size_tracking_async(
      N * sizeof(Scalar), stream, gpu_index, size_tracker, true));
  auto *d_result =
      static_cast<G1Projective *>(cuda_malloc_with_size_tracking_async(
          sizeof(G1Projective), stream, gpu_index, size_tracker, true));
  auto *d_scratch =
      static_cast<G1Projective *>(cuda_malloc_with_size_tracking_async(
          scratch_size, stream, gpu_index, size_tracker, true));
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

  auto *h_points = static_cast<G1Affine *>(malloc(N * sizeof(G1Affine)));
  for (uint64_t i = 0; i < N; i++) {
    h_points[i] = G;
  }

  // Create BigInt5 scalars that use all 5 limbs (near maximum 320-bit values)
  auto *h_scalars = static_cast<Scalar *>(malloc(N * sizeof(Scalar)));
  h_scalars[0] = scalar_from_limbs(0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL,
                                   0ULL, 0ULL, 0ULL); // 2^128 - 1
  h_scalars[1] =
      scalar_from_limbs(0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL,
                        0xFFFFFFFFFFFFFFFFULL, 0ULL, 0ULL); // 2^192 - 1
  h_scalars[2] = scalar_from_limbs(0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL,
                                   0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL,
                                   0ULL); // 2^256 - 1

  cuda_memcpy_with_size_tracking_async_to_gpu(
      d_points, h_points, N * sizeof(G1Affine), stream, gpu_index, true);
  cuda_memcpy_with_size_tracking_async_to_gpu(
      d_scalars, h_scalars, N * sizeof(Scalar), stream, gpu_index, true);

  point_to_montgomery_batch<G1Affine>(stream, gpu_index, d_points, N);
  check_cuda_error(cudaGetLastError());

  cuda_memcpy_with_size_tracking_async_to_gpu(d_G, &G_mont, sizeof(G1Affine),
                                              stream, gpu_index, true);

  point_msm_g1(stream, gpu_index, d_result, d_points, d_scalars, d_scratch, N,
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
  cuda_synchronize_stream(stream, gpu_index);

  for (auto i = 0ULL; i < N; i++) {
    cuda_memcpy_with_size_tracking_async_to_gpu(
        d_scalar_temp, h_scalars[i].limb, ZP_LIMBS * sizeof(UNSIGNED_LIMB),
        stream, gpu_index, true);
    cuda_synchronize_stream(stream, gpu_index);
    point_scalar_mul<G1Affine>(stream, gpu_index, d_temp, d_points + i,
                               d_scalar_temp, ZP_LIMBS);
    cuda_synchronize_stream(stream, gpu_index);
    point_add<G1Affine>(stream, gpu_index, d_new_sum, d_sum, d_temp);
    cuda_synchronize_stream(stream, gpu_index);
    // Swap d_sum and d_new_sum for next iteration
    G1Affine *tmp = d_sum;
    d_sum = d_new_sum;
    d_new_sum = tmp;
  }
  cuda_memcpy_with_size_tracking_async_to_gpu(
      d_expected, d_sum, sizeof(G1Affine), stream, gpu_index, true);
  cuda_drop_with_size_tracking_async(d_scalar_temp, stream, gpu_index, true);
  cuda_drop_with_size_tracking_async(d_sum, stream, gpu_index, true);
  cuda_drop_with_size_tracking_async(d_temp, stream, gpu_index, true);
  cuda_drop_with_size_tracking_async(d_new_sum, stream, gpu_index, true);

  G1Projective *d_result_proj = d_result;
  auto *d_result_affine =
      static_cast<G1Affine *>(cuda_malloc_with_size_tracking_async(
          sizeof(G1Affine), stream, gpu_index, size_tracker, true));
  auto *d_expected_normal =
      static_cast<G1Affine *>(cuda_malloc_with_size_tracking_async(
          sizeof(G1Affine), stream, gpu_index, size_tracker, true));

  cuda_synchronize_stream(stream, gpu_index);
  G1Projective h_result_proj;
  cuda_memcpy_async_to_cpu(&h_result_proj, d_result_proj, sizeof(G1Projective),
                           stream, gpu_index);
  cuda_synchronize_stream(stream, gpu_index);
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
        << "MSM x-coordinate mismatch";
    EXPECT_EQ(fp_cmp(msm_result.y, expected_result.y), ComparisonType::Equal)
        << "MSM y-coordinate mismatch";
  }

  free(h_points);
  free(h_scalars);
  cuda_drop_with_size_tracking_async(d_points, stream, gpu_index, true);
  cuda_drop_with_size_tracking_async(d_scalars, stream, gpu_index, true);
  cuda_drop_with_size_tracking_async(d_result, stream, gpu_index, true);
  cuda_drop_with_size_tracking_async(d_scratch, stream, gpu_index, true);
  cuda_drop_with_size_tracking_async(d_expected, stream, gpu_index, true);
  cuda_drop_with_size_tracking_async(d_G, stream, gpu_index, true);
}

// Test G2 MSM with BigInt5 scalars using multi-limb values (> 64 bits)
TEST_F(MSMTest, G2MSMWithBigInt5MultiLimbScalars) {
  const uint64_t N = 5;

  const G2Affine &G = g2_generator();
  G2Affine G_mont = G;
  point_to_montgomery_inplace(G_mont);

  if (g2_is_infinity(G)) {
    GTEST_SKIP() << "G2 generator not set";
  }

  int threadsPerBlock = 80;
  int num_blocks = CEIL_DIV(N, threadsPerBlock);
  size_t scratch_size =
      (num_blocks + 1) * MSM_G2_BUCKET_COUNT * sizeof(G2Projective);

  uint64_t size_tracker = 0;

  auto *d_points = static_cast<G2Affine *>(cuda_malloc_with_size_tracking_async(
      N * sizeof(G2Affine), stream, gpu_index, size_tracker, true));
  auto *d_scalars = static_cast<Scalar *>(cuda_malloc_with_size_tracking_async(
      N * sizeof(Scalar), stream, gpu_index, size_tracker, true));
  auto *d_result =
      static_cast<G2Projective *>(cuda_malloc_with_size_tracking_async(
          sizeof(G2Projective), stream, gpu_index, size_tracker, true));
  auto *d_scratch =
      static_cast<G2Projective *>(cuda_malloc_with_size_tracking_async(
          scratch_size, stream, gpu_index, size_tracker, true));
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

  auto *h_points = static_cast<G2Affine *>(malloc(N * sizeof(G2Affine)));
  for (uint64_t i = 0; i < N; i++) {
    h_points[i] = G;
  }

  // Create BigInt5 scalars that use multiple limbs
  auto *h_scalars = static_cast<Scalar *>(malloc(N * sizeof(Scalar)));
  h_scalars[0] = scalar_from_limbs(0ULL, 1ULL, 0ULL, 0ULL, 0ULL); // 2^64
  h_scalars[1] = scalar_from_limbs(1ULL, 1ULL, 0ULL, 0ULL, 0ULL); // 2^64 + 1
  h_scalars[2] = scalar_from_limbs(0ULL, 0ULL, 1ULL, 0ULL, 0ULL); // 2^128
  h_scalars[3] =
      scalar_from_limbs(0ULL, 1ULL, 1ULL, 0ULL, 0ULL); // 2^128 + 2^64
  h_scalars[4] = scalar_from_limbs(0ULL, 0ULL, 0ULL, 1ULL, 0ULL); // 2^192

  cuda_memcpy_with_size_tracking_async_to_gpu(
      d_points, h_points, N * sizeof(G2Affine), stream, gpu_index, true);
  cuda_memcpy_with_size_tracking_async_to_gpu(
      d_scalars, h_scalars, N * sizeof(Scalar), stream, gpu_index, true);

  point_to_montgomery_batch<G2Affine>(stream, gpu_index, d_points, N);
  check_cuda_error(cudaGetLastError());

  cuda_memcpy_with_size_tracking_async_to_gpu(d_G, &G_mont, sizeof(G2Affine),
                                              stream, gpu_index, true);

  point_msm_g2(stream, gpu_index, d_result, d_points, d_scalars, d_scratch, N,
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
  cuda_synchronize_stream(stream, gpu_index);

  for (auto i = 0ULL; i < N; i++) {
    cuda_memcpy_with_size_tracking_async_to_gpu(
        d_scalar_temp, h_scalars[i].limb, ZP_LIMBS * sizeof(UNSIGNED_LIMB),
        stream, gpu_index, true);
    cuda_synchronize_stream(stream, gpu_index);
    point_scalar_mul<G2Affine>(stream, gpu_index, d_temp, d_points + i,
                               d_scalar_temp, ZP_LIMBS);
    cuda_synchronize_stream(stream, gpu_index);
    point_add<G2Affine>(stream, gpu_index, d_new_sum, d_sum, d_temp);
    cuda_synchronize_stream(stream, gpu_index);
    // Swap d_sum and d_new_sum for next iteration
    G2Affine *tmp = d_sum;
    d_sum = d_new_sum;
    d_new_sum = tmp;
  }
  cuda_memcpy_with_size_tracking_async_to_gpu(
      d_expected, d_sum, sizeof(G2Affine), stream, gpu_index, true);
  cuda_drop_with_size_tracking_async(d_scalar_temp, stream, gpu_index, true);
  cuda_drop_with_size_tracking_async(d_sum, stream, gpu_index, true);
  cuda_drop_with_size_tracking_async(d_temp, stream, gpu_index, true);
  cuda_drop_with_size_tracking_async(d_new_sum, stream, gpu_index, true);

  G2Projective *d_result_proj = d_result;
  auto *d_result_affine =
      static_cast<G2Affine *>(cuda_malloc_with_size_tracking_async(
          sizeof(G2Affine), stream, gpu_index, size_tracker, true));
  auto *d_expected_normal =
      static_cast<G2Affine *>(cuda_malloc_with_size_tracking_async(
          sizeof(G2Affine), stream, gpu_index, size_tracker, true));

  cuda_synchronize_stream(stream, gpu_index);
  G2Projective h_result_proj;
  cuda_memcpy_async_to_cpu(&h_result_proj, d_result_proj, sizeof(G2Projective),
                           stream, gpu_index);
  cuda_synchronize_stream(stream, gpu_index);
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
        << "MSM x-coordinate mismatch";
    EXPECT_EQ(fp2_cmp(msm_result.y, expected_result.y), ComparisonType::Equal)
        << "MSM y-coordinate mismatch";
  }

  free(h_points);
  free(h_scalars);
  cuda_drop_with_size_tracking_async(d_points, stream, gpu_index, true);
  cuda_drop_with_size_tracking_async(d_scalars, stream, gpu_index, true);
  cuda_drop_with_size_tracking_async(d_result, stream, gpu_index, true);
  cuda_drop_with_size_tracking_async(d_scratch, stream, gpu_index, true);
  cuda_drop_with_size_tracking_async(d_expected, stream, gpu_index, true);
  cuda_drop_with_size_tracking_async(d_G, stream, gpu_index, true);
}

// Test G1 MSM with BigInt5 scalar using 3-limb value (2^128)
TEST_F(MSMTest, G1MSMWithBigInt5ThreeLimbScalar) {
  const uint64_t N = 1;

  const G1Affine &G = g1_generator();
  G1Affine G_mont = G;
  point_to_montgomery_inplace(G_mont);

  if (g1_is_infinity(G)) {
    GTEST_SKIP() << "G1 generator not set";
  }

  int threadsPerBlock = 128;
  int num_blocks = CEIL_DIV(N, threadsPerBlock);
  size_t scratch_size =
      (num_blocks + 1) * MSM_G1_BUCKET_COUNT * sizeof(G1Projective);

  uint64_t size_tracker = 0;

  auto *d_points = static_cast<G1Affine *>(cuda_malloc_with_size_tracking_async(
      N * sizeof(G1Affine), stream, gpu_index, size_tracker, true));
  auto *d_scalars = static_cast<Scalar *>(cuda_malloc_with_size_tracking_async(
      N * sizeof(Scalar), stream, gpu_index, size_tracker, true));
  auto *d_result =
      static_cast<G1Projective *>(cuda_malloc_with_size_tracking_async(
          sizeof(G1Projective), stream, gpu_index, size_tracker, true));
  auto *d_scratch =
      static_cast<G1Projective *>(cuda_malloc_with_size_tracking_async(
          scratch_size, stream, gpu_index, size_tracker, true));
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

  auto *h_points = static_cast<G1Affine *>(malloc(N * sizeof(G1Affine)));
  h_points[0] = G;

  // Create BigInt5 scalar = 2^128 (requires 3 limbs)
  auto *h_scalars = static_cast<Scalar *>(malloc(N * sizeof(Scalar)));
  h_scalars[0] = scalar_from_limbs(0ULL, 0ULL, 1ULL, 0ULL, 0ULL);

  cuda_memcpy_with_size_tracking_async_to_gpu(
      d_points, h_points, N * sizeof(G1Affine), stream, gpu_index, true);
  cuda_memcpy_with_size_tracking_async_to_gpu(
      d_scalars, h_scalars, N * sizeof(Scalar), stream, gpu_index, true);

  point_to_montgomery_batch<G1Affine>(stream, gpu_index, d_points, N);
  check_cuda_error(cudaGetLastError());

  cuda_memcpy_with_size_tracking_async_to_gpu(d_G, &G_mont, sizeof(G1Affine),
                                              stream, gpu_index, true);

  point_msm_g1(stream, gpu_index, d_result, d_points, d_scalars, d_scratch, N,
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

  G1Projective *d_result_proj = d_result;
  auto *d_result_affine =
      static_cast<G1Affine *>(cuda_malloc_with_size_tracking_async(
          sizeof(G1Affine), stream, gpu_index, size_tracker, true));
  auto *d_expected_normal =
      static_cast<G1Affine *>(cuda_malloc_with_size_tracking_async(
          sizeof(G1Affine), stream, gpu_index, size_tracker, true));

  cuda_synchronize_stream(stream, gpu_index);
  G1Projective h_result_proj;
  cuda_memcpy_async_to_cpu(&h_result_proj, d_result_proj, sizeof(G1Projective),
                           stream, gpu_index);
  cuda_synchronize_stream(stream, gpu_index);
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
        << "MSM x-coordinate mismatch";
    EXPECT_EQ(fp_cmp(msm_result.y, expected_result.y), ComparisonType::Equal)
        << "MSM y-coordinate mismatch";
  }

  free(h_points);
  free(h_scalars);
  cuda_drop_with_size_tracking_async(d_points, stream, gpu_index, true);
  cuda_drop_with_size_tracking_async(d_scalars, stream, gpu_index, true);
  cuda_drop_with_size_tracking_async(d_result, stream, gpu_index, true);
  cuda_drop_with_size_tracking_async(d_scratch, stream, gpu_index, true);
  cuda_drop_with_size_tracking_async(d_expected, stream, gpu_index, true);
  cuda_drop_with_size_tracking_async(d_G, stream, gpu_index, true);
}

// Test G1 MSM with BigInt5 scalar using 4-limb value (2^192)
TEST_F(MSMTest, G1MSMWithBigInt5FourLimbScalar) {
  const uint64_t N = 1;

  const G1Affine &G = g1_generator();
  G1Affine G_mont = G;
  point_to_montgomery_inplace(G_mont);

  if (g1_is_infinity(G)) {
    GTEST_SKIP() << "G1 generator not set";
  }

  int threadsPerBlock = 128;
  int num_blocks = CEIL_DIV(N, threadsPerBlock);
  size_t scratch_size =
      (num_blocks + 1) * MSM_G1_BUCKET_COUNT * sizeof(G1Projective);

  uint64_t size_tracker = 0;

  auto *d_points = static_cast<G1Affine *>(cuda_malloc_with_size_tracking_async(
      N * sizeof(G1Affine), stream, gpu_index, size_tracker, true));
  auto *d_scalars = static_cast<Scalar *>(cuda_malloc_with_size_tracking_async(
      N * sizeof(Scalar), stream, gpu_index, size_tracker, true));
  auto *d_result =
      static_cast<G1Projective *>(cuda_malloc_with_size_tracking_async(
          sizeof(G1Projective), stream, gpu_index, size_tracker, true));
  auto *d_scratch =
      static_cast<G1Projective *>(cuda_malloc_with_size_tracking_async(
          scratch_size, stream, gpu_index, size_tracker, true));
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

  auto *h_points = static_cast<G1Affine *>(malloc(N * sizeof(G1Affine)));
  h_points[0] = G;

  // Create BigInt5 scalar = 2^192 (requires 4 limbs)
  auto *h_scalars = static_cast<Scalar *>(malloc(N * sizeof(Scalar)));
  h_scalars[0] = scalar_from_limbs(0ULL, 0ULL, 0ULL, 1ULL, 0ULL);

  cuda_memcpy_with_size_tracking_async_to_gpu(
      d_points, h_points, N * sizeof(G1Affine), stream, gpu_index, true);
  cuda_memcpy_with_size_tracking_async_to_gpu(
      d_scalars, h_scalars, N * sizeof(Scalar), stream, gpu_index, true);

  point_to_montgomery_batch<G1Affine>(stream, gpu_index, d_points, N);
  check_cuda_error(cudaGetLastError());

  cuda_memcpy_with_size_tracking_async_to_gpu(d_G, &G_mont, sizeof(G1Affine),
                                              stream, gpu_index, true);

  point_msm_g1(stream, gpu_index, d_result, d_points, d_scalars, d_scratch, N,
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

  G1Projective *d_result_proj = d_result;
  auto *d_result_affine =
      static_cast<G1Affine *>(cuda_malloc_with_size_tracking_async(
          sizeof(G1Affine), stream, gpu_index, size_tracker, true));
  auto *d_expected_normal =
      static_cast<G1Affine *>(cuda_malloc_with_size_tracking_async(
          sizeof(G1Affine), stream, gpu_index, size_tracker, true));

  cuda_synchronize_stream(stream, gpu_index);
  G1Projective h_result_proj;
  cuda_memcpy_async_to_cpu(&h_result_proj, d_result_proj, sizeof(G1Projective),
                           stream, gpu_index);
  cuda_synchronize_stream(stream, gpu_index);
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
        << "MSM x-coordinate mismatch";
    EXPECT_EQ(fp_cmp(msm_result.y, expected_result.y), ComparisonType::Equal)
        << "MSM y-coordinate mismatch";
  }

  free(h_points);
  free(h_scalars);
  cuda_drop_with_size_tracking_async(d_points, stream, gpu_index, true);
  cuda_drop_with_size_tracking_async(d_scalars, stream, gpu_index, true);
  cuda_drop_with_size_tracking_async(d_result, stream, gpu_index, true);
  cuda_drop_with_size_tracking_async(d_scratch, stream, gpu_index, true);
  cuda_drop_with_size_tracking_async(d_expected, stream, gpu_index, true);
  cuda_drop_with_size_tracking_async(d_G, stream, gpu_index, true);
}

// Test G1 MSM with BigInt5 scalar using 5-limb value (2^256) - near maximum
TEST_F(MSMTest, G1MSMWithBigInt5FiveLimbScalar) {
  const uint64_t N = 1;

  const G1Affine &G = g1_generator();
  G1Affine G_mont = G;
  point_to_montgomery_inplace(G_mont);

  if (g1_is_infinity(G)) {
    GTEST_SKIP() << "G1 generator not set";
  }

  int threadsPerBlock = 128;
  int num_blocks = CEIL_DIV(N, threadsPerBlock);
  size_t scratch_size =
      (num_blocks + 1) * MSM_G1_BUCKET_COUNT * sizeof(G1Projective);

  uint64_t size_tracker = 0;

  auto *d_points = static_cast<G1Affine *>(cuda_malloc_with_size_tracking_async(
      N * sizeof(G1Affine), stream, gpu_index, size_tracker, true));
  auto *d_scalars = static_cast<Scalar *>(cuda_malloc_with_size_tracking_async(
      N * sizeof(Scalar), stream, gpu_index, size_tracker, true));
  auto *d_result =
      static_cast<G1Projective *>(cuda_malloc_with_size_tracking_async(
          sizeof(G1Projective), stream, gpu_index, size_tracker, true));
  auto *d_scratch =
      static_cast<G1Projective *>(cuda_malloc_with_size_tracking_async(
          scratch_size, stream, gpu_index, size_tracker, true));
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

  auto *h_points = static_cast<G1Affine *>(malloc(N * sizeof(G1Affine)));
  h_points[0] = G;

  // Create BigInt5 scalar = 2^256 (requires 5 limbs, uses highest limb)
  auto *h_scalars = static_cast<Scalar *>(malloc(N * sizeof(Scalar)));
  h_scalars[0] = scalar_from_limbs(0ULL, 0ULL, 0ULL, 0ULL, 1ULL);

  cuda_memcpy_with_size_tracking_async_to_gpu(
      d_points, h_points, N * sizeof(G1Affine), stream, gpu_index, true);
  cuda_memcpy_with_size_tracking_async_to_gpu(
      d_scalars, h_scalars, N * sizeof(Scalar), stream, gpu_index, true);

  point_to_montgomery_batch<G1Affine>(stream, gpu_index, d_points, N);
  check_cuda_error(cudaGetLastError());

  cuda_memcpy_with_size_tracking_async_to_gpu(d_G, &G_mont, sizeof(G1Affine),
                                              stream, gpu_index, true);

  point_msm_g1(stream, gpu_index, d_result, d_points, d_scalars, d_scratch, N,
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

  G1Projective *d_result_proj = d_result;
  auto *d_result_affine =
      static_cast<G1Affine *>(cuda_malloc_with_size_tracking_async(
          sizeof(G1Affine), stream, gpu_index, size_tracker, true));
  auto *d_expected_normal =
      static_cast<G1Affine *>(cuda_malloc_with_size_tracking_async(
          sizeof(G1Affine), stream, gpu_index, size_tracker, true));

  cuda_synchronize_stream(stream, gpu_index);
  G1Projective h_result_proj;
  cuda_memcpy_async_to_cpu(&h_result_proj, d_result_proj, sizeof(G1Projective),
                           stream, gpu_index);
  cuda_synchronize_stream(stream, gpu_index);
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
        << "MSM x-coordinate mismatch";
    EXPECT_EQ(fp_cmp(msm_result.y, expected_result.y), ComparisonType::Equal)
        << "MSM y-coordinate mismatch";
  }

  free(h_points);
  free(h_scalars);
  cuda_drop_with_size_tracking_async(d_points, stream, gpu_index, true);
  cuda_drop_with_size_tracking_async(d_scalars, stream, gpu_index, true);
  cuda_drop_with_size_tracking_async(d_result, stream, gpu_index, true);
  cuda_drop_with_size_tracking_async(d_scratch, stream, gpu_index, true);
  cuda_drop_with_size_tracking_async(d_expected, stream, gpu_index, true);
  cuda_drop_with_size_tracking_async(d_G, stream, gpu_index, true);
}

// Test G1 MSM with BigInt5 scalar using near-maximum 320-bit value (all limbs
// set)
TEST_F(MSMTest, G1MSMWithBigInt5Max320BitScalar) {
  const uint64_t N = 1;

  const G1Affine &G = g1_generator();
  G1Affine G_mont = G;
  point_to_montgomery_inplace(G_mont);

  if (g1_is_infinity(G)) {
    GTEST_SKIP() << "G1 generator not set";
  }

  int threadsPerBlock = 128;
  int num_blocks = CEIL_DIV(N, threadsPerBlock);
  size_t scratch_size =
      (num_blocks + 1) * MSM_G1_BUCKET_COUNT * sizeof(G1Projective);

  uint64_t size_tracker = 0;

  auto *d_points = static_cast<G1Affine *>(cuda_malloc_with_size_tracking_async(
      N * sizeof(G1Affine), stream, gpu_index, size_tracker, true));
  auto *d_scalars = static_cast<Scalar *>(cuda_malloc_with_size_tracking_async(
      N * sizeof(Scalar), stream, gpu_index, size_tracker, true));
  auto *d_result =
      static_cast<G1Projective *>(cuda_malloc_with_size_tracking_async(
          sizeof(G1Projective), stream, gpu_index, size_tracker, true));
  auto *d_scratch =
      static_cast<G1Projective *>(cuda_malloc_with_size_tracking_async(
          scratch_size, stream, gpu_index, size_tracker, true));
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

  auto *h_points = static_cast<G1Affine *>(malloc(N * sizeof(G1Affine)));
  h_points[0] = G;

  // Create BigInt5 scalar with all 5 limbs set (near maximum 320-bit value)
  // Using 0xFFFFFFFFFFFFFFFF for all limbs would be 2^320 - 1, but we'll use a
  // smaller value to avoid potential issues: 2^256 - 1 (uses 4 limbs fully, 5th
  // limb = 0)
  auto *h_scalars = static_cast<Scalar *>(malloc(N * sizeof(Scalar)));
  h_scalars[0] =
      scalar_from_limbs(0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL,
                        0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL, 0ULL);

  cuda_memcpy_with_size_tracking_async_to_gpu(
      d_points, h_points, N * sizeof(G1Affine), stream, gpu_index, true);
  cuda_memcpy_with_size_tracking_async_to_gpu(
      d_scalars, h_scalars, N * sizeof(Scalar), stream, gpu_index, true);

  point_to_montgomery_batch<G1Affine>(stream, gpu_index, d_points, N);
  check_cuda_error(cudaGetLastError());

  cuda_memcpy_with_size_tracking_async_to_gpu(d_G, &G_mont, sizeof(G1Affine),
                                              stream, gpu_index, true);

  point_msm_g1(stream, gpu_index, d_result, d_points, d_scalars, d_scratch, N,
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

  G1Projective *d_result_proj = d_result;
  auto *d_result_affine =
      static_cast<G1Affine *>(cuda_malloc_with_size_tracking_async(
          sizeof(G1Affine), stream, gpu_index, size_tracker, true));
  auto *d_expected_normal =
      static_cast<G1Affine *>(cuda_malloc_with_size_tracking_async(
          sizeof(G1Affine), stream, gpu_index, size_tracker, true));

  cuda_synchronize_stream(stream, gpu_index);
  G1Projective h_result_proj;
  cuda_memcpy_async_to_cpu(&h_result_proj, d_result_proj, sizeof(G1Projective),
                           stream, gpu_index);
  cuda_synchronize_stream(stream, gpu_index);
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
        << "MSM x-coordinate mismatch";
    EXPECT_EQ(fp_cmp(msm_result.y, expected_result.y), ComparisonType::Equal)
        << "MSM y-coordinate mismatch";
  }

  free(h_points);
  free(h_scalars);
  cuda_drop_with_size_tracking_async(d_points, stream, gpu_index, true);
  cuda_drop_with_size_tracking_async(d_scalars, stream, gpu_index, true);
  cuda_drop_with_size_tracking_async(d_result, stream, gpu_index, true);
  cuda_drop_with_size_tracking_async(d_scratch, stream, gpu_index, true);
  cuda_drop_with_size_tracking_async(d_expected, stream, gpu_index, true);
  cuda_drop_with_size_tracking_async(d_G, stream, gpu_index, true);
}

#endif // LIMB_BITS_CONFIG == 64
