#include "curve.h"
#include "device.h"
#include "fp.h"
#include <cstdint>
#include <cstring>
#include <cuda_runtime.h>
#include <gtest/gtest.h>
#include <iomanip>
#include <iostream>
#include <string>

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

// Helper function to print Fp value as decimal scalar
void print_fp(const char *label, const Fp &val) {
  std::string decimal = fp_to_decimal_string(val);
  std::cout << label << ": " << decimal << std::endl;
}

// Test fixture for point operation tests
class PointOpsTest : public ::testing::Test {
protected:
  void SetUp() override {
    // Initialize CUDA
    if (!cuda_is_available()) {
      GTEST_SKIP() << "CUDA not available";
    }

    gpu_index = 0;
    stream = cuda_create_stream(gpu_index);
  }

  void TearDown() override {
    if (stream != nullptr) {
      cuda_destroy_stream(stream, gpu_index);
    }
  }

  uint32_t gpu_index;
  cudaStream_t stream;

  // Helper to check if a point is on the curve y^2 = x^3 + b
  bool is_on_curve(const G1Affine &point) {
    if (point.infinity) {
      return true; // Point at infinity is on the curve
    }

    // Convert from Montgomery form to normal form for verification
    Fp x_normal, y_normal;
    fp_from_montgomery(x_normal, point.x);
    fp_from_montgomery(y_normal, point.y);

    // Compute y^2 (operator* returns Montgomery form, convert to normal)
    Fp y_squared_mont = y_normal * y_normal;
    Fp y_squared;
    fp_from_montgomery(y_squared, y_squared_mont);

    // Compute x^3 (operator* returns Montgomery form, convert to normal)
    Fp x_squared_mont = x_normal * x_normal;
    Fp x_squared;
    fp_from_montgomery(x_squared, x_squared_mont);
    Fp x_cubed_mont = x_squared * x_normal;
    Fp x_cubed;
    fp_from_montgomery(x_cubed, x_cubed_mont);

    // Compute x^3 + b (b = 1)
    Fp b;
    fp_zero(b);
    b.limb[0] = 1;
    Fp x_cubed_plus_b = x_cubed + b;

    // Check if y^2 == x^3 + b
    bool on_curve = y_squared == x_cubed_plus_b;

    // Debug output if not on curve
    if (!on_curve) {
      std::cout << "WARNING: Point is NOT on the curve!" << std::endl;
      print_fp("  y^2", y_squared);
      print_fp("  x^3 + b", x_cubed_plus_b);
    }

    return on_curve;
  }

  // Helper to print point (using decimal format like test_msm.cu)
  void print_point(const char *label, const G1Affine &point) {
    std::cout << label << ":" << std::endl;
    if (point.infinity) {
      std::cout << "  Infinity: true" << std::endl;
    } else {
      std::cout << "  Infinity: false" << std::endl;
      print_fp("  X", point.x);
      print_fp("  Y", point.y);
    }
  }
};

// Test: Point doubling (2*G)
TEST_F(PointOpsTest, G1PointDouble) {
  const G1Affine &G = g1_generator();
  if (g1_is_infinity(G)) {
    GTEST_SKIP() << "G1 generator not set";
  }

  uint64_t size_tracker = 0;

  // Convert to Montgomery form
  G1Affine G_mont = G;
  point_to_montgomery_inplace(G_mont);

  // Allocate device memory
  auto *d_G = static_cast<G1Affine *>(cuda_malloc_with_size_tracking_async(
      sizeof(G1Affine), stream, gpu_index, size_tracker, true));
  auto *d_2G = static_cast<G1Affine *>(cuda_malloc_with_size_tracking_async(
      sizeof(G1Affine), stream, gpu_index, size_tracker, true));

  cuda_memcpy_with_size_tracking_async_to_gpu(d_G, &G_mont, sizeof(G1Affine),
                                              stream, gpu_index, true);

  // Double the point
  point_double<G1Affine>(stream, gpu_index, d_2G, d_G);

  // Copy result back
  G1Affine result;
  cuda_memcpy_async_to_cpu(&result, d_2G, sizeof(G1Affine), stream, gpu_index);
  cuda_synchronize_stream(stream, gpu_index);

  // Verify result is not infinity
  EXPECT_FALSE(result.infinity) << "2*G should not be infinity";

  // Verify result is on the curve
  bool on_curve = is_on_curve(result);
  if (!on_curve) {
    // Convert to normal form for comparison with Python
    point_from_montgomery<G1Affine>(stream, gpu_index, d_2G, d_2G);
    G1Affine result_normal;
    cuda_memcpy_async_to_cpu(&result_normal, d_2G, sizeof(G1Affine), stream,
                             gpu_index);
    cuda_synchronize_stream(stream, gpu_index);
    print_point("Output 2*G (normal)", result_normal);
  }
  EXPECT_TRUE(on_curve) << "2*G is not on the curve!";

  cuda_drop_with_size_tracking_async(d_G, stream, gpu_index, true);
  cuda_drop_with_size_tracking_async(d_2G, stream, gpu_index, true);
}

// Test: Point addition (G + 2*G = 3*G)
TEST_F(PointOpsTest, G1PointAdd) {
  const G1Affine &G = g1_generator();
  if (g1_is_infinity(G)) {
    GTEST_SKIP() << "G1 generator not set";
  }

  uint64_t size_tracker = 0;

  // Convert to Montgomery form
  G1Affine G_mont = G;
  point_to_montgomery_inplace(G_mont);

  // Allocate device memory
  auto *d_G = static_cast<G1Affine *>(cuda_malloc_with_size_tracking_async(
      sizeof(G1Affine), stream, gpu_index, size_tracker, true));
  auto *d_2G = static_cast<G1Affine *>(cuda_malloc_with_size_tracking_async(
      sizeof(G1Affine), stream, gpu_index, size_tracker, true));
  auto *d_3G = static_cast<G1Affine *>(cuda_malloc_with_size_tracking_async(
      sizeof(G1Affine), stream, gpu_index, size_tracker, true));

  cuda_memcpy_with_size_tracking_async_to_gpu(d_G, &G_mont, sizeof(G1Affine),
                                              stream, gpu_index, true);

  // Compute 2*G
  point_double<G1Affine>(stream, gpu_index, d_2G, d_G);

  // Compute G + 2*G = 3*G
  point_add<G1Affine>(stream, gpu_index, d_3G, d_G, d_2G);

  // Copy result back
  G1Affine result;
  cuda_memcpy_async_to_cpu(&result, d_3G, sizeof(G1Affine), stream, gpu_index);
  cuda_synchronize_stream(stream, gpu_index);

  // Verify result is not infinity
  EXPECT_FALSE(result.infinity) << "3*G should not be infinity";

  // Verify result is on the curve
  EXPECT_TRUE(is_on_curve(result)) << "3*G is not on the curve!";

  cuda_drop_with_size_tracking_async(d_G, stream, gpu_index, true);
  cuda_drop_with_size_tracking_async(d_2G, stream, gpu_index, true);
  cuda_drop_with_size_tracking_async(d_3G, stream, gpu_index, true);
}

// Test: Adding to infinity (INF + G = G)
TEST_F(PointOpsTest, G1AddToInfinity) {
  const G1Affine &G = g1_generator();
  if (g1_is_infinity(G)) {
    GTEST_SKIP() << "G1 generator not set";
  }

  uint64_t size_tracker = 0;

  // Convert to Montgomery form
  G1Affine G_mont = G;
  point_to_montgomery_inplace(G_mont);

  // Create point at infinity
  G1Affine inf;
  g1_point_at_infinity(inf);

  // Allocate device memory
  auto *d_inf = static_cast<G1Affine *>(cuda_malloc_with_size_tracking_async(
      sizeof(G1Affine), stream, gpu_index, size_tracker, true));
  auto *d_G = static_cast<G1Affine *>(cuda_malloc_with_size_tracking_async(
      sizeof(G1Affine), stream, gpu_index, size_tracker, true));
  auto *d_result = static_cast<G1Affine *>(cuda_malloc_with_size_tracking_async(
      sizeof(G1Affine), stream, gpu_index, size_tracker, true));

  cuda_memcpy_with_size_tracking_async_to_gpu(d_inf, &inf, sizeof(G1Affine),
                                              stream, gpu_index, true);
  cuda_memcpy_with_size_tracking_async_to_gpu(d_G, &G_mont, sizeof(G1Affine),
                                              stream, gpu_index, true);

  // Compute INF + G
  point_add<G1Affine>(stream, gpu_index, d_result, d_inf, d_G);

  // Copy result back
  G1Affine result;
  cuda_memcpy_async_to_cpu(&result, d_result, sizeof(G1Affine), stream,
                           gpu_index);
  cuda_synchronize_stream(stream, gpu_index);

  // Verify result equals G
  EXPECT_FALSE(result.infinity) << "INF + G should equal G (not infinity)";

  // Convert to normal form for comparison
  point_from_montgomery<G1Affine>(stream, gpu_index, d_result, d_result);
  cuda_synchronize_stream(stream, gpu_index);
  G1Affine result_normal;
  cuda_memcpy_async_to_cpu(&result_normal, d_result, sizeof(G1Affine), stream,
                           gpu_index);
  cuda_synchronize_stream(stream, gpu_index);

  // Compare with original G
  EXPECT_EQ(fp_cmp(result_normal.x, G.x), ComparisonType::Equal)
      << "INF + G should equal G (x-coordinate mismatch)";
  EXPECT_EQ(fp_cmp(result_normal.y, G.y), ComparisonType::Equal)
      << "INF + G should equal G (y-coordinate mismatch)";

  cuda_drop_with_size_tracking_async(d_inf, stream, gpu_index, true);
  cuda_drop_with_size_tracking_async(d_G, stream, gpu_index, true);
  cuda_drop_with_size_tracking_async(d_result, stream, gpu_index, true);
}

// Test: Scalar multiplication 1*G = G
TEST_F(PointOpsTest, G1ScalarMul1) {
  const G1Affine &G = g1_generator();
  if (g1_is_infinity(G)) {
    GTEST_SKIP() << "G1 generator not set";
  }

  uint64_t size_tracker = 0;

  // Convert to Montgomery form
  G1Affine G_mont = G;
  point_to_montgomery_inplace(G_mont);

  // Allocate device memory
  auto *d_G = static_cast<G1Affine *>(cuda_malloc_with_size_tracking_async(
      sizeof(G1Affine), stream, gpu_index, size_tracker, true));
  auto *d_result = static_cast<G1Affine *>(cuda_malloc_with_size_tracking_async(
      sizeof(G1Affine), stream, gpu_index, size_tracker, true));

  cuda_memcpy_with_size_tracking_async_to_gpu(d_G, &G_mont, sizeof(G1Affine),
                                              stream, gpu_index, true);

  // Compute 1*G
  single_point_scalar_mul<G1Affine>(stream, gpu_index, d_result, d_G, 1);

  // Copy result back
  G1Affine result;
  cuda_memcpy_async_to_cpu(&result, d_result, sizeof(G1Affine), stream,
                           gpu_index);
  cuda_synchronize_stream(stream, gpu_index);

  // Verify result is not infinity
  EXPECT_FALSE(result.infinity) << "1*G should not be infinity";

  // Verify result is on the curve
  EXPECT_TRUE(is_on_curve(result)) << "1*G is not on the curve!";

  // Convert to normal form for comparison
  point_from_montgomery<G1Affine>(stream, gpu_index, d_result, d_result);
  cuda_synchronize_stream(stream, gpu_index);
  G1Affine result_normal;
  cuda_memcpy_async_to_cpu(&result_normal, d_result, sizeof(G1Affine), stream,
                           gpu_index);
  cuda_synchronize_stream(stream, gpu_index);

  // Compare with original G
  EXPECT_EQ(fp_cmp(result_normal.x, G.x), ComparisonType::Equal)
      << "1*G should equal G (x-coordinate mismatch)";
  EXPECT_EQ(fp_cmp(result_normal.y, G.y), ComparisonType::Equal)
      << "1*G should equal G (y-coordinate mismatch)";

  cuda_drop_with_size_tracking_async(d_G, stream, gpu_index, true);
  cuda_drop_with_size_tracking_async(d_result, stream, gpu_index, true);
}

// Test: Scalar multiplication 2*G (using scalar mul)
TEST_F(PointOpsTest, G1ScalarMul2) {
  const G1Affine &G = g1_generator();
  if (g1_is_infinity(G)) {
    GTEST_SKIP() << "G1 generator not set";
  }

  uint64_t size_tracker = 0;

  // Convert to Montgomery form
  G1Affine G_mont = G;
  point_to_montgomery_inplace(G_mont);

  // Allocate device memory
  auto *d_G = static_cast<G1Affine *>(cuda_malloc_with_size_tracking_async(
      sizeof(G1Affine), stream, gpu_index, size_tracker, true));
  auto *d_result_scalar =
      static_cast<G1Affine *>(cuda_malloc_with_size_tracking_async(
          sizeof(G1Affine), stream, gpu_index, size_tracker, true));
  auto *d_result_double =
      static_cast<G1Affine *>(cuda_malloc_with_size_tracking_async(
          sizeof(G1Affine), stream, gpu_index, size_tracker, true));

  cuda_memcpy_with_size_tracking_async_to_gpu(d_G, &G_mont, sizeof(G1Affine),
                                              stream, gpu_index, true);

  // Compute 2*G using scalar multiplication
  single_point_scalar_mul<G1Affine>(stream, gpu_index, d_result_scalar, d_G, 2);

  // Compute 2*G using point doubling
  point_double<G1Affine>(stream, gpu_index, d_result_double, d_G);

  // Copy results back
  G1Affine result_scalar, result_double;
  cuda_memcpy_async_to_cpu(&result_scalar, d_result_scalar, sizeof(G1Affine),
                           stream, gpu_index);
  cuda_memcpy_async_to_cpu(&result_double, d_result_double, sizeof(G1Affine),
                           stream, gpu_index);
  cuda_synchronize_stream(stream, gpu_index);

  // Verify both are on the curve
  EXPECT_TRUE(is_on_curve(result_scalar))
      << "2*G (scalar mul) is not on the curve!";
  EXPECT_TRUE(is_on_curve(result_double))
      << "2*G (doubling) is not on the curve!";

  // Convert to normal form for comparison
  point_from_montgomery<G1Affine>(stream, gpu_index, d_result_scalar,
                                  d_result_scalar);
  point_from_montgomery<G1Affine>(stream, gpu_index, d_result_double,
                                  d_result_double);
  cuda_synchronize_stream(stream, gpu_index);
  G1Affine result_scalar_normal, result_double_normal;
  cuda_memcpy_async_to_cpu(&result_scalar_normal, d_result_scalar,
                           sizeof(G1Affine), stream, gpu_index);
  cuda_memcpy_async_to_cpu(&result_double_normal, d_result_double,
                           sizeof(G1Affine), stream, gpu_index);
  cuda_synchronize_stream(stream, gpu_index);

  // Compare results
  EXPECT_EQ(fp_cmp(result_scalar_normal.x, result_double_normal.x),
            ComparisonType::Equal)
      << "2*G (scalar mul) != 2*G (doubling) - x-coordinate mismatch";
  EXPECT_EQ(fp_cmp(result_scalar_normal.y, result_double_normal.y),
            ComparisonType::Equal)
      << "2*G (scalar mul) != 2*G (doubling) - y-coordinate mismatch";

  cuda_drop_with_size_tracking_async(d_G, stream, gpu_index, true);
  cuda_drop_with_size_tracking_async(d_result_scalar, stream, gpu_index, true);
  cuda_drop_with_size_tracking_async(d_result_double, stream, gpu_index, true);
}

// Test: Scalar multiplication 3*G
TEST_F(PointOpsTest, G1ScalarMul3) {
  const G1Affine &G = g1_generator();
  if (g1_is_infinity(G)) {
    GTEST_SKIP() << "G1 generator not set";
  }

  uint64_t size_tracker = 0;

  // Convert to Montgomery form
  G1Affine G_mont = G;
  point_to_montgomery_inplace(G_mont);

  // Allocate device memory
  auto *d_G = static_cast<G1Affine *>(cuda_malloc_with_size_tracking_async(
      sizeof(G1Affine), stream, gpu_index, size_tracker, true));
  auto *d_result_scalar =
      static_cast<G1Affine *>(cuda_malloc_with_size_tracking_async(
          sizeof(G1Affine), stream, gpu_index, size_tracker, true));
  auto *d_2G = static_cast<G1Affine *>(cuda_malloc_with_size_tracking_async(
      sizeof(G1Affine), stream, gpu_index, size_tracker, true));
  auto *d_result_add =
      static_cast<G1Affine *>(cuda_malloc_with_size_tracking_async(
          sizeof(G1Affine), stream, gpu_index, size_tracker, true));

  cuda_memcpy_with_size_tracking_async_to_gpu(d_G, &G_mont, sizeof(G1Affine),
                                              stream, gpu_index, true);

  // Compute 3*G using scalar multiplication
  single_point_scalar_mul<G1Affine>(stream, gpu_index, d_result_scalar, d_G, 3);

  // Compute 3*G using addition (G + 2*G)
  point_double<G1Affine>(stream, gpu_index, d_2G, d_G);
  point_add<G1Affine>(stream, gpu_index, d_result_add, d_G, d_2G);

  // Copy results back
  G1Affine result_scalar, result_add;
  cuda_memcpy_async_to_cpu(&result_scalar, d_result_scalar, sizeof(G1Affine),
                           stream, gpu_index);
  cuda_memcpy_async_to_cpu(&result_add, d_result_add, sizeof(G1Affine), stream,
                           gpu_index);
  cuda_synchronize_stream(stream, gpu_index);

  // Verify both are on the curve
  EXPECT_TRUE(is_on_curve(result_scalar))
      << "3*G (scalar mul) is not on the curve!";
  EXPECT_TRUE(is_on_curve(result_add)) << "3*G (addition) is not on the curve!";

  // Convert to normal form for comparison
  point_from_montgomery<G1Affine>(stream, gpu_index, d_result_scalar,
                                  d_result_scalar);
  point_from_montgomery<G1Affine>(stream, gpu_index, d_result_add,
                                  d_result_add);
  cuda_synchronize_stream(stream, gpu_index);
  G1Affine result_scalar_normal, result_add_normal;
  cuda_memcpy_async_to_cpu(&result_scalar_normal, d_result_scalar,
                           sizeof(G1Affine), stream, gpu_index);
  cuda_memcpy_async_to_cpu(&result_add_normal, d_result_add, sizeof(G1Affine),
                           stream, gpu_index);
  cuda_synchronize_stream(stream, gpu_index);

  // Compare results
  EXPECT_EQ(fp_cmp(result_scalar_normal.x, result_add_normal.x),
            ComparisonType::Equal)
      << "3*G (scalar mul) != 3*G (addition) - x-coordinate mismatch";
  EXPECT_EQ(fp_cmp(result_scalar_normal.y, result_add_normal.y),
            ComparisonType::Equal)
      << "3*G (scalar mul) != 3*G (addition) - y-coordinate mismatch";

  cuda_drop_with_size_tracking_async(d_G, stream, gpu_index, true);
  cuda_drop_with_size_tracking_async(d_result_scalar, stream, gpu_index, true);
  cuda_drop_with_size_tracking_async(d_2G, stream, gpu_index, true);
  cuda_drop_with_size_tracking_async(d_result_add, stream, gpu_index, true);
}

// Test: Scalar multiplication 55*G (the problematic case)
TEST_F(PointOpsTest, G1ScalarMul55) {
  const G1Affine &G = g1_generator();
  if (g1_is_infinity(G)) {
    GTEST_SKIP() << "G1 generator not set";
  }

  uint64_t size_tracker = 0;

  // Convert to Montgomery form
  G1Affine G_mont = G;
  point_to_montgomery_inplace(G_mont);

  // Allocate device memory
  auto *d_G = static_cast<G1Affine *>(cuda_malloc_with_size_tracking_async(
      sizeof(G1Affine), stream, gpu_index, size_tracker, true));
  auto *d_result = static_cast<G1Affine *>(cuda_malloc_with_size_tracking_async(
      sizeof(G1Affine), stream, gpu_index, size_tracker, true));

  cuda_memcpy_with_size_tracking_async_to_gpu(d_G, &G_mont, sizeof(G1Affine),
                                              stream, gpu_index, true);

  // Compute 55*G
  single_point_scalar_mul<G1Affine>(stream, gpu_index, d_result, d_G, 55);

  // Copy result back
  G1Affine result;
  cuda_memcpy_async_to_cpu(&result, d_result, sizeof(G1Affine), stream,
                           gpu_index);
  cuda_synchronize_stream(stream, gpu_index);

  // Verify result is not infinity
  EXPECT_FALSE(result.infinity) << "55*G should not be infinity";

  // Verify result is on the curve (this is the key test!)
  EXPECT_TRUE(is_on_curve(result))
      << "55*G is not on the curve! This indicates a bug in point operations.";

  cuda_drop_with_size_tracking_async(d_G, stream, gpu_index, true);
  cuda_drop_with_size_tracking_async(d_result, stream, gpu_index, true);
}

// Test: Sequential doubling (G, 2*G, 4*G, 8*G, ...)
TEST_F(PointOpsTest, G1SequentialDoubling) {
  const G1Affine &G = g1_generator();
  if (g1_is_infinity(G)) {
    GTEST_SKIP() << "G1 generator not set";
  }

  uint64_t size_tracker = 0;

  // Convert to Montgomery form
  G1Affine G_mont = G;
  point_to_montgomery_inplace(G_mont);

  // Allocate device memory
  auto *d_point = static_cast<G1Affine *>(cuda_malloc_with_size_tracking_async(
      sizeof(G1Affine), stream, gpu_index, size_tracker, true));
  auto *d_temp = static_cast<G1Affine *>(cuda_malloc_with_size_tracking_async(
      sizeof(G1Affine), stream, gpu_index, size_tracker, true));

  cuda_memcpy_with_size_tracking_async_to_gpu(
      d_point, &G_mont, sizeof(G1Affine), stream, gpu_index, true);

  // Double multiple times: G -> 2*G -> 4*G -> 8*G -> 16*G
  for (int i = 0; i < 4; i++) {
    point_double<G1Affine>(stream, gpu_index, d_temp, d_point);

    // Copy result back to check
    G1Affine result;
    cuda_memcpy_async_to_cpu(&result, d_temp, sizeof(G1Affine), stream,
                             gpu_index);
    cuda_synchronize_stream(stream, gpu_index);

    // Verify result is on the curve
    EXPECT_TRUE(is_on_curve(result))
        << "Point after " << (i + 1) << " doubling(s) is not on the curve!";

    // Swap pointers for next iteration
    std::swap(d_point, d_temp);
  }

  cuda_drop_with_size_tracking_async(d_point, stream, gpu_index, true);
  cuda_drop_with_size_tracking_async(d_temp, stream, gpu_index, true);
}
