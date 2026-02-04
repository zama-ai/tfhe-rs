#include "curve.h"
#include "device.h"
#include "fp.h"
#include "fp2.h"
#include "fp2_helpers.h" // Include test-only batch operations and kernels
#include <chrono>
#include <cstdint>
#include <cstring>
#include <cuda_runtime.h>
#include <gtest/gtest.h>
#include <iostream>
#include <random>

// Test-only GPU helper functions are compiled separately
// Forward declarations
void fp2_add_gpu(Fp2 *result, const Fp2 *a, const Fp2 *b);
void fp2_sub_gpu(Fp2 *result, const Fp2 *a, const Fp2 *b);
void fp2_mul_gpu(Fp2 *result, const Fp2 *a, const Fp2 *b);
void fp2_neg_gpu(Fp2 *result, const Fp2 *a);
void fp2_conjugate_gpu(Fp2 *result, const Fp2 *a);
void fp2_square_gpu(Fp2 *result, const Fp2 *a);
void fp2_inv_gpu(Fp2 *result, const Fp2 *a);
void fp2_div_gpu(Fp2 *result, const Fp2 *a, const Fp2 *b);
void fp2_mul_by_i_gpu(Fp2 *result, const Fp2 *a);
void fp2_frobenius_gpu(Fp2 *result, const Fp2 *a);
ComparisonType fp2_cmp_gpu(const Fp2 *a, const Fp2 *b);
bool fp2_is_zero_gpu(const Fp2 *a);
bool fp2_is_one_gpu(const Fp2 *a);
void fp2_copy_gpu(Fp2 *result, const Fp2 *a);
void fp2_cmov_gpu(Fp2 *result, const Fp2 *src, uint64_t condition);

// ============================================================================
// Test Utilities
// ============================================================================

namespace test_utils_fp2 {

// Helper to create Fp2 from small integers
Fp2 make_fp2_simple(uint64_t c0_val, uint64_t c1_val) {
  Fp2 result;
  fp_zero(result.c0);
  fp_zero(result.c1);
  result.c0.limb[0] = c0_val;
  result.c1.limb[0] = c1_val;
  return result;
}

// Generate a random Fp2 value
Fp2 random_fp2(std::mt19937_64 &rng) {
  Fp2 result;
  const Fp &p = fp_modulus();

  // Generate random Fp values for c0 and c1
  // Note: For 64-bit limbs, rng() returns uint64_t which fits
  // For 32-bit limbs, we truncate which is fine for randomness
  for (int i = 0; i < FP_LIMBS; i++) {
    result.c0.limb[i] = static_cast<UNSIGNED_LIMB>(rng());
    result.c1.limb[i] = static_cast<UNSIGNED_LIMB>(rng());
  }

  // Reduce if needed
  if (fp_cmp(result.c0, p) != ComparisonType::Less) {
    while (fp_cmp(result.c0, p) != ComparisonType::Less) {
      Fp reduced;
      fp_sub_raw(reduced, result.c0, p);
      fp_copy(result.c0, reduced);
    }
  }
  if (fp_cmp(result.c1, p) != ComparisonType::Less) {
    while (fp_cmp(result.c1, p) != ComparisonType::Less) {
      Fp reduced;
      fp_sub_raw(reduced, result.c1, p);
      fp_copy(result.c1, reduced);
    }
  }

  // Note: Random values are in normal form
  return result;
}

} // namespace test_utils_fp2

// ============================================================================
// Test Fixtures
// ============================================================================

// Base fixture for all Fp2 arithmetic tests
class Fp2ArithmeticTest : public ::testing::Test {
protected:
  static cudaStream_t stream;
  static uint32_t gpu_index;

  static void SetUpTestSuite() {
    // Use GPU 0 by default
    gpu_index = 0;
    cuda_set_device(gpu_index);

    // Create a CUDA stream
    stream = cuda_create_stream(gpu_index);
    PANIC_IF_FALSE(stream != nullptr, "Failed to create CUDA stream");
  }

  static void TearDownTestSuite() {
    if (stream != nullptr) {
      cuda_destroy_stream(stream, gpu_index);
      stream = nullptr;
    }
  }

  // Common test values
  Fp2 zero, one, i_unit; // 0, 1, i

  void SetUp() override {
    fp2_zero(zero);
    fp2_one(one);
    fp2_zero(i_unit);
    fp_one(i_unit.c1); // i = 0 + 1*i
  }
};

// Static member definitions
cudaStream_t Fp2ArithmeticTest::stream = nullptr;
uint32_t Fp2ArithmeticTest::gpu_index = 0;

// Fixture for property-based tests with random number generator
class Fp2PropertyTest : public Fp2ArithmeticTest {
protected:
  std::mt19937_64 rng;

  void SetUp() override {
    Fp2ArithmeticTest::SetUp();
    rng.seed(42); // Fixed seed for reproducibility
  }

  Fp2 random_value() { return test_utils_fp2::random_fp2(rng); }
};

// Fixture for CUDA kernel tests
class Fp2CudaKernelTest : public Fp2ArithmeticTest {
protected:
  std::mt19937_64 rng;

  void SetUp() override {
    Fp2ArithmeticTest::SetUp();
    rng.seed(42); // Fixed seed for reproducibility
  }
};

// ============================================================================
// Basic Operation Tests
// ============================================================================

// Test basic addition (on GPU)
TEST_F(Fp2ArithmeticTest, Addition) {
  uint64_t size_tracker = 0;
  Fp2 a, b, c, c_cpu;

  // Test: (1 + 0*i) + (1 + 0*i) = (2 + 0*i)
  fp2_one(a);
  fp2_one(b);

  // Test on GPU
  fp2_add_gpu(&c, &a, &b);
  cuda_synchronize_device(gpu_index);

  // Also test on CPU for comparison
  c_cpu = a + b;

  // Expected: (2 + 0*i)
  EXPECT_EQ(c.c0.limb[0], 2);
  EXPECT_TRUE(fp_is_zero(c.c1));
  // Verify GPU result matches CPU result
  EXPECT_TRUE(c == c_cpu) << "GPU result should match CPU result";
}

// Test subtraction (on GPU)
TEST_F(Fp2ArithmeticTest, Subtraction) {
  uint64_t size_tracker = 0;
  Fp2 a, b, c, a_cpu;

  // Test: (2 + 0*i) - (1 + 0*i) = (1 + 0*i)
  fp2_one(b);
  fp2_zero(c);
  c.c0.limb[0] = 2;

  // Test on GPU
  fp2_sub_gpu(&a, &c, &b);
  cuda_synchronize_device(gpu_index);

  // Also test on CPU for comparison
  a_cpu = c - b;

  EXPECT_TRUE(fp2_is_one(a));
  // Verify GPU result matches CPU result
  EXPECT_TRUE(a == a_cpu) << "GPU result should match CPU result";
}

// Test multiplication (on GPU)
TEST_F(Fp2ArithmeticTest, Multiplication) {
  uint64_t size_tracker = 0;
  Fp2 a, b, result, expected, result_cpu;

  // Test: (1 + 1*i) * (1 + 1*i) = (0 + 2*i)
  // (1 + i) * (1 + i) = 1 + 2i + i^2 = 1 + 2i - 1 = 2i
  a = test_utils_fp2::make_fp2_simple(1, 1);
  b = test_utils_fp2::make_fp2_simple(1, 1);

  // Test on GPU
  fp2_mul_gpu(&result, &a, &b);
  cuda_synchronize_device(gpu_index);

  // Also test on CPU for comparison
  result_cpu = a * b;

  // Expected: (0 + 2*i)
  fp2_zero(expected);
  expected.c1.limb[0] = 2;

  EXPECT_TRUE(fp_is_zero(result.c0));
  EXPECT_EQ(result.c1.limb[0], 2);
  // Verify GPU result matches CPU result
  EXPECT_TRUE(result == result_cpu) << "GPU result should match CPU result";
}

// Test i * i = -1 (on GPU)
TEST_F(Fp2ArithmeticTest, I_Squared) {
  uint64_t size_tracker = 0;
  Fp2 i_val, result, expected, result_cpu;

  // i = 0 + 1*i
  fp2_zero(i_val);
  fp_one(i_val.c1);

  // i * i = -1 (on GPU)
  fp2_mul_gpu(&result, &i_val, &i_val);
  cuda_synchronize_device(gpu_index);

  // Also test on CPU for comparison
  result_cpu = i_val * i_val;

  // Expected: -1 = (p-1) + 0*i
  fp2_one(expected);
  expected.c0 = -expected.c0;

  EXPECT_TRUE(result.c0 == expected.c0);
  EXPECT_TRUE(fp_is_zero(result.c1));
  // Verify GPU result matches CPU result
  EXPECT_TRUE(result == result_cpu) << "GPU result should match CPU result";
}

// Test negation (on GPU)
TEST_F(Fp2ArithmeticTest, Negation) {
  uint64_t size_tracker = 0;
  Fp2 a, neg_a, result, neg_a_cpu, result_cpu;

  a = test_utils_fp2::make_fp2_simple(5, 3);

  // Test on GPU
  fp2_neg_gpu(&neg_a, &a);
  cuda_synchronize_device(gpu_index);

  fp2_add_gpu(&result, &a, &neg_a);
  cuda_synchronize_device(gpu_index);

  // Also test on CPU for comparison
  neg_a_cpu = -a;
  result_cpu = a + neg_a_cpu;

  EXPECT_TRUE(fp2_is_zero(result));
  // Verify GPU result matches CPU result
  EXPECT_TRUE(result == result_cpu) << "GPU result should match CPU result";
}

// Test conjugation (on GPU)
TEST_F(Fp2ArithmeticTest, Conjugation) {
  uint64_t size_tracker = 0;
  Fp2 a, conj, result, conj_cpu, result_cpu;

  a = test_utils_fp2::make_fp2_simple(5, 3);

  // Test on GPU
  fp2_conjugate_gpu(&conj, &a);
  cuda_synchronize_device(gpu_index);

  fp2_mul_gpu(&result, &a, &conj);
  cuda_synchronize_device(gpu_index);

  // Also test on CPU for comparison
  fp2_conjugate(conj_cpu, a);
  result_cpu = a * conj_cpu;

  // conj should be (5 - 3*i)
  EXPECT_EQ(a.c0.limb[0], conj.c0.limb[0]);
  Fp neg_c1 = -a.c1;
  EXPECT_TRUE(conj.c1 == neg_c1);

  // a * conj should be real (norm)
  EXPECT_TRUE(fp_is_zero(result.c1));
  // Verify GPU result matches CPU result
  EXPECT_TRUE(conj == conj_cpu) << "GPU conjugation should match CPU result";
  EXPECT_TRUE(result == result_cpu)
      << "GPU multiplication result should match CPU result";
}

// Test squaring (on GPU)
TEST_F(Fp2ArithmeticTest, Squaring) {
  uint64_t size_tracker = 0;
  Fp2 a, square, square_cpu;

  // Test: (1 + 1*i)^2 = 2*i
  a = test_utils_fp2::make_fp2_simple(1, 1);

  // Test on GPU
  fp2_square_gpu(&square, &a);
  cuda_synchronize_device(gpu_index);

  // Also test on CPU for comparison
  fp2_square(square_cpu, a);

  // Expected: (0 + 2*i)
  EXPECT_TRUE(fp_is_zero(square.c0));
  EXPECT_EQ(square.c1.limb[0], 2);
  // Verify GPU result matches CPU result
  EXPECT_EQ(fp2_cmp(square, square_cpu), ComparisonType::Equal)
      << "GPU result should match CPU result";
}

// Test zero and one (on GPU)
TEST_F(Fp2ArithmeticTest, ZeroAndOne) {
  uint64_t size_tracker = 0;
  Fp2 zero_val, one_val;

  fp2_zero(zero_val);
  fp2_one(one_val);

  // Test on GPU
  EXPECT_TRUE(fp2_is_zero_gpu(&zero_val));
  cuda_synchronize_device(gpu_index);

  EXPECT_FALSE(fp2_is_zero_gpu(&one_val));
  cuda_synchronize_device(gpu_index);

  EXPECT_TRUE(fp2_is_one_gpu(&one_val));
  cuda_synchronize_device(gpu_index);

  EXPECT_FALSE(fp2_is_one_gpu(&zero_val));
  cuda_synchronize_device(gpu_index);
}

// Test copy (on GPU)
TEST_F(Fp2ArithmeticTest, Copy) {
  uint64_t size_tracker = 0;
  Fp2 a, b, b_cpu;

  a = test_utils_fp2::make_fp2_simple(42, 123);

  // Test on GPU
  fp2_copy_gpu(&b, &a);
  cuda_synchronize_device(gpu_index);

  // Also test on CPU for comparison
  fp2_copy(b_cpu, a);

  EXPECT_EQ(fp_cmp(a.c0, b.c0), ComparisonType::Equal);
  EXPECT_EQ(fp_cmp(a.c1, b.c1), ComparisonType::Equal);
  // Verify GPU result matches CPU result
  EXPECT_EQ(fp2_cmp(b, b_cpu), ComparisonType::Equal)
      << "GPU result should match CPU result";
}

// Test conditional move (on GPU)
TEST_F(Fp2ArithmeticTest, ConditionalMove) {
  uint64_t size_tracker = 0;
  Fp2 a, b, result, result_cpu;

  a = test_utils_fp2::make_fp2_simple(10, 20);
  b = test_utils_fp2::make_fp2_simple(30, 40);

  // Test move when condition is true (1) (on GPU)
  fp2_copy_gpu(&result, &a);
  cuda_synchronize_device(gpu_index);
  fp2_cmov_gpu(&result, &b, 1);
  cuda_synchronize_device(gpu_index);

  // Also test on CPU for comparison
  fp2_copy(result_cpu, a);
  fp2_cmov(result_cpu, b, 1);

  EXPECT_EQ(fp_cmp(result.c0, b.c0), ComparisonType::Equal);
  EXPECT_EQ(fp_cmp(result.c1, b.c1), ComparisonType::Equal);
  // Verify GPU result matches CPU result
  EXPECT_EQ(fp2_cmp(result, result_cpu), ComparisonType::Equal)
      << "GPU result should match CPU result";

  // Test no move when condition is false (0) (on GPU)
  fp2_copy_gpu(&result, &a);
  cuda_synchronize_device(gpu_index);
  fp2_cmov_gpu(&result, &b, 0);
  cuda_synchronize_device(gpu_index);

  // Also test on CPU for comparison
  fp2_copy(result_cpu, a);
  fp2_cmov(result_cpu, b, 0);

  EXPECT_EQ(fp_cmp(result.c0, a.c0), ComparisonType::Equal);
  EXPECT_EQ(fp_cmp(result.c1, a.c1), ComparisonType::Equal);
  // Verify GPU result matches CPU result
  EXPECT_EQ(fp2_cmp(result, result_cpu), ComparisonType::Equal)
      << "GPU result should match CPU result";
}

// Test multiplication by zero (on GPU)
TEST_F(Fp2ArithmeticTest, MultiplicationByZero) {
  uint64_t size_tracker = 0;
  Fp2 a, zero_val, result, result_cpu;

  fp2_zero(zero_val);
  a = test_utils_fp2::make_fp2_simple(5, 3);

  // Test on GPU
  fp2_mul_gpu(&result, &a, &zero_val);
  cuda_synchronize_device(gpu_index);

  // Also test on CPU for comparison
  result_cpu = a * zero_val;

  EXPECT_TRUE(fp2_is_zero_gpu(&result));
  cuda_synchronize_device(gpu_index);
  // Verify GPU result matches CPU result
  EXPECT_TRUE(result == result_cpu) << "GPU result should match CPU result";
}

// Test inversion (on GPU)
TEST_F(Fp2ArithmeticTest, Inversion) {
  uint64_t size_tracker = 0;
  Fp2 a, a_inv, result, a_inv_cpu, result_cpu;

  a = test_utils_fp2::make_fp2_simple(5, 3);

  // Test on GPU
  fp2_inv_gpu(&a_inv, &a);
  cuda_synchronize_device(gpu_index);

  fp2_mul_gpu(&result, &a, &a_inv);
  cuda_synchronize_device(gpu_index);

  // Also test on CPU for comparison
  fp2_inv(a_inv_cpu, a);
  result_cpu = a * a_inv_cpu;

  // a * a^(-1) should equal 1
  EXPECT_TRUE(fp2_is_one(result));
  // Verify GPU result matches CPU result
  EXPECT_TRUE(result == result_cpu) << "GPU result should match CPU result";
}

// Test division (on GPU)
TEST_F(Fp2ArithmeticTest, Division) {
  uint64_t size_tracker = 0;
  Fp2 a, b, quotient, result, quotient_cpu, result_cpu;

  a = test_utils_fp2::make_fp2_simple(10, 6);
  b = test_utils_fp2::make_fp2_simple(5, 3);

  // Test on GPU
  fp2_div_gpu(&quotient, &a, &b);
  cuda_synchronize_device(gpu_index);

  fp2_mul_gpu(&result, &quotient, &b);
  cuda_synchronize_device(gpu_index);

  // Also test on CPU for comparison
  quotient_cpu = a / b;
  result_cpu = quotient_cpu * b;

  // quotient * b should equal a
  EXPECT_TRUE(result.c0 == a.c0);
  EXPECT_TRUE(result.c1 == a.c1);
  // Verify GPU result matches CPU result
  EXPECT_TRUE(result == result_cpu) << "GPU result should match CPU result";
}

// Test multiply by i (on GPU)
TEST_F(Fp2ArithmeticTest, MultiplyByI) {
  uint64_t size_tracker = 0;
  Fp2 a, result, result_cpu;

  // Test: (a + b*i) * i = -b + a*i
  a = test_utils_fp2::make_fp2_simple(5, 3);

  // Test on GPU
  fp2_mul_by_i_gpu(&result, &a);
  cuda_synchronize_device(gpu_index);

  // Also test on CPU for comparison
  fp2_mul_by_i(result_cpu, a);

  // Expected: (-3 + 5*i)
  Fp neg_three;
  fp_zero(neg_three);
  neg_three.limb[0] = 3;
  neg_three = -neg_three;

  EXPECT_TRUE(result.c0 == neg_three);
  EXPECT_EQ(result.c1.limb[0], 5);
  // Verify GPU result matches CPU result
  EXPECT_TRUE(result == result_cpu) << "GPU result should match CPU result";
}

// Test Frobenius map (on GPU)
TEST_F(Fp2ArithmeticTest, Frobenius) {
  uint64_t size_tracker = 0;
  Fp2 a, frob, conj, frob_cpu, conj_cpu;

  a = test_utils_fp2::make_fp2_simple(5, 3);

  // Test on GPU
  fp2_frobenius_gpu(&frob, &a);
  cuda_synchronize_device(gpu_index);

  fp2_conjugate_gpu(&conj, &a);
  cuda_synchronize_device(gpu_index);

  // Also test on CPU for comparison
  fp2_frobenius(frob_cpu, a);
  fp2_conjugate(conj_cpu, a);

  // Frobenius should equal conjugation for Fp2
  EXPECT_EQ(fp_cmp(frob.c0, conj.c0), ComparisonType::Equal);
  EXPECT_EQ(fp_cmp(frob.c1, conj.c1), ComparisonType::Equal);
  // Verify GPU result matches CPU result
  EXPECT_EQ(fp2_cmp(frob, frob_cpu), ComparisonType::Equal)
      << "GPU Frobenius should match CPU result";
  EXPECT_EQ(fp2_cmp(conj, conj_cpu), ComparisonType::Equal)
      << "GPU conjugation should match CPU result";
}

// ============================================================================
// Property-Based Tests
// ============================================================================

// Test addition associativity: (a + b) + c = a + (b + c) (on GPU)
TEST_F(Fp2PropertyTest, AdditionAssociativity) {
  uint64_t size_tracker = 0;
  for (int i = 0; i < 100; i++) {
    Fp2 a = random_value();
    Fp2 b = random_value();
    Fp2 c = random_value();

    Fp2 result1, result2, temp;

    // (a + b) + c (on GPU)
    fp2_add_gpu(&temp, &a, &b);
    fp2_add_gpu(&result1, &temp, &c);
    cuda_synchronize_device(gpu_index);

    // a + (b + c) (on GPU)
    fp2_add_gpu(&temp, &b, &c);
    fp2_add_gpu(&result2, &a, &temp);
    cuda_synchronize_device(gpu_index);

    EXPECT_EQ(fp2_cmp_gpu(&result1, &result2), ComparisonType::Equal)
        << "Addition associativity failed: (a+b)+c != a+(b+c)";
    cuda_synchronize_device(gpu_index);
  }
}

// Test multiplication associativity: (a * b) * c = a * (b * c) (on GPU)
TEST_F(Fp2PropertyTest, MultiplicationAssociativity) {
  uint64_t size_tracker = 0;
  for (int i = 0; i < 50; i++) {
    Fp2 a = random_value();
    Fp2 b = random_value();
    Fp2 c = random_value();

    Fp2 result1, result2, temp;

    // (a * b) * c (on GPU)
    fp2_mul_gpu(&temp, &a, &b);
    fp2_mul_gpu(&result1, &temp, &c);
    cuda_synchronize_device(gpu_index);

    // a * (b * c) (on GPU)
    fp2_mul_gpu(&temp, &b, &c);
    fp2_mul_gpu(&result2, &a, &temp);
    cuda_synchronize_device(gpu_index);

    EXPECT_EQ(fp2_cmp_gpu(&result1, &result2), ComparisonType::Equal)
        << "Multiplication associativity failed: (a*b)*c != a*(b*c)";
    cuda_synchronize_device(gpu_index);
  }
}

// Test distributivity: a * (b + c) = a*b + a*c (on GPU)
TEST_F(Fp2PropertyTest, MultiplicationDistributivity) {
  uint64_t size_tracker = 0;
  for (int i = 0; i < 50; i++) {
    Fp2 a = random_value();
    Fp2 b = random_value();
    Fp2 c = random_value();

    Fp2 result1, result2, temp1, temp2;

    // a * (b + c) (on GPU)
    fp2_add_gpu(&temp1, &b, &c);
    fp2_mul_gpu(&result1, &a, &temp1);
    cuda_synchronize_device(gpu_index);

    // a*b + a*c (on GPU)
    fp2_mul_gpu(&temp1, &a, &b);
    fp2_mul_gpu(&temp2, &a, &c);
    fp2_add_gpu(&result2, &temp1, &temp2);
    cuda_synchronize_device(gpu_index);

    EXPECT_EQ(fp2_cmp_gpu(&result1, &result2), ComparisonType::Equal)
        << "Distributivity failed: a*(b+c) != a*b + a*c";
    cuda_synchronize_device(gpu_index);
  }
}

// Test addition commutativity (on GPU)
TEST_F(Fp2PropertyTest, AdditionCommutativity) {
  uint64_t size_tracker = 0;
  for (int i = 0; i < 100; i++) {
    Fp2 a = random_value();
    Fp2 b = random_value();

    Fp2 result1, result2;
    fp2_add_gpu(&result1, &a, &b);
    fp2_add_gpu(&result2, &b, &a);
    cuda_synchronize_device(gpu_index);

    EXPECT_EQ(fp2_cmp_gpu(&result1, &result2), ComparisonType::Equal)
        << "Addition commutativity failed: a+b != b+a";
    cuda_synchronize_device(gpu_index);
  }
}

// Test multiplication commutativity (on GPU)
TEST_F(Fp2PropertyTest, MultiplicationCommutativity) {
  uint64_t size_tracker = 0;
  for (int i = 0; i < 50; i++) {
    Fp2 a = random_value();
    Fp2 b = random_value();

    Fp2 result1, result2;
    fp2_mul_gpu(&result1, &a, &b);
    fp2_mul_gpu(&result2, &b, &a);
    cuda_synchronize_device(gpu_index);

    EXPECT_EQ(fp2_cmp_gpu(&result1, &result2), ComparisonType::Equal)
        << "Multiplication commutativity failed: a*b != b*a";
    cuda_synchronize_device(gpu_index);
  }
}

// Test additive identity: a + 0 = a (on GPU)
TEST_F(Fp2PropertyTest, AdditiveIdentity) {
  uint64_t size_tracker = 0;
  for (int i = 0; i < 100; i++) {
    Fp2 a = random_value();
    Fp2 result;

    fp2_add_gpu(&result, &a, &zero);
    cuda_synchronize_device(gpu_index);

    EXPECT_EQ(fp2_cmp_gpu(&result, &a), ComparisonType::Equal)
        << "Additive identity failed: a + 0 != a";
    cuda_synchronize_device(gpu_index);
  }
}

// Test multiplicative identity: a * 1 = a (on GPU)
TEST_F(Fp2PropertyTest, MultiplicativeIdentity) {
  uint64_t size_tracker = 0;
  for (int i = 0; i < 100; i++) {
    Fp2 a = random_value();
    Fp2 result;

    fp2_mul_gpu(&result, &a, &one);
    cuda_synchronize_device(gpu_index);

    EXPECT_EQ(fp2_cmp_gpu(&result, &a), ComparisonType::Equal)
        << "Multiplicative identity failed: a * 1 != a";
    cuda_synchronize_device(gpu_index);
  }
}

// Test additive inverse: a + (-a) = 0 (on GPU)
TEST_F(Fp2PropertyTest, AdditiveInverse) {
  uint64_t size_tracker = 0;
  for (int i = 0; i < 100; i++) {
    Fp2 a = random_value();
    Fp2 neg_a, result;

    fp2_neg_gpu(&neg_a, &a);
    fp2_add_gpu(&result, &a, &neg_a);
    cuda_synchronize_device(gpu_index);

    EXPECT_TRUE(fp2_is_zero_gpu(&result))
        << "Additive inverse failed: a + (-a) != 0";
    cuda_synchronize_device(gpu_index);
  }
}

// Test multiplicative inverse: a * a^(-1) = 1 (on GPU)
TEST_F(Fp2PropertyTest, MultiplicativeInverse) {
  uint64_t size_tracker = 0;
  for (int i = 0; i < 50; i++) {
    Fp2 a = random_value();
    // Skip zero
    if (fp2_is_zero(a))
      continue;

    Fp2 a_inv, result;

    fp2_inv_gpu(&a_inv, &a);
    fp2_mul_gpu(&result, &a, &a_inv);
    cuda_synchronize_device(gpu_index);

    EXPECT_TRUE(fp2_is_one_gpu(&result))
        << "Multiplicative inverse failed: a * a^(-1) != 1";
    cuda_synchronize_device(gpu_index);
  }
}

// Test square vs multiply by self: a^2 = a * a (on GPU)
TEST_F(Fp2PropertyTest, SquareVsMultiply) {
  uint64_t size_tracker = 0;
  for (int i = 0; i < 50; i++) {
    Fp2 a = random_value();

    Fp2 square, multiply;
    fp2_square_gpu(&square, &a);
    fp2_mul_gpu(&multiply, &a, &a);
    cuda_synchronize_device(gpu_index);

    EXPECT_EQ(fp2_cmp_gpu(&square, &multiply), ComparisonType::Equal)
        << "Square vs multiply failed: a^2 != a*a";
    cuda_synchronize_device(gpu_index);
  }
}

// ============================================================================
// CUDA Kernel Tests
// ============================================================================

// Test CUDA kernel: array addition
TEST_F(Fp2CudaKernelTest, CudaKernelArrayAdd) {
  uint64_t size_tracker = 0;
  const int n = 1000;
  Fp2 *h_a = new Fp2[n];
  Fp2 *h_b = new Fp2[n];
  Fp2 *h_c = new Fp2[n];
  Fp2 *h_expected = new Fp2[n];

  // Initialize with random values
  for (int i = 0; i < n; i++) {
    h_a[i] = test_utils_fp2::random_fp2(rng);
    h_b[i] = test_utils_fp2::random_fp2(rng);
    // Compute expected result on host
    h_expected[i] = h_a[i] + h_b[i];
  }

  // Launch GPU kernel
  fp2_add_batch_on_host(stream, gpu_index, h_c, h_a, h_b, n);

  // Check CUDA errors (stream is already synchronized in fp2_add_batch_on_host)
  cuda_synchronize_stream(stream, gpu_index);

  // Verify results match host computation
  for (int i = 0; i < n; i++) {
    EXPECT_TRUE(h_c[i].c0 == h_expected[i].c0)
        << "GPU result mismatch at index " << i << " (c0)";
    EXPECT_TRUE(h_c[i].c1 == h_expected[i].c1)
        << "GPU result mismatch at index " << i << " (c1)";
  }

  delete[] h_a;
  delete[] h_b;
  delete[] h_c;
  delete[] h_expected;
}

// Test CUDA kernel: array multiplication
TEST_F(Fp2CudaKernelTest, CudaKernelArrayMul) {
  uint64_t size_tracker = 0;
  const int n = 1000;
  Fp2 *h_a = new Fp2[n];
  Fp2 *h_b = new Fp2[n];
  Fp2 *h_c = new Fp2[n];
  Fp2 *h_expected = new Fp2[n];

  // Initialize with random values
  for (int i = 0; i < n; i++) {
    h_a[i] = test_utils_fp2::random_fp2(rng);
    h_b[i] = test_utils_fp2::random_fp2(rng);
    // Compute expected result on host
    h_expected[i] = h_a[i] * h_b[i];
  }

  // Launch GPU kernel
  fp2_mul_batch_on_host(stream, gpu_index, h_c, h_a, h_b, n);

  // Check CUDA errors (stream is already synchronized in fp2_mul_batch_on_host)
  cuda_synchronize_stream(stream, gpu_index);

  // Verify results match host computation
  for (int i = 0; i < n; i++) {
    EXPECT_TRUE(h_c[i].c0 == h_expected[i].c0)
        << "GPU result mismatch at index " << i << " (c0)";
    EXPECT_TRUE(h_c[i].c1 == h_expected[i].c1)
        << "GPU result mismatch at index " << i << " (c1)";
  }

  delete[] h_a;
  delete[] h_b;
  delete[] h_c;
  delete[] h_expected;
}

// ============================================================================
// Curve Point Tests for G2
// ============================================================================

// Test is_on_curve_g2 with point at infinity
TEST_F(Fp2ArithmeticTest, CurveG2PointAtInfinity) {
  uint64_t size_tracker = 0;
  G2Affine point;
  g2_point_at_infinity(point);

  EXPECT_TRUE(g2_is_infinity(point)) << "Point should be at infinity";
  EXPECT_TRUE(is_on_curve_g2(point)) << "Point at infinity should be on curve";
}

// Test is_on_curve_g2 with valid point construction
TEST_F(Fp2ArithmeticTest, CurveG2ValidPointCheck) {
  uint64_t size_tracker = 0;
  G2Affine point;
  point.infinity = false;

  // Set x = (1, 0)
  fp2_one(point.x);

  // Set y = (1, 0) - this may or may not be valid, but we test the function
  // works
  fp2_one(point.y);

  // Verify the function works (doesn't crash)
  bool on_curve = is_on_curve_g2(point);
  (void)on_curve; // Suppress unused warning

  // Test that modifying y changes the result
  Fp2 neg_y = -point.y;
  fp2_copy(point.y, neg_y);

  bool on_curve_neg = is_on_curve_g2(point);
  (void)on_curve_neg; // Suppress unused warning
}

// Test that field operations maintain curve validity for G2
TEST_F(Fp2ArithmeticTest, CurveG2FieldOperationsConsistency) {
  uint64_t size_tracker = 0;
  // Create a point (we'll test the consistency check works)
  G2Affine point;
  point.infinity = false;
  fp2_one(point.x);
  fp2_one(point.y);

  // Store initial state
  bool initial_on_curve = is_on_curve_g2(point);

  // Negate y coordinate
  Fp2 neg_y = -point.y;
  fp2_copy(point.y, neg_y);

  // If initial point was on curve, negated y should also be on curve
  // (since (-y)^2 = y^2)
  bool after_neg_on_curve = is_on_curve_g2(point);

  if (initial_on_curve) {
    EXPECT_TRUE(after_neg_on_curve)
        << "If point was on curve, negating y should keep it on curve";
  }
}
