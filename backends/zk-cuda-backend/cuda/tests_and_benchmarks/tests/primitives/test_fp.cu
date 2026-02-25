#include "curve.h"
#include "device.h"
#include "fp.h"
#include "fp_helpers.h" // Include test-only batch operations and kernels
#include <chrono>
#include <cstdint>
#include <cstring>
#include <cuda_runtime.h>
#include <gtest/gtest.h>
#include <iostream>
#include <random>

// Test-only GPU helper functions are compiled separately
// Forward declarations
void fp_add_gpu(cudaStream_t stream, uint32_t gpu_index, Fp *result,
                const Fp *a, const Fp *b);
void fp_sub_gpu(cudaStream_t stream, uint32_t gpu_index, Fp *result,
                const Fp *a, const Fp *b);
void fp_mul_gpu(cudaStream_t stream, uint32_t gpu_index, Fp *result,
                const Fp *a, const Fp *b);
void fp_neg_gpu(cudaStream_t stream, uint32_t gpu_index, Fp *result,
                const Fp *a);
void fp_inv_gpu(cudaStream_t stream, uint32_t gpu_index, Fp *result,
                const Fp *a);
void fp_div_gpu(cudaStream_t stream, uint32_t gpu_index, Fp *result,
                const Fp *a, const Fp *b);
ComparisonType fp_cmp_gpu(cudaStream_t stream, uint32_t gpu_index, const Fp *a,
                          const Fp *b);
bool fp_is_zero_gpu(cudaStream_t stream, uint32_t gpu_index, const Fp *a);
bool fp_is_one_gpu(cudaStream_t stream, uint32_t gpu_index, const Fp *a);
void fp_to_montgomery_gpu(cudaStream_t stream, uint32_t gpu_index, Fp *result,
                          const Fp *a);
void fp_from_montgomery_gpu(cudaStream_t stream, uint32_t gpu_index, Fp *result,
                            const Fp *a);
void fp_mont_mul_gpu(cudaStream_t stream, uint32_t gpu_index, Fp *result,
                     const Fp *a, const Fp *b);
void fp_copy_gpu(cudaStream_t stream, uint32_t gpu_index, Fp *result,
                 const Fp *a);
void fp_cmov_gpu(cudaStream_t stream, uint32_t gpu_index, Fp *result,
                 const Fp *src, uint64_t condition);
bool fp_sqrt_gpu(cudaStream_t stream, uint32_t gpu_index, Fp *result,
                 const Fp *a);
bool fp_is_quadratic_residue_gpu(cudaStream_t stream, uint32_t gpu_index,
                                 const Fp *a);
void fp_pow_u64_gpu(cudaStream_t stream, uint32_t gpu_index, Fp *result,
                    const Fp *base, uint64_t exp);

// ============================================================================
// Test Utilities
// ============================================================================

namespace test_utils {

// Create an Fp from limb values (64-bit limbs only)
// This helper is only available for 64-bit limb configurations
#if LIMB_BITS_CONFIG == 64
Fp make_fp(uint64_t l0, uint64_t l1, uint64_t l2, uint64_t l3, uint64_t l4,
           uint64_t l5, uint64_t l6) {
  Fp result;
  result.limb[0] = l0;
  result.limb[1] = l1;
  result.limb[2] = l2;
  result.limb[3] = l3;
  result.limb[4] = l4;
  result.limb[5] = l5;
  result.limb[6] = l6;
  return result;
}
#endif

// Get the modulus p (use fp_modulus() from the library)
Fp get_modulus() { return fp_modulus(); }

// Get p - 1
Fp get_modulus_minus_one() {
  Fp p = fp_modulus();
  Fp one;
  fp_one(one);
  Fp result;
  fp_sub_raw(result, p, one);
  return result;
}

// Get p - 2
Fp get_modulus_minus_two() {
  Fp p_minus_1 = get_modulus_minus_one();
  Fp one;
  fp_one(one);
  return p_minus_1 - one;
}

// Check if a < p
bool is_valid_fp(const Fp &a) {
  Fp p = get_modulus();
  return fp_cmp(a, p) == ComparisonType::Less;
}

// Generate a random Fp value in [0, p-1]
// Uses a simple rejection sampling approach
// Note: Returns value in normal form
Fp random_fp(std::mt19937_64 &rng) {
  Fp result;
  Fp p = get_modulus();

  // Generate random limbs, ensuring result < p
  // We'll generate random values and reduce if needed
  for (int i = 0; i < FP_LIMBS; i++) {
    result.limb[i] = static_cast<UNSIGNED_LIMB>(rng());
  }

  // If result >= p, reduce it
  if (fp_cmp(result, p) != ComparisonType::Less) {
    // Subtract p until result < p
    while (fp_cmp(result, p) != ComparisonType::Less) {
      Fp reduced;
      fp_sub_raw(reduced, result, p);
      fp_copy(result, reduced);
    }
  }

  return result;
}

// Generate a random Fp value in [0, max]
Fp random_fp_bounded(std::mt19937_64 &rng, const Fp &max) {
  Fp result = random_fp(rng);
  // If result > max, reduce modulo (max + 1)
  // For simplicity, just generate again if too large
  // (This is not perfect but works for testing)
  if (fp_cmp(result, max) == ComparisonType::Greater) {
    // Use modulo operation: result = result mod (max + 1)
    // For testing, we'll just generate a new one
    // In practice, you'd want proper modular reduction
    return random_fp_bounded(rng, max);
  }
  return result;
}

// Create Fp with all limbs set to max value
// Note: Returns value in normal form
Fp max_limb_fp() {
  Fp result;
  for (int i = 0; i < FP_LIMBS; i++) {
    result.limb[i] = LIMB_MAX;
  }
  // Reduce if needed - keep subtracting p until result < p
  Fp p = get_modulus();
  while (fp_cmp(result, p) != ComparisonType::Less) {
    Fp reduced;
    fp_sub_raw(reduced, result, p);
    fp_copy(result, reduced);
  }
  return result;
}

// Create Fp with alternating bit pattern
Fp alternating_bits_fp() {
  Fp result;
  for (int i = 0; i < FP_LIMBS; i++) {
#if LIMB_BITS_CONFIG == 64
    result.limb[i] =
        (i % 2 == 0) ? 0xAAAAAAAAAAAAAAAAULL : 0x5555555555555555ULL;
#elif LIMB_BITS_CONFIG == 32
    result.limb[i] = (i % 2 == 0) ? 0xAAAAAAAAU : 0x55555555U;
#endif
  }
  // Reduce if needed - keep subtracting p until result < p
  Fp p = get_modulus();
  while (fp_cmp(result, p) != ComparisonType::Less) {
    Fp reduced;
    fp_sub_raw(reduced, result, p);
    fp_copy(result, reduced);
  }
  return result;
}

// Better comparison helper with detailed error message
::testing::AssertionResult AssertFpEqual(const char *a_expr, const char *b_expr,
                                         const Fp &a, const Fp &b) {
  if (fp_cmp(a, b) == ComparisonType::Equal) {
    return ::testing::AssertionSuccess();
  }

  ::testing::AssertionResult result = ::testing::AssertionFailure()
                                      << "Expected equality of these values:\n"
                                      << "  " << a_expr << "\n"
                                      << "    Which is: ";
  for (int i = FP_LIMBS - 1; i >= 0; i--) {
    result << std::hex << "0x" << a.limb[i];
    if (i > 0)
      result << " ";
  }
  result << "\n"
         << "  " << b_expr << "\n"
         << "    Which is: ";
  for (int i = FP_LIMBS - 1; i >= 0; i--) {
    result << std::hex << "0x" << b.limb[i];
    if (i > 0)
      result << " ";
  }
  return result;
}

} // namespace test_utils

// ============================================================================
// Test Fixtures
// ============================================================================

// Base fixture for all Fp arithmetic tests
class FpArithmeticTest : public ::testing::Test {
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

    // Device modulus and curve constants are now hardcoded at compile time, no
    // initialization needed
  }

  static void TearDownTestSuite() {
    if (stream != nullptr) {
      cuda_destroy_stream(stream, gpu_index);
      stream = nullptr;
    }
  }

  // Common test values
  Fp zero, one, two;
  Fp modulus, modulus_minus_one, modulus_minus_two;

  void SetUp() override {
    fp_zero(zero);
    fp_one(one);
    fp_zero(two);
    two.limb[0] = 2;

    modulus = test_utils::get_modulus();
    modulus_minus_one = test_utils::get_modulus_minus_one();
    modulus_minus_two = test_utils::get_modulus_minus_two();
  }
};

// Static member definitions
cudaStream_t FpArithmeticTest::stream = nullptr;
uint32_t FpArithmeticTest::gpu_index = 0;

// Fixture for property-based tests with random number generator
class FpPropertyTest : public FpArithmeticTest {
protected:
  std::mt19937_64 rng;

  void SetUp() override {
    FpArithmeticTest::SetUp();
    // Seed with current time for reproducibility in tests
    rng.seed(42); // Fixed seed for reproducibility
  }

  Fp random_value() { return test_utils::random_fp(rng); }
};

// Fixture for edge case tests
class FpEdgeCaseTest : public FpArithmeticTest {
protected:
  Fp max_limb_value;
  Fp alternating_bits;
  std::mt19937_64 rng;

  void SetUp() override {
    FpArithmeticTest::SetUp();
    rng.seed(42); // Fixed seed for reproducibility
    max_limb_value = test_utils::max_limb_fp();
    alternating_bits = test_utils::alternating_bits_fp();
  }
};

// Fixture for CUDA kernel tests
class FpCudaKernelTest : public FpArithmeticTest {
protected:
  std::mt19937_64 rng;

  void SetUp() override {
    FpArithmeticTest::SetUp();
    rng.seed(42); // Fixed seed for reproducibility
  }

  // Helper to check CUDA errors
};

// Test basic addition (on GPU)
TEST_F(FpArithmeticTest, Addition) {
  uint64_t size_tracker = 0;
  Fp a, b, c, c_cpu;

  // Test: 1 + 1 = 2
  fp_one(a);
  fp_one(b);

  // Test on GPU
  fp_add_gpu(stream, gpu_index, &c, &a, &b);

  // Also test on CPU for comparison
  c_cpu = a + b;

  EXPECT_EQ(c.limb[0], 2);
  for (int i = 1; i < FP_LIMBS; i++) {
    EXPECT_EQ(c.limb[i], 0);
  }
  // Verify GPU result matches CPU result
  EXPECT_TRUE(c == c_cpu) << "GPU result should match CPU result";
}

// Test subtraction (on GPU)
TEST_F(FpArithmeticTest, Subtraction) {
  uint64_t size_tracker = 0;
  Fp a, b, c, a_cpu;

  // Test: 2 - 1 = 1
  fp_one(b);
  fp_zero(c);
  c.limb[0] = 2;

  // Test on GPU
  fp_sub_gpu(stream, gpu_index, &a, &c, &b);

  // Also test on CPU for comparison
  a_cpu = c - b;

  EXPECT_TRUE(fp_is_one(a));
  // Verify GPU result matches CPU result
  EXPECT_TRUE(a == a_cpu) << "GPU result should match CPU result";
}

// Test multiplication (on GPU)
TEST_F(FpArithmeticTest, Multiplication) {
  uint64_t size_tracker = 0;
  Fp five, three, result, expected;

  fp_zero(five);
  fp_zero(three);
  fp_zero(expected);
  five.limb[0] = 5;
  three.limb[0] = 3;
  expected.limb[0] = 15;

  // Test on GPU
  fp_mul_gpu(stream, gpu_index, &result, &five, &three);

  // Also test on CPU for comparison
  // operator* expects Montgomery-form inputs and returns Montgomery form
  Fp five_m, three_m;
  fp_to_montgomery(five_m, five);
  fp_to_montgomery(three_m, three);
  Fp result_cpu_mont = five_m * three_m;
  Fp result_cpu;
  fp_from_montgomery(result_cpu, result_cpu_mont);

  EXPECT_TRUE(result == expected);
  // Verify GPU result matches CPU result
  EXPECT_TRUE(result == result_cpu) << "GPU result should match CPU result";
}

// Test negation (on GPU)
TEST_F(FpArithmeticTest, Negation) {
  uint64_t size_tracker = 0;
  Fp a, neg_a, result;

  fp_zero(a);
  a.limb[0] = 5;

  // Test on GPU
  fp_neg_gpu(stream, gpu_index, &neg_a, &a);
  fp_add_gpu(stream, gpu_index, &result, &a, &neg_a);

  // Also test on CPU for comparison
  Fp neg_a_cpu = -a;
  Fp result_cpu = a + neg_a_cpu;

  EXPECT_TRUE(fp_is_zero_gpu(stream, gpu_index, &result));
  cuda_synchronize_stream(stream, gpu_index);
  // Verify GPU result matches CPU result
  EXPECT_EQ(fp_cmp_gpu(stream, gpu_index, &result, &result_cpu),
            ComparisonType::Equal)
      << "GPU result should match CPU result";
  cuda_synchronize_stream(stream, gpu_index);
}

// Test Montgomery conversion round-trip (on GPU)
TEST_F(FpArithmeticTest, MontgomeryRoundTrip) {
  uint64_t size_tracker = 0;
  Fp value, mont_form, back, mont_form_cpu, back_cpu;

  fp_zero(value);
  value.limb[0] = 5;

  // Test on GPU
  fp_to_montgomery_gpu(stream, gpu_index, &mont_form, &value);
  fp_from_montgomery_gpu(stream, gpu_index, &back, &mont_form);

  // Also test on CPU for comparison
  fp_to_montgomery(mont_form_cpu, value);
  fp_from_montgomery(back_cpu, mont_form_cpu);

  EXPECT_EQ(fp_cmp_gpu(stream, gpu_index, &back, &value),
            ComparisonType::Equal);
  cuda_synchronize_stream(stream, gpu_index);
  // Verify GPU result matches CPU result
  EXPECT_EQ(fp_cmp_gpu(stream, gpu_index, &back, &back_cpu),
            ComparisonType::Equal)
      << "GPU result should match CPU result";
  cuda_synchronize_stream(stream, gpu_index);
}

// Test Montgomery multiplication (on GPU)
TEST_F(FpArithmeticTest, MontgomeryMultiplication) {
  uint64_t size_tracker = 0;
  Fp five, three, five_m, three_m, result_m, result, expected, result_cpu;

  fp_zero(five);
  fp_zero(three);
  fp_zero(expected);
  five.limb[0] = 5;
  three.limb[0] = 3;
  expected.limb[0] = 15;

  // Convert to Montgomery form (on GPU)
  fp_to_montgomery_gpu(stream, gpu_index, &five_m, &five);
  fp_to_montgomery_gpu(stream, gpu_index, &three_m, &three);

  // Multiply in Montgomery form (on GPU)
  fp_mont_mul_gpu(stream, gpu_index, &result_m, &five_m, &three_m);

  // Convert back (on GPU)
  fp_from_montgomery_gpu(stream, gpu_index, &result, &result_m);

  // Also test on CPU for comparison
  Fp five_m_cpu, three_m_cpu, result_m_cpu;
  fp_to_montgomery(five_m_cpu, five);
  fp_to_montgomery(three_m_cpu, three);
  fp_mont_mul(result_m_cpu, five_m_cpu, three_m_cpu);
  fp_from_montgomery(result_cpu, result_m_cpu);

  EXPECT_EQ(fp_cmp_gpu(stream, gpu_index, &result, &expected),
            ComparisonType::Equal);
  cuda_synchronize_stream(stream, gpu_index);
  // Verify GPU result matches CPU result
  EXPECT_EQ(fp_cmp_gpu(stream, gpu_index, &result, &result_cpu),
            ComparisonType::Equal)
      << "GPU result should match CPU result";
  cuda_synchronize_stream(stream, gpu_index);
}

// Test comparison operations (on GPU)
TEST_F(FpArithmeticTest, Comparison) {
  uint64_t size_tracker = 0;
  Fp five, three;

  fp_zero(five);
  fp_zero(three);
  five.limb[0] = 5;
  three.limb[0] = 3;

  // Test on GPU
  EXPECT_EQ(fp_cmp_gpu(stream, gpu_index, &five, &three),
            ComparisonType::Greater); // 5 > 3

  EXPECT_EQ(fp_cmp_gpu(stream, gpu_index, &three, &five),
            ComparisonType::Less); // 3 < 5

  EXPECT_EQ(fp_cmp_gpu(stream, gpu_index, &five, &five),
            ComparisonType::Equal); // 5 == 5
}

// Test zero and one (on GPU)
TEST_F(FpArithmeticTest, ZeroAndOne) {
  uint64_t size_tracker = 0;
  Fp zero, one;

  fp_zero(zero);
  fp_one(one);

  // Test on GPU
  EXPECT_TRUE(fp_is_zero_gpu(stream, gpu_index, &zero));

  EXPECT_FALSE(fp_is_zero_gpu(stream, gpu_index, &one));

  EXPECT_TRUE(fp_is_one_gpu(stream, gpu_index, &one));

  EXPECT_FALSE(fp_is_one_gpu(stream, gpu_index, &zero));
}

// Test copy (on GPU)
TEST_F(FpArithmeticTest, Copy) {
  uint64_t size_tracker = 0;
  Fp a, b, b_cpu;

  fp_zero(a);
  a.limb[0] = 42;
  a.limb[1] = 123;

  // Test on GPU
  fp_copy_gpu(stream, gpu_index, &b, &a);

  // Also test on CPU for comparison
  fp_copy(b_cpu, a);

  EXPECT_EQ(fp_cmp_gpu(stream, gpu_index, &a, &b), ComparisonType::Equal);
  cuda_synchronize_stream(stream, gpu_index);
  // Verify GPU result matches CPU result
  EXPECT_EQ(fp_cmp_gpu(stream, gpu_index, &b, &b_cpu), ComparisonType::Equal)
      << "GPU result should match CPU result";
  cuda_synchronize_stream(stream, gpu_index);
}

// Test conditional move (on GPU)
TEST_F(FpArithmeticTest, ConditionalMove) {
  uint64_t size_tracker = 0;
  Fp a, b, result, result_cpu;

  fp_zero(a);
  fp_zero(b);
  a.limb[0] = 10;
  b.limb[0] = 20;

  // Test move when condition is true (1) on GPU
  fp_copy_gpu(stream, gpu_index, &result, &a);
  fp_cmov_gpu(stream, gpu_index, &result, &b, 1);

  // Also test on CPU for comparison
  fp_copy(result_cpu, a);
  fp_cmov(result_cpu, b, 1);

  EXPECT_EQ(fp_cmp_gpu(stream, gpu_index, &result, &b), ComparisonType::Equal);
  cuda_synchronize_stream(stream, gpu_index);
  EXPECT_EQ(fp_cmp_gpu(stream, gpu_index, &result, &result_cpu),
            ComparisonType::Equal)
      << "GPU result should match CPU result";
  cuda_synchronize_stream(stream, gpu_index);

  // Test no move when condition is false (0) on GPU
  fp_copy_gpu(stream, gpu_index, &result, &a);
  fp_cmov_gpu(stream, gpu_index, &result, &b, 0);

  // Also test on CPU for comparison
  fp_copy(result_cpu, a);
  fp_cmov(result_cpu, b, 0);

  EXPECT_EQ(fp_cmp_gpu(stream, gpu_index, &result, &a), ComparisonType::Equal);
  cuda_synchronize_stream(stream, gpu_index);
  EXPECT_EQ(fp_cmp_gpu(stream, gpu_index, &result, &result_cpu),
            ComparisonType::Equal)
      << "GPU result should match CPU result";
  cuda_synchronize_stream(stream, gpu_index);
}

// Test multiplication by zero (on GPU)
TEST_F(FpArithmeticTest, MultiplicationByZero) {
  uint64_t size_tracker = 0;
  Fp a, zero, result, result_cpu;

  fp_zero(zero);
  fp_zero(a);
  a.limb[0] = 5;

  // Test on GPU
  fp_mul_gpu(stream, gpu_index, &result, &a, &zero);

  // Also test on CPU for comparison
  // operator* expects Montgomery-form inputs and returns Montgomery form
  Fp a_m, zero_m;
  fp_to_montgomery(a_m, a);
  fp_to_montgomery(zero_m, zero);
  Fp result_cpu_mont = a_m * zero_m;
  fp_from_montgomery(result_cpu, result_cpu_mont);

  EXPECT_TRUE(fp_is_zero_gpu(stream, gpu_index, &result));
  cuda_synchronize_stream(stream, gpu_index);
  EXPECT_EQ(fp_cmp_gpu(stream, gpu_index, &result, &result_cpu),
            ComparisonType::Equal)
      << "GPU result should match CPU result";
  cuda_synchronize_stream(stream, gpu_index);
}

// Test inversion (on GPU)
TEST_F(FpArithmeticTest, Inversion) {
  uint64_t size_tracker = 0;
  Fp a, a_inv, result, a_inv_cpu;

  fp_zero(a);
  a.limb[0] = 5;

  // Test on GPU
  fp_inv_gpu(stream, gpu_index, &a_inv, &a);
  fp_mul_gpu(stream, gpu_index, &result, &a, &a_inv);

  // Also test on CPU for comparison
  // fp_inv returns normal form, convert both operands to Montgomery for
  // operator*
  fp_inv(a_inv_cpu, a);
  Fp a_m, a_inv_cpu_m;
  fp_to_montgomery(a_m, a);
  fp_to_montgomery(a_inv_cpu_m, a_inv_cpu);
  Fp result_cpu_mont = a_m * a_inv_cpu_m;
  Fp result_cpu;
  fp_from_montgomery(result_cpu, result_cpu_mont);

  EXPECT_TRUE(fp_is_one_gpu(stream, gpu_index, &result))
      << "a * a^(-1) should equal 1";
  cuda_synchronize_stream(stream, gpu_index);
  EXPECT_EQ(fp_cmp_gpu(stream, gpu_index, &result, &result_cpu),
            ComparisonType::Equal)
      << "GPU result should match CPU result";
  cuda_synchronize_stream(stream, gpu_index);
}

// Test inversion of one (on GPU)
TEST_F(FpArithmeticTest, InversionOfOne) {
  uint64_t size_tracker = 0;
  Fp one, one_inv, one_inv_cpu;

  fp_one(one);

  // Test on GPU
  fp_inv_gpu(stream, gpu_index, &one_inv, &one);

  // Also test on CPU for comparison
  fp_inv(one_inv_cpu, one);

  EXPECT_TRUE(fp_is_one_gpu(stream, gpu_index, &one_inv))
      << "1^(-1) should equal 1";
  cuda_synchronize_stream(stream, gpu_index);
  EXPECT_EQ(fp_cmp_gpu(stream, gpu_index, &one_inv, &one_inv_cpu),
            ComparisonType::Equal)
      << "GPU result should match CPU result";
  cuda_synchronize_stream(stream, gpu_index);
}

// Test division (on GPU)
TEST_F(FpArithmeticTest, Division) {
  uint64_t size_tracker = 0;
  Fp a, b, quotient, result;

  fp_zero(a);
  fp_zero(b);
  a.limb[0] = 15;
  b.limb[0] = 3;

  // Test on GPU
  fp_div_gpu(stream, gpu_index, &quotient, &a, &b);
  fp_mul_gpu(stream, gpu_index, &result, &quotient, &b);

  // operator/ now expects Montgomery-form inputs and returns Montgomery form
  Fp a_m, b_m;
  fp_to_montgomery(a_m, a);
  fp_to_montgomery(b_m, b);
  Fp quotient_cpu_m = a_m / b_m;
  // quotient_cpu_m * b_m should give a_m back
  Fp result_cpu_mont = quotient_cpu_m * b_m;
  Fp result_cpu;
  fp_from_montgomery(result_cpu, result_cpu_mont);

  EXPECT_EQ(fp_cmp_gpu(stream, gpu_index, &result, &a), ComparisonType::Equal)
      << "quotient * b should equal a";
  cuda_synchronize_stream(stream, gpu_index);
  EXPECT_EQ(fp_cmp_gpu(stream, gpu_index, &result, &result_cpu),
            ComparisonType::Equal)
      << "GPU result should match CPU result";
  cuda_synchronize_stream(stream, gpu_index);
}

// Test division by one (on GPU)
TEST_F(FpArithmeticTest, DivisionByOne) {
  uint64_t size_tracker = 0;
  Fp a, one, result;

  fp_one(one);
  fp_zero(a);
  a.limb[0] = 42;

  // Test on GPU
  fp_div_gpu(stream, gpu_index, &result, &a, &one);

  // operator/ expects Montgomery-form inputs, returns Montgomery form
  Fp a_m, one_m;
  fp_to_montgomery(a_m, a);
  fp_to_montgomery(one_m, one);
  Fp result_cpu_m = a_m / one_m;
  Fp result_cpu;
  fp_from_montgomery(result_cpu, result_cpu_m);

  EXPECT_EQ(fp_cmp_gpu(stream, gpu_index, &result, &a), ComparisonType::Equal)
      << "a / 1 should equal a";
  cuda_synchronize_stream(stream, gpu_index);
  EXPECT_EQ(fp_cmp_gpu(stream, gpu_index, &result, &result_cpu),
            ComparisonType::Equal)
      << "GPU result should match CPU result";
  cuda_synchronize_stream(stream, gpu_index);
}

// Test exponentiation with small exponent (on GPU)
TEST_F(FpArithmeticTest, ExponentiationSmall) {
  uint64_t size_tracker = 0;
  Fp base, result, expected, result_cpu;

  fp_zero(base);
  base.limb[0] = 5;

  fp_zero(expected);
  expected.limb[0] = 125;

  // Test on GPU
  fp_pow_u64_gpu(stream, gpu_index, &result, &base, 3);

  // Also test on CPU for comparison
  fp_pow_u64(result_cpu, base, 3);

  EXPECT_EQ(fp_cmp_gpu(stream, gpu_index, &result, &expected),
            ComparisonType::Equal)
      << "5^3 should equal 125";
  cuda_synchronize_stream(stream, gpu_index);
  EXPECT_EQ(fp_cmp_gpu(stream, gpu_index, &result, &result_cpu),
            ComparisonType::Equal)
      << "GPU result should match CPU result";
  cuda_synchronize_stream(stream, gpu_index);
}

// Test exponentiation to power of one (on GPU)
TEST_F(FpArithmeticTest, ExponentiationToPowerOfOne) {
  uint64_t size_tracker = 0;
  Fp base, result, result_cpu;

  fp_zero(base);
  base.limb[0] = 42;

  // Test on GPU
  fp_pow_u64_gpu(stream, gpu_index, &result, &base, 1);

  // Also test on CPU for comparison
  fp_pow_u64(result_cpu, base, 1);

  EXPECT_EQ(fp_cmp_gpu(stream, gpu_index, &result, &base),
            ComparisonType::Equal)
      << "a^1 should equal a";
  cuda_synchronize_stream(stream, gpu_index);
  EXPECT_EQ(fp_cmp_gpu(stream, gpu_index, &result, &result_cpu),
            ComparisonType::Equal)
      << "GPU result should match CPU result";
  cuda_synchronize_stream(stream, gpu_index);
}

// Test exponentiation to power of zero (on GPU)
TEST_F(FpArithmeticTest, ExponentiationToPowerOfZero) {
  uint64_t size_tracker = 0;
  Fp base, result, one, result_cpu;

  fp_zero(base);
  base.limb[0] = 42;
  fp_one(one);

  // Test on GPU
  fp_pow_u64_gpu(stream, gpu_index, &result, &base, 0);

  // Also test on CPU for comparison
  fp_pow_u64(result_cpu, base, 0);

  EXPECT_TRUE(fp_is_one_gpu(stream, gpu_index, &result))
      << "a^0 should equal 1";
  cuda_synchronize_stream(stream, gpu_index);
  EXPECT_EQ(fp_cmp_gpu(stream, gpu_index, &result, &result_cpu),
            ComparisonType::Equal)
      << "GPU result should match CPU result";
  cuda_synchronize_stream(stream, gpu_index);
}

// Test exponentiation with large exponent (Fermat's little theorem)
TEST_F(FpArithmeticTest, ExponentiationFermat) {
  uint64_t size_tracker = 0;
  Fp a, result;

  fp_zero(a);
  a.limb[0] = 5;

  // a^p mod p = a mod p (Fermat's little theorem)
  const Fp &p = fp_modulus();
  fp_pow(result, a, p.limb, FP_LIMBS);

  EXPECT_EQ(fp_cmp(result, a), ComparisonType::Equal)
      << "a^p mod p should equal a (Fermat's little theorem)";
}

// Test exponentiation: a^(p-1) = 1 mod p
TEST_F(FpArithmeticTest, ExponentiationFermatInverse) {
  uint64_t size_tracker = 0;
  Fp a, result, one;

  fp_zero(a);
  a.limb[0] = 5;
  fp_one(one);

  // Skip if a is zero
  if (fp_is_zero(a)) {
    return;
  }

  // a^(p-1) mod p = 1 (Fermat's little theorem)
  Fp p_minus_1 = modulus_minus_one;
  fp_pow(result, a, p_minus_1.limb, FP_LIMBS);

  EXPECT_TRUE(fp_is_one(result))
      << "a^(p-1) mod p should equal 1 (Fermat's little theorem)";
}

// Test square root (on GPU)
TEST_F(FpArithmeticTest, SquareRoot) {
  uint64_t size_tracker = 0;
  Fp a, square, sqrt_result, verify, square_cpu, sqrt_result_cpu, verify_cpu;

  // Test: sqrt(a^2) = a or -a
  fp_zero(a);
  a.limb[0] = 5;

  // Compute a^2 (on GPU)
  fp_mul_gpu(stream, gpu_index, &square, &a, &a);

  // Also test on CPU for comparison
  // operator* expects Montgomery-form inputs and returns Montgomery form
  Fp a_m;
  fp_to_montgomery(a_m, a);
  Fp square_cpu_mont = a_m * a_m;
  fp_from_montgomery(square_cpu, square_cpu_mont);

  // Verify that square is a quadratic residue (on GPU)
  EXPECT_TRUE(fp_is_quadratic_residue_gpu(stream, gpu_index, &square))
      << "Square should be a quadratic residue";

  // Compute sqrt(a^2) (on GPU)
  bool has_sqrt = fp_sqrt_gpu(stream, gpu_index, &sqrt_result, &square);

  EXPECT_TRUE(has_sqrt)
      << "Square of non-zero element should have a square root";

  if (has_sqrt) {
    // Verify: sqrt_result^2 = square (on GPU)
    fp_mul_gpu(stream, gpu_index, &verify, &sqrt_result, &sqrt_result);
    cuda_synchronize_stream(stream, gpu_index);

    // Also test on CPU for comparison
    // fp_sqrt returns normal form; convert to Montgomery for operator*
    fp_sqrt(sqrt_result_cpu, square_cpu);
    Fp sqrt_result_cpu_m;
    fp_to_montgomery(sqrt_result_cpu_m, sqrt_result_cpu);
    Fp verify_cpu_mont = sqrt_result_cpu_m * sqrt_result_cpu_m;
    fp_from_montgomery(verify_cpu, verify_cpu_mont);

    EXPECT_EQ(fp_cmp_gpu(stream, gpu_index, &verify, &square),
              ComparisonType::Equal)
        << "sqrt(a^2)^2 should equal a^2";
    cuda_synchronize_stream(stream, gpu_index);

    // Verify sqrt_result is either a or -a (on GPU)
    Fp neg_a;
    fp_neg_gpu(stream, gpu_index, &neg_a, &a);

    // Also test on CPU for comparison
    Fp neg_a_cpu = -a;

    bool matches_a = (fp_cmp_gpu(stream, gpu_index, &sqrt_result, &a) ==
                      ComparisonType::Equal);
    cuda_synchronize_stream(stream, gpu_index);
    bool matches_neg_a = (fp_cmp_gpu(stream, gpu_index, &sqrt_result, &neg_a) ==
                          ComparisonType::Equal);
    cuda_synchronize_stream(stream, gpu_index);
    EXPECT_TRUE(matches_a || matches_neg_a)
        << "sqrt(a^2) should equal either a or -a";

    // Verify GPU result matches CPU result
    EXPECT_EQ(fp_cmp_gpu(stream, gpu_index, &sqrt_result, &sqrt_result_cpu),
              ComparisonType::Equal)
        << "GPU result should match CPU result";
    cuda_synchronize_stream(stream, gpu_index);
  }
}

// Test square root of zero (on GPU)
TEST_F(FpArithmeticTest, SquareRootOfZero) {
  uint64_t size_tracker = 0;
  Fp zero, result, result_cpu;
  fp_zero(zero);

  // Test on GPU
  bool has_sqrt = fp_sqrt_gpu(stream, gpu_index, &result, &zero);

  // Also test on CPU for comparison
  bool has_sqrt_cpu = fp_sqrt(result_cpu, zero);

  EXPECT_TRUE(has_sqrt) << "sqrt(0) should exist";
  EXPECT_TRUE(fp_is_zero_gpu(stream, gpu_index, &result))
      << "sqrt(0) should equal 0";
  cuda_synchronize_stream(stream, gpu_index);
  EXPECT_EQ(fp_cmp_gpu(stream, gpu_index, &result, &result_cpu),
            ComparisonType::Equal)
      << "GPU result should match CPU result";
  cuda_synchronize_stream(stream, gpu_index);
}

// Test square root of one (on GPU)
TEST_F(FpArithmeticTest, SquareRootOfOne) {
  uint64_t size_tracker = 0;
  Fp one, result, result_cpu;
  fp_one(one);

  // Test on GPU
  bool has_sqrt = fp_sqrt_gpu(stream, gpu_index, &result, &one);

  // Also test on CPU for comparison
  bool has_sqrt_cpu = fp_sqrt(result_cpu, one);

  EXPECT_TRUE(has_sqrt) << "sqrt(1) should exist";
  EXPECT_TRUE(fp_is_one_gpu(stream, gpu_index, &result))
      << "sqrt(1) should equal 1";
  cuda_synchronize_stream(stream, gpu_index);
  EXPECT_EQ(fp_cmp_gpu(stream, gpu_index, &result, &result_cpu),
            ComparisonType::Equal)
      << "GPU result should match CPU result";
  cuda_synchronize_stream(stream, gpu_index);
}

// Test quadratic residue check (on GPU)
TEST_F(FpArithmeticTest, IsQuadraticResidue) {
  uint64_t size_tracker = 0;
  Fp a, square, square_cpu, zero;

  fp_zero(a);
  a.limb[0] = 5;
  fp_zero(zero);

  // a^2 is always a quadratic residue (on GPU)
  fp_mul_gpu(stream, gpu_index, &square, &a, &a);

  // Also test on CPU for comparison
  // operator* expects Montgomery-form inputs and returns Montgomery form
  Fp a_m;
  fp_to_montgomery(a_m, a);
  Fp square_cpu_mont = a_m * a_m;
  fp_from_montgomery(square_cpu, square_cpu_mont);

  EXPECT_TRUE(fp_is_quadratic_residue_gpu(stream, gpu_index, &square))
      << "Square of any element should be a quadratic residue";
  cuda_synchronize_stream(stream, gpu_index);
  EXPECT_TRUE(fp_is_quadratic_residue_gpu(stream, gpu_index, &zero))
      << "Zero should be a quadratic residue";
  cuda_synchronize_stream(stream, gpu_index);

  Fp one;
  fp_one(one);
  EXPECT_TRUE(fp_is_quadratic_residue_gpu(stream, gpu_index, &one))
      << "One should be a quadratic residue";
  cuda_synchronize_stream(stream, gpu_index);
}

// Test batch Montgomery conversion (on GPU)
// Note: batch functions are __host__ __device__, so they can be called from
// device. For now, we test individual conversions on GPU and verify with GPU
// comparisons
TEST_F(FpArithmeticTest, BatchMontgomeryConversion) {
  uint64_t size_tracker = 0;
  const int n = 10;
  Fp normal[n], montgomery[n], back[n];

  // Initialize with small values
  for (int i = 0; i < n; i++) {
    fp_zero(normal[i]);
    normal[i].limb[0] = i + 1;
  }

  // Convert to Montgomery (individual GPU calls for testing)
  for (int i = 0; i < n; i++) {
    fp_to_montgomery_gpu(stream, gpu_index, &montgomery[i], &normal[i]);
  }
  cuda_synchronize_stream(stream, gpu_index);

  // Convert back (individual GPU calls for testing)
  for (int i = 0; i < n; i++) {
    fp_from_montgomery_gpu(stream, gpu_index, &back[i], &montgomery[i]);
  }
  cuda_synchronize_stream(stream, gpu_index);

  // Verify round-trip (on GPU)
  for (int i = 0; i < n; i++) {
    EXPECT_EQ(fp_cmp_gpu(stream, gpu_index, &back[i], &normal[i]),
              ComparisonType::Equal)
        << "Batch Montgomery round-trip failed at index " << i;
    cuda_synchronize_stream(stream, gpu_index);
  }
}

// ============================================================================
// Hardcoded Large Value Tests - Testing with values near modulus
// These tests use hardcoded 64-bit limb values, so they're only valid for
// 64-bit limb configurations.
// ============================================================================
#if LIMB_BITS_CONFIG == 64

// Test 1: Addition that doesn't overflow (on GPU)
TEST_F(FpArithmeticTest, LargeAddition1) {
  uint64_t size_tracker = 0;
  // a = large value
  Fp a = test_utils::make_fp(0x18e00013555855ULL, 0x2b772294629DAULL,
                             0x412736E1F11D66ULL, 0x87BAD325DD638ULL,
                             0x4CAD5BC5017FULL, 0x1007E1A4B2D56ULL,
                             0x1E6F707D94629ULL);

  // b = small value
  Fp b = test_utils::make_fp(0x1234567890ABCULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL,
                             0x0ULL, 0x0ULL);

  // Test on GPU
  Fp result, result2, expected_cpu;
  fp_add_gpu(stream, gpu_index, &result, &a, &b);

  // Also test on CPU for comparison
  expected_cpu = a + b;

  EXPECT_EQ(fp_cmp_gpu(stream, gpu_index, &result, &expected_cpu),
            ComparisonType::Equal)
      << "Large addition without overflow failed";
  cuda_synchronize_stream(stream, gpu_index);

  // Verify commutativity: a + b = b + a (on GPU)
  fp_add_gpu(stream, gpu_index, &result2, &b, &a);
  EXPECT_EQ(fp_cmp_gpu(stream, gpu_index, &result, &result2),
            ComparisonType::Equal)
      << "Addition commutativity failed";
  cuda_synchronize_stream(stream, gpu_index);
}

// Test 2: Addition that triggers reduction (sum > p) (on GPU)
TEST_F(FpArithmeticTest, LargeAddition2WithReduction) {
  uint64_t size_tracker = 0;
  // Use two large numbers that will trigger reduction
  // a + b should wrap around modulus
  Fp a = test_utils::make_fp(0x311c0026aab0aaaaULL, 0x56ee4528c573b5ccULL,
                             0x824e6dc3e23acdeeULL, 0x0f75a64bbac71602ULL,
                             0x0095a4b78a02fe32ULL, 0x200fc34965aad640ULL,
                             0x3cdee0fb28c5e535ULL);

  // b = 1 (so a+b should wrap to 0 if a = p-1)
  Fp b;
  fp_zero(b);
  b.limb[0] = 1;

  // Test on GPU
  Fp result, result_cpu;
  fp_add_gpu(stream, gpu_index, &result, &a, &b);

  // Also test on CPU for comparison
  result_cpu = a + b;

  // (p-1) + 1 = 0 (mod p)
  EXPECT_TRUE(fp_is_zero_gpu(stream, gpu_index, &result))
      << "Addition with reduction (p-1)+1 should equal 0";
  cuda_synchronize_stream(stream, gpu_index);
  EXPECT_EQ(fp_cmp_gpu(stream, gpu_index, &result, &result_cpu),
            ComparisonType::Equal)
      << "GPU result should match CPU result";
  cuda_synchronize_stream(stream, gpu_index);
}

// Test 3: Subtraction without borrow (on GPU)
TEST_F(FpArithmeticTest, LargeSubtraction1) {
  uint64_t size_tracker = 0;
  // a = large value
  Fp a = test_utils::make_fp(0x18e00013555855ULL, 0x2b772294629DAULL,
                             0x412736E1F11D66ULL, 0x87BAD325DD638ULL,
                             0x4CAD5BC5017FULL, 0x1007E1A4B2D56ULL,
                             0x1E6F707D94629ULL);

  // b = 1000
  Fp b;
  fp_zero(b);
  b.limb[0] = 1000;

  // Test on GPU
  Fp result, verify, result_cpu, verify_cpu;
  fp_sub_gpu(stream, gpu_index, &result, &a, &b);

  // Verify: (a - b) + b = a (on GPU)
  fp_add_gpu(stream, gpu_index, &verify, &result, &b);

  // Also test on CPU for comparison
  result_cpu = a - b;
  verify_cpu = result_cpu + b;

  EXPECT_EQ(fp_cmp_gpu(stream, gpu_index, &verify, &a), ComparisonType::Equal)
      << "Large subtraction failed: (a-b)+b != a";
  cuda_synchronize_stream(stream, gpu_index);
  EXPECT_EQ(fp_cmp_gpu(stream, gpu_index, &result, &result_cpu),
            ComparisonType::Equal)
      << "GPU result should match CPU result";
  cuda_synchronize_stream(stream, gpu_index);
}

// Test 4: Subtraction with borrow (a < b) (on GPU)
TEST_F(FpArithmeticTest, LargeSubtraction2WithBorrow) {
  uint64_t size_tracker = 0;
  // a = 50
  Fp a = test_utils::make_fp(0x32ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL,
                             0x0ULL);

  // b = 100
  Fp b = test_utils::make_fp(0x64ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL,
                             0x0ULL);

  // Expected: 50 - 100 = -50 = p - 50 (mod p)
  Fp expected = test_utils::make_fp(
      0x311c0026aab0aa79ULL, 0x56ee4528c573b5ccULL, 0x824e6dc3e23acdeeULL,
      0xf75a64bbac71602ULL, 0x95a4b78a02fe32ULL, 0x200fc34965aad640ULL,
      0x3cdee0fb28c5e535ULL);

  // Test on GPU
  Fp result, result_cpu;
  fp_sub_gpu(stream, gpu_index, &result, &a, &b);

  // Also test on CPU for comparison
  result_cpu = a - b;

  EXPECT_EQ(fp_cmp_gpu(stream, gpu_index, &result, &expected),
            ComparisonType::Equal)
      << "Subtraction with borrow failed";
  cuda_synchronize_stream(stream, gpu_index);
  EXPECT_EQ(fp_cmp_gpu(stream, gpu_index, &result, &result_cpu),
            ComparisonType::Equal)
      << "GPU result should match CPU result";
  cuda_synchronize_stream(stream, gpu_index);
}

// Test 5: Multiplication of large values (triggers reduction) (on GPU)
TEST_F(FpArithmeticTest, LargeMultiplication1) {
  uint64_t size_tracker = 0;
  // a = 2^200 (bit 200 set)
  Fp a;
  fp_zero(a);
  a.limb[3] = 0x100ULL; // bit 200 = bit 8 of limb 3

  // b = 2^100 (bit 100 set)
  Fp b;
  fp_zero(b);
  b.limb[1] = 0x10ULL; // bit 100 = bit 36 of limb 1

  // Test on GPU
  Fp result, verify, result2, one, result_cpu;
  fp_mul_gpu(stream, gpu_index, &result, &a, &b);

  // Verify: a * b * 1 = a * b (consistency check) (on GPU)
  fp_one(one);
  fp_mul_gpu(stream, gpu_index, &verify, &result, &one);

  // Also test on CPU for comparison
  // operator* expects Montgomery-form inputs and returns Montgomery form
  Fp a_m, b_m;
  fp_to_montgomery(a_m, a);
  fp_to_montgomery(b_m, b);
  Fp result_cpu_mont = a_m * b_m;
  fp_from_montgomery(result_cpu, result_cpu_mont);

  EXPECT_EQ(fp_cmp_gpu(stream, gpu_index, &result, &verify),
            ComparisonType::Equal)
      << "Large multiplication consistency failed";
  cuda_synchronize_stream(stream, gpu_index);

  // Verify commutativity: a * b = b * a (on GPU)
  fp_mul_gpu(stream, gpu_index, &result2, &b, &a);
  EXPECT_EQ(fp_cmp_gpu(stream, gpu_index, &result, &result2),
            ComparisonType::Equal)
      << "Multiplication commutativity failed";
  cuda_synchronize_stream(stream, gpu_index);
  EXPECT_EQ(fp_cmp_gpu(stream, gpu_index, &result, &result_cpu),
            ComparisonType::Equal)
      << "GPU result should match CPU result";
  cuda_synchronize_stream(stream, gpu_index);
}

// Test 6: (p-1) * (p-1) = 1 (mod p) (on GPU)
TEST_F(FpArithmeticTest, LargeMultiplication2ModulusMinus1) {
  uint64_t size_tracker = 0;
  // a = p - 1
  Fp a = test_utils::make_fp(0x311c0026aab0aaaaULL, 0x56ee4528c573b5ccULL,
                             0x824e6dc3e23acdeeULL, 0xf75a64bbac71602ULL,
                             0x95a4b78a02fe32ULL, 0x200fc34965aad640ULL,
                             0x3cdee0fb28c5e535ULL);

  // b = p - 1
  Fp b = a;

  // Expected: (p-1) * (p-1) = p^2 - 2p + 1 = 1 (mod p)
  Fp expected = test_utils::make_fp(0x1ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL,
                                    0x0ULL, 0x0ULL);

  // Test on GPU
  Fp result, result_cpu;
  fp_mul_gpu(stream, gpu_index, &result, &a, &b);

  // Also test on CPU for comparison
  // operator* expects Montgomery-form inputs and returns Montgomery form
  Fp a_m, b_m;
  fp_to_montgomery(a_m, a);
  fp_to_montgomery(b_m, b);
  Fp result_cpu_mont = a_m * b_m;
  fp_from_montgomery(result_cpu, result_cpu_mont);

  EXPECT_EQ(fp_cmp_gpu(stream, gpu_index, &result, &expected),
            ComparisonType::Equal)
      << "(p-1) * (p-1) should equal 1";
  cuda_synchronize_stream(stream, gpu_index);
  EXPECT_EQ(fp_cmp_gpu(stream, gpu_index, &result, &result_cpu),
            ComparisonType::Equal)
      << "GPU result should match CPU result";
  cuda_synchronize_stream(stream, gpu_index);
}

// Test 7: Multiplication with 2: a * 2 = a + a (on GPU)
TEST_F(FpArithmeticTest, LargeMultiplication3Half) {
  uint64_t size_tracker = 0;
  // a = large value
  Fp a = test_utils::make_fp(0x18e00013555855ULL, 0x2b772294629DAE6ULL,
                             0x412736E1F11D66F7ULL, 0x7BAD325DD638B01ULL,
                             0x4CAD5BC5017F19ULL, 0x1007E1A4B2D56B20ULL,
                             0x1E6F707D9462F2ULL);

  // b = 2
  Fp b;
  fp_zero(b);
  b.limb[0] = 2;

  // Test on GPU
  Fp result, expected, result_cpu, expected_cpu;
  fp_mul_gpu(stream, gpu_index, &result, &a, &b);

  // Verify: a * 2 = a + a (on GPU)
  fp_add_gpu(stream, gpu_index, &expected, &a, &a);

  // Also test on CPU for comparison
  // operator* expects Montgomery-form inputs and returns Montgomery form
  Fp a_m, b_m;
  fp_to_montgomery(a_m, a);
  fp_to_montgomery(b_m, b);
  Fp result_cpu_mont = a_m * b_m;
  fp_from_montgomery(result_cpu, result_cpu_mont);
  expected_cpu = a + a;

  EXPECT_EQ(fp_cmp_gpu(stream, gpu_index, &result, &expected),
            ComparisonType::Equal)
      << "a * 2 should equal a + a";
  cuda_synchronize_stream(stream, gpu_index);
  EXPECT_EQ(fp_cmp_gpu(stream, gpu_index, &result, &result_cpu),
            ComparisonType::Equal)
      << "GPU result should match CPU result";
  cuda_synchronize_stream(stream, gpu_index);
}

// Test 8: Large number squared (on GPU)
TEST_F(FpArithmeticTest, LargeMultiplication4Square) {
  uint64_t size_tracker = 0;
  // a = large value
  Fp a = test_utils::make_fp(0x123456789ABCDEFULL, 0xFEDCBA9876543210ULL,
                             0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL);

  // Test on GPU
  Fp result, verify, one, result_cpu;
  fp_mul_gpu(stream, gpu_index, &result, &a, &a);

  // Verify: a^2 * 1 = a^2 (on GPU)
  fp_one(one);
  fp_mul_gpu(stream, gpu_index, &verify, &result, &one);

  // Also test on CPU for comparison
  // operator* expects Montgomery-form inputs and returns Montgomery form
  Fp a_m;
  fp_to_montgomery(a_m, a);
  Fp result_cpu_mont = a_m * a_m;
  fp_from_montgomery(result_cpu, result_cpu_mont);

  EXPECT_EQ(fp_cmp_gpu(stream, gpu_index, &result, &verify),
            ComparisonType::Equal)
      << "Square consistency check failed";
  cuda_synchronize_stream(stream, gpu_index);

  // Verify: a^2 should not equal zero (unless a is zero) (on GPU)
  EXPECT_FALSE(fp_is_zero_gpu(stream, gpu_index, &result))
      << "Square of non-zero element is zero";
  cuda_synchronize_stream(stream, gpu_index);
  EXPECT_EQ(fp_cmp_gpu(stream, gpu_index, &result, &result_cpu),
            ComparisonType::Equal)
      << "GPU result should match CPU result";
  cuda_synchronize_stream(stream, gpu_index);
}

// Test 9: Addition chain near modulus (on GPU)
TEST_F(FpArithmeticTest, LargeAddition3Chain) {
  uint64_t size_tracker = 0;
  // Start with p-1
  Fp a = test_utils::make_fp(0x311c0026aab0aaaaULL, 0x56ee4528c573b5ccULL,
                             0x824e6dc3e23acdeeULL, 0x0f75a64bbac71602ULL,
                             0x0095a4b78a02fe32ULL, 0x200fc34965aad640ULL,
                             0x3cdee0fb28c5e535ULL);

  // Add 1 repeatedly
  Fp one;
  fp_one(one);

  // Test on GPU
  Fp result = a;

  // (p-1) + 1 = 0, then 0 + 1 = 1 (on GPU)
  fp_add_gpu(stream, gpu_index, &result, &result, &one); // result should be 0
  EXPECT_TRUE(fp_is_zero_gpu(stream, gpu_index, &result))
      << "Addition chain: (p-1)+1 should be 0";

  fp_add_gpu(stream, gpu_index, &result, &result, &one); // result should be 1
  EXPECT_EQ(fp_cmp_gpu(stream, gpu_index, &result, &one), ComparisonType::Equal)
      << "Addition chain: 0+1 should be 1";
  cuda_synchronize_stream(stream, gpu_index);
}

// Test 10: Complex multiplication with reduction (on GPU)
TEST_F(FpArithmeticTest, LargeMultiplication5Complex) {
  uint64_t size_tracker = 0;
  // a = large prime-like number
  Fp a = test_utils::make_fp(0x123456789ABCDEFULL, 0xFEDCBA9876543210ULL,
                             0x0123456789ABCDEFULL, 0xFEDCBA9876543210ULL,
                             0x123456789ABULL, 0x1000000000000ULL,
                             0x10000000000ULL);

  // b = another large number
  Fp b = test_utils::make_fp(0xABCDEF0123456789ULL, 0x0123456789ABCDEFULL,
                             0xFEDCBA9876543210ULL, 0x123456789ABCDEFULL,
                             0xFEDCBA98765ULL, 0x2000000000000ULL,
                             0x20000000000ULL);

  // Test on GPU
  Fp result, verify, one, result2, result_cpu;
  fp_mul_gpu(stream, gpu_index, &result, &a, &b);

  // Verify: (a * b) * 1 = a * b (on GPU)
  fp_one(one);
  fp_mul_gpu(stream, gpu_index, &verify, &result, &one);

  // Also test on CPU for comparison
  // operator* expects Montgomery-form inputs and returns Montgomery form
  Fp a_m, b_m;
  fp_to_montgomery(a_m, a);
  fp_to_montgomery(b_m, b);
  Fp result_cpu_mont = a_m * b_m;
  fp_from_montgomery(result_cpu, result_cpu_mont);

  EXPECT_EQ(fp_cmp_gpu(stream, gpu_index, &result, &verify),
            ComparisonType::Equal)
      << "Complex large multiplication consistency check failed";
  cuda_synchronize_stream(stream, gpu_index);

  // Verify: a * b = b * a (commutativity) (on GPU)
  fp_mul_gpu(stream, gpu_index, &result2, &b, &a);
  EXPECT_EQ(fp_cmp_gpu(stream, gpu_index, &result, &result2),
            ComparisonType::Equal)
      << "Multiplication commutativity failed for large values";
  cuda_synchronize_stream(stream, gpu_index);
  EXPECT_EQ(fp_cmp_gpu(stream, gpu_index, &result, &result_cpu),
            ComparisonType::Equal)
      << "GPU result should match CPU result";
  cuda_synchronize_stream(stream, gpu_index);
}

#endif // LIMB_BITS_CONFIG == 64

// ============================================================================
// Property-Based Tests
// ============================================================================

// Test addition associativity: (a + b) + c = a + (b + c) (on GPU)
TEST_F(FpPropertyTest, AdditionAssociativity) {
  uint64_t size_tracker = 0;
  for (int i = 0; i < 100; i++) {
    Fp a = random_value();
    Fp b = random_value();
    Fp c = random_value();

    Fp result1, result2;
    Fp temp;

    // (a + b) + c (on GPU)
    fp_add_gpu(stream, gpu_index, &temp, &a, &b);
    fp_add_gpu(stream, gpu_index, &result1, &temp, &c);

    // a + (b + c) (on GPU)
    fp_add_gpu(stream, gpu_index, &temp, &b, &c);
    fp_add_gpu(stream, gpu_index, &result2, &a, &temp);

    EXPECT_EQ(fp_cmp_gpu(stream, gpu_index, &result1, &result2),
              ComparisonType::Equal)
        << "Addition associativity failed: (a+b)+c != a+(b+c)";
    cuda_synchronize_stream(stream, gpu_index);
  }
}

// Test multiplication associativity: (a * b) * c = a * (b * c) (on GPU)
TEST_F(FpPropertyTest, MultiplicationAssociativity) {
  uint64_t size_tracker = 0;
  for (int i = 0; i < 50; i++) { // Fewer iterations due to multiplication cost
    Fp a = random_value();
    Fp b = random_value();
    Fp c = random_value();

    Fp result1, result2;
    Fp temp;

    // (a * b) * c (on GPU)
    fp_mul_gpu(stream, gpu_index, &temp, &a, &b);
    fp_mul_gpu(stream, gpu_index, &result1, &temp, &c);

    // a * (b * c) (on GPU)
    fp_mul_gpu(stream, gpu_index, &temp, &b, &c);
    fp_mul_gpu(stream, gpu_index, &result2, &a, &temp);

    EXPECT_EQ(fp_cmp_gpu(stream, gpu_index, &result1, &result2),
              ComparisonType::Equal)
        << "Multiplication associativity failed: (a*b)*c != a*(b*c)";
    cuda_synchronize_stream(stream, gpu_index);
  }
}

// Test distributivity: a * (b + c) = a*b + a*c (on GPU)
TEST_F(FpPropertyTest, MultiplicationDistributivity) {
  uint64_t size_tracker = 0;
  for (int i = 0; i < 50; i++) {
    Fp a = random_value();
    Fp b = random_value();
    Fp c = random_value();

    Fp result1, result2;
    Fp temp1, temp2;

    // a * (b + c) (on GPU)
    fp_add_gpu(stream, gpu_index, &temp1, &b, &c);
    fp_mul_gpu(stream, gpu_index, &result1, &a, &temp1);

    // a*b + a*c (on GPU)
    fp_mul_gpu(stream, gpu_index, &temp1, &a, &b);
    fp_mul_gpu(stream, gpu_index, &temp2, &a, &c);
    fp_add_gpu(stream, gpu_index, &result2, &temp1, &temp2);

    EXPECT_EQ(fp_cmp_gpu(stream, gpu_index, &result1, &result2),
              ComparisonType::Equal)
        << "Distributivity failed: a*(b+c) != a*b + a*c";
    cuda_synchronize_stream(stream, gpu_index);
  }
}

// Test addition commutativity with random values (on GPU)
TEST_F(FpPropertyTest, AdditionCommutativityRandom) {
  uint64_t size_tracker = 0;
  for (int i = 0; i < 100; i++) {
    Fp a = random_value();
    Fp b = random_value();

    Fp result1, result2;
    fp_add_gpu(stream, gpu_index, &result1, &a, &b);
    fp_add_gpu(stream, gpu_index, &result2, &b, &a);

    EXPECT_EQ(fp_cmp_gpu(stream, gpu_index, &result1, &result2),
              ComparisonType::Equal)
        << "Addition commutativity failed: a+b != b+a";
    cuda_synchronize_stream(stream, gpu_index);
  }
}

// Test multiplication commutativity with random values (on GPU)
TEST_F(FpPropertyTest, MultiplicationCommutativityRandom) {
  uint64_t size_tracker = 0;
  for (int i = 0; i < 50; i++) {
    Fp a = random_value();
    Fp b = random_value();

    Fp result1, result2;
    fp_mul_gpu(stream, gpu_index, &result1, &a, &b);
    fp_mul_gpu(stream, gpu_index, &result2, &b, &a);

    EXPECT_EQ(fp_cmp_gpu(stream, gpu_index, &result1, &result2),
              ComparisonType::Equal)
        << "Multiplication commutativity failed: a*b != b*a";
    cuda_synchronize_stream(stream, gpu_index);
  }
}

// Test additive identity: a + 0 = a (on GPU)
TEST_F(FpPropertyTest, AdditiveIdentity) {
  uint64_t size_tracker = 0;
  for (int i = 0; i < 100; i++) {
    Fp a = random_value();
    Fp result;

    fp_add_gpu(stream, gpu_index, &result, &a, &zero);
    cuda_synchronize_stream(stream, gpu_index);

    EXPECT_EQ(fp_cmp_gpu(stream, gpu_index, &result, &a), ComparisonType::Equal)
        << "Additive identity failed: a + 0 != a";
    cuda_synchronize_stream(stream, gpu_index);
  }
}

// Test multiplicative identity: a * 1 = a (on GPU)
TEST_F(FpPropertyTest, MultiplicativeIdentity) {
  uint64_t size_tracker = 0;
  for (int i = 0; i < 100; i++) {
    Fp a = random_value();
    Fp result;

    fp_mul_gpu(stream, gpu_index, &result, &a, &one);
    cuda_synchronize_stream(stream, gpu_index);

    EXPECT_EQ(fp_cmp_gpu(stream, gpu_index, &result, &a), ComparisonType::Equal)
        << "Multiplicative identity failed: a * 1 != a";
    cuda_synchronize_stream(stream, gpu_index);
  }
}

// Test additive inverse: a + (-a) = 0 (on GPU)
TEST_F(FpPropertyTest, AdditiveInverse) {
  uint64_t size_tracker = 0;
  for (int i = 0; i < 100; i++) {
    Fp a = random_value();
    Fp neg_a, result;

    fp_neg_gpu(stream, gpu_index, &neg_a, &a);
    fp_add_gpu(stream, gpu_index, &result, &a, &neg_a);
    cuda_synchronize_stream(stream, gpu_index);

    EXPECT_TRUE(fp_is_zero_gpu(stream, gpu_index, &result))
        << "Additive inverse failed: a + (-a) != 0";
    cuda_synchronize_stream(stream, gpu_index);
  }
}

// Test double negation: -(-a) = a (on GPU)
TEST_F(FpPropertyTest, DoubleNegation) {
  uint64_t size_tracker = 0;
  for (int i = 0; i < 100; i++) {
    Fp a = random_value();
    Fp neg_a, neg_neg_a;

    fp_neg_gpu(stream, gpu_index, &neg_a, &a);
    fp_neg_gpu(stream, gpu_index, &neg_neg_a, &neg_a);
    cuda_synchronize_stream(stream, gpu_index);

    EXPECT_EQ(fp_cmp_gpu(stream, gpu_index, &neg_neg_a, &a),
              ComparisonType::Equal)
        << "Double negation failed: -(-a) != a";
    cuda_synchronize_stream(stream, gpu_index);
  }
}

// Test subtraction as addition of negation: a - b = a + (-b) (on GPU)
TEST_F(FpPropertyTest, SubtractionAsNegation) {
  uint64_t size_tracker = 0;
  for (int i = 0; i < 100; i++) {
    Fp a = random_value();
    Fp b = random_value();

    Fp result1, result2;
    Fp neg_b;

    fp_sub_gpu(stream, gpu_index, &result1, &a, &b);
    fp_neg_gpu(stream, gpu_index, &neg_b, &b);
    fp_add_gpu(stream, gpu_index, &result2, &a, &neg_b);
    cuda_synchronize_stream(stream, gpu_index);

    EXPECT_EQ(fp_cmp_gpu(stream, gpu_index, &result1, &result2),
              ComparisonType::Equal)
        << "Subtraction as negation failed: a - b != a + (-b)";
    cuda_synchronize_stream(stream, gpu_index);
  }
}

// Test Montgomery form round-trip with random values (on GPU)
TEST_F(FpPropertyTest, MontgomeryRoundTripRandom) {
  uint64_t size_tracker = 0;
  for (int i = 0; i < 100; i++) {
    Fp a = random_value();
    Fp mont_form, back;

    fp_to_montgomery_gpu(stream, gpu_index, &mont_form, &a);
    fp_from_montgomery_gpu(stream, gpu_index, &back, &mont_form);
    cuda_synchronize_stream(stream, gpu_index);

    EXPECT_EQ(fp_cmp_gpu(stream, gpu_index, &back, &a), ComparisonType::Equal)
        << "Montgomery round-trip failed for random value";
    cuda_synchronize_stream(stream, gpu_index);
  }
}

// Test multiplicative inverse: a * a^(-1) = 1 (on GPU)
TEST_F(FpPropertyTest, MultiplicativeInverse) {
  uint64_t size_tracker = 0;
  for (int i = 0; i < 50; i++) {
    Fp a = random_value();
    // Skip zero (on GPU)
    if (fp_is_zero_gpu(stream, gpu_index, &a)) {
      cuda_synchronize_stream(stream, gpu_index);
      continue;
    }
    cuda_synchronize_stream(stream, gpu_index);

    Fp a_inv, result;
    fp_inv_gpu(stream, gpu_index, &a_inv, &a);
    fp_mul_gpu(stream, gpu_index, &result, &a, &a_inv);
    cuda_synchronize_stream(stream, gpu_index);

    EXPECT_TRUE(fp_is_one_gpu(stream, gpu_index, &result))
        << "Multiplicative inverse failed: a * a^(-1) != 1";
    cuda_synchronize_stream(stream, gpu_index);
  }
}

// Test division: (a / b) * b = a (on GPU)
TEST_F(FpPropertyTest, DivisionProperty) {
  uint64_t size_tracker = 0;
  for (int i = 0; i < 50; i++) {
    Fp a = random_value();
    Fp b = random_value();
    // Skip zero divisor (on GPU)
    if (fp_is_zero_gpu(stream, gpu_index, &b)) {
      cuda_synchronize_stream(stream, gpu_index);
      continue;
    }
    cuda_synchronize_stream(stream, gpu_index);

    Fp quotient, result;
    fp_div_gpu(stream, gpu_index, &quotient, &a, &b);
    fp_mul_gpu(stream, gpu_index, &result, &quotient, &b);
    cuda_synchronize_stream(stream, gpu_index);

    EXPECT_EQ(fp_cmp_gpu(stream, gpu_index, &result, &a), ComparisonType::Equal)
        << "Division property failed: (a / b) * b != a";
    cuda_synchronize_stream(stream, gpu_index);
  }
}

// Test division as multiplication by inverse: a / b = a * b^(-1) (on GPU)
TEST_F(FpPropertyTest, DivisionAsInverse) {
  uint64_t size_tracker = 0;
  for (int i = 0; i < 50; i++) {
    Fp a = random_value();
    Fp b = random_value();
    // Skip zero divisor (on GPU)
    if (fp_is_zero_gpu(stream, gpu_index, &b)) {
      cuda_synchronize_stream(stream, gpu_index);
      continue;
    }
    cuda_synchronize_stream(stream, gpu_index);

    Fp result1, result2;
    Fp b_inv;

    fp_div_gpu(stream, gpu_index, &result1, &a, &b);
    fp_inv_gpu(stream, gpu_index, &b_inv, &b);
    fp_mul_gpu(stream, gpu_index, &result2, &a, &b_inv);
    cuda_synchronize_stream(stream, gpu_index);

    EXPECT_EQ(fp_cmp_gpu(stream, gpu_index, &result1, &result2),
              ComparisonType::Equal)
        << "Division as inverse failed: a / b != a * b^(-1)";
    cuda_synchronize_stream(stream, gpu_index);
  }
}

// Test exponentiation: (a^e1)^e2 = a^(e1*e2) for small exponents (on GPU)
TEST_F(FpPropertyTest, ExponentiationPowerOfPower) {
  uint64_t size_tracker = 0;
  for (int i = 0; i < 20; i++) { // Fewer iterations due to cost
    Fp a = random_value();
    // Skip zero (on GPU)
    if (fp_is_zero_gpu(stream, gpu_index, &a)) {
      cuda_synchronize_stream(stream, gpu_index);
      continue;
    }
    cuda_synchronize_stream(stream, gpu_index);

    uint64_t e1 = (rng() % 100) + 1; // 1 to 100
    uint64_t e2 = (rng() % 10) + 1;  // 1 to 10

    Fp result1, result2, temp;

    // (a^e1)^e2 (on GPU)
    fp_pow_u64_gpu(stream, gpu_index, &temp, &a, e1);
    fp_pow_u64_gpu(stream, gpu_index, &result1, &temp, e2);
    cuda_synchronize_stream(stream, gpu_index);

    // a^(e1*e2) (on GPU)
    uint64_t e_product = e1 * e2;
    fp_pow_u64_gpu(stream, gpu_index, &result2, &a, e_product);
    cuda_synchronize_stream(stream, gpu_index);

    EXPECT_EQ(fp_cmp_gpu(stream, gpu_index, &result1, &result2),
              ComparisonType::Equal)
        << "Exponentiation power of power failed: (a^e1)^e2 != a^(e1*e2)";
    cuda_synchronize_stream(stream, gpu_index);
  }
}

// Test exponentiation: a^e1 * a^e2 = a^(e1+e2) (on GPU)
TEST_F(FpPropertyTest, ExponentiationProduct) {
  uint64_t size_tracker = 0;
  for (int i = 0; i < 20; i++) { // Fewer iterations due to cost
    Fp a = random_value();
    // Skip zero (on GPU)
    if (fp_is_zero_gpu(stream, gpu_index, &a)) {
      cuda_synchronize_stream(stream, gpu_index);
      continue;
    }
    cuda_synchronize_stream(stream, gpu_index);

    uint64_t e1 = (rng() % 50) + 1; // 1 to 50
    uint64_t e2 = (rng() % 50) + 1; // 1 to 50

    Fp result1, result2, temp1, temp2;

    // a^e1 * a^e2 (on GPU)
    fp_pow_u64_gpu(stream, gpu_index, &temp1, &a, e1);
    fp_pow_u64_gpu(stream, gpu_index, &temp2, &a, e2);
    fp_mul_gpu(stream, gpu_index, &result1, &temp1, &temp2);
    cuda_synchronize_stream(stream, gpu_index);

    // a^(e1+e2) (on GPU)
    uint64_t e_sum = e1 + e2;
    fp_pow_u64_gpu(stream, gpu_index, &result2, &a, e_sum);
    cuda_synchronize_stream(stream, gpu_index);

    EXPECT_EQ(fp_cmp_gpu(stream, gpu_index, &result1, &result2),
              ComparisonType::Equal)
        << "Exponentiation product failed: a^e1 * a^e2 != a^(e1+e2)";
    cuda_synchronize_stream(stream, gpu_index);
  }
}

// Test inversion of inversion: (a^(-1))^(-1) = a (on GPU)
TEST_F(FpPropertyTest, DoubleInversion) {
  uint64_t size_tracker = 0;
  for (int i = 0; i < 50; i++) {
    Fp a = random_value();
    // Skip zero (on GPU)
    if (fp_is_zero_gpu(stream, gpu_index, &a)) {
      cuda_synchronize_stream(stream, gpu_index);
      continue;
    }
    cuda_synchronize_stream(stream, gpu_index);

    Fp a_inv, a_inv_inv;
    fp_inv_gpu(stream, gpu_index, &a_inv, &a);
    fp_inv_gpu(stream, gpu_index, &a_inv_inv, &a_inv);
    cuda_synchronize_stream(stream, gpu_index);

    EXPECT_EQ(fp_cmp_gpu(stream, gpu_index, &a_inv_inv, &a),
              ComparisonType::Equal)
        << "Double inversion failed: (a^(-1))^(-1) != a";
    cuda_synchronize_stream(stream, gpu_index);
  }
}

// Test square root property: sqrt(a^2) = a (for random a) (on GPU)
TEST_F(FpPropertyTest, SquareRootProperty) {
  uint64_t size_tracker = 0;
  for (int i = 0; i < 50; i++) {
    Fp a = random_value();
    Fp square, sqrt_result, verify;

    // Compute a^2 (on GPU)
    fp_mul_gpu(stream, gpu_index, &square, &a, &a);
    cuda_synchronize_stream(stream, gpu_index);

    // Compute sqrt(a^2) (on GPU)
    bool has_sqrt = fp_sqrt_gpu(stream, gpu_index, &sqrt_result, &square);
    cuda_synchronize_stream(stream, gpu_index);
    EXPECT_TRUE(has_sqrt) << "Square of any element should have a square root";

    if (!has_sqrt)
      continue; // Skip if square root doesn't exist (shouldn't happen for
                // squares)

    // Verify: sqrt_result^2 = square (on GPU)
    fp_mul_gpu(stream, gpu_index, &verify, &sqrt_result, &sqrt_result);
    cuda_synchronize_stream(stream, gpu_index);
    EXPECT_EQ(fp_cmp_gpu(stream, gpu_index, &verify, &square),
              ComparisonType::Equal)
        << "Square root property failed: sqrt(a^2)^2 != a^2";
    cuda_synchronize_stream(stream, gpu_index);

    // Also verify that sqrt_result is either a or -a (on GPU)
    Fp neg_a;
    fp_neg_gpu(stream, gpu_index, &neg_a, &a);
    cuda_synchronize_stream(stream, gpu_index);
    bool matches_a = (fp_cmp_gpu(stream, gpu_index, &sqrt_result, &a) ==
                      ComparisonType::Equal);
    cuda_synchronize_stream(stream, gpu_index);
    bool matches_neg_a = (fp_cmp_gpu(stream, gpu_index, &sqrt_result, &neg_a) ==
                          ComparisonType::Equal);
    cuda_synchronize_stream(stream, gpu_index);
    EXPECT_TRUE(matches_a || matches_neg_a)
        << "sqrt(a^2) should equal either a or -a";
  }
}

// Test quadratic residue property: squares are always quadratic residues (on
// GPU)
TEST_F(FpPropertyTest, QuadraticResidueProperty) {
  uint64_t size_tracker = 0;
  for (int i = 0; i < 100; i++) {
    Fp a = random_value();
    Fp square;

    // Compute a^2 (on GPU)
    fp_mul_gpu(stream, gpu_index, &square, &a, &a);
    cuda_synchronize_stream(stream, gpu_index);

    // a^2 should always be a quadratic residue (on GPU)
    EXPECT_TRUE(fp_is_quadratic_residue_gpu(stream, gpu_index, &square))
        << "Square of any element should be a quadratic residue";
    cuda_synchronize_stream(stream, gpu_index);
  }
}

// ============================================================================
// Edge Case Tests
// ============================================================================

// Test operations with p-1 (on GPU)
TEST_F(FpEdgeCaseTest, OperationsWithModulusMinusOne) {
  uint64_t size_tracker = 0;
  // (p-1) + 1 = 0 (on GPU)
  Fp result;
  fp_add_gpu(stream, gpu_index, &result, &modulus_minus_one, &one);
  cuda_synchronize_stream(stream, gpu_index);
  EXPECT_TRUE(fp_is_zero_gpu(stream, gpu_index, &result))
      << "(p-1) + 1 should equal 0";
  cuda_synchronize_stream(stream, gpu_index);

  // (p-1) * (p-1) = 1 (on GPU)
  fp_mul_gpu(stream, gpu_index, &result, &modulus_minus_one,
             &modulus_minus_one);
  cuda_synchronize_stream(stream, gpu_index);
  EXPECT_TRUE(fp_is_one_gpu(stream, gpu_index, &result))
      << "(p-1) * (p-1) should equal 1";
  cuda_synchronize_stream(stream, gpu_index);

  // -(p-1) = 1 (on GPU)
  fp_neg_gpu(stream, gpu_index, &result, &modulus_minus_one);
  cuda_synchronize_stream(stream, gpu_index);
  EXPECT_TRUE(fp_is_one_gpu(stream, gpu_index, &result))
      << "-(p-1) should equal 1";
  cuda_synchronize_stream(stream, gpu_index);
}

// Test operations with p-2 (on GPU)
TEST_F(FpEdgeCaseTest, OperationsWithModulusMinusTwo) {
  uint64_t size_tracker = 0;
  // (p-2) + 1 = p-1 (on GPU)
  Fp result;
  fp_add_gpu(stream, gpu_index, &result, &modulus_minus_two, &one);
  cuda_synchronize_stream(stream, gpu_index);
  EXPECT_EQ(fp_cmp_gpu(stream, gpu_index, &result, &modulus_minus_one),
            ComparisonType::Equal)
      << "(p-2) + 1 should equal p-1";
  cuda_synchronize_stream(stream, gpu_index);

  // (p-2) + 2 = 0 (on GPU)
  fp_add_gpu(stream, gpu_index, &result, &modulus_minus_two, &two);
  cuda_synchronize_stream(stream, gpu_index);
  EXPECT_TRUE(fp_is_zero_gpu(stream, gpu_index, &result))
      << "(p-2) + 2 should equal 0";
  cuda_synchronize_stream(stream, gpu_index);
}

// Test operations with very small values (on GPU)
TEST_F(FpEdgeCaseTest, VerySmallValues) {
  uint64_t size_tracker = 0;
  Fp zero_val, one_val, two_val, three_val;
  fp_zero(zero_val);
  fp_one(one_val);
  fp_zero(two_val);
  two_val.limb[0] = 2;
  fp_zero(three_val);
  three_val.limb[0] = 3;

  // 0 + 0 = 0 (on GPU)
  Fp result;
  fp_add_gpu(stream, gpu_index, &result, &zero_val, &zero_val);
  cuda_synchronize_stream(stream, gpu_index);
  EXPECT_TRUE(fp_is_zero_gpu(stream, gpu_index, &result));
  cuda_synchronize_stream(stream, gpu_index);

  // 1 + 1 = 2 (on GPU)
  fp_add_gpu(stream, gpu_index, &result, &one_val, &one_val);
  cuda_synchronize_stream(stream, gpu_index);
  EXPECT_EQ(fp_cmp_gpu(stream, gpu_index, &result, &two_val),
            ComparisonType::Equal);
  cuda_synchronize_stream(stream, gpu_index);

  // 2 * 2 = 4 (on GPU)
  Fp four;
  fp_zero(four);
  four.limb[0] = 4;
  fp_mul_gpu(stream, gpu_index, &result, &two_val, &two_val);
  cuda_synchronize_stream(stream, gpu_index);
  EXPECT_EQ(fp_cmp_gpu(stream, gpu_index, &result, &four),
            ComparisonType::Equal);
  cuda_synchronize_stream(stream, gpu_index);

  // 3 - 2 = 1 (on GPU)
  fp_sub_gpu(stream, gpu_index, &result, &three_val, &two_val);
  cuda_synchronize_stream(stream, gpu_index);
  EXPECT_TRUE(fp_is_one_gpu(stream, gpu_index, &result));
  cuda_synchronize_stream(stream, gpu_index);
}

// Test operations with max limb values (on GPU)
TEST_F(FpEdgeCaseTest, MaxLimbValues) {
  uint64_t size_tracker = 0;
  // Test that max_limb_value is valid
  EXPECT_TRUE(test_utils::is_valid_fp(max_limb_value))
      << "max_limb_value should be < p";

  // max_limb_value + 0 = max_limb_value (on GPU)
  Fp result;
  fp_add_gpu(stream, gpu_index, &result, &max_limb_value, &zero);
  cuda_synchronize_stream(stream, gpu_index);
  EXPECT_EQ(fp_cmp_gpu(stream, gpu_index, &result, &max_limb_value),
            ComparisonType::Equal);
  cuda_synchronize_stream(stream, gpu_index);

  // max_limb_value * 1 = max_limb_value (on GPU)
  fp_mul_gpu(stream, gpu_index, &result, &max_limb_value, &one);
  cuda_synchronize_stream(stream, gpu_index);
  EXPECT_EQ(fp_cmp_gpu(stream, gpu_index, &result, &max_limb_value),
            ComparisonType::Equal);
  cuda_synchronize_stream(stream, gpu_index);
}

// Test operations with alternating bit patterns (on GPU)
TEST_F(FpEdgeCaseTest, AlternatingBitPatterns) {
  uint64_t size_tracker = 0;
  // Test that alternating_bits is valid
  EXPECT_TRUE(test_utils::is_valid_fp(alternating_bits))
      << "alternating_bits should be < p";

  // alternating_bits + 0 = alternating_bits (on GPU)
  Fp result;
  fp_add_gpu(stream, gpu_index, &result, &alternating_bits, &zero);
  cuda_synchronize_stream(stream, gpu_index);
  EXPECT_EQ(fp_cmp_gpu(stream, gpu_index, &result, &alternating_bits),
            ComparisonType::Equal);
  cuda_synchronize_stream(stream, gpu_index);

  // alternating_bits * 1 = alternating_bits (on GPU)
  fp_mul_gpu(stream, gpu_index, &result, &alternating_bits, &one);
  cuda_synchronize_stream(stream, gpu_index);
  EXPECT_EQ(fp_cmp_gpu(stream, gpu_index, &result, &alternating_bits),
            ComparisonType::Equal);
  cuda_synchronize_stream(stream, gpu_index);
}

// Test edge case: zero operations (on GPU)
TEST_F(FpEdgeCaseTest, ZeroOperations) {
  uint64_t size_tracker = 0;
  // 0 + 0 = 0 (on GPU)
  Fp result;
  fp_add_gpu(stream, gpu_index, &result, &zero, &zero);
  cuda_synchronize_stream(stream, gpu_index);
  EXPECT_TRUE(fp_is_zero_gpu(stream, gpu_index, &result));
  cuda_synchronize_stream(stream, gpu_index);

  // 0 - 0 = 0 (on GPU)
  fp_sub_gpu(stream, gpu_index, &result, &zero, &zero);
  cuda_synchronize_stream(stream, gpu_index);
  EXPECT_TRUE(fp_is_zero_gpu(stream, gpu_index, &result));
  cuda_synchronize_stream(stream, gpu_index);

  // 0 * anything = 0 (on GPU)
  Fp random = test_utils::random_fp(rng);
  fp_mul_gpu(stream, gpu_index, &result, &zero, &random);
  cuda_synchronize_stream(stream, gpu_index);
  EXPECT_TRUE(fp_is_zero_gpu(stream, gpu_index, &result));
  cuda_synchronize_stream(stream, gpu_index);

  // -0 = 0 (on GPU)
  fp_neg_gpu(stream, gpu_index, &result, &zero);
  cuda_synchronize_stream(stream, gpu_index);
  EXPECT_TRUE(fp_is_zero_gpu(stream, gpu_index, &result));
  cuda_synchronize_stream(stream, gpu_index);
}

// Test edge case: one operations (on GPU)
TEST_F(FpEdgeCaseTest, OneOperations) {
  uint64_t size_tracker = 0;
  // 1 + 1 = 2 (on GPU)
  Fp result;
  fp_add_gpu(stream, gpu_index, &result, &one, &one);
  cuda_synchronize_stream(stream, gpu_index);
  EXPECT_EQ(fp_cmp_gpu(stream, gpu_index, &result, &two),
            ComparisonType::Equal);
  cuda_synchronize_stream(stream, gpu_index);

  // 1 * anything = anything (on GPU)
  Fp random = test_utils::random_fp(rng);
  fp_mul_gpu(stream, gpu_index, &result, &one, &random);
  cuda_synchronize_stream(stream, gpu_index);
  EXPECT_EQ(fp_cmp_gpu(stream, gpu_index, &result, &random),
            ComparisonType::Equal);
  cuda_synchronize_stream(stream, gpu_index);

  // -1 = p-1 (on GPU)
  fp_neg_gpu(stream, gpu_index, &result, &one);
  cuda_synchronize_stream(stream, gpu_index);
  EXPECT_EQ(fp_cmp_gpu(stream, gpu_index, &result, &modulus_minus_one),
            ComparisonType::Equal);
  cuda_synchronize_stream(stream, gpu_index);
}

// Test fp_one_montgomery (on GPU)
TEST_F(FpEdgeCaseTest, OneMontgomery) {
  uint64_t size_tracker = 0;
  Fp one_mont, one_normal;
  fp_one(one_normal);
  fp_one_montgomery(one_mont);

  // Convert one_mont back to normal form should give 1 (on GPU)
  Fp converted_back;
  fp_from_montgomery_gpu(stream, gpu_index, &converted_back, &one_mont);
  cuda_synchronize_stream(stream, gpu_index);
  EXPECT_TRUE(fp_is_one_gpu(stream, gpu_index, &converted_back))
      << "fp_one_montgomery should represent 1 in Montgomery form";
  cuda_synchronize_stream(stream, gpu_index);
}

// Test repeated operations (stress test) (on GPU)
TEST_F(FpEdgeCaseTest, RepeatedOperations) {
  uint64_t size_tracker = 0;
  Fp a = test_utils::random_fp(rng);
  Fp result = a;

  // Add 0 many times (on GPU)
  for (int i = 0; i < 1000; i++) {
    fp_add_gpu(stream, gpu_index, &result, &result, &zero);
  }
  cuda_synchronize_stream(stream, gpu_index);
  EXPECT_EQ(fp_cmp_gpu(stream, gpu_index, &result, &a), ComparisonType::Equal)
      << "Adding 0 many times should not change value";
  cuda_synchronize_stream(stream, gpu_index);

  // Multiply by 1 many times (on GPU)
  result = a;
  for (int i = 0; i < 1000; i++) {
    fp_mul_gpu(stream, gpu_index, &result, &result, &one);
  }
  cuda_synchronize_stream(stream, gpu_index);
  EXPECT_EQ(fp_cmp_gpu(stream, gpu_index, &result, &a), ComparisonType::Equal)
      << "Multiplying by 1 many times should not change value";
  cuda_synchronize_stream(stream, gpu_index);

  // Add and subtract same value (on GPU)
  result = a;
  Fp b = test_utils::random_fp(rng);
  for (int i = 0; i < 100; i++) {
    fp_add_gpu(stream, gpu_index, &result, &result, &b);
    fp_sub_gpu(stream, gpu_index, &result, &result, &b);
  }
  cuda_synchronize_stream(stream, gpu_index);
  EXPECT_EQ(fp_cmp_gpu(stream, gpu_index, &result, &a), ComparisonType::Equal)
      << "Repeated add/subtract should return to original";
  cuda_synchronize_stream(stream, gpu_index);
}

// ============================================================================
// CUDA Kernel Tests
// ============================================================================

// Test CUDA kernel: array addition
TEST_F(FpCudaKernelTest, CudaKernelArrayAdd) {
  uint64_t size_tracker = 0;
  const int n = 1000;
  Fp *h_a = new Fp[n];
  Fp *h_b = new Fp[n];
  Fp *h_c = new Fp[n];
  Fp *h_expected = new Fp[n];

  // Initialize with random values
  for (int i = 0; i < n; i++) {
    h_a[i] = test_utils::random_fp(rng);
    h_b[i] = test_utils::random_fp(rng);
    // Compute expected result on host
    h_expected[i] = h_a[i] + h_b[i];
  }

  // Launch GPU kernel
  fp_add_batch_on_host(stream, gpu_index, h_c, h_a, h_b, n);

  // Check CUDA errors
  cuda_synchronize_stream(stream, gpu_index);

  // Verify results match host computation
  for (int i = 0; i < n; i++) {
    EXPECT_EQ(fp_cmp(h_c[i], h_expected[i]), ComparisonType::Equal)
        << "GPU result mismatch at index " << i;
  }

  delete[] h_a;
  delete[] h_b;
  delete[] h_c;
  delete[] h_expected;
}

// Test CUDA kernel: array multiplication
TEST_F(FpCudaKernelTest, CudaKernelArrayMul) {
  uint64_t size_tracker = 0;
  const int n = 1000;
  Fp *h_a = new Fp[n];
  Fp *h_b = new Fp[n];
  Fp *h_c = new Fp[n];
  Fp *h_expected = new Fp[n];

  // Initialize with random values
  for (int i = 0; i < n; i++) {
    h_a[i] = test_utils::random_fp(rng);
    h_b[i] = test_utils::random_fp(rng);
    // Compute expected result on host
    // operator* expects Montgomery-form inputs and returns Montgomery form
    Fp a_m, b_m;
    fp_to_montgomery(a_m, h_a[i]);
    fp_to_montgomery(b_m, h_b[i]);
    Fp expected_mont = a_m * b_m;
    fp_from_montgomery(h_expected[i], expected_mont);
  }

  // Launch GPU kernel
  fp_mul_batch_on_host(stream, gpu_index, h_c, h_a, h_b, n);

  // Check CUDA errors
  cuda_synchronize_stream(stream, gpu_index);

  // Verify results match host computation
  for (int i = 0; i < n; i++) {
    EXPECT_EQ(fp_cmp(h_c[i], h_expected[i]), ComparisonType::Equal)
        << "GPU result mismatch at index " << i;
  }

  delete[] h_a;
  delete[] h_b;
  delete[] h_c;
  delete[] h_expected;
}

// Test CUDA kernel: array addition with edge cases
TEST_F(FpCudaKernelTest, CudaKernelArrayAddEdgeCases) {
  uint64_t size_tracker = 0;
  const int n = 100;
  Fp *h_a = new Fp[n];
  Fp *h_b = new Fp[n];
  Fp *h_c = new Fp[n];
  Fp *h_expected = new Fp[n];

  // Test with various edge cases
  for (int i = 0; i < n; i++) {
    if (i < 10) {
      // First 10: zero + zero
      fp_zero(h_a[i]);
      fp_zero(h_b[i]);
    } else if (i < 20) {
      // Next 10: one + one
      fp_one(h_a[i]);
      fp_one(h_b[i]);
    } else if (i < 30) {
      // Next 10: (p-1) + 1 = 0
      h_a[i] = modulus_minus_one;
      fp_one(h_b[i]);
    } else {
      // Rest: random values
      h_a[i] = test_utils::random_fp(rng);
      h_b[i] = test_utils::random_fp(rng);
    }
    // Compute expected result on host
    h_expected[i] = h_a[i] + h_b[i];
  }

  // Launch GPU kernel
  fp_add_batch_on_host(stream, gpu_index, h_c, h_a, h_b, n);

  // Check CUDA errors
  cuda_synchronize_stream(stream, gpu_index);

  // Verify results
  for (int i = 0; i < n; i++) {
    EXPECT_TRUE(h_c[i] == h_expected[i])
        << "GPU result mismatch at index " << i;
  }

  delete[] h_a;
  delete[] h_b;
  delete[] h_c;
  delete[] h_expected;
}

// Test CUDA kernel: array multiplication with edge cases
TEST_F(FpCudaKernelTest, CudaKernelArrayMulEdgeCases) {
  uint64_t size_tracker = 0;
  const int n = 100;
  Fp *h_a = new Fp[n];
  Fp *h_b = new Fp[n];
  Fp *h_c = new Fp[n];
  Fp *h_expected = new Fp[n];

  // Test with various edge cases
  for (int i = 0; i < n; i++) {
    if (i < 10) {
      // First 10: zero * anything = zero
      fp_zero(h_a[i]);
      h_b[i] = test_utils::random_fp(rng);
    } else if (i < 20) {
      // Next 10: one * anything = anything
      fp_one(h_a[i]);
      h_b[i] = test_utils::random_fp(rng);
    } else if (i < 30) {
      // Next 10: (p-1) * (p-1) = 1
      h_a[i] = modulus_minus_one;
      h_b[i] = modulus_minus_one;
    } else {
      // Rest: random values
      h_a[i] = test_utils::random_fp(rng);
      h_b[i] = test_utils::random_fp(rng);
    }
    // Compute expected result on host
    // operator* expects Montgomery-form inputs and returns Montgomery form
    Fp a_m, b_m;
    fp_to_montgomery(a_m, h_a[i]);
    fp_to_montgomery(b_m, h_b[i]);
    Fp expected_mont = a_m * b_m;
    fp_from_montgomery(h_expected[i], expected_mont);
  }

  // Launch GPU kernel
  fp_mul_batch_on_host(stream, gpu_index, h_c, h_a, h_b, n);

  // Check CUDA errors
  cuda_synchronize_stream(stream, gpu_index);

  // Verify results
  for (int i = 0; i < n; i++) {
    EXPECT_TRUE(h_c[i] == h_expected[i])
        << "GPU result mismatch at index " << i;
  }

  delete[] h_a;
  delete[] h_b;
  delete[] h_c;
  delete[] h_expected;
}

// Test CUDA kernel: large array
TEST_F(FpCudaKernelTest, CudaKernelLargeArray) {
  uint64_t size_tracker = 0;
  const int n = 10000;
  Fp *h_a = new Fp[n];
  Fp *h_b = new Fp[n];
  Fp *h_c = new Fp[n];

  // Initialize with random values
  for (int i = 0; i < n; i++) {
    h_a[i] = test_utils::random_fp(rng);
    h_b[i] = test_utils::random_fp(rng);
  }

  // Launch GPU kernel
  fp_add_batch_on_host(stream, gpu_index, h_c, h_a, h_b, n);

  // Check CUDA errors
  cuda_synchronize_stream(stream, gpu_index);

  // Verify a sample of results (checking all would be slow)
  for (int i = 0; i < 100; i++) {
    Fp expected = h_a[i] + h_b[i];
    EXPECT_TRUE(h_c[i] == expected) << "GPU result mismatch at index " << i;
  }

  // Check some random indices
  std::uniform_int_distribution<int> dist(0, n - 1);
  for (int i = 0; i < 10; i++) {
    int idx = dist(rng);
    Fp expected = h_a[idx] + h_b[idx];
    EXPECT_TRUE(h_c[idx] == expected)
        << "GPU result mismatch at random index " << idx;
  }

  delete[] h_a;
  delete[] h_b;
  delete[] h_c;
}

// Test CUDA kernel: boundary conditions for launch configuration
// Tests that the "if (idx < n)" check works correctly at block boundaries
TEST_F(FpCudaKernelTest, CudaKernelBoundaryConditions) {
  uint64_t size_tracker = 0;
  // Test sizes that stress the launch configuration
  // threadsPerBlock = 256, so test around block boundaries
  std::vector<int> test_sizes = {1,   255, 256,  257,  511,
                                 512, 513, 1023, 1024, 1025};

  for (int n : test_sizes) {
    Fp *h_a = new Fp[n];
    Fp *h_b = new Fp[n];
    Fp *h_c = new Fp[n];
    Fp *h_expected = new Fp[n];

    // Initialize
    for (int i = 0; i < n; i++) {
      h_a[i] = test_utils::random_fp(rng);
      h_b[i] = test_utils::random_fp(rng);
      h_expected[i] = h_a[i] + h_b[i];
    }

    // Launch GPU kernel
    fp_add_batch_on_host(stream, gpu_index, h_c, h_a, h_b, n);

    // Check CUDA errors
    cuda_synchronize_stream(stream, gpu_index);

    // Verify ALL results (important for boundary testing)
    for (int i = 0; i < n; i++) {
      EXPECT_TRUE(h_c[i] == h_expected[i])
          << "GPU result mismatch at index " << i << " for size " << n;
    }

    delete[] h_a;
    delete[] h_b;
    delete[] h_c;
    delete[] h_expected;
  }
}

// Test CUDA kernel: verify kernel actually launches (not just CPU fallback)
TEST_F(FpCudaKernelTest, CudaKernelActuallyLaunches) {
  uint64_t size_tracker = 0;
  const int n = 1000;
  Fp *h_a = new Fp[n];
  Fp *h_b = new Fp[n];
  Fp *h_c = new Fp[n];

  // Initialize
  for (int i = 0; i < n; i++) {
    h_a[i] = test_utils::random_fp(rng);
    h_b[i] = test_utils::random_fp(rng);
  }

  // Check that we can query device properties (verifies CUDA is available)
  int deviceCount = cuda_get_number_of_gpus();
  EXPECT_GT(deviceCount, 0) << "No CUDA devices available";

  // Launch kernel and check for launch errors immediately
  fp_add_batch_on_host(stream, gpu_index, h_c, h_a, h_b, n);

  // Check for kernel launch errors (not just sync errors)
  check_cuda_error(cudaGetLastError());

  // Synchronize to ensure kernel completes
  cuda_synchronize_device(gpu_index);

  delete[] h_a;
  delete[] h_b;
  delete[] h_c;
}

// Test CUDA kernel: verify device constant memory is accessible
TEST_F(FpCudaKernelTest, CudaKernelDeviceConstants) {
  uint64_t size_tracker = 0;
  // This test verifies that DEVICE_MODULUS is properly initialized
  // by running a kernel that uses it (multiplication uses Montgomery which
  // needs modulus)
  const int n = 100;
  Fp *h_a = new Fp[n];
  Fp *h_b = new Fp[n];
  Fp *h_c = new Fp[n];
  Fp *h_expected = new Fp[n];

  // Initialize with values that will trigger modular reduction
  for (int i = 0; i < n; i++) {
    h_a[i] = test_utils::random_fp(rng);
    h_b[i] = test_utils::random_fp(rng);
    // operator* expects Montgomery-form inputs and returns Montgomery form
    Fp a_m, b_m;
    fp_to_montgomery(a_m, h_a[i]);
    fp_to_montgomery(b_m, h_b[i]);
    Fp expected_mont = a_m * b_m;
    fp_from_montgomery(h_expected[i], expected_mont);
  }

  // Launch multiplication kernel (uses DEVICE_MODULUS via Montgomery reduction)
  fp_mul_batch_on_host(stream, gpu_index, h_c, h_a, h_b, n);

  // Check CUDA errors
  cuda_synchronize_stream(stream, gpu_index);

  // Verify results (if constants are wrong, results will be wrong)
  for (int i = 0; i < n; i++) {
    EXPECT_TRUE(h_c[i] == h_expected[i])
        << "GPU result mismatch - possible device constant memory issue at "
           "index "
        << i;
  }

  delete[] h_a;
  delete[] h_b;
  delete[] h_c;
  delete[] h_expected;
}

// Test CUDA kernel: empty array (edge case)
TEST_F(FpCudaKernelTest, CudaKernelEmptyArray) {
  uint64_t size_tracker = 0;
  const int n = 0;
  Fp *h_a = nullptr;
  Fp *h_b = nullptr;
  Fp *h_c = nullptr;

  // Should handle empty array gracefully
  fp_add_batch_on_host(stream, gpu_index, h_c, h_a, h_b, n);

  // Check CUDA errors
  cuda_synchronize_stream(stream, gpu_index);

  // No assertions needed - just verify it doesn't crash
}

// Test CUDA kernel: single element
TEST_F(FpCudaKernelTest, CudaKernelSingleElement) {
  uint64_t size_tracker = 0;
  const int n = 1;
  Fp *h_a = new Fp[n];
  Fp *h_b = new Fp[n];
  Fp *h_c = new Fp[n];

  fp_one(h_a[0]);
  fp_one(h_b[0]);

  fp_add_batch_on_host(stream, gpu_index, h_c, h_a, h_b, n);

  cuda_synchronize_stream(stream, gpu_index);

  Fp expected = h_a[0] + h_b[0];
  EXPECT_TRUE(h_c[0] == expected) << "Single element test failed";

  delete[] h_a;
  delete[] h_b;
  delete[] h_c;
}

// ============================================================================
// Curve Point Tests
// ============================================================================

// Test to print generator values (for hardcoding)
TEST_F(FpArithmeticTest, PrintGenerators) {
  uint64_t size_tracker = 0;
  const G1Affine &g1 = g1_generator();
  const G2Affine &g2 = g2_generator();

  printf("\n=== G1 Generator (Montgomery form) ===\n");
  printf("x: {0x%llxULL, 0x%llxULL, 0x%llxULL, 0x%llxULL, 0x%llxULL, "
         "0x%llxULL, 0x%llxULL}\n",
         g1.x.limb[0], g1.x.limb[1], g1.x.limb[2], g1.x.limb[3], g1.x.limb[4],
         g1.x.limb[5], g1.x.limb[6]);
  printf("y: {0x%llxULL, 0x%llxULL, 0x%llxULL, 0x%llxULL, 0x%llxULL, "
         "0x%llxULL, 0x%llxULL}\n",
         g1.y.limb[0], g1.y.limb[1], g1.y.limb[2], g1.y.limb[3], g1.y.limb[4],
         g1.y.limb[5], g1.y.limb[6]);

  printf("\n=== G2 Generator (Montgomery form) ===\n");
  printf("x.c0: {0x%llxULL, 0x%llxULL, 0x%llxULL, 0x%llxULL, 0x%llxULL, "
         "0x%llxULL, 0x%llxULL}\n",
         g2.x.c0.limb[0], g2.x.c0.limb[1], g2.x.c0.limb[2], g2.x.c0.limb[3],
         g2.x.c0.limb[4], g2.x.c0.limb[5], g2.x.c0.limb[6]);
  printf("x.c1: {0x%llxULL, 0x%llxULL, 0x%llxULL, 0x%llxULL, 0x%llxULL, "
         "0x%llxULL, 0x%llxULL}\n",
         g2.x.c1.limb[0], g2.x.c1.limb[1], g2.x.c1.limb[2], g2.x.c1.limb[3],
         g2.x.c1.limb[4], g2.x.c1.limb[5], g2.x.c1.limb[6]);
  printf("y.c0: {0x%llxULL, 0x%llxULL, 0x%llxULL, 0x%llxULL, 0x%llxULL, "
         "0x%llxULL, 0x%llxULL}\n",
         g2.y.c0.limb[0], g2.y.c0.limb[1], g2.y.c0.limb[2], g2.y.c0.limb[3],
         g2.y.c0.limb[4], g2.y.c0.limb[5], g2.y.c0.limb[6]);
  printf("y.c1: {0x%llxULL, 0x%llxULL, 0x%llxULL, 0x%llxULL, 0x%llxULL, "
         "0x%llxULL, 0x%llxULL}\n",
         g2.y.c1.limb[0], g2.y.c1.limb[1], g2.y.c1.limb[2], g2.y.c1.limb[3],
         g2.y.c1.limb[4], g2.y.c1.limb[5], g2.y.c1.limb[6]);
  printf("\n");
}

// Test is_on_curve_g1 with point at infinity
TEST_F(FpArithmeticTest, CurveG1PointAtInfinity) {
  uint64_t size_tracker = 0;
  G1Affine point;
  g1_point_at_infinity(point);

  EXPECT_TRUE(g1_is_infinity(point)) << "Point should be at infinity";
  EXPECT_TRUE(is_on_curve_g1(point)) << "Point at infinity should be on curve";
}

// Test is_on_curve_g1 with valid point (on GPU)
// We'll create a point by starting with a valid y and computing x
// Or use a known valid point
TEST_F(FpArithmeticTest, CurveG1ValidPoint) {
  uint64_t size_tracker = 0;
  G1Affine point;
  point.infinity = false;

  // Strategy: Start with a small y value, compute y^2, then find x such that
  // x^3 = y^2 - b Or simpler: test with x=0, which gives y^2 = b, so y =
  // sqrt(b)
  fp_zero(point.x);

  const Fp &b = curve_b_g1();

  // Compute y = sqrt(b) (on GPU)
  bool has_sqrt = fp_sqrt_gpu(stream, gpu_index, &point.y, &b);
  cuda_synchronize_stream(stream, gpu_index);

  if (!has_sqrt) {
    // If b is not a quadratic residue, try x=2 (on GPU)
    fp_zero(point.x);
    point.x.limb[0] = 2;

    Fp x_squared, x_cubed, x_cubed_plus_b;
    fp_mul_gpu(stream, gpu_index, &x_squared, &point.x, &point.x);
    fp_mul_gpu(stream, gpu_index, &x_cubed, &x_squared, &point.x);
    fp_add_gpu(stream, gpu_index, &x_cubed_plus_b, &x_cubed, &b);
    cuda_synchronize_stream(stream, gpu_index);

    has_sqrt = fp_sqrt_gpu(stream, gpu_index, &point.y, &x_cubed_plus_b);
    cuda_synchronize_stream(stream, gpu_index);
  }

  if (!has_sqrt) {
    // Try a few more x values (on GPU)
    for (uint64_t x_val = 0; x_val <= 10; x_val++) {
      fp_zero(point.x);
      point.x.limb[0] = x_val;

      Fp x_squared, x_cubed, x_cubed_plus_b;
      fp_mul_gpu(stream, gpu_index, &x_squared, &point.x, &point.x);
      fp_mul_gpu(stream, gpu_index, &x_cubed, &x_squared, &point.x);
      fp_add_gpu(stream, gpu_index, &x_cubed_plus_b, &x_cubed, &b);
      cuda_synchronize_stream(stream, gpu_index);

      if (fp_is_quadratic_residue_gpu(stream, gpu_index, &x_cubed_plus_b)) {
        cuda_synchronize_stream(stream, gpu_index);
        has_sqrt = fp_sqrt_gpu(stream, gpu_index, &point.y, &x_cubed_plus_b);
        cuda_synchronize_stream(stream, gpu_index);
        if (has_sqrt)
          break;
      }
    }
  }

  ASSERT_TRUE(has_sqrt) << "Should be able to find at least one valid point";

  // Verify point is on curve
  EXPECT_TRUE(is_on_curve_g1(point)) << "Computed point should be on curve";

  // Verify: y^2 = x^3 + b (on GPU)
  Fp y_squared;
  fp_mul_gpu(stream, gpu_index, &y_squared, &point.y, &point.y);
  Fp x_squared, x_cubed, x_cubed_plus_b;
  fp_mul_gpu(stream, gpu_index, &x_squared, &point.x, &point.x);
  fp_mul_gpu(stream, gpu_index, &x_cubed, &x_squared, &point.x);
  fp_add_gpu(stream, gpu_index, &x_cubed_plus_b, &x_cubed, &b);
  cuda_synchronize_stream(stream, gpu_index);
  EXPECT_EQ(fp_cmp_gpu(stream, gpu_index, &y_squared, &x_cubed_plus_b),
            ComparisonType::Equal)
      << "y^2 should equal x^3 + b";
  cuda_synchronize_stream(stream, gpu_index);
}

// Test is_on_curve_g1 with invalid point
TEST_F(FpArithmeticTest, CurveG1InvalidPoint) {
  uint64_t size_tracker = 0;
  G1Affine point;
  point.infinity = false;

  // Set x = 1, y = 1 (which doesn't satisfy y^2 = x^3 + b = 5)
  fp_one(point.x);
  fp_one(point.y);

  EXPECT_FALSE(is_on_curve_g1(point)) << "Invalid point should not be on curve";
}

// Test that negating y preserves curve validity (on GPU)
TEST_F(FpArithmeticTest, CurveG1FieldOperationsConsistency) {
  uint64_t size_tracker = 0;
  G1Affine point;
  point.infinity = false;

  // Find a valid point by trying different x values (on GPU)
  const Fp &b = curve_b_g1();
  bool found_valid = false;

  for (uint64_t x_val = 0; x_val <= 10; x_val++) {
    fp_zero(point.x);
    point.x.limb[0] = x_val;

    Fp x_squared, x_cubed, x_cubed_plus_b;
    fp_mul_gpu(stream, gpu_index, &x_squared, &point.x, &point.x);
    fp_mul_gpu(stream, gpu_index, &x_cubed, &x_squared, &point.x);
    fp_add_gpu(stream, gpu_index, &x_cubed_plus_b, &x_cubed, &b);
    cuda_synchronize_stream(stream, gpu_index);

    if (fp_is_quadratic_residue_gpu(stream, gpu_index, &x_cubed_plus_b)) {
      cuda_synchronize_stream(stream, gpu_index);
      bool has_sqrt = fp_sqrt_gpu(stream, gpu_index, &point.y, &x_cubed_plus_b);
      cuda_synchronize_stream(stream, gpu_index);
      if (has_sqrt) {
        found_valid = true;
        break;
      }
    }
  }

  ASSERT_TRUE(found_valid) << "Should be able to find at least one valid point";
  ASSERT_TRUE(is_on_curve_g1(point)) << "Initial point should be valid";

  // Negate y: (-y)^2 = y^2, so point should still be valid (on GPU)
  Fp neg_y;
  fp_neg_gpu(stream, gpu_index, &neg_y, &point.y);
  fp_copy_gpu(stream, gpu_index, &point.y, &neg_y);
  cuda_synchronize_stream(stream, gpu_index);

  EXPECT_TRUE(is_on_curve_g1(point))
      << "Point with negated y should still be on curve";
}

// Test is_on_curve_g2 with point at infinity
TEST_F(FpArithmeticTest, CurveG2PointAtInfinity) {
  uint64_t size_tracker = 0;
  G2Affine point;
  g2_point_at_infinity(point);

  EXPECT_TRUE(g2_is_infinity(point)) << "Point should be at infinity";
  EXPECT_TRUE(is_on_curve_g2(point)) << "Point at infinity should be on curve";
}
