// Basic finite field (Fp) arithmetic over BLS12-446.
//
// Demonstrates host-side Fp operations intended as a learning reference.
// All arithmetic in the field is modular with respect to the BLS12-446 prime.
//
// Internal representation uses Montgomery form for multiplications.
// See README.md and include/fp.h for the full API reference.
//
// Build (from cuda/):
//   cmake -B build -DZK_CUDA_BACKEND_BUILD_TESTS=ON
//   cmake --build build --target basic_fp_ops
//   ./build/tests_and_benchmarks/tests/basic/basic_fp_ops

#include "fp.h"
#include <cassert>
#include <cstdio>

int main() {
  // ---- Addition and subtraction ----
  // fp_one() and fp_zero() produce values in normal (non-Montgomery) form.
  // fp_add / fp_sub perform modular addition/subtraction and are form-agnostic
  // (addition is linear, so the result stays in the same form).
  Fp a, b, c;
  fp_one(a); // a = 1
  fp_one(b); // b = 1

  c = a + b; // c = 2
  assert(c.limb[0] == 2);

  c = c - a; // c = 1
  assert(fp_is_one(c));

  // Compound assignment
  c += a; // c = 2
  assert(c.limb[0] == 2);
  c -= b; // c = 1
  assert(fp_is_one(c));

  printf("Addition/subtraction: OK\n");

  // ---- Negation ----
  // fp_neg computes p - a (mod p). For consistency use values in Montgomery
  // form, but for add/sub/neg small normal-form values also work correctly.
  Fp neg_a = -a; // neg_a = -1 mod p
  Fp sum = a + neg_a;
  assert(fp_is_zero(sum)); // 1 + (-1) = 0
  printf("Negation: OK\n");

  // ---- Multiplication (Montgomery form required) ----
  // The * operator calls fp_mont_mul, which requires both operands to be in
  // Montgomery form.  Use fp_to_montgomery() to convert, or the helper
  // fp_one_montgomery() / fp_two_montgomery() for small constants.
  Fp one_m, two_m, result_m, result;
  fp_one_montgomery(one_m); // one_m  = 1 in Montgomery form
  fp_two_montgomery(two_m); // two_m  = 2 in Montgomery form

  result_m = one_m * two_m; // result_m = 2 in Montgomery form
  fp_from_montgomery(result, result_m);
  assert(result.limb[0] == 2);

  result_m = two_m * two_m; // result_m = 4 in Montgomery form
  fp_from_montgomery(result, result_m);
  assert(result.limb[0] == 4);

  // Compound multiplication
  result_m = two_m;
  result_m *= two_m; // result_m = 4
  fp_from_montgomery(result, result_m);
  assert(result.limb[0] == 4);

  // Convert an arbitrary normal-form value to Montgomery before multiplying
  Fp five_normal, five_m, twenty_five_m, twenty_five;
  fp_zero(five_normal);
  five_normal.limb[0] = 5;
  fp_to_montgomery(five_m, five_normal);

  fp_mont_mul(twenty_five_m, five_m, five_m); // 5 * 5 = 25
  fp_from_montgomery(twenty_five, twenty_five_m);
  assert(twenty_five.limb[0] == 25);

  printf("Multiplication: OK\n");

  // ---- Inversion and division (normal-form convenience API) ----
  // fp_inv and fp_div accept and return values in normal form (they handle
  // the Montgomery conversion internally).
  Fp five_inv;
  fp_inv(five_inv, five_normal); // five_inv = 5^{-1} mod p

  Fp one_check;
  fp_div(one_check, five_normal, five_normal); // 5 / 5 = 1
  assert(fp_is_one(one_check));

  // Verify: 5 * 5^{-1} == 1  (using fp_div as a cross-check)
  Fp product;
  fp_zero(product);
  product.limb[0] = 1; // product = 1
  Fp two_normal;
  fp_zero(two_normal);
  two_normal.limb[0] = 2;
  fp_div(product, two_normal, two_normal); // 2 / 2 = 1
  assert(fp_is_one(product));

  printf("Inversion/division: OK\n");

  printf("All Fp operations passed.\n");
  return 0;
}
