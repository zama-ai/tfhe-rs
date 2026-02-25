// Basic elliptic curve operations on BLS12-446 G1.
//
// Demonstrates G1 projective point arithmetic on the host.  Projective points
// support operator overloads (+, -, *, ==) that cover the common use cases.
// Affine points are used for input/output; coordinates are in Montgomery form
// during arithmetic and converted back by normalize_from_montgomery_g1().
//
// See README.md and include/curve.h for the full API reference.
//
// Build (from cuda/):
//   cmake -B build -DZK_CUDA_BACKEND_BUILD_TESTS=ON
//   cmake --build build --target basic_curve_ops
//   ./build/tests_and_benchmarks/tests/basic/basic_curve_ops

#include "curve.h"
#include "fp.h"
#include <cassert>
#include <cstdio>
#include <cstring>

int main() {
  // ---- Generator point ----
  // g1_generator() returns the hardcoded BLS12-446 G1 generator in normal
  // (non-Montgomery) form. Convert to Montgomery, then lift to projective for
  // host-side arithmetic.
  const G1Affine &gen_normal = g1_generator();
  assert(!g1_is_infinity(gen_normal));

  G1Affine gen_affine = gen_normal;
  point_to_montgomery_inplace(gen_affine);

  G1Projective G;
  affine_to_projective(G, gen_affine);

  // ---- Negation: -G ----
  G1Projective neg_G = -G;

  // G + (-G) = identity (Z = 0 in the projective convention)
  G1Projective identity = G + neg_G;
  assert(fp_is_zero(identity.Z));
  printf("Negation (-G) and G + (-G) = identity: OK\n");

  // ---- Addition: 2*G = G + G, 3*G = 2*G + G ----
  G1Projective two_G = G + G;
  assert(!(two_G == G1Projective())); // not the identity

  G1Projective three_G = two_G + G;
  assert(!(three_G == G1Projective()));
  printf("Addition (2*G, 3*G): OK\n");

  // ---- Compound assignment: G += G ----
  G1Projective acc = G;
  acc += G; // acc = 2*G
  assert(acc == two_G);
  printf("Compound assignment (+=): OK\n");

  // ---- Scalar multiplication: 3*G using Scalar type ----
  // The * operator calls projective_scalar_mul internally.
  Scalar scalar_3;
  memset(&scalar_3, 0, sizeof(scalar_3));
  scalar_3.limb[0] = 3;

  G1Projective three_G_via_scalar = G * scalar_3;
  assert(!(three_G_via_scalar == G1Projective()));

  // Normalise both to Z = 1 (Montgomery) before comparing coordinates.
  normalize_projective_g1(three_G);
  normalize_projective_g1(three_G_via_scalar);
  assert(three_G == three_G_via_scalar);
  printf("Scalar multiplication (3*G == G + G + G): OK\n");

  // ---- Projective -> affine conversion ----
  // projective_to_affine_g1 keeps coordinates in Montgomery form.
  G1Affine three_G_affine;
  projective_to_affine_g1(three_G_affine, three_G);
  assert(!g1_is_infinity(three_G_affine));
  printf("Projective -> affine conversion: OK\n");

  // ---- Convert to normal-form coordinates ----
  // normalize_from_montgomery_g1 strips Montgomery form and sets Z = 1 in one
  // pass.
  G1Projective result = three_G_via_scalar;
  normalize_from_montgomery_g1(
      result); // coordinates now in normal (non-Montgomery) form
  assert(!fp_is_zero(result.Z)); // Z = 1 (non-zero)
  printf("Conversion to normal-form projective: OK\n");

  printf("All G1 curve operations passed.\n");
  return 0;
}
