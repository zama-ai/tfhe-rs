#pragma once

#include "curve.h"
#include "fp.h"
#include "fp2.h"

// XYZZ Extended Jacobian Coordinates for BLS12-446

// G1 XYZZ point: (X, Y, ZZ, ZZZ) in Fp
struct G1XYZZ {
  Fp X;
  Fp Y;
  Fp ZZ;
  Fp ZZZ;

  // Default constructor: initializes to point at infinity (ZZ=ZZZ=0)
  __host__ __device__ G1XYZZ() {
    fp_zero(X);
    fp_zero(Y);
    fp_zero(ZZ);
    fp_zero(ZZZ);
  }
};

// G2 XYZZ point: (X, Y, ZZ, ZZZ) in Fp2
struct G2XYZZ {
  Fp2 X;
  Fp2 Y;
  Fp2 ZZ;
  Fp2 ZZZ;

  // Default constructor: initializes to point at infinity (ZZ=ZZZ=0)
  __host__ __device__ G2XYZZ() {
    fp2_zero(X);
    fp2_zero(Y);
    fp2_zero(ZZ);
    fp2_zero(ZZZ);
  }
};

// Initialize XYZZ from an affine point: X=x, Y=y, ZZ=ZZZ=1 (Montgomery form)
__host__ __device__ void xyzz_from_affine(G1XYZZ &xyzz, const G1Affine &affine);
__host__ __device__ void xyzz_from_affine(G2XYZZ &xyzz, const G2Affine &affine);

// Set XYZZ to the point at infinity: ZZ=ZZZ=0 (X,Y left undefined)
__host__ __device__ void xyzz_infinity(G1XYZZ &p);
__host__ __device__ void xyzz_infinity(G2XYZZ &p);

__host__ __device__ bool xyzz_is_infinity(const G1XYZZ &p);
__host__ __device__ bool xyzz_is_infinity(const G2XYZZ &p);

__host__ __device__ void xyzz_mixed_add(G1XYZZ &acc, const G1Affine &p);
__host__ __device__ void xyzz_mixed_add(G2XYZZ &acc, const G2Affine &p);

__host__ __device__ void xyzz_to_projective(G1Projective &proj,
                                            const G1XYZZ &xyzz);
__host__ __device__ void xyzz_to_projective(G2Projective &proj,
                                            const G2XYZZ &xyzz);
