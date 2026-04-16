#include "fp.h"
#include "fp2.h"
#include "xyzz.h"

__host__ __device__ void xyzz_infinity(G1XYZZ &p) {
  fp_zero(p.ZZ);
  fp_zero(p.ZZZ);
}

__host__ __device__ bool xyzz_is_infinity(const G1XYZZ &p) {
  return fp_is_zero(p.ZZ);
}

__host__ __device__ void xyzz_from_affine(G1XYZZ &xyzz,
                                          const G1Affine &affine) {
  xyzz.X = affine.x;
  xyzz.Y = affine.y;
  fp_one_montgomery(xyzz.ZZ);
  fp_one_montgomery(xyzz.ZZZ);
}

__host__ __device__ void xyzz_mixed_add(G1XYZZ &acc, const G1Affine &p) {
  if (p.infinity)
    return;

  if (xyzz_is_infinity(acc)) {
    xyzz_from_affine(acc, p);
    return;
  }

  // S2 = y2*ZZZ1, U2 = x2*ZZ1
  Fp S2, U2;
  fp_mont_mul(S2, p.y, acc.ZZZ);
  fp_mont_mul(U2, p.x, acc.ZZ);

  Fp P = U2 - acc.X; // P = U2 - X1
  Fp R = S2 - acc.Y; // R = S2 - Y1

  if (fp_is_zero(P)) {
    if (fp_is_zero(R)) {
      //   U    = 2*y2
      //   ZZ3  = V = U^2
      //   ZZZ3 = W = V*U
      //   S    = x2*V
      //   M    = 3*x2^2
      //   X3   = M^2 - 2*S
      //   Y3   = M*(S-X3) - W*y2
      Fp U, S, M;
      fp_double(U, p.y);                // U = 2*y2
      fp_mont_sqr(acc.ZZ, U);           // ZZ3 = V = U^2
      fp_mont_mul(acc.ZZZ, acc.ZZ, U);  // ZZZ3 = W = V*U
      fp_mont_mul(S, p.x, acc.ZZ);      // S = x2*V
      fp_mont_sqr(M, p.x);              // x2^2
      fp_mul3(M, M);                    // M = 3*x2^2
      fp_mont_sqr(acc.X, M);            // M^2
      acc.X = acc.X - S - S;            // X3 = M^2 - 2*S
      fp_mont_mul(acc.Y, acc.ZZZ, p.y); // W*y2
      Fp tmp = S - acc.X;               // S - X3
      fp_mont_mul(tmp, tmp, M);         // M*(S-X3)
      acc.Y = tmp - acc.Y;              // Y3 = M*(S-X3) - W*y2
    } else {
      xyzz_infinity(acc);
    }
    return;
  }

  // General addition (P != 0): 8M + 2S
  Fp PP, PPP, Q;
  fp_mont_sqr(PP, P);                 // PP = P^2
  fp_mont_mul(PPP, P, PP);            // PPP = P*PP
  fp_mont_mul(Q, acc.X, PP);          // Q = X1*PP
  fp_mont_mul(acc.ZZ, acc.ZZ, PP);    // ZZ3 = ZZ1*PP
  fp_mont_mul(acc.ZZZ, acc.ZZZ, PPP); // ZZZ3 = ZZZ1*PPP

  Fp X3;
  fp_mont_sqr(X3, R);    // R^2
  X3 = X3 - PPP - Q - Q; // X3 = R^2 - PPP - 2*Q

  Fp QmX3 = Q - X3;
  fp_mont_mul(QmX3, QmX3, R);     // R*(Q-X3)
  fp_mont_mul(acc.Y, acc.Y, PPP); // Y1*PPP
  acc.Y = QmX3 - acc.Y;           // Y3 = R*(Q-X3) - Y1*PPP
  acc.X = X3;
}

__host__ __device__ void xyzz_to_projective(G1Projective &proj,
                                            const G1XYZZ &xyzz) {
  fp_mont_mul(proj.X, xyzz.X, xyzz.ZZZ);
  fp_mont_mul(proj.Y, xyzz.Y, xyzz.ZZ);
  fp_mont_mul(proj.Z, xyzz.ZZ, xyzz.ZZZ);
}

__host__ __device__ void xyzz_infinity(G2XYZZ &p) {
  fp2_zero(p.ZZ);
  fp2_zero(p.ZZZ);
}

__host__ __device__ bool xyzz_is_infinity(const G2XYZZ &p) {
  return fp2_is_zero(p.ZZ);
}

__host__ __device__ void xyzz_from_affine(G2XYZZ &xyzz,
                                          const G2Affine &affine) {
  xyzz.X = affine.x;
  xyzz.Y = affine.y;
  // ZZ = ZZZ = 1 in Fp2 Montgomery form: (1_mont, 0)
  fp_one_montgomery(xyzz.ZZ.c0);
  fp_zero(xyzz.ZZ.c1);
  fp_one_montgomery(xyzz.ZZZ.c0);
  fp_zero(xyzz.ZZZ.c1);
}

__host__ __device__ void xyzz_mixed_add(G2XYZZ &acc, const G2Affine &p) {
  if (p.infinity)
    return;

  if (xyzz_is_infinity(acc)) {
    xyzz_from_affine(acc, p);
    return;
  }

  Fp2 S2, U2;
  fp2_mont_mul(S2, p.y, acc.ZZZ); // S2 = y2*ZZZ1
  fp2_mont_mul(U2, p.x, acc.ZZ);  // U2 = x2*ZZ1

  Fp2 P = U2 - acc.X;
  Fp2 R = S2 - acc.Y;

  if (fp2_is_zero(P)) {
    if (fp2_is_zero(R)) {
      Fp2 U, S, M;
      fp2_double(U, p.y);
      fp2_mont_square(acc.ZZ, U);        // ZZ3 = V = U^2
      fp2_mont_mul(acc.ZZZ, acc.ZZ, U);  // ZZZ3 = W = V*U
      fp2_mont_mul(S, p.x, acc.ZZ);      // S = x2*V
      fp2_mont_square(M, p.x);           // x2^2
      fp2_mul3(M, M);                    // M = 3*x2^2
      fp2_mont_square(acc.X, M);         // M^2
      acc.X = acc.X - S - S;             // X3 = M^2 - 2*S
      fp2_mont_mul(acc.Y, acc.ZZZ, p.y); // W*y2
      Fp2 tmp = S - acc.X;
      fp2_mont_mul(tmp, tmp, M); // M*(S-X3)
      acc.Y = tmp - acc.Y;       // Y3 = M*(S-X3)-W*y2
    } else {
      xyzz_infinity(acc);
    }
    return;
  }

  // General addition (8M_Fp2 + 2S_Fp2)
  Fp2 PP, PPP, Q;
  fp2_mont_square(PP, P);              // PP = P^2
  fp2_mont_mul(PPP, P, PP);            // PPP = P*PP
  fp2_mont_mul(Q, acc.X, PP);          // Q = X1*PP
  fp2_mont_mul(acc.ZZ, acc.ZZ, PP);    // ZZ3 = ZZ1*PP
  fp2_mont_mul(acc.ZZZ, acc.ZZZ, PPP); // ZZZ3 = ZZZ1*PPP

  Fp2 X3;
  fp2_mont_square(X3, R); // R^2
  X3 = X3 - PPP - Q - Q;  // X3 = R^2 - PPP - 2*Q

  Fp2 QmX3 = Q - X3;
  fp2_mont_mul(QmX3, QmX3, R);     // R*(Q-X3)
  fp2_mont_mul(acc.Y, acc.Y, PPP); // Y1*PPP
  acc.Y = QmX3 - acc.Y;            // Y3 = R*(Q-X3) - Y1*PPP
  acc.X = X3;
}

__host__ __device__ void xyzz_to_projective(G2Projective &proj,
                                            const G2XYZZ &xyzz) {
  fp2_mont_mul(proj.X, xyzz.X, xyzz.ZZZ);
  fp2_mont_mul(proj.Y, xyzz.Y, xyzz.ZZ);
  fp2_mont_mul(proj.Z, xyzz.ZZ, xyzz.ZZZ);
}
