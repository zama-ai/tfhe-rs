#include "checked_arithmetic.h"
#include "device.h"
#include "pbs/programmable_bootstrap.h"
#include "gtest/gtest.h"
#include <cmath>
#include <cstdint>
#include <cstring>
#include <cuda_runtime.h>
#include <iostream>
#include <random>
#include <vector>

// AVX-512 host reference path (x86 only). Compiled with per-function target
// attributes so the rest of the TU needs no global -mavx512* flags, and gated
// at runtime with __builtin_cpu_supports below.
#if defined(__x86_64__) || defined(__i386__)
#include <immintrin.h>
#define FFT16_HAVE_AVX512 1
#endif

// The forward transform's twiddle factors live in GPU constant memory, defined
// once in the backend (src/fft/fft16x4x16_twiddles.cu) and declared here with
// the same `extern __device__ __constant__` signatures. Rather than duplicating
// the ~1500 hex-float constants on the host, the test copies these exact device
// tables down to host memory at runtime (cudaMemcpyFromSymbol below), so the
// CPU reference and the GPU kernel provably use the identical bytes.
//
//   tw_1024[k-1][tid]    = exp(-2*pi*i * k * tid / 1024), k=1..15, tid=0..63
//   twisting_twiddles[k] = exp(-i*pi*k / 2048),           k=0..512
extern __device__ __constant__ double2 tw_1024[15][64];
extern __device__ __constant__ double2 twisting_twiddles[513];

// ============================================================================
// Bit-exact CPU-vs-GPU cross-check for the throughput-oriented FFT16x4x16
// forward transform (the FFT used by the specialized 2_2_params PBS).
//
// This test is fully self-contained in the CUDA backend test suite: it carries
// its own host CPU reference implementation of the forward transform (below)
// and the host copies of the twiddle tables (fft16x4x16_cpu_twiddles.h). None
// of that leaks into the backend itself.
//
// On every run it draws a FRESH set of random complex inputs, transforms them
// with both the GPU kernel (cuda_forward_fft16x4x16_async) and the CPU
// reference, and asserts the two spectra are IDENTICAL BIT FOR BIT (not merely
// close). This is possible because the GPU kernel is written entirely with
// round-to-nearest intrinsics (__dadd_rn / __dsub_rn / __dmul_rn / __fma_rn) —
// every operation is IEEE-754 correctly rounded with fusion pinned exactly
// where the author placed it, so a faithful serial CPU port that uses plain
// +/-/* (never contracted into an FMA) and std::fma reproduces it exactly.
//
// The FFT16x4x16 core is specialized for N = 2048 and needs the sm_90
// named-barrier / mbarrier primitives, so it runs on H100 (Hopper, compute
// capability 9.x). The test skips on every other architecture.
// ============================================================================

namespace {

// --- Scalar twiddle constants (exact bit patterns, matching the CUDA
// #defines).
//   D_COS_PI_8 = cos(pi/8), D_SIN_PI_8 = sin(pi/8), D_SQRT1_2 = 1/sqrt(2).
// D_SQRT1_2 is the correctly-rounded 1/sqrt(2) (...bcd), one ULP off a naive
// 1.0 / sqrt(2.0) (...bcc) — hence the explicit bit pattern.
static inline double bits_to_f64(uint64_t b) {
  double d;
  std::memcpy(&d, &b, sizeof(d));
  return d;
}
static const double D_COS_PI_8 = bits_to_f64(0x3fed906bcf328d46ULL);
static const double D_SIN_PI_8 = bits_to_f64(0x3fd87de2a6aea963ULL);
static const double D_SQRT1_2 = bits_to_f64(0x3fe6a09e667f3bcdULL);

// Number of "threads" in one GPU FFT group; each holds 16 registers.
constexpr int THREADS = 64;
// Registers per thread.
constexpr int REGS = 16;

// Host copies of the GPU twiddle tables, filled once per test run from the
// device constants via cudaMemcpyFromSymbol (see the TEST body). The CPU
// reference reads from these, so it uses the exact same values as the kernel.
static double2 g_tw_1024[15][64];
static double2 g_twisting_twiddles[513];

// --- Complex primitives on double2, matching types/complex/operations.cuh.
//   x = real, y = imaginary. Plain +/-/* map to __dadd_rn/__dsub_rn/__dmul_rn
//   (no source-level a*b+c pattern exists here, so no FP contraction is
//   possible); std::fma maps to __fma_rn (single-rounding fused multiply-add).
static inline double2 mk(double re, double im) { return double2{re, im}; }
static inline double2 c_add(double2 a, double2 b) {
  return mk(a.x + b.x, a.y + b.y);
}
static inline double2 c_sub(double2 a, double2 b) {
  return mk(a.x - b.x, a.y - b.y);
}
// Complex product, matching operator*(double2, double2) exactly:
//   re = fma(a.x, b.x, -(a.y * b.y)),  im = fma(a.x, b.y, a.y * b.x).
static inline double2 c_mul(double2 a, double2 b) {
  return mk(std::fma(a.x, b.x, -(a.y * b.y)), std::fma(a.x, b.y, a.y * b.x));
}
// Scalar product, matching operator*(double2, double) (__dmul_rn).
static inline double2 c_scale(double2 a, double s) {
  return mk(a.x * s, a.y * s);
}
// Multiply by exp(-i*pi/2) = -i: (x, y) -> (y, -x).
static inline double2 c_mul_exp_1_4(double2 a) { return mk(a.y, -a.x); }

// Bit-reversal table for the 16-element FFT (register index -> natural order).
static const int BITREV16[16] = {0, 8, 4, 12, 2, 10, 6, 14,
                                 1, 9, 5, 13, 3, 11, 7, 15};

// --- Butterfly primitives (forward, sign = -1) — direct ports of
// fft16x4x16.cuh.
static inline void fft2(double2 *a, int i, int j) {
  double2 c0 = a[i];
  a[i] = c_add(c0, a[j]);
  a[j] = c_sub(c0, a[j]);
}
// FFT2 fused with a * exp(-i*pi/2) twist on the second output.
static inline void fft2_mul_exp_1_4(double2 *a, int i, int j) {
  double2 c0 = a[i];
  double2 a1 = a[j];
  a[i].x = c0.x + a1.y;
  a[i].y = c0.y - a1.x;
  a[j].x = c0.x - a1.y;
  a[j].y = c0.y + a1.x;
}
static inline void fft4(double2 *a, int i0, int i1, int i2, int i3) {
  fft2(a, i0, i2);
  fft2(a, i1, i3);
  fft2(a, i0, i1);
  fft2_mul_exp_1_4(a, i2, i3);
}

// 16-point DFT held in 16 registers (4x4 Cooley-Tukey grid), in place. Output
// is in bit-reversed order: a[j] holds coefficient BITREV16[j].
static inline void fft16(double2 *a) {
  const double2 d_exp_1_16 = mk(D_COS_PI_8, -D_SIN_PI_8);
  const double2 d_exp_3_16 = mk(D_SIN_PI_8, -D_COS_PI_8);
  const double2 d_exp_9_16 = mk(-D_COS_PI_8, D_SIN_PI_8);
  const double2 d_exp_1_8 = mk(1.0, -1.0);  // post-multiply by 1/sqrt(2)
  const double2 d_exp_3_8 = mk(-1.0, -1.0); // post-multiply by 1/sqrt(2)

  fft4(a, 0, 4, 8, 12);
  fft4(a, 1, 5, 9, 13);
  fft4(a, 2, 6, 10, 14);
  fft4(a, 3, 7, 11, 15);

  a[5] = c_scale(c_mul(a[5], d_exp_1_8), D_SQRT1_2);
  a[6] = c_mul_exp_1_4(a[6]);
  a[7] = c_scale(c_mul(a[7], d_exp_3_8), D_SQRT1_2);
  a[9] = c_mul(a[9], d_exp_1_16);
  a[10] = c_scale(c_mul(a[10], d_exp_1_8), D_SQRT1_2);
  a[11] = c_mul(a[11], d_exp_3_16);
  a[13] = c_mul(a[13], d_exp_3_16);
  a[14] = c_scale(c_mul(a[14], d_exp_3_8), D_SQRT1_2);
  a[15] = c_mul(a[15], d_exp_9_16);

  fft4(a, 0, 1, 2, 3);
  fft4(a, 4, 5, 6, 7);
  fft4(a, 8, 9, 10, 11);
  fft4(a, 12, 13, 14, 15);
}

static inline void fft4x4(double2 *a) {
  fft4(a, 0, 1, 2, 3);
  fft4(a, 4, 5, 6, 7);
  fft4(a, 8, 9, 10, 11);
  fft4(a, 12, 13, 14, 15);
}

// --- Per-thread twiddle layers.

// Fused negacyclic pre-twist (matches
// apply_negacyclic_pre_twist_16x64_stage_fused). The half-table split at j == 8
// (<=> k == 512) is resolved statically, exactly as the GPU #pragma unroll
// does.
static inline void pre_twist(double2 *a, int tid) {
  for (int j = 0; j < 8; j++) {
    double2 tw = g_twisting_twiddles[tid + j * 64];
    a[j] = c_mul(a[j], mk(tw.x, -tw.y));
  }
  for (int j = 8; j < 16; j++) {
    double2 tw = g_twisting_twiddles[1024 - (tid + j * 64)];
    a[j] = c_mul(a[j], mk(-tw.y, tw.x));
  }
}

// Inter-stage twiddles from g_tw_1024 (matches mul_twiddles_16):
//   a[j] *= g_tw_1024[BITREV16[j] - 1][tid] for j = 1..15.
static inline void mul_twiddles_16(double2 *a, int tid) {
  for (int j = 1; j < 16; j++) {
    int r = BITREV16[j] - 1;
    a[j] = c_mul(a[j], g_tw_1024[r][tid]);
  }
}

// Compact twiddle layer (matches mul_twiddles_4x4_regs): the three active
// columns come from g_tw_1024[{7,3,11}][4 * lo4].
static inline void mul_twiddles_4x4(double2 *a, int tid) {
  int lo4 = tid & 15;
  double2 w1 = g_tw_1024[7][4 * lo4];
  double2 w2 = g_tw_1024[3][4 * lo4];
  double2 w3 = g_tw_1024[11][4 * lo4];
  const int c1[4] = {1, 5, 9, 13};
  const int c2[4] = {2, 6, 10, 14};
  const int c3[4] = {3, 7, 11, 15};
  for (int i : c1)
    a[i] = c_mul(a[i], w1);
  for (int i : c2)
    a[i] = c_mul(a[i], w2);
  for (int i : c3)
    a[i] = c_mul(a[i], w3);
}

// --- Shared-memory transposes. On the GPU these shuffle data between the 64
// threads of the FFT group; serially we route every thread's registers through
// a shared scratch buffer, reproducing the exact index arithmetic. Pure data
// movement — no arithmetic — so they cannot perturb any bit pattern.

// 16x64 transpose after the first FFT16 pass (matches permute_16x64_optimized).
static inline void permute_16x64(double2 regs[THREADS][REGS], double2 *smem) {
  for (int tid = 0; tid < THREADS; tid++) {
    int lo4 = tid & 15;
    int hi4 = tid >> 4;
    int sb = lo4 * 65 + hi4;
    for (int i = 0; i < 16; i++) {
      int ri = BITREV16[i];
      smem[sb + (i << 2)] = regs[tid][ri];
    }
  }
  for (int tid = 0; tid < THREADS; tid++) {
    int lo4 = tid & 15;
    int hi4 = tid >> 4;
    int lb = lo4 * 65 + (hi4 << 2);
    for (int i = 0; i < 16; i++) {
      int li = lb + (i >> 2) * 16 + (i & 3);
      regs[tid][i] = smem[li];
    }
  }
}

// 4x4 block transpose after the FFT4x4 pass (matches permute_4x4_optimized).
static inline void permute_4x4(double2 regs[THREADS][REGS], double2 *smem) {
  for (int tid = 0; tid < THREADS; tid++) {
    int lo2 = tid & 3;
    int mi2 = (tid >> 2) & 3;
    int hi2 = tid >> 4;
    int sb = hi2 * 17 + (mi2 << 2) + lo2;
    for (int i = 0; i < 16; i++) {
      int ri = (i & 12) | ((i & 1) << 1) | ((i & 2) >> 1);
      smem[sb + i * 69] = regs[tid][ri];
    }
  }
  for (int tid = 0; tid < THREADS; tid++) {
    int lo2 = tid & 3;
    int mi2 = (tid >> 2) & 3;
    int hi2 = tid >> 4;
    int lb = mi2 * 276 + hi2 * 69 + lo2 * 17;
    for (int i = 0; i < 16; i++)
      regs[tid][i] = smem[lb + i];
  }
}

// Forward FFT16x4x16 for a single polynomial (host reference).
//
// input / output are POLYNOMIAL_SIZE / 2 = 1024 complex coefficients, encoding
// complex[i] = (poly[i], poly[i + N/2]) — the same layout the device kernel
// consumes. Applies the fused negacyclic pre-twist and writes the spectrum in
// NATURAL frequency order, matching cuda_forward_fft16x4x16_async.
static void cpu_forward_fft16x4x16(const double2 *input, double2 *output) {
  // Load: regs[tid][j] = input[tid + j * 64].
  double2 regs[THREADS][REGS];
  for (int tid = 0; tid < THREADS; tid++)
    for (int j = 0; j < REGS; j++)
      regs[tid][j] = input[tid + j * 64];

  // Forward core (matches FFT16x4x16_fwd_optimized_for_pbs).
  for (int tid = 0; tid < THREADS; tid++) {
    pre_twist(regs[tid], tid);
    fft16(regs[tid]);
    mul_twiddles_16(regs[tid], tid);
  }
  // 65 * 16 = 1040 covers permute_16x64; 69 * 16 = 1104 covers permute_4x4.
  std::vector<double2> smem(69 * REGS, mk(0.0, 0.0));
  permute_16x64(regs, smem.data());
  for (int tid = 0; tid < THREADS; tid++) {
    fft4x4(regs[tid]);
    mul_twiddles_4x4(regs[tid], tid);
  }
  permute_4x4(regs, smem.data());
  for (int tid = 0; tid < THREADS; tid++)
    fft16(regs[tid]);

  // Store: un-scramble bit-reversed registers to natural frequency order.
  //   output[BITREV16[j] * 64 + tid] = regs[tid][j].
  for (int tid = 0; tid < THREADS; tid++)
    for (int j = 0; j < REGS; j++)
      output[BITREV16[j] * 64 + tid] = regs[tid][j];
}

// Reinterpret a double as its raw 64-bit pattern for exact comparison.
static inline uint64_t as_bits(double d) {
  uint64_t b;
  std::memcpy(&b, &d, sizeof(b));
  return b;
}

// ===========================================================================
//  AVX-512 host reference — a port of the Rust `avx512.rs`, vectorized across
//  the tid dimension (lane = tid, 8 tids per __m512d, struct-of-arrays layout,
//  which is exactly the GPU's within-FFT parallelism). Every op is a lane-wise
//  IEEE-754 correctly-rounded double operation, so each lane executes the same
//  sequence as the scalar path for its tid — hence bit-identical to both the
//  scalar reference and the GPU kernel. The two inter-stage transposes are
//  folded into the loads of the next phase (pure data movement, no arithmetic).
// ===========================================================================
#ifdef FFT16_HAVE_AVX512
namespace avx512 {

#define FFT16_AVX_TARGET __attribute__((target("avx512f,avx512dq")))

// Per-tid twiddle multipliers, separated into real/imag planes so a group of 8
// consecutive tids is one contiguous vector load. Built once from the same host
// twiddle tables (g_tw_1024 / g_twisting_twiddles) the scalar path uses.
struct Tw {
  double pre_re[REGS][THREADS];
  double pre_im[REGS][THREADS];
  double tw16_re[REGS][THREADS];
  double tw16_im[REGS][THREADS];
  double tw4_re[REGS][THREADS];
  double tw4_im[REGS][THREADS];
};

static void build_tw(Tw &t) {
  std::memset(&t, 0, sizeof(t));
  for (int tid = 0; tid < THREADS; tid++) {
    // Pre-twist: conj(psi) for the low half, (-im, re) for the high half.
    for (int j = 0; j < 8; j++) {
      double2 w = g_twisting_twiddles[tid + j * 64];
      t.pre_re[j][tid] = w.x;
      t.pre_im[j][tid] = -w.y;
    }
    for (int j = 8; j < 16; j++) {
      double2 w = g_twisting_twiddles[1024 - (tid + j * 64)];
      t.pre_re[j][tid] = -w.y;
      t.pre_im[j][tid] = w.x;
    }
    // mul_twiddles_16: a[j] *= g_tw_1024[BITREV16[j] - 1][tid].
    for (int j = 1; j < 16; j++) {
      double2 w = g_tw_1024[BITREV16[j] - 1][tid];
      t.tw16_re[j][tid] = w.x;
      t.tw16_im[j][tid] = w.y;
    }
    // mul_twiddles_4x4: three columns from g_tw_1024[{7,3,11}][4*lo4].
    int lo4 = tid & 15;
    double2 w1 = g_tw_1024[7][4 * lo4];
    double2 w2 = g_tw_1024[3][4 * lo4];
    double2 w3 = g_tw_1024[11][4 * lo4];
    const int c1[4] = {1, 5, 9, 13};
    const int c2[4] = {2, 6, 10, 14};
    const int c3[4] = {3, 7, 11, 15};
    for (int j : c1) {
      t.tw4_re[j][tid] = w1.x;
      t.tw4_im[j][tid] = w1.y;
    }
    for (int j : c2) {
      t.tw4_re[j][tid] = w2.x;
      t.tw4_im[j][tid] = w2.y;
    }
    for (int j : c3) {
      t.tw4_re[j][tid] = w3.x;
      t.tw4_im[j][tid] = w3.y;
    }
  }
}

// Complex product, encoding-identical to the scalar c_mul:
//   re = fmsub(are, bre, aim*bim),  im = fmadd(are, bim, aim*bre).
FFT16_AVX_TARGET static inline void cmul(__m512d are, __m512d aim, __m512d bre,
                                         __m512d bim, __m512d &ore,
                                         __m512d &oim) {
  ore = _mm512_fmsub_pd(are, bre, _mm512_mul_pd(aim, bim));
  oim = _mm512_fmadd_pd(are, bim, _mm512_mul_pd(aim, bre));
}
FFT16_AVX_TARGET static inline void cmul_c(__m512d are, __m512d aim, double cre,
                                           double cim, __m512d &ore,
                                           __m512d &oim) {
  cmul(are, aim, _mm512_set1_pd(cre), _mm512_set1_pd(cim), ore, oim);
}
// IEEE sign-bit flip (matches unary -, including the -0.0 edge case).
FFT16_AVX_TARGET static inline __m512d vnegate(__m512d x) {
  return _mm512_xor_pd(x, _mm512_set1_pd(-0.0));
}

FFT16_AVX_TARGET static inline void fft2(__m512d *re, __m512d *im, int i,
                                         int j) {
  __m512d c0re = re[i], c0im = im[i];
  re[i] = _mm512_add_pd(c0re, re[j]);
  im[i] = _mm512_add_pd(c0im, im[j]);
  re[j] = _mm512_sub_pd(c0re, re[j]);
  im[j] = _mm512_sub_pd(c0im, im[j]);
}
FFT16_AVX_TARGET static inline void fft2_mul_exp_1_4(__m512d *re, __m512d *im,
                                                     int i, int j) {
  __m512d c0re = re[i], c0im = im[i], a1re = re[j], a1im = im[j];
  re[i] = _mm512_add_pd(c0re, a1im);
  im[i] = _mm512_sub_pd(c0im, a1re);
  re[j] = _mm512_sub_pd(c0re, a1im);
  im[j] = _mm512_add_pd(c0im, a1re);
}
FFT16_AVX_TARGET static inline void fft4(__m512d *re, __m512d *im, int i0,
                                         int i1, int i2, int i3) {
  fft2(re, im, i0, i2);
  fft2(re, im, i1, i3);
  fft2(re, im, i0, i1);
  fft2_mul_exp_1_4(re, im, i2, i3);
}

FFT16_AVX_TARGET static void fft16(__m512d *re, __m512d *im) {
  fft4(re, im, 0, 4, 8, 12);
  fft4(re, im, 1, 5, 9, 13);
  fft4(re, im, 2, 6, 10, 14);
  fft4(re, im, 3, 7, 11, 15);

  __m512d s = _mm512_set1_pd(D_SQRT1_2);
  __m512d r, i;
  cmul_c(re[5], im[5], 1.0, -1.0, r, i);
  re[5] = _mm512_mul_pd(r, s);
  im[5] = _mm512_mul_pd(i, s);
  { // a[6] = (im, -re)
    __m512d t = im[6];
    im[6] = vnegate(re[6]);
    re[6] = t;
  }
  cmul_c(re[7], im[7], -1.0, -1.0, r, i);
  re[7] = _mm512_mul_pd(r, s);
  im[7] = _mm512_mul_pd(i, s);
  cmul_c(re[9], im[9], D_COS_PI_8, -D_SIN_PI_8, re[9], im[9]);
  cmul_c(re[10], im[10], 1.0, -1.0, r, i);
  re[10] = _mm512_mul_pd(r, s);
  im[10] = _mm512_mul_pd(i, s);
  cmul_c(re[11], im[11], D_SIN_PI_8, -D_COS_PI_8, re[11], im[11]);
  cmul_c(re[13], im[13], D_SIN_PI_8, -D_COS_PI_8, re[13], im[13]);
  cmul_c(re[14], im[14], -1.0, -1.0, r, i);
  re[14] = _mm512_mul_pd(r, s);
  im[14] = _mm512_mul_pd(i, s);
  cmul_c(re[15], im[15], -D_COS_PI_8, D_SIN_PI_8, re[15], im[15]);

  fft4(re, im, 0, 1, 2, 3);
  fft4(re, im, 4, 5, 6, 7);
  fft4(re, im, 8, 9, 10, 11);
  fft4(re, im, 12, 13, 14, 15);
}

FFT16_AVX_TARGET static inline void fft4x4(__m512d *re, __m512d *im) {
  fft4(re, im, 0, 1, 2, 3);
  fft4(re, im, 4, 5, 6, 7);
  fft4(re, im, 8, 9, 10, 11);
  fft4(re, im, 12, 13, 14, 15);
}

static inline int perm4(int x) {
  return (x & 12) | ((x & 1) << 1) | ((x & 2) >> 1);
}

// Phase A: deinterleave load from input -> pre-twist -> FFT16 ->
// mul_twiddles_16, writing SoA to a.
FFT16_AVX_TARGET static void phase_a(const Tw &tw, const double *input,
                                     double a_re[REGS][THREADS],
                                     double a_im[REGS][THREADS]) {
  __m512i idx_re = _mm512_setr_epi64(0, 2, 4, 6, 8, 10, 12, 14);
  __m512i idx_im = _mm512_setr_epi64(1, 3, 5, 7, 9, 11, 13, 15);
  for (int g = 0; g < THREADS / 8; g++) {
    int base = g * 8;
    __m512d vre[REGS], vim[REGS];
    for (int j = 0; j < REGS; j++) {
      int k = base + j * 64; // complex index of lane 0
      __m512d inp0 = _mm512_loadu_pd(input + 2 * k);
      __m512d inp1 = _mm512_loadu_pd(input + 2 * k + 8);
      vre[j] = _mm512_permutex2var_pd(inp0, idx_re, inp1);
      vim[j] = _mm512_permutex2var_pd(inp0, idx_im, inp1);
    }
    for (int j = 0; j < REGS; j++)
      cmul(vre[j], vim[j], _mm512_loadu_pd(&tw.pre_re[j][base]),
           _mm512_loadu_pd(&tw.pre_im[j][base]), vre[j], vim[j]);
    fft16(vre, vim);
    for (int j = 1; j < REGS; j++)
      cmul(vre[j], vim[j], _mm512_loadu_pd(&tw.tw16_re[j][base]),
           _mm512_loadu_pd(&tw.tw16_im[j][base]), vre[j], vim[j]);
    for (int j = 0; j < REGS; j++) {
      _mm512_storeu_pd(&a_re[j][base], vre[j]);
      _mm512_storeu_pd(&a_im[j][base], vim[j]);
    }
  }
}

// Phase B: folded permute_16x64 load from a -> FFT4x4 -> mul_twiddles_4x4,
// writing SoA to b.
FFT16_AVX_TARGET static void phase_b(const Tw &tw,
                                     const double a_re[REGS][THREADS],
                                     const double a_im[REGS][THREADS],
                                     double b_re[REGS][THREADS],
                                     double b_im[REGS][THREADS]) {
  for (int g = 0; g < THREADS / 8; g++) {
    int base = g * 8;
    __m512d vre[REGS], vim[REGS];
    for (int j = 0; j < REGS; j++) {
      int sreg = BITREV16[4 * (j >> 2) + (g >> 1)];
      int sbase = 8 * (g & 1) + 16 * (j & 3);
      vre[j] = _mm512_loadu_pd(&a_re[sreg][sbase]);
      vim[j] = _mm512_loadu_pd(&a_im[sreg][sbase]);
    }
    fft4x4(vre, vim);
    const int cols[12] = {1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15};
    for (int j : cols)
      cmul(vre[j], vim[j], _mm512_loadu_pd(&tw.tw4_re[j][base]),
           _mm512_loadu_pd(&tw.tw4_im[j][base]), vre[j], vim[j]);
    for (int j = 0; j < REGS; j++) {
      _mm512_storeu_pd(&b_re[j][base], vre[j]);
      _mm512_storeu_pd(&b_im[j][base], vim[j]);
    }
  }
}

// Phase C: folded permute_4x4 gather from b -> FFT16 -> interleaved store to
// output in natural frequency order.
FFT16_AVX_TARGET static void phase_c(const double b_re[REGS][THREADS],
                                     const double b_im[REGS][THREADS],
                                     double *output) {
  __m512i idx0 = _mm512_setr_epi64(0, 8, 1, 9, 2, 10, 3, 11);
  __m512i idx1 = _mm512_setr_epi64(4, 12, 5, 13, 6, 14, 7, 15);
  for (int g = 0; g < THREADS / 8; g++) {
    int base = g * 8;
    int hi2 = g >> 1;
    int ra = perm4(4 * ((2 * g) & 3) + hi2);
    int rb = perm4(4 * ((2 * g + 1) & 3) + hi2);
    __m512d vre[REGS], vim[REGS];
    for (int j = 0; j < REGS; j++) {
      double tre[8], tim[8];
      for (int r = 0; r < 4; r++) {
        int tid = j + 16 * r;
        tre[r] = b_re[ra][tid];
        tim[r] = b_im[ra][tid];
        tre[4 + r] = b_re[rb][tid];
        tim[4 + r] = b_im[rb][tid];
      }
      vre[j] = _mm512_loadu_pd(tre);
      vim[j] = _mm512_loadu_pd(tim);
    }
    fft16(vre, vim);
    for (int j = 0; j < REGS; j++) {
      int f = BITREV16[j] * 64 + base; // complex index of lane 0
      __m512d out0 = _mm512_permutex2var_pd(vre[j], idx0, vim[j]);
      __m512d out1 = _mm512_permutex2var_pd(vre[j], idx1, vim[j]);
      _mm512_storeu_pd(output + 2 * f, out0);
      _mm512_storeu_pd(output + 2 * f + 8, out1);
    }
  }
}

// AVX-512 forward FFT16x4x16 for a single polynomial. input/output are
// POLYNOMIAL_SIZE / 2 = 1024 complex coefficients (same layout as the scalar
// path); double2 is contiguous {re, im}, so it aliases the interleaved f64 view
// the phases use.
FFT16_AVX_TARGET static void forward(const Tw &tw, const double2 *input,
                                     double2 *output) {
  static double a_re[REGS][THREADS], a_im[REGS][THREADS];
  static double b_re[REGS][THREADS], b_im[REGS][THREADS];
  const double *in = reinterpret_cast<const double *>(input);
  double *out = reinterpret_cast<double *>(output);
  phase_a(tw, in, a_re, a_im);
  phase_b(tw, a_re, a_im, b_re, b_im);
  phase_c(b_re, b_im, out);
}

} // namespace avx512
#endif // FFT16_HAVE_AVX512

} // namespace

// FFT16x4x16 is specialized for N = 2048; run a batch of samples per
// invocation.
constexpr size_t FFT16_POLYNOMIAL_SIZE = 2048;
constexpr int FFT16_SAMPLES = 100;

TEST(CpuGpuFFT16x4x16, forward_matches_cpu_bitwise) {
  const uint32_t gpu_index = 0;

  // H100 gate: the FFT16x4x16 core needs the mbarrier / named-barrier
  // primitives introduced with sm_90 (Hopper). Restrict to compute capability
  // 9.x (H100 / H200 / GH200) and skip everything else. Loosen the check to
  // `prop.major >= 9` to also cover newer architectures (Blackwell, ...).
  cudaDeviceProp prop;
  cudaError_t err = cudaGetDeviceProperties(&prop, gpu_index);
  if (err != cudaSuccess || prop.major != 9) {
    GTEST_SKIP() << "FFT16x4x16 CPU/GPU bit-exact test runs only on H100 "
                 << "(compute capability 9.x); detected "
                 << (err == cudaSuccess ? prop.major : -1) << "."
                 << (err == cudaSuccess ? prop.minor : -1);
  }

  // Pull the GPU twiddle tables down to host memory so the CPU reference uses
  // the exact same constants the kernel does (single source of truth in the
  // backend). If the device symbols are not reachable, fail loudly rather than
  // silently comparing against uninitialized tables.
  ASSERT_EQ(cudaMemcpyFromSymbol(g_tw_1024, tw_1024, sizeof(g_tw_1024)),
            cudaSuccess)
      << "cudaMemcpyFromSymbol(tw_1024) failed";
  ASSERT_EQ(cudaMemcpyFromSymbol(g_twisting_twiddles, twisting_twiddles,
                                 sizeof(g_twisting_twiddles)),
            cudaSuccess)
      << "cudaMemcpyFromSymbol(twisting_twiddles) failed";

  const size_t half = FFT16_POLYNOMIAL_SIZE / 2; // 1024 complex coeffs
  const size_t total = half * (size_t)FFT16_SAMPLES;

  // Fresh random complex input on every run: seed from the OS entropy source
  // so no two invocations share a set of values.
  std::random_device rd;
  std::mt19937_64 gen(rd());
  std::uniform_real_distribution<double> unif(-1.0, 1.0);

  std::vector<double2> h_input(total);
  for (size_t i = 0; i < total; i++)
    h_input[i] = double2{unif(gen), unif(gen)};

  cudaStream_t stream = cuda_create_stream(gpu_index);

  double2 *d_input = (double2 *)cuda_malloc_async(
      safe_mul_sizeof<double2>(total), stream, gpu_index);
  double2 *d_output = (double2 *)cuda_malloc_async(
      safe_mul_sizeof<double2>(total), stream, gpu_index);

  cuda_memcpy_async_to_gpu(d_input, h_input.data(),
                           safe_mul_sizeof<double2>(total), stream, gpu_index);

  cuda_forward_fft16x4x16_async(stream, gpu_index, d_input, d_output,
                                FFT16_POLYNOMIAL_SIZE, FFT16_SAMPLES);

  std::vector<double2> h_gpu(total);
  cuda_memcpy_async_to_cpu(h_gpu.data(), d_output,
                           safe_mul_sizeof<double2>(total), stream, gpu_index);
  cuda_synchronize_stream(stream, gpu_index);

  // CPU reference on the exact same input, one polynomial at a time.
  std::vector<double2> h_cpu(total);
  for (int p = 0; p < FFT16_SAMPLES; p++)
    cpu_forward_fft16x4x16(&h_input[(size_t)p * half],
                           &h_cpu[(size_t)p * half]);

  // Bit-for-bit comparison: GPU vs scalar CPU reference.
  for (int p = 0; p < FFT16_SAMPLES; p++) {
    for (size_t f = 0; f < half; f++) {
      size_t idx = (size_t)p * half + f;
      ASSERT_EQ(as_bits(h_gpu[idx].x), as_bits(h_cpu[idx].x))
          << "scalar sample " << p << " frequency " << f << " (real): gpu "
          << h_gpu[idx].x << " vs cpu " << h_cpu[idx].x;
      ASSERT_EQ(as_bits(h_gpu[idx].y), as_bits(h_cpu[idx].y))
          << "scalar sample " << p << " frequency " << f << " (imag): gpu "
          << h_gpu[idx].y << " vs cpu " << h_cpu[idx].y;
    }
  }

  // Additional comparison: GPU vs the AVX-512 host path (which, being lane-wise
  // over tid, must also be bit-identical). Runs only where AVX-512 is
  // available; otherwise it is reported as skipped without failing the scalar
  // check above.
#ifdef FFT16_HAVE_AVX512
  if (__builtin_cpu_supports("avx512f") && __builtin_cpu_supports("avx512dq")) {
    static avx512::Tw tw_avx;
    avx512::build_tw(tw_avx);
    std::vector<double2> h_avx(total);
    for (int p = 0; p < FFT16_SAMPLES; p++)
      avx512::forward(tw_avx, &h_input[(size_t)p * half],
                      &h_avx[(size_t)p * half]);
    for (int p = 0; p < FFT16_SAMPLES; p++) {
      for (size_t f = 0; f < half; f++) {
        size_t idx = (size_t)p * half + f;
        ASSERT_EQ(as_bits(h_gpu[idx].x), as_bits(h_avx[idx].x))
            << "avx512 sample " << p << " frequency " << f << " (real): gpu "
            << h_gpu[idx].x << " vs avx " << h_avx[idx].x;
        ASSERT_EQ(as_bits(h_gpu[idx].y), as_bits(h_avx[idx].y))
            << "avx512 sample " << p << " frequency " << f << " (imag): gpu "
            << h_gpu[idx].y << " vs avx " << h_avx[idx].y;
      }
    }
    std::cout << "[ INFO     ] AVX-512 path compared bit-for-bit vs GPU ("
              << FFT16_SAMPLES << " polynomials)" << std::endl;
  } else {
    std::cout << "[ INFO     ] AVX-512 unavailable at runtime; AVX comparison "
                 "skipped (scalar vs GPU still checked)"
              << std::endl;
  }
#else
  std::cout << "[ INFO     ] AVX-512 not compiled on this architecture; AVX "
               "comparison skipped (scalar vs GPU still checked)"
            << std::endl;
#endif

  cuda_drop_async(d_input, stream, gpu_index);
  cuda_drop_async(d_output, stream, gpu_index);
  cuda_synchronize_stream(stream, gpu_index);
  cuda_destroy_stream(stream, gpu_index);
}
