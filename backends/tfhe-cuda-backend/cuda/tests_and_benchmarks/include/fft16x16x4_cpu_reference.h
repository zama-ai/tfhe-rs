#ifndef FFT16X16X4_CPU_REFERENCE_H
#define FFT16X16X4_CPU_REFERENCE_H

#include "device.h"
#include <cmath>
#include <cstdint>
#include <cstring>
#include <cuda_runtime.h>

// AVX-512 host reference (x86 only): per-function target attributes, so the
// rest of the test build needs no global -mavx512* flags; gated at runtime.
#if defined(__x86_64__) || defined(__i386__)
#include <immintrin.h>
#define FFT16_HAVE_AVX512 1
#endif

// Serial host port of the paired FFT16x16x4 transforms (fft16x16x4.cuh) for
// the bit-exact CPU-vs-GPU tests. Every operation is the IEEE-754 correctly
// rounded one the kernel performs: plain +, -, * for __dadd_rn / __dsub_rn /
// __dmul_rn and std::fma for __fma_rn, in the same order, so the results are
// identical bit for bit. The shared-memory transposes become index arithmetic
// on host arrays; they move data and never round. One call models one
// (64, 2, 1) block, i.e. a pair of polynomials.

// Device twiddle tables, defined once in src/fft/fft16x16x4_twiddles.cu and
// copied to the host at runtime so both sides use identical bytes.
extern __device__ __constant__ double2 tw_1024[15][64];
extern __device__ __constant__ double2 twisting_twiddles[513];

namespace fft16x16x4_cpu {

constexpr int THREADS = 64; // threads per group
constexpr int GROUPS = 2;   // y-groups per block, one polynomial each
constexpr int REGS = 16;    // registers per thread
constexpr int HALF = 1024;  // complex coefficients per polynomial

static inline double bits_to_f64(uint64_t b) {
  double d;
  std::memcpy(&d, &b, sizeof(d));
  return d;
}
static inline uint64_t f64_to_bits(double d) {
  uint64_t b;
  std::memcpy(&b, &d, sizeof(b));
  return b;
}

// Scalar constants, exact bit patterns of the CUDA #defines and of M_SQRT1_2.
static const double D_COS_PI_8 = bits_to_f64(0x3fed906bcf328d46ULL);
static const double D_SIN_PI_8 = bits_to_f64(0x3fd87de2a6aea963ULL);
static const double D_SQRT1_2 = bits_to_f64(0x3fe6a09e667f3bcdULL);

// W64^c = cos - i*sin, c = 0..15, the literals of fft16x16x4_w64.
static const double COS_C[16] = {
    0x1.0000000000000p+0, 0x1.fd88da3d12526p-1, 0x1.f6297cff75cb0p-1,
    0x1.e9f4156c62ddap-1, 0x1.d906bcf328d46p-1, 0x1.c38b2f180bdb1p-1,
    0x1.a9b66290ea1a3p-1, 0x1.8bc806b151741p-1, 0x1.6a09e667f3bcdp-1,
    0x1.44cf325091dd6p-1, 0x1.1c73b39ae68c9p-1, 0x1.e2b5d3806f63ep-2,
    0x1.87de2a6aea964p-2, 0x1.294062ed59f05p-2, 0x1.8f8b83c69a60dp-3,
    0x1.917a6bc29b438p-4,
};
static const double SIN_C[16] = {
    0x0.0000000000000p+0, 0x1.917a6bc29b42cp-4, 0x1.8f8b83c69a60ap-3,
    0x1.294062ed59f05p-2, 0x1.87de2a6aea963p-2, 0x1.e2b5d3806f63bp-2,
    0x1.1c73b39ae68c8p-1, 0x1.44cf325091dd6p-1, 0x1.6a09e667f3bccp-1,
    0x1.8bc806b151741p-1, 0x1.a9b66290ea1a3p-1, 0x1.c38b2f180bdb0p-1,
    0x1.d906bcf328d46p-1, 0x1.e9f4156c62ddbp-1, 0x1.f6297cff75cb0p-1,
    0x1.fd88da3d12525p-1,
};

// Complex primitives, matching types/complex/operations.cuh.
static inline double2 mk(double re, double im) { return double2{re, im}; }
static inline double2 c_add(double2 a, double2 b) {
  return mk(a.x + b.x, a.y + b.y);
}
static inline double2 c_sub(double2 a, double2 b) {
  return mk(a.x - b.x, a.y - b.y);
}
// re = fma(a.x, b.x, -(a.y * b.y)), im = fma(a.x, b.y, a.y * b.x).
static inline double2 c_mul(double2 a, double2 b) {
  return mk(std::fma(a.x, b.x, -(a.y * b.y)), std::fma(a.x, b.y, a.y * b.x));
}
static inline double2 c_scale(double2 a, double s) {
  return mk(a.x * s, a.y * s);
}
static inline double2 c_conj(double2 a) { return mk(a.x, -a.y); }
static inline double2 w64(int c) { return mk(COS_C[c], -SIN_C[c]); }

static const int BITREV16[16] = {0, 8, 4, 12, 2, 10, 6, 14,
                                 1, 9, 5, 13, 3, 11, 7, 15};
static inline int bitrev4(int v) { return ((v & 1) << 1) | ((v & 2) >> 1); }
static inline int first_index(int r, int u) {
  return (r << 6) + (u ^ ((r & 1) << 2));
}
static inline int last_index(int q, int a) {
  return (q << 2) + (a ^ ((q >> 1) & 3));
}
static inline int first_read(int tid, int b) {
  return ((tid >> 2) << 6) + (tid & 3) + ((tid & 4) ^ ((b & 1) << 2)) +
         ((b >> 1) << 3);
}
// Natural-order frequency held by thread T in register 4*h + v.
static inline int paired_frequency(int T, int h, int v) {
  return T + 128 * h + 256 * bitrev4(v);
}

// Butterflies, direct ports of fft16x16x4.cuh (forward sign = -1).
static inline void fft2(double2 *a, int i, int j) {
  double2 c0 = a[i];
  a[i] = c_add(c0, a[j]);
  a[j] = c_sub(c0, a[j]);
}
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
static inline void fft16(double2 *a) {
  const double2 d_exp_1_16 = mk(D_COS_PI_8, -D_SIN_PI_8);
  const double2 d_exp_3_16 = mk(D_SIN_PI_8, -D_COS_PI_8);
  const double2 d_exp_9_16 = mk(-D_COS_PI_8, D_SIN_PI_8);
  const double2 d_exp_1_8 = mk(1.0, -1.0);
  const double2 d_exp_3_8 = mk(-1.0, -1.0);

  fft4(a, 0, 4, 8, 12);
  fft4(a, 1, 5, 9, 13);
  fft4(a, 2, 6, 10, 14);
  fft4(a, 3, 7, 11, 15);

  a[5] = c_scale(c_mul(a[5], d_exp_1_8), D_SQRT1_2);
  a[6] = mk(a[6].y, -a[6].x);
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

// Inverse butterflies (sign = +1).
static inline void ifft2_mul_iexp_1_4(double2 *a, int i, int j) {
  double2 c0 = a[i];
  double2 a1 = a[j];
  a[i].x = c0.x - a1.y;
  a[i].y = c0.y + a1.x;
  a[j].x = c0.x + a1.y;
  a[j].y = c0.y - a1.x;
}
static inline void ifft4(double2 *a, int i0, int i1, int i2, int i3) {
  fft2(a, i0, i2);
  fft2(a, i1, i3);
  fft2(a, i0, i1);
  ifft2_mul_iexp_1_4(a, i2, i3);
}
static inline void ifft16(double2 *a) {
  const double2 d_iexp_1_16 = mk(D_COS_PI_8, D_SIN_PI_8);
  const double2 d_iexp_3_16 = mk(D_SIN_PI_8, D_COS_PI_8);
  const double2 d_iexp_9_16 = mk(-D_COS_PI_8, -D_SIN_PI_8);
  const double2 d_iexp_1_8 = mk(1.0, 1.0);
  const double2 d_iexp_3_8 = mk(-1.0, 1.0);

  ifft4(a, 0, 4, 8, 12);
  ifft4(a, 1, 5, 9, 13);
  ifft4(a, 2, 6, 10, 14);
  ifft4(a, 3, 7, 11, 15);

  a[5] = c_scale(c_mul(a[5], d_iexp_1_8), D_SQRT1_2);
  a[6] = mk(-a[6].y, a[6].x);
  a[7] = c_scale(c_mul(a[7], d_iexp_3_8), D_SQRT1_2);
  a[9] = c_mul(a[9], d_iexp_1_16);
  a[10] = c_scale(c_mul(a[10], d_iexp_1_8), D_SQRT1_2);
  a[11] = c_mul(a[11], d_iexp_3_16);
  a[13] = c_mul(a[13], d_iexp_3_16);
  a[14] = c_scale(c_mul(a[14], d_iexp_3_8), D_SQRT1_2);
  a[15] = c_mul(a[15], d_iexp_9_16);

  ifft4(a, 0, 1, 2, 3);
  ifft4(a, 4, 5, 6, 7);
  ifft4(a, 8, 9, 10, 11);
  ifft4(a, 12, 13, 14, 15);
}
static inline void ifft4x4(double2 *a) {
  ifft4(a, 0, 1, 2, 3);
  ifft4(a, 4, 5, 6, 7);
  ifft4(a, 8, 9, 10, 11);
  ifft4(a, 12, 13, 14, 15);
}

// Host copies of the device tables plus the twist-folded rows the block
// loader computes (fft16x16x4_load_shared_twiddles_folded_128t).
struct Tables {
  double2 tw_1024[15][64];
  double2 twisting[513];
  double2 folded[15][64]; // folded[r][lane] = tw_1024[r][lane] * conj(psi^lane)
};

static inline void load_tables_from_device(Tables &t) {
  check_cuda_error(cudaMemcpyFromSymbol(t.tw_1024, tw_1024, sizeof(t.tw_1024)));
  check_cuda_error(
      cudaMemcpyFromSymbol(t.twisting, twisting_twiddles, sizeof(t.twisting)));
  for (int r = 0; r < 15; r++)
    for (int lane = 0; lane < 64; lane++)
      t.folded[r][lane] = c_mul(t.tw_1024[r][lane], c_conj(t.twisting[lane]));
}

// Per-thread register state of the block setup (fft16x16x4_block_setup).
struct ThreadTw {
  double2 r0;         // conj(psi^tid), row 0 of the folded table
  double2 small_w[6]; // W64^(s*a) roots of the thread's two q groups
};
static inline ThreadTw thread_twiddles(const Tables &t, int T) {
  ThreadTw w;
  w.r0 = c_conj(t.twisting[T & 63]);
  for (int h = 0; h < 2; h++) {
    int s = (T >> 4) + 8 * h;
    w.small_w[3 * h + 0] = t.tw_1024[3][4 * s];
    w.small_w[3 * h + 1] = t.tw_1024[7][4 * s];
    w.small_w[3 * h + 2] = t.tw_1024[11][4 * s];
  }
  return w;
}

// mul_twiddles_16_folded_cached: the cached rows hold the same folded values
// as the table, so every register reads folded[bitreversal16(j) - 1][tid].
static inline void mul_twiddles_16_folded(const Tables &t, double2 r0,
                                          double2 *a, int tid) {
  a[0] = c_mul(a[0], r0);
  for (int j = 1; j < 16; j++)
    a[j] = c_mul(a[j], t.folded[BITREV16[j] - 1][tid]);
}
// mul_itwiddles_16_natural_cached: n[j] times the conjugate of folded row j.
static inline void mul_itwiddles_16_natural(const Tables &t, double2 r0,
                                            double2 *n, int tid) {
  n[0] = c_mul(n[0], c_conj(r0));
  for (int j = 1; j < 16; j++)
    n[j] = c_mul(n[j], c_conj(t.folded[j - 1][tid]));
}
// mul_small_twiddles_16x16x4<Inverse>.
static inline void mul_small_twiddles(const double2 *w, double2 *a,
                                      bool inverse) {
  for (int h = 0; h < 2; h++) {
    double2 w1 = w[3 * h + 0], w2 = w[3 * h + 1], w3 = w[3 * h + 2];
    if (inverse) {
      w1 = c_conj(w1);
      w2 = c_conj(w2);
      w3 = c_conj(w3);
    }
    for (int p = 0; p < 2; p++) {
      a[8 * p + 4 * h + 1] = c_mul(a[8 * p + 4 * h + 1], w1);
      a[8 * p + 4 * h + 2] = c_mul(a[8 * p + 4 * h + 2], w2);
      a[8 * p + 4 * h + 3] = c_mul(a[8 * p + 4 * h + 3], w3);
    }
  }
}

// Register file and transpose regions of one block.
struct Block {
  double2 a[GROUPS * THREADS][REGS];
  double2 P[GROUPS][HALF]; // xpose_y
  double2 Q[GROUPS][HALF]; // xpose_pong_y
};

// Forward pair (batch_forward_fft16x16x4): natural time order in, natural
// frequency order out, no 1/N.
static inline void forward_pair(const Tables &t, const double2 *in0,
                                const double2 *in1, double2 *out0,
                                double2 *out1) {
  static Block blk;
  const double2 *in[2] = {in0, in1};

  // Load, pre-twist constants, FFT16 along c, folded twiddles, transpose #1.
  for (int y = 0; y < GROUPS; y++)
    for (int tid = 0; tid < THREADS; tid++) {
      const int T = tid + 64 * y;
      const ThreadTw w = thread_twiddles(t, T);
      double2 *a = blk.a[T];
      for (int j = 0; j < REGS; j++)
        a[j] = in[y][tid + j * 64];
      for (int c = 1; c < 16; c++)
        a[c] = c_mul(a[c], c_conj(w64(c)));
      fft16(a);
      mul_twiddles_16_folded(t, w.r0, a, tid);
      for (int j = 0; j < REGS; j++)
        blk.P[y][first_index(BITREV16[j], tid)] = a[j];
    }
  // Read back, FFT16 along b, transpose #2 (ownership change).
  for (int y = 0; y < GROUPS; y++)
    for (int tid = 0; tid < THREADS; tid++) {
      double2 *a = blk.a[tid + 64 * y];
      for (int b = 0; b < REGS; b++)
        a[b] = blk.P[y][first_read(tid, b)];
      fft16(a);
      for (int j = 0; j < REGS; j++)
        blk.Q[y][last_index((tid >> 2) + 16 * BITREV16[j], tid & 3)] = a[j];
    }
  // Paired read of both components, small twiddles, FFT4 along a, store.
  for (int y = 0; y < GROUPS; y++)
    for (int tid = 0; tid < THREADS; tid++) {
      const int T = tid + 64 * y;
      const ThreadTw w = thread_twiddles(t, T);
      double2 *a = blk.a[T];
      for (int h = 0; h < 2; h++)
        for (int v = 0; v < 4; v++) {
          a[4 * h + v] = blk.Q[0][last_index(T + 128 * h, v)];
          a[8 + 4 * h + v] = blk.Q[1][last_index(T + 128 * h, v)];
        }
      mul_small_twiddles(w.small_w, a, false);
      fft4x4(a);
      for (int h = 0; h < 2; h++)
        for (int v = 0; v < 4; v++) {
          const int f = paired_frequency(T, h, v);
          out0[f] = a[4 * h + v];
          out1[f] = a[8 + 4 * h + v];
        }
    }
}

// Inverse pair (batch_backward_fft16x16x4): natural-order spectra in,
// natural time order out, no 1/N.
static inline void inverse_pair(const Tables &t, const double2 *in0,
                                const double2 *in1, double2 *out0,
                                double2 *out1) {
  static Block blk;
  const double2 *in[2] = {in0, in1};
  double2 *out[2] = {out0, out1};

  // Owner-relative paired load, IFFT4 along a, small twiddles, un-pairing.
  for (int y = 0; y < GROUPS; y++)
    for (int tid = 0; tid < THREADS; tid++) {
      const int T = tid + 64 * y;
      const ThreadTw w = thread_twiddles(t, T);
      double2 *a = blk.a[T];
      double2 n[REGS];
      for (int h = 0; h < 2; h++)
        for (int v = 0; v < 4; v++) {
          const int f = paired_frequency(T, h, v);
          a[4 * h + v] = in[y][f];
          a[8 + 4 * h + v] = in[1 - y][f];
        }
      for (int g = 0; g < 4; g++)
        for (int v = 0; v < 4; v++)
          n[4 * g + v] = a[4 * g + bitrev4(v)];
      ifft4x4(n);
      for (int g = 0; g < 4; g++)
        for (int v = 0; v < 4; v++)
          a[4 * g + v] = n[4 * g + bitrev4(v)];
      mul_small_twiddles(w.small_w, a, true);
      for (int h = 0; h < 2; h++)
        for (int v = 0; v < 4; v++) {
          blk.P[1 - y][last_index(T + 128 * h, v)] = a[8 + 4 * h + v];
          blk.P[y][last_index(T + 128 * h, v)] = a[4 * h + v];
        }
    }
  // IFFT16 along b, transpose #1 reversed.
  for (int y = 0; y < GROUPS; y++)
    for (int tid = 0; tid < THREADS; tid++) {
      double2 n[REGS];
      for (int j = 0; j < REGS; j++)
        n[j] = blk.P[y][last_index((tid >> 2) + 16 * j, tid & 3)];
      ifft16(n);
      for (int j = 0; j < REGS; j++)
        blk.Q[y][first_read(tid, j)] = n[BITREV16[j]];
    }
  // Inverse large twiddles, IFFT16 along c, post-twist constants, store.
  for (int y = 0; y < GROUPS; y++)
    for (int tid = 0; tid < THREADS; tid++) {
      const int T = tid + 64 * y;
      const ThreadTw w = thread_twiddles(t, T);
      double2 n[REGS];
      for (int j = 0; j < REGS; j++)
        n[j] = blk.Q[y][first_index(j, tid)];
      mul_itwiddles_16_natural(t, w.r0, n, tid);
      ifft16(n);
      for (int j = 1; j < 16; j++)
        n[j] = c_mul(n[j], w64(BITREV16[j]));
      for (int j = 0; j < REGS; j++)
        out[y][BITREV16[j] * 64 + tid] = n[j];
    }
}

// ============================================================================
//  AVX-512 reference: the same transforms vectorised across the thread index
//  (lane = thread, 8 threads per __m512d, struct-of-arrays planes). Every op
//  is a lane-wise IEEE-754 correctly rounded double operation, so each lane
//  runs the scalar sequence of its thread and the result is bit-identical to
//  the scalar path and to the GPU. The transposes move data between phases.
// ============================================================================
#ifdef FFT16_HAVE_AVX512
namespace avx512 {
#define FFT16_AVX_TARGET __attribute__((target("avx512f,avx512dq")))

constexpr int NT = GROUPS * THREADS; // 128 threads per block
constexpr int LANES = 8;

// Register file of the block as planes: re[j][T], im[j][T].
struct Soa {
  double re[REGS][NT];
  double im[REGS][NT];
};

// Per-thread twiddle planes, built once from the host tables.
struct Tw {
  double fold_re[REGS][NT], fold_im[REGS][NT];   // forward twiddle layer
  double ifold_re[REGS][NT], ifold_im[REGS][NT]; // inverse twiddle layer
  double sw_re[6][NT], sw_im[6][NT];             // W64^(s*a) roots
};

static void build_tw(const Tables &t, Tw &w) {
  std::memset(&w, 0, sizeof(w));
  for (int T = 0; T < NT; T++) {
    const int tid = T & 63;
    const ThreadTw tt = thread_twiddles(t, T);
    w.fold_re[0][T] = tt.r0.x;
    w.fold_im[0][T] = tt.r0.y;
    w.ifold_re[0][T] = tt.r0.x;
    w.ifold_im[0][T] = -tt.r0.y;
    for (int j = 1; j < REGS; j++) {
      const double2 f = t.folded[BITREV16[j] - 1][tid];
      w.fold_re[j][T] = f.x;
      w.fold_im[j][T] = f.y;
      const double2 g = t.folded[j - 1][tid];
      w.ifold_re[j][T] = g.x;
      w.ifold_im[j][T] = -g.y;
    }
    for (int k = 0; k < 6; k++) {
      w.sw_re[k][T] = tt.small_w[k].x;
      w.sw_im[k][T] = tt.small_w[k].y;
    }
  }
}

// Complex product, encoding-identical to c_mul:
//   re = fmsub(a_re, b_re, a_im*b_im), im = fmadd(a_re, b_im, a_im*b_re).
FFT16_AVX_TARGET static inline void cmul(__m512d a_re, __m512d a_im,
                                         __m512d b_re, __m512d b_im,
                                         __m512d &o_re, __m512d &o_im) {
  o_re = _mm512_fmsub_pd(a_re, b_re, _mm512_mul_pd(a_im, b_im));
  o_im = _mm512_fmadd_pd(a_re, b_im, _mm512_mul_pd(a_im, b_re));
}
FFT16_AVX_TARGET static inline void cmul_c(__m512d a_re, __m512d a_im,
                                           double c_re, double c_im,
                                           __m512d &o_re, __m512d &o_im) {
  cmul(a_re, a_im, _mm512_set1_pd(c_re), _mm512_set1_pd(c_im), o_re, o_im);
}
// IEEE sign-bit flip (matches unary -, including -0.0).
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
FFT16_AVX_TARGET static inline void ifft2_mul_iexp_1_4(__m512d *re, __m512d *im,
                                                       int i, int j) {
  __m512d c0re = re[i], c0im = im[i], a1re = re[j], a1im = im[j];
  re[i] = _mm512_sub_pd(c0re, a1im);
  im[i] = _mm512_add_pd(c0im, a1re);
  re[j] = _mm512_add_pd(c0re, a1im);
  im[j] = _mm512_sub_pd(c0im, a1re);
}
FFT16_AVX_TARGET static inline void fft4(__m512d *re, __m512d *im, int i0,
                                         int i1, int i2, int i3) {
  fft2(re, im, i0, i2);
  fft2(re, im, i1, i3);
  fft2(re, im, i0, i1);
  fft2_mul_exp_1_4(re, im, i2, i3);
}
FFT16_AVX_TARGET static inline void ifft4(__m512d *re, __m512d *im, int i0,
                                          int i1, int i2, int i3) {
  fft2(re, im, i0, i2);
  fft2(re, im, i1, i3);
  fft2(re, im, i0, i1);
  ifft2_mul_iexp_1_4(re, im, i2, i3);
}
// (a * (c_re, c_im)) * D_SQRT1_2 on register j.
FFT16_AVX_TARGET static inline void scale_diag(__m512d *re, __m512d *im, int j,
                                               double c_re, double c_im) {
  __m512d r, i;
  cmul_c(re[j], im[j], c_re, c_im, r, i);
  const __m512d s = _mm512_set1_pd(D_SQRT1_2);
  re[j] = _mm512_mul_pd(r, s);
  im[j] = _mm512_mul_pd(i, s);
}
FFT16_AVX_TARGET static void fft16(__m512d *re, __m512d *im) {
  fft4(re, im, 0, 4, 8, 12);
  fft4(re, im, 1, 5, 9, 13);
  fft4(re, im, 2, 6, 10, 14);
  fft4(re, im, 3, 7, 11, 15);
  scale_diag(re, im, 5, 1.0, -1.0);
  { // a[6] = (im, -re)
    __m512d t = im[6];
    im[6] = vnegate(re[6]);
    re[6] = t;
  }
  scale_diag(re, im, 7, -1.0, -1.0);
  cmul_c(re[9], im[9], D_COS_PI_8, -D_SIN_PI_8, re[9], im[9]);
  scale_diag(re, im, 10, 1.0, -1.0);
  cmul_c(re[11], im[11], D_SIN_PI_8, -D_COS_PI_8, re[11], im[11]);
  cmul_c(re[13], im[13], D_SIN_PI_8, -D_COS_PI_8, re[13], im[13]);
  scale_diag(re, im, 14, -1.0, -1.0);
  cmul_c(re[15], im[15], -D_COS_PI_8, D_SIN_PI_8, re[15], im[15]);
  fft4(re, im, 0, 1, 2, 3);
  fft4(re, im, 4, 5, 6, 7);
  fft4(re, im, 8, 9, 10, 11);
  fft4(re, im, 12, 13, 14, 15);
}
FFT16_AVX_TARGET static void ifft16(__m512d *re, __m512d *im) {
  ifft4(re, im, 0, 4, 8, 12);
  ifft4(re, im, 1, 5, 9, 13);
  ifft4(re, im, 2, 6, 10, 14);
  ifft4(re, im, 3, 7, 11, 15);
  scale_diag(re, im, 5, 1.0, 1.0);
  { // a[6] = (-im, re)
    __m512d t = re[6];
    re[6] = vnegate(im[6]);
    im[6] = t;
  }
  scale_diag(re, im, 7, -1.0, 1.0);
  cmul_c(re[9], im[9], D_COS_PI_8, D_SIN_PI_8, re[9], im[9]);
  scale_diag(re, im, 10, 1.0, 1.0);
  cmul_c(re[11], im[11], D_SIN_PI_8, D_COS_PI_8, re[11], im[11]);
  cmul_c(re[13], im[13], D_SIN_PI_8, D_COS_PI_8, re[13], im[13]);
  scale_diag(re, im, 14, -1.0, 1.0);
  cmul_c(re[15], im[15], -D_COS_PI_8, -D_SIN_PI_8, re[15], im[15]);
  ifft4(re, im, 0, 1, 2, 3);
  ifft4(re, im, 4, 5, 6, 7);
  ifft4(re, im, 8, 9, 10, 11);
  ifft4(re, im, 12, 13, 14, 15);
}
FFT16_AVX_TARGET static inline void fft4x4(__m512d *re, __m512d *im) {
  fft4(re, im, 0, 1, 2, 3);
  fft4(re, im, 4, 5, 6, 7);
  fft4(re, im, 8, 9, 10, 11);
  fft4(re, im, 12, 13, 14, 15);
}
FFT16_AVX_TARGET static inline void ifft4x4(__m512d *re, __m512d *im) {
  ifft4(re, im, 0, 1, 2, 3);
  ifft4(re, im, 4, 5, 6, 7);
  ifft4(re, im, 8, 9, 10, 11);
  ifft4(re, im, 12, 13, 14, 15);
}

// Vector load/store of the 16 registers of threads base..base+7.
FFT16_AVX_TARGET static inline void load_regs(const Soa &s, int base,
                                              __m512d *re, __m512d *im) {
  for (int j = 0; j < REGS; j++) {
    re[j] = _mm512_loadu_pd(&s.re[j][base]);
    im[j] = _mm512_loadu_pd(&s.im[j][base]);
  }
}
FFT16_AVX_TARGET static inline void
store_regs(Soa &s, int base, const __m512d *re, const __m512d *im) {
  for (int j = 0; j < REGS; j++) {
    _mm512_storeu_pd(&s.re[j][base], re[j]);
    _mm512_storeu_pd(&s.im[j][base], im[j]);
  }
}
// Twiddle layer with per-thread planes on registers j0..j1.
FFT16_AVX_TARGET static inline void mul_planes(const double (*pre)[NT],
                                               const double (*pim)[NT],
                                               int base, int j0, int j1,
                                               __m512d *re, __m512d *im) {
  for (int j = j0; j < j1; j++)
    cmul(re[j], im[j], _mm512_loadu_pd(&pre[j][base]),
         _mm512_loadu_pd(&pim[j][base]), re[j], im[j]);
}
// mul_small_twiddles with the sw planes (conjugated for the inverse).
FFT16_AVX_TARGET static inline void
mul_small(const Tw &w, int base, bool inverse, __m512d *re, __m512d *im) {
  for (int h = 0; h < 2; h++)
    for (int k = 0; k < 3; k++) {
      __m512d w_re = _mm512_loadu_pd(&w.sw_re[3 * h + k][base]);
      __m512d w_im = _mm512_loadu_pd(&w.sw_im[3 * h + k][base]);
      if (inverse)
        w_im = vnegate(w_im);
      for (int p = 0; p < 2; p++) {
        const int j = 8 * p + 4 * h + k + 1;
        cmul(re[j], im[j], w_re, w_im, re[j], im[j]);
      }
    }
}

// Transposes as plane-to-plane data movement (no arithmetic).
static inline void set(Soa &s, int j, int T, double2 v) {
  s.re[j][T] = v.x;
  s.im[j][T] = v.y;
}
static inline double2 get(const Soa &s, int j, int T) {
  return mk(s.re[j][T], s.im[j][T]);
}

// Forward pair, same contract as the scalar forward_pair.
FFT16_AVX_TARGET static void forward_pair(const Tw &w, const double2 *in0,
                                          const double2 *in1, double2 *out0,
                                          double2 *out1) {
  static Soa s;
  static double2 P[GROUPS][HALF], Q[GROUPS][HALF];
  const double2 *in[2] = {in0, in1};
  __m512d re[REGS], im[REGS];

  // Phase A: load, pre-twist constants, FFT16 along c, folded twiddles.
  for (int T = 0; T < NT; T++)
    for (int j = 0; j < REGS; j++)
      set(s, j, T, in[T >> 6][(T & 63) + j * 64]);
  for (int base = 0; base < NT; base += LANES) {
    load_regs(s, base, re, im);
    for (int c = 1; c < 16; c++)
      cmul_c(re[c], im[c], COS_C[c], SIN_C[c], re[c], im[c]);
    fft16(re, im);
    mul_planes(w.fold_re, w.fold_im, base, 0, REGS, re, im);
    store_regs(s, base, re, im);
  }
  // Transpose #1 (group-local).
  for (int T = 0; T < NT; T++)
    for (int j = 0; j < REGS; j++)
      P[T >> 6][first_index(BITREV16[j], T & 63)] = get(s, j, T);
  for (int T = 0; T < NT; T++)
    for (int b = 0; b < REGS; b++)
      set(s, b, T, P[T >> 6][first_read(T & 63, b)]);
  // Phase B: FFT16 along b.
  for (int base = 0; base < NT; base += LANES) {
    load_regs(s, base, re, im);
    fft16(re, im);
    store_regs(s, base, re, im);
  }
  // Transpose #2 (ownership change): both components per thread.
  for (int T = 0; T < NT; T++)
    for (int j = 0; j < REGS; j++)
      Q[T >> 6][last_index(((T & 63) >> 2) + 16 * BITREV16[j], T & 3)] =
          get(s, j, T);
  for (int T = 0; T < NT; T++)
    for (int h = 0; h < 2; h++)
      for (int v = 0; v < 4; v++) {
        set(s, 4 * h + v, T, Q[0][last_index(T + 128 * h, v)]);
        set(s, 8 + 4 * h + v, T, Q[1][last_index(T + 128 * h, v)]);
      }
  // Phase C: small twiddles, FFT4 along a.
  for (int base = 0; base < NT; base += LANES) {
    load_regs(s, base, re, im);
    mul_small(w, base, false, re, im);
    fft4x4(re, im);
    store_regs(s, base, re, im);
  }
  for (int T = 0; T < NT; T++)
    for (int h = 0; h < 2; h++)
      for (int v = 0; v < 4; v++) {
        const int f = paired_frequency(T, h, v);
        out0[f] = get(s, 4 * h + v, T);
        out1[f] = get(s, 8 + 4 * h + v, T);
      }
}

// Inverse pair, same contract as the scalar inverse_pair.
FFT16_AVX_TARGET static void inverse_pair(const Tw &w, const double2 *in0,
                                          const double2 *in1, double2 *out0,
                                          double2 *out1) {
  static Soa s;
  static double2 P[GROUPS][HALF], Q[GROUPS][HALF];
  const double2 *in[2] = {in0, in1};
  double2 *out[2] = {out0, out1};
  __m512d re[REGS], im[REGS], nre[REGS], nim[REGS];

  // Phase A: owner-relative paired load, IFFT4 along a, small twiddles.
  for (int T = 0; T < NT; T++) {
    const int y = T >> 6;
    for (int h = 0; h < 2; h++)
      for (int v = 0; v < 4; v++) {
        const int f = paired_frequency(T, h, v);
        set(s, 4 * h + v, T, in[y][f]);
        set(s, 8 + 4 * h + v, T, in[1 - y][f]);
      }
  }
  for (int base = 0; base < NT; base += LANES) {
    load_regs(s, base, re, im);
    for (int g = 0; g < 4; g++)
      for (int v = 0; v < 4; v++) {
        nre[4 * g + v] = re[4 * g + bitrev4(v)];
        nim[4 * g + v] = im[4 * g + bitrev4(v)];
      }
    ifft4x4(nre, nim);
    for (int g = 0; g < 4; g++)
      for (int v = 0; v < 4; v++) {
        re[4 * g + v] = nre[4 * g + bitrev4(v)];
        im[4 * g + v] = nim[4 * g + bitrev4(v)];
      }
    mul_small(w, base, true, re, im);
    store_regs(s, base, re, im);
  }
  // Un-pairing: each thread writes the other group's half and its own.
  for (int T = 0; T < NT; T++) {
    const int y = T >> 6;
    for (int h = 0; h < 2; h++)
      for (int v = 0; v < 4; v++) {
        P[1 - y][last_index(T + 128 * h, v)] = get(s, 8 + 4 * h + v, T);
        P[y][last_index(T + 128 * h, v)] = get(s, 4 * h + v, T);
      }
  }
  for (int T = 0; T < NT; T++)
    for (int j = 0; j < REGS; j++)
      set(s, j, T, P[T >> 6][last_index(((T & 63) >> 2) + 16 * j, T & 3)]);
  // Phase B: IFFT16 along b.
  for (int base = 0; base < NT; base += LANES) {
    load_regs(s, base, re, im);
    ifft16(re, im);
    store_regs(s, base, re, im);
  }
  // Transpose #1 reversed (group-local), natural order out.
  for (int T = 0; T < NT; T++)
    for (int j = 0; j < REGS; j++)
      Q[T >> 6][first_read(T & 63, j)] = get(s, BITREV16[j], T);
  for (int T = 0; T < NT; T++)
    for (int j = 0; j < REGS; j++)
      set(s, j, T, Q[T >> 6][first_index(j, T & 63)]);
  // Phase C: inverse twiddles, IFFT16 along c, post-twist constants.
  for (int base = 0; base < NT; base += LANES) {
    load_regs(s, base, re, im);
    mul_planes(w.ifold_re, w.ifold_im, base, 0, REGS, re, im);
    ifft16(re, im);
    for (int j = 1; j < 16; j++)
      cmul_c(re[j], im[j], COS_C[BITREV16[j]], -SIN_C[BITREV16[j]], re[j],
             im[j]);
    store_regs(s, base, re, im);
  }
  for (int T = 0; T < NT; T++)
    for (int j = 0; j < REGS; j++)
      out[T >> 6][BITREV16[j] * 64 + (T & 63)] = get(s, j, T);
}

} // namespace avx512
#endif // FFT16_HAVE_AVX512

} // namespace fft16x16x4_cpu

#endif // FFT16X16X4_CPU_REFERENCE_H
