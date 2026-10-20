#pragma once

#include <cuda_runtime.h>
#include <math.h>

#include "fft/fft16x16x4_twiddles.cuh"
#include "types/complex/operations.cuh"

// ============================================================================
//  FFT16x16x4: paired 1024-point negacyclic FFT of the specialized 2_2 PBS on a
//  (64, 2, 1) block; n = a + 4b + 64c, FFT16 along c and b, FFT4 along a.
// ============================================================================

// ============================================================================
//  Building blocks: twiddle constants, radix-2/4/16 butterflies, twiddle rows
// ============================================================================
#define D_COS_PI_8 0.9238795325112867561281831893967882868
#define D_SIN_PI_8 0.3826834323650897717284599840303988667

// Forward (sign = -1): exp(-i * angle)
#define d_exp_1_16 make_double2(D_COS_PI_8, -D_SIN_PI_8)
#define d_exp_3_16 make_double2(D_SIN_PI_8, -D_COS_PI_8)
#define d_exp_9_16 make_double2(-D_COS_PI_8, D_SIN_PI_8)
#define d_exp_1_8 make_double2(1.0, -1.0)  // post-multiply by 1/sqrt(2)
#define d_exp_3_8 make_double2(-1.0, -1.0) // post-multiply by 1/sqrt(2)

// Inverse (sign = +1): exp(+i * angle)
#define d_iexp_1_16 make_double2(D_COS_PI_8, D_SIN_PI_8)
#define d_iexp_3_16 make_double2(D_SIN_PI_8, D_COS_PI_8)
#define d_iexp_9_16 make_double2(-D_COS_PI_8, -D_SIN_PI_8)
#define d_iexp_1_8 make_double2(1.0, 1.0)  // post-multiply by 1/sqrt(2)
#define d_iexp_3_8 make_double2(-1.0, 1.0) // post-multiply by 1/sqrt(2)

// bitreversal16(j): natural-order index of register j after the in-register
// FFT16 below; for the whole transform, register j holds time position
// bitreversal16(j)*64 + tid. Used inside unrolled loops, so it folds at
// compile time.
static __device__ __forceinline__ int bitreversal16(int bits) {
  const int t[] = {0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15};
  return t[bits];
}

// ============================================================================
//  Special-case complex multipliers (multiply by unit-magnitude pure angles)
// ============================================================================

// Multiply by exp(-i*pi/2) = -i: (a.x, a.y) → (a.y, -a.x)
static inline __device__ double2 cmul_exp_1_4(double2 a) {
  return make_double2(a.y, -a.x);
}

// Multiply by exp(+i*pi/2) = +i: (a.x, a.y) → (-a.y, a.x)
static inline __device__ double2 cmul_iexp_1_4(double2 a) {
  return make_double2(-a.y, a.x);
}

// ============================================================================
//  Butterfly primitives — forward FFT (sign = -1)
// ============================================================================
static inline __device__ void FFT2(double2 &a0, double2 &a1) {
  double2 c0 = a0;
  a0 = c0 + a1;
  a1 = c0 - a1;
}

// Component ops pinned: nothing here may be contracted with a multiply.
static inline __device__ void FFT2_mul_exp_1_4(double2 &a0, double2 &a1) {
  double2 c0 = a0;
  a0.x = __dadd_rn(c0.x, a1.y);
  a0.y = __dsub_rn(c0.y, a1.x);
  double a1_x = a1.x;
  a1.x = __dsub_rn(c0.x, a1.y);
  a1.y = __dadd_rn(c0.y, a1_x);
}

static inline __device__ void FFT4(double2 &a0, double2 &a1, double2 &a2,
                                   double2 &a3) {
  FFT2(a0, a2);
  FFT2(a1, a3);
  FFT2(a0, a1);
  FFT2_mul_exp_1_4(a2, a3);
}

// ---------------------------------------------------------------------------
//  16-point DFT held entirely in 16 registers a[0..15] (the in-register
//  passes of the transform). Computed as a 4x4 Cooley-Tukey grid, IN PLACE:
//  no transpose happens here, so every register keeps its index across both
//  passes and the two FFT4 layers just couple different subsets of the lines.
//
//  PASS 1 runs an FFT4 down each STRIDE-4 group; PASS 2 runs an FFT4 across
//  each CONTIGUOUS block; a twiddle layer scales 9 registers in between.
//  W = exp(-2*pi*i / 16).
//
//   reg   PASS 1 group (stride-4 FFT4)   x W^e     PASS 2 group (block FFT4)
//   ----  ---------------------------   -------    -------------------------
//   a0    {0, 4, 8,12}                  x 1        {0, 1, 2, 3}
//   a1    {1, 5, 9,13}                  x 1        {0, 1, 2, 3}
//   a2    {2, 6,10,14}                  x 1        {0, 1, 2, 3}
//   a3    {3, 7,11,15}                  x 1        {0, 1, 2, 3}
//   a4    {0, 4, 8,12}                  x 1        {4, 5, 6, 7}
//   a5    {1, 5, 9,13}                  x W^2      {4, 5, 6, 7}
//   a6    {2, 6,10,14}                  x W^4      {4, 5, 6, 7}
//   a7    {3, 7,11,15}                  x W^6      {4, 5, 6, 7}
//   a8    {0, 4, 8,12}                  x 1        {8, 9,10,11}
//   a9    {1, 5, 9,13}                  x W^1      {8, 9,10,11}
//   a10   {2, 6,10,14}                  x W^2      {8, 9,10,11}
//   a11   {3, 7,11,15}                  x W^3      {8, 9,10,11}
//   a12   {0, 4, 8,12}                  x 1        {12,13,14,15}
//   a13   {1, 5, 9,13}                  x W^3      {12,13,14,15}
//   a14   {2, 6,10,14}                  x W^6      {12,13,14,15}
//   a15   {3, 7,11,15}                  x W^9      {12,13,14,15}
//
//  Twiddle exponent e = bitrev2(j >> 2) * (j & 3): registers in pass-1 output
//  slot 0 (a0,a4,a8,a12) or in block 0 (a0..a3) fall on e = 0 and are left
//  untouched. W^4 = -i and W^2/W^6 = (+/-1 -i)/sqrt(2) are applied directly
//  (cmul_exp_1_4, d_exp_1_8, d_exp_3_8); the rest come from the d_exp_* table.
//
//  Output is in bit-reversed order: a[j] holds coefficient bitreversal16(j).
// ---------------------------------------------------------------------------
static inline __device__ void FFT16(double2 *a) {
  FFT4(a[0], a[4], a[8], a[12]);
  FFT4(a[1], a[5], a[9], a[13]);
  FFT4(a[2], a[6], a[10], a[14]);
  FFT4(a[3], a[7], a[11], a[15]);

  a[5] = (a[5] * d_exp_1_8) * M_SQRT1_2;
  a[6] = cmul_exp_1_4(a[6]);
  a[7] = (a[7] * d_exp_3_8) * M_SQRT1_2;
  a[9] = a[9] * d_exp_1_16;
  a[10] = (a[10] * d_exp_1_8) * M_SQRT1_2;
  a[11] = a[11] * d_exp_3_16;
  a[13] = a[13] * d_exp_3_16;
  a[14] = (a[14] * d_exp_3_8) * M_SQRT1_2;
  a[15] = a[15] * d_exp_9_16;

  FFT4(a[0], a[1], a[2], a[3]);
  FFT4(a[4], a[5], a[6], a[7]);
  FFT4(a[8], a[9], a[10], a[11]);
  FFT4(a[12], a[13], a[14], a[15]);
}

static inline __device__ void FFT4x4(double2 *a) {
  FFT4(a[0], a[1], a[2], a[3]);
  FFT4(a[4], a[5], a[6], a[7]);
  FFT4(a[8], a[9], a[10], a[11]);
  FFT4(a[12], a[13], a[14], a[15]);
}

// ============================================================================
//  Butterfly primitives — inverse FFT (sign = +1)
// ============================================================================
static inline __device__ void IFFT2(double2 &a0, double2 &a1) { FFT2(a0, a1); }

static inline __device__ void IFFT2_mul_iexp_1_4(double2 &a0, double2 &a1) {
  double2 c0 = a0;
  double a1_x = a1.x;
  a0.x = __dsub_rn(c0.x, a1.y);
  a0.y = __dadd_rn(c0.y, a1_x);
  a1.x = __dadd_rn(c0.x, a1.y);
  a1.y = __dsub_rn(c0.y, a1_x);
}

static inline __device__ void IFFT4(double2 &a0, double2 &a1, double2 &a2,
                                    double2 &a3) {
  IFFT2(a0, a2);
  IFFT2(a1, a3);
  IFFT2(a0, a1);
  IFFT2_mul_iexp_1_4(a2, a3);
}

static inline __device__ void IFFT16(double2 *a) {
  IFFT4(a[0], a[4], a[8], a[12]);
  IFFT4(a[1], a[5], a[9], a[13]);
  IFFT4(a[2], a[6], a[10], a[14]);
  IFFT4(a[3], a[7], a[11], a[15]);

  a[5] = (a[5] * d_iexp_1_8) * M_SQRT1_2;
  a[6] = cmul_iexp_1_4(a[6]);
  a[7] = (a[7] * d_iexp_3_8) * M_SQRT1_2;
  a[9] = a[9] * d_iexp_1_16;
  a[10] = (a[10] * d_iexp_1_8) * M_SQRT1_2;
  a[11] = a[11] * d_iexp_3_16;
  a[13] = a[13] * d_iexp_3_16;
  a[14] = (a[14] * d_iexp_3_8) * M_SQRT1_2;
  a[15] = a[15] * d_iexp_9_16;

  IFFT4(a[0], a[1], a[2], a[3]);
  IFFT4(a[4], a[5], a[6], a[7]);
  IFFT4(a[8], a[9], a[10], a[11]);
  IFFT4(a[12], a[13], a[14], a[15]);
}

static inline __device__ void IFFT4x4(double2 *a) {
  IFFT4(a[0], a[1], a[2], a[3]);
  IFFT4(a[4], a[5], a[6], a[7]);
  IFFT4(a[8], a[9], a[10], a[11]);
  IFFT4(a[12], a[13], a[14], a[15]);
}

// Register-cached variants: tw_r7/r3/r11/r1 are the twiddles for r==7 (j==1),
// r==3 (j==2), r==11 (j==3), r==1 (j==4), preloaded once before the PBS loop
// (= tw[{7,3,11,1}*64+tid]) and held in registers across all iterations.
// Because j (hence r) is compile-time inside the unrolled loop, the selects
// below resolve at compile time to "use the register for these four, smem for
// the other 11" — no branch. The SAME cached values feed the inverse via
// conjugate(), so 4 double2 (16 regs) remove 4 smem twiddle loads from the fwd
// AND 4 from the inv each iteration. Shared-memory table is unchanged (the
// other 11 still read from `tw`). NOTE: 4 is the tuned optimum, confirmed twice
// (before and after the bsk 1/N fold): 2 = smaller win, 6 = no further gain, 8
// = plateau.
static inline __device__ void
mul_twiddles_16_cached(double2 *__restrict__ a, int tid,
                       const double2 *__restrict__ tw, double2 tw_r7,
                       double2 tw_r3, double2 tw_r11, double2 tw_r1) {
#pragma unroll
  for (int j = 1; j < 16; j++) {
    int r =
        (((j & 1) << 3) | ((j & 2) << 1) | ((j & 4) >> 1) | ((j & 8) >> 3)) - 1;
    double2 w = (r == 7)    ? tw_r7
                : (r == 3)  ? tw_r3
                : (r == 11) ? tw_r11
                : (r == 1)  ? tw_r1
                            : tw[r * 64 + tid];
    a[j] = a[j] * w;
  }
}

// Shared-memory size of the twiddle table: 15 rows x 64 double2.
static constexpr int TW_SMEM_DOUBLES = 2 * 15 * 64; // 1920 doubles = 15360 B

// ============================================================================
//  Cross-warp synchronisation — a partial (named) barrier over the 64 threads
//  of one FFT y-group, so the sibling y-group is never stalled.
// ============================================================================
static __device__ __forceinline__ void
fft16x16x4_named_barrier_sync(unsigned barrier_id, unsigned thread_count) {
#if defined(__CUDA_ARCH__)
  __barrier_sync_count(barrier_id, thread_count);
#else
  (void)barrier_id;
  (void)thread_count;
#endif
}

// Partial named-barrier sync over one 64-thread FFT y-group (2 warps).
// Named barriers are hardware CTA barriers: the participant count is an
// operand of every bar.sync and the barrier self-resets, so unlike an mbarrier
// there is nothing to allocate in shared memory and nothing to initialise.
// y-group g (= threadIdx.y) uses named barrier id (g+1):
// groups use ids 1 and 2 — id 0 is reserved for __syncthreads() (== bar.sync
// 0). 64 = 2 warps; bar.sync carries the CTA-scope shared-memory fence the
// transpose store -> sibling-warp-load relies on.
static __device__ __forceinline__ void sync_coupled_warps() {
  fft16x16x4_named_barrier_sync(threadIdx.y + 1u, 64u);
}

// One transpose region: 1024 double2 slots, in doubles.
static constexpr int FFT16x16x4_XPOSE_DOUBLES = 2 * 1024;

// Shared layout of the paired transforms: folded twiddle table, then the four
// transpose regions xpose_y (first transpose) and xpose_pong_y (second).
static constexpr int FFT16x16x4_DUAL_XPOSE0_OFFSET = TW_SMEM_DOUBLES;
static constexpr int FFT16x16x4_DUAL_XPOSE1_OFFSET =
    FFT16x16x4_DUAL_XPOSE0_OFFSET + FFT16x16x4_XPOSE_DOUBLES;
static constexpr int FFT16x16x4_DUAL_XPOSE0_PONG_OFFSET =
    FFT16x16x4_DUAL_XPOSE1_OFFSET + FFT16x16x4_XPOSE_DOUBLES;
static constexpr int FFT16x16x4_DUAL_XPOSE1_PONG_OFFSET =
    FFT16x16x4_DUAL_XPOSE0_PONG_OFFSET + FFT16x16x4_XPOSE_DOUBLES;
static constexpr int FFT16x16x4_DUAL_SMEM_DOUBLES =
    FFT16x16x4_DUAL_XPOSE1_PONG_OFFSET + FFT16x16x4_XPOSE_DOUBLES;
static constexpr size_t FFT16x16x4_DUAL_SMEM_BYTES =
    static_cast<size_t>(FFT16x16x4_DUAL_SMEM_DOUBLES) * sizeof(double);

static __device__ __forceinline__ int fft16x16x4_first_index(int r, int u) {
  return (r << 6) + (u ^ ((r & 1) << 2));
}

static __device__ __forceinline__ int fft16x16x4_last_index(int q, int a) {
  return (q << 2) + (a ^ ((q >> 1) & 3));
}

// first_index(tid >> 2, (tid & 3) + 4*b) with the b-dependent terms split out
// so the unrolled loads resolve to one base plus immediates.
static __device__ __forceinline__ int fft16x16x4_first_read(int tid, int b) {
  return ((tid >> 2) << 6) + (tid & 3) + ((tid & 4) ^ ((b & 1) << 2)) +
         ((b >> 1) << 3);
}

// 2-bit reversal: after the final FFT4, register 4h + v of thread T holds
// frequency T + 128*h + 256*bitreversal4(v), key slot tid + 64*(j + 8*y).
static __device__ __forceinline__ int bitreversal4(int v) {
  return ((v & 1) << 1) | ((v & 2) >> 1);
}

// Negacyclic twist folded into the twiddles: conj(psi^tid) into the first-stage
// rows (row 0 kept in a register) and conj(W64^c) as constants; same inverse.

// W64^c = cos - i*sin as compile-time literals; a __constant__ table measured
// 6.5% slower at one block per SM on the H100, so the literals are kept.
static __device__ __forceinline__ double2 fft16x16x4_w64(int c) {
  const double cos_c[16] = {
      0x1.0000000000000p+0, 0x1.fd88da3d12526p-1, 0x1.f6297cff75cb0p-1,
      0x1.e9f4156c62ddap-1, 0x1.d906bcf328d46p-1, 0x1.c38b2f180bdb1p-1,
      0x1.a9b66290ea1a3p-1, 0x1.8bc806b151741p-1, 0x1.6a09e667f3bcdp-1,
      0x1.44cf325091dd6p-1, 0x1.1c73b39ae68c9p-1, 0x1.e2b5d3806f63ep-2,
      0x1.87de2a6aea964p-2, 0x1.294062ed59f05p-2, 0x1.8f8b83c69a60dp-3,
      0x1.917a6bc29b438p-4,
  };
  const double sin_c[16] = {
      0x0.0000000000000p+0, 0x1.917a6bc29b42cp-4, 0x1.8f8b83c69a60ap-3,
      0x1.294062ed59f05p-2, 0x1.87de2a6aea963p-2, 0x1.e2b5d3806f63bp-2,
      0x1.1c73b39ae68c8p-1, 0x1.44cf325091dd6p-1, 0x1.6a09e667f3bccp-1,
      0x1.8bc806b151741p-1, 0x1.a9b66290ea1a3p-1, 0x1.c38b2f180bdb0p-1,
      0x1.d906bcf328d46p-1, 0x1.e9f4156c62ddbp-1, 0x1.f6297cff75cb0p-1,
      0x1.fd88da3d12525p-1,
  };
  return make_double2(cos_c[c], -sin_c[c]);
}

// Forward: a[c] holds time position tid + 64*c; multiply by conj(W64^c).
static __device__ __forceinline__ void
fft16x16x4_pre_twist_constants(double2 *a) {
#pragma unroll
  for (int c = 1; c < 16; c++)
    a[c] = a[c] * conjugate(fft16x16x4_w64(c));
}

// Inverse: register j holds time position bitreversal16(j)*64 + tid;
// multiply by W64^bitreversal16(j).
static __device__ __forceinline__ void
fft16x16x4_post_twist_constants(double2 *a) {
#pragma unroll
  for (int j = 1; j < 16; j++)
    a[j] = a[j] * fft16x16x4_w64(bitreversal16(j));
}

// Loads rows 1..15 of tw_1024 times conj(psi^tid) at the start of `smem`;
// row 0 (conj(psi^tid)) is read into a register by the caller.
static __device__ __forceinline__ void
fft16x16x4_load_shared_twiddles_folded_128t(double *smem) {
  double2 *smem_tw = reinterpret_cast<double2 *>(smem);
  const int linear_tid = threadIdx.x + (threadIdx.y << 6);

#pragma unroll
  for (int idx = linear_tid; idx < 15 * 64; idx += 128) {
    const int lane = idx & 63;
    smem_tw[idx] = tw_1024[idx >> 6][lane] * conjugate(twisting_twiddles[lane]);
  }
}

// mul_twiddles_16_cached plus the now non-trivial row 0 on register 0.
static __device__ __forceinline__ void
mul_twiddles_16_folded_cached(double2 *__restrict__ a, int tid,
                              const double2 *__restrict__ tw, double2 tw_r0,
                              double2 tw_r7, double2 tw_r3, double2 tw_r11,
                              double2 tw_r1) {
  a[0] = a[0] * tw_r0;
  mul_twiddles_16_cached(a, tid, tw, tw_r7, tw_r3, tw_r11, tw_r1);
}

// bar.arrive: counts this warp's arrival without waiting; writes before it are
// visible to threads returning from the matching bar.sync on the same id.
static __device__ __forceinline__ void
fft16x16x4_named_barrier_arrive(unsigned barrier_id, unsigned thread_count) {
#if defined(__CUDA_ARCH__)
  asm volatile("bar.arrive %0, %1;" ::"r"(barrier_id), "r"(thread_count)
               : "memory");
#else
  (void)barrier_id;
  (void)thread_count;
#endif
}

// The six W64^(s*a) roots of this thread's two q groups (a = 1..3), from rows
// 3, 7 and 11 of tw_1024, kept in registers across the PBS loop.
static __device__ __forceinline__ void
fft16x16x4_load_small_twiddles(double2 *w) {
  const int T = threadIdx.x + (threadIdx.y << 6);
#pragma unroll
  for (int h = 0; h < 2; h++) {
    const int s = (T >> 4) + 8 * h; // q >> 4 for q = T + 128*h
    w[3 * h + 0] = tw_1024[3][4 * s];
    w[3 * h + 1] = tw_1024[7][4 * s];
    w[3 * h + 2] = tw_1024[11][4 * s];
  }
}

// W64^(s*a) on the a = 1..3 members of each quartet, both components. The
// inverse uses the conjugate roots.
template <bool Inverse>
static __device__ __forceinline__ void
mul_small_twiddles_16x16x4(double2 *a, const double2 *w) {
#pragma unroll
  for (int h = 0; h < 2; h++) {
    double2 w1 = w[3 * h + 0];
    double2 w2 = w[3 * h + 1];
    double2 w3 = w[3 * h + 2];
    if constexpr (Inverse) {
      w1 = conjugate(w1);
      w2 = conjugate(w2);
      w3 = conjugate(w3);
    }
#pragma unroll
    for (int p = 0; p < 2; p++) {
      a[8 * p + 4 * h + 1] = a[8 * p + 4 * h + 1] * w1;
      a[8 * p + 4 * h + 2] = a[8 * p + 4 * h + 2] * w2;
      a[8 * p + 4 * h + 3] = a[8 * p + 4 * h + 3] * w3;
    }
  }
}

// Inverse twiddles for natural-order registers (n[j] holds r = j): n[j] times
// the conjugate of folded row j, row 0 included; rows 7, 3, 11, 1, 0 cached.
static __device__ __forceinline__ void
mul_itwiddles_16_natural_cached(double2 *__restrict__ n, int tid,
                                const double2 *__restrict__ tw, double2 tw_r0,
                                double2 tw_r7, double2 tw_r3, double2 tw_r11,
                                double2 tw_r1) {
  n[0] = n[0] * conjugate(tw_r0);
#pragma unroll
  for (int j = 1; j < 16; j++) {
    const int r = j - 1;
    double2 w = (r == 7)    ? tw_r7
                : (r == 3)  ? tw_r3
                : (r == 11) ? tw_r11
                : (r == 1)  ? tw_r1
                            : tw[r * 64 + tid];
    n[j] = n[j] * conjugate(w);
  }
}

// Forward transform, twist folded in. In: register j = time tid + 64*j of this
// group's component. Out: a[0..7] mask, a[8..15] body, paired by frequency.
static __device__ void
FFT16x16x4_fwd_paired_for_pbs(double2 *a, const double2 *tw, double2 tw_r0,
                              double *smem_p_own, double *smem_q_own,
                              const double *smem_q0, const double *smem_q1,
                              const double2 *small_w, double2 tw_r7,
                              double2 tw_r3, double2 tw_r11, double2 tw_r1) {
  const int tid = threadIdx.x;
  const int T = tid + (threadIdx.y << 6);
  double2 *P = reinterpret_cast<double2 *>(smem_p_own);
  double2 *Q = reinterpret_cast<double2 *>(smem_q_own);
  const double2 *Q0 = reinterpret_cast<const double2 *>(smem_q0);
  const double2 *Q1 = reinterpret_cast<const double2 *>(smem_q1);

  fft16x16x4_pre_twist_constants(a);
  FFT16(a); // along c; register j holds r = bitreversal16(j)
  mul_twiddles_16_folded_cached(a, tid, tw, tw_r0, tw_r7, tw_r3, tw_r11, tw_r1);

  // Transpose #1 (group-local, hence a 64-thread named barrier): thread tid
  // takes r = tid >> 2, a = tid & 3, all sixteen b; loads issued in FFT16's
  // first-pass group order to overlap.
#pragma unroll
  for (int j = 0; j < 16; j++)
    P[fft16x16x4_first_index(bitreversal16(j), tid)] = a[j];
  sync_coupled_warps();
#pragma unroll
  for (int g = 0; g < 4; g++) {
#pragma unroll
    for (int m = 0; m < 4; m++) {
      const int b = g + 4 * m;
      a[b] = P[fft16x16x4_first_read(tid, b)];
    }
  }

  FFT16(a); // along b; register j holds s = bitreversal16(j)

  // Transpose #2, the pairing: each group writes its own component's second
  // transpose into its own pong region, and after the barrier every thread T
  // of the block reads frequencies q = T and q = T + 128 from BOTH regions
  // (Q0 mask, Q1 body), one quartet at a time so loads overlap. A thread thus
  // leaves holding both components of its two frequencies, which is what lets
  // the external product consume the two GGSW rows with no further exchange.
  // The barrier has to be block-wide: both groups read both regions, so the
  // 64-thread group barrier of transpose #1 would order only one component.
  // It is also the block-wide barrier the inverse's split-phase un-pairing
  // relies on between two calls (see FFT16x16x4_inv_paired_for_pbs). The
  // partner's reads of this pong region in the previous iteration are ordered
  // before this iteration's writes by that un-pairing barrier; the own group's
  // reads by sync_coupled_warps at the top of the PBS loop.
#pragma unroll
  for (int j = 0; j < 16; j++)
    Q[fft16x16x4_last_index((tid >> 2) + 16 * bitreversal16(j), tid & 3)] =
        a[j];
  __syncthreads();
#pragma unroll
  for (int h = 0; h < 2; h++) {
#pragma unroll
    for (int v = 0; v < 4; v++)
      a[4 * h + v] = Q0[fft16x16x4_last_index(T + 128 * h, v)];
#pragma unroll
    for (int v = 0; v < 4; v++)
      a[8 + 4 * h + v] = Q1[fft16x16x4_last_index(T + 128 * h, v)];
  }

  // W64^(s*a) after the transpose: six cached roots serve both components.
  mul_small_twiddles_16x16x4<false>(a, small_w);
  FFT4x4(a); // along a; quartet member v holds bitreversal4(v)
}

// Inverse transform, post-twist folded in. In: a[0..7] this group's output,
// a[8..15] the other's. Out: register j = time bitreversal16(j)*64 + tid.
//
// Precondition: consecutive calls on the same block must be separated by a
// block-wide barrier (__syncthreads). The un-pairing at the end uses
// split-phase named barriers 3 and 4 shared by the two y-groups, and a group
// that re-arrived on an incomplete barrier would corrupt the count. The PBS
// loop satisfies this through the forward transform's transpose #2.
static __device__ void FFT16x16x4_inv_paired_for_pbs(
    double2 *a, const double2 *tw, double2 tw_r0, double *smem_p_own,
    double *smem_p_other, double *smem_q_own, const double2 *small_w,
    double2 tw_r7, double2 tw_r3, double2 tw_r11, double2 tw_r1) {
  const int tid = threadIdx.x;
  const int T = tid + (threadIdx.y << 6);
  const unsigned own = threadIdx.y; // component this group reads back
  double2 *P = reinterpret_cast<double2 *>(smem_p_own);
  double2 *P_other = reinterpret_cast<double2 *>(smem_p_other);
  double2 *Q = reinterpret_cast<double2 *>(smem_q_own);
  double2 n[16];

  // IFFT4 along a. The quartets come in FFT4 output order and IFFT4 returns
  // that same order, so both reorders are resolved at compile time.
#pragma unroll
  for (int g = 0; g < 4; g++) {
#pragma unroll
    for (int v = 0; v < 4; v++)
      n[4 * g + v] = a[4 * g + bitreversal4(v)];
  }
  IFFT4x4(n);
#pragma unroll
  for (int g = 0; g < 4; g++) {
#pragma unroll
    for (int v = 0; v < 4; v++)
      a[4 * g + v] = n[4 * g + bitreversal4(v)];
  }
  mul_small_twiddles_16x16x4<true>(a, small_w);

  // Un-pairing: each thread holds eight values of the other group's component
  // and eight of its own. The partner's half is written to its region first and
  // announced with bar.arrive on the partner's barrier (group 0 -> id 4,
  // group 1 -> id 3); then the own half is written and bar.sync on the own
  // barrier (group 0 -> id 3, group 1 -> id 4) waits until the partner has done
  // the same. Both barriers count 128: 64 arrivals from the writer plus 64
  // syncs from the reader. Arriving is non-blocking, so a group can be released
  // from its own barrier and run ahead while the partner is still waiting on
  // the other one. That is only safe if no warp can arrive a second time on a
  // barrier that has not completed yet (undefined in PTX), i.e. the next call
  // of this function must be separated from this one by a block-wide barrier.
  // The PBS loop guarantees it: between two inverses every thread passes the
  // forward's transpose #2 __syncthreads, and the partner reaches it only after
  // its own bar.sync here has completed; the last iteration is covered by the
  // __syncthreads before the final accumulation, and the backward test kernel
  // calls this once per block. The split phase buys the overlap of the own-half
  // stores with the partner's wait; two plain bar.sync would drop the
  // precondition and that overlap.
#pragma unroll
  for (int h = 0; h < 2; h++) {
#pragma unroll
    for (int v = 0; v < 4; v++)
      P_other[fft16x16x4_last_index(T + 128 * h, v)] = a[8 + 4 * h + v];
  }
  fft16x16x4_named_barrier_arrive(4u - own, 128u);
#pragma unroll
  for (int h = 0; h < 2; h++) {
#pragma unroll
    for (int v = 0; v < 4; v++)
      P[fft16x16x4_last_index(T + 128 * h, v)] = a[4 * h + v];
  }
  fft16x16x4_named_barrier_sync(3u + own, 128u);
  // IFFT16 along b wants natural order (n[j] holds s = j); loads in first-pass
  // group order so each IFFT4 starts as soon as its four values arrive.
#pragma unroll
  for (int g = 0; g < 4; g++) {
#pragma unroll
    for (int m = 0; m < 4; m++) {
      const int j = g + 4 * m;
      n[j] = P[fft16x16x4_last_index((tid >> 2) + 16 * j, tid & 3)];
    }
  }
  IFFT16(n); // register j holds b = bitreversal16(j)

  // Transpose #1 reversed (group-local). Natural-order loads again
  // (n[j] holds r = j), followed by the inverse large twiddles in that order.
#pragma unroll
  for (int j = 0; j < 16; j++)
    Q[fft16x16x4_first_read(tid, j)] = n[bitreversal16(j)];
  sync_coupled_warps();
#pragma unroll
  for (int g = 0; g < 4; g++) {
#pragma unroll
    for (int m = 0; m < 4; m++) {
      const int j = g + 4 * m;
      n[j] = Q[fft16x16x4_first_index(j, tid)];
    }
  }
  mul_itwiddles_16_natural_cached(n, tid, tw, tw_r0, tw_r7, tw_r3, tw_r11,
                                  tw_r1);
  IFFT16(n); // along c; register j holds position bitreversal16(j)*64 + tid
#pragma unroll
  for (int j = 0; j < 16; j++)
    a[j] = n[j];
  fft16x16x4_post_twist_constants(a);
}
