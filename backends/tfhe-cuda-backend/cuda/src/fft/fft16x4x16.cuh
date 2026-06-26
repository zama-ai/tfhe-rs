#pragma once

#include <cuda_runtime.h>
#include <math.h>

#include "fft/fft16x4x16_twiddles.cuh"
#include "types/complex/operations.cuh"

// ============================================================================
//  shfl helpers — warp shuffle for double2 and double2 index-based broadcast
// ============================================================================

// Index-based broadcast: all lanes get the value held by src_lane.
// shfl_idx_d2 does NOT have an equivalent in operations.cuh, so it is ported
// here.
static __device__ __forceinline__ double2 shfl_idx_d2(double2 a, int src_lane) {
  unsigned int lo, hi;
  unsigned long long bits;

  bits = __double_as_longlong(a.x);
  lo = (unsigned int)(bits);
  hi = (unsigned int)(bits >> 32);
  lo = __shfl_sync(0xFFFFFFFF, lo, src_lane);
  hi = __shfl_sync(0xFFFFFFFF, hi, src_lane);
  a.x = __longlong_as_double(((unsigned long long)hi << 32) | lo);

  bits = __double_as_longlong(a.y);
  lo = (unsigned int)(bits);
  hi = (unsigned int)(bits >> 32);
  lo = __shfl_sync(0xFFFFFFFF, lo, src_lane);
  hi = __shfl_sync(0xFFFFFFFF, hi, src_lane);
  a.y = __longlong_as_double(((unsigned long long)hi << 32) | lo);

  return a;
}

// ============================================================================
//  Twiddle-factor constants (double precision)
// ============================================================================
#define D_COS_PI_8 0.9238795325112867561281831893967882868
#define D_SIN_PI_8 0.3826834323650897717284599840303988667

// Forward (sign = -1): exp(-i * angle)
#define d_exp_1_16 make_double2(D_COS_PI_8, -D_SIN_PI_8)
#define d_exp_3_16 make_double2(D_SIN_PI_8, -D_COS_PI_8)
#define d_exp_5_16 make_double2(-D_SIN_PI_8, -D_COS_PI_8)
#define d_exp_7_16 make_double2(-D_COS_PI_8, -D_SIN_PI_8)
#define d_exp_9_16 make_double2(-D_COS_PI_8, D_SIN_PI_8)
#define d_exp_1_8 make_double2(1.0, -1.0) // post-multiply by 1/sqrt(2)
#define d_exp_1_4 make_double2(0.0, -1.0)
#define d_exp_3_8 make_double2(-1.0, -1.0) // post-multiply by 1/sqrt(2)

// Inverse (sign = +1): exp(+i * angle)
#define d_iexp_1_16 make_double2(D_COS_PI_8, D_SIN_PI_8)
#define d_iexp_3_16 make_double2(D_SIN_PI_8, D_COS_PI_8)
#define d_iexp_5_16 make_double2(-D_SIN_PI_8, D_COS_PI_8)
#define d_iexp_7_16 make_double2(-D_COS_PI_8, D_SIN_PI_8)
#define d_iexp_9_16 make_double2(-D_COS_PI_8, -D_SIN_PI_8)
#define d_iexp_1_8 make_double2(1.0, 1.0) // post-multiply by 1/sqrt(2)
#define d_iexp_1_4 make_double2(0.0, 1.0)
#define d_iexp_3_8 make_double2(-1.0, 1.0) // post-multiply by 1/sqrt(2)

// ============================================================================
//  Bit-reversal table for 16-element FFT (register index → time-domain index)
// ============================================================================
// bitreversal16(j): maps register j to its natural-order position after
// FFT16x4x16. After FFT16x4x16_fwd_core, register[j] holds DFT coefficient at
// frequency bitreversal16(j)*64 + tid; after IFFT it holds time-domain element
// at that position. Because it is used within unrolled regions it is solved at
// compilation time.
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

static inline __device__ void FFT2_mul_exp_1_4(double2 &a0, double2 &a1) {
  double2 c0 = a0;
  a0.x = c0.x + a1.y;
  a0.y = c0.y - a1.x;
  double a1_x = a1.x;
  a1.x = c0.x - a1.y;
  a1.y = c0.y + a1_x;
}

static inline __device__ void FFT4(double2 &a0, double2 &a1, double2 &a2,
                                   double2 &a3) {
  FFT2(a0, a2);
  FFT2(a1, a3);
  FFT2(a0, a1);
  FFT2_mul_exp_1_4(a2, a3);
}

static inline __device__ void FFT4(double2 *a) { FFT4(a[0], a[1], a[2], a[3]); }

// 16-point DFT on 16 registers (column pass for FFT16x4x16's outer stage)
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
  a0.x = c0.x - a1.y;
  a0.y = c0.y + a1_x;
  a1.x = c0.x + a1.y;
  a1.y = c0.y - a1_x;
}

static inline __device__ void IFFT4(double2 &a0, double2 &a1, double2 &a2,
                                    double2 &a3) {
  IFFT2(a0, a2);
  IFFT2(a1, a3);
  IFFT2(a0, a1);
  IFFT2_mul_iexp_1_4(a2, a3);
}

static inline __device__ void IFFT4(double2 *a) {
  IFFT4(a[0], a[1], a[2], a[3]);
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

// ============================================================================
//  Twiddle-factor application from precalculated table tw_1024[k-1][tid]
//
//  tw_1024[k-1][tid] = exp(-2*pi*i * k * tid / 1024), k=1..15, tid=0..63.
//  Row k=0 (all-ones) is omitted.  d_rev<16>(j)-1 maps register index to row.
// ============================================================================
static inline __device__ void mul_twiddles_16(double2 *__restrict__ a, int tid,
                                              const double2 *__restrict__ tw) {
#pragma unroll
  for (int j = 1; j < 16; j++) {
    int r =
        (((j & 1) << 3) | ((j & 2) << 1) | ((j & 4) >> 1) | ((j & 8) >> 3)) - 1;
    a[j] = a[j] * tw[r * 64 + tid];
  }
}

// Inverse twiddles are conjugates of the forward ones (exp(+2*pi*i))
static inline __device__ void mul_itwiddles_16(double2 *__restrict__ a, int tid,
                                               const double2 *__restrict__ tw) {
#pragma unroll
  for (int j = 1; j < 16; j++) {
    int r =
        (((j & 1) << 3) | ((j & 2) << 1) | ((j & 4) >> 1) | ((j & 8) >> 3)) - 1;
    a[j] = a[j] * conjugate(tw[r * 64 + tid]);
  }
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

static inline __device__ void
mul_itwiddles_16_cached(double2 *__restrict__ a, int tid,
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
    a[j] = a[j] * conjugate(w);
  }
}

// compact_twiddles layout (doubles, 6 sub-rows × 17 entries each = 102
// doubles):
//   sub-rows 0..2 (re): compact_twiddles[r*17 + lo4]       =
//   tw_1024[{7,3,11}[r]][4*lo4].x sub-rows 3..5 (im): compact_twiddles[3*17 +
//   r*17 + lo4] = tw_1024[{7,3,11}[r]][4*lo4].y
// Each sub-row has 16 active entries + 1 padding double to avoid bank conflicts
// (stride-1).
static inline __device__ void mul_twiddles_4x4(double2 *a,
                                               const double *compact_twiddles) {
  int lane = threadIdx.x & 31;
  int lo4 = lane & 15;
  const double *re = compact_twiddles, *im = compact_twiddles + 3 * 17;
  double2 w1 = make_double2(0.0, 0.0);
  double2 w2 = make_double2(0.0, 0.0);
  double2 w3 = make_double2(0.0, 0.0);
  if (lane < 16) {
    w1 = make_double2(re[lo4], im[lo4]);
    w2 = make_double2(re[17 + lo4], im[17 + lo4]);
    w3 = make_double2(re[34 + lo4], im[34 + lo4]);
  }
  // Broadcast to all lanes in the warp (each thread needs the twiddle for its
  // lo4 column)
  w1 = shfl_idx_d2(w1, lo4);
  w2 = shfl_idx_d2(w2, lo4);
  w3 = shfl_idx_d2(w3, lo4);
  a[1] = a[1] * w1;
  a[5] = a[5] * w1;
  a[9] = a[9] * w1;
  a[13] = a[13] * w1;
  a[2] = a[2] * w2;
  a[6] = a[6] * w2;
  a[10] = a[10] * w2;
  a[14] = a[14] * w2;
  a[3] = a[3] * w3;
  a[7] = a[7] * w3;
  a[11] = a[11] * w3;
  a[15] = a[15] * w3;
}

static inline __device__ void mul_twiddles_4x4_regs(double2 *a, double2 w1,
                                                    double2 w2, double2 w3) {
  a[1] = a[1] * w1;
  a[5] = a[5] * w1;
  a[9] = a[9] * w1;
  a[13] = a[13] * w1;
  a[2] = a[2] * w2;
  a[6] = a[6] * w2;
  a[10] = a[10] * w2;
  a[14] = a[14] * w2;
  a[3] = a[3] * w3;
  a[7] = a[7] * w3;
  a[11] = a[11] * w3;
  a[15] = a[15] * w3;
}

static inline __device__ void
mul_itwiddles_4x4(double2 *a, const double *compact_twiddles) {
  int lane = threadIdx.x & 31;
  int lo4 = lane & 15;
  const double *re = compact_twiddles, *im = compact_twiddles + 3 * 17;
  double2 w1 = make_double2(0.0, 0.0);
  double2 w2 = make_double2(0.0, 0.0);
  double2 w3 = make_double2(0.0, 0.0);
  if (lane < 16) {
    // Conjugate by negating the imaginary part
    w1 = make_double2(re[lo4], -im[lo4]);
    w2 = make_double2(re[17 + lo4], -im[17 + lo4]);
    w3 = make_double2(re[34 + lo4], -im[34 + lo4]);
  }
  w1 = shfl_idx_d2(w1, lo4);
  w2 = shfl_idx_d2(w2, lo4);
  w3 = shfl_idx_d2(w3, lo4);
  a[1] = a[1] * w1;
  a[5] = a[5] * w1;
  a[9] = a[9] * w1;
  a[13] = a[13] * w1;
  a[2] = a[2] * w2;
  a[6] = a[6] * w2;
  a[10] = a[10] * w2;
  a[14] = a[14] * w2;
  a[3] = a[3] * w3;
  a[7] = a[7] * w3;
  a[11] = a[11] * w3;
  a[15] = a[15] * w3;
}

static inline __device__ void mul_itwiddles_4x4_regs(double2 *a, double2 w1,
                                                     double2 w2, double2 w3) {
  w1 = make_double2(w1.x, -w1.y);
  w2 = make_double2(w2.x, -w2.y);
  w3 = make_double2(w3.x, -w3.y);
  a[1] = a[1] * w1;
  a[5] = a[5] * w1;
  a[9] = a[9] * w1;
  a[13] = a[13] * w1;
  a[2] = a[2] * w2;
  a[6] = a[6] * w2;
  a[10] = a[10] * w2;
  a[14] = a[14] * w2;
  a[3] = a[3] * w3;
  a[7] = a[7] * w3;
  a[11] = a[11] * w3;
  a[15] = a[15] * w3;
}

// ============================================================================
//  Smem layout (offset from base in doubles):
//    [0 .. TW_SMEM_DOUBLES-1]                               twiddle table
//    (double2*)smem [15][64] [TW_SMEM_DOUBLES .. COMPACT_TW_SMEM_OFFSET-1]
//    transpose scratch (re+im halves) [COMPACT_TW_SMEM_OFFSET ..
//    +COMPACT_TW_SMEM_DOUBLES-1] compact_twiddles (6 sub-rows × 17 doubles)
//    [TWIST_HALF_SMEM_OFFSET .. +1026]                      negacyclic twist
//    half-table (513 double2s)
//
//  Dual-FFT variant (128-thread block, threadIdx.y=0/1 selects FFT group):
//    Shared twiddle table (row 0) + compact_twiddles (1 copy, shared by both
//    groups) Each group gets its own xpose scratch area and mbarrier storage.
//    A startup mbarrier gates the twiddle-load phase.
// ============================================================================
static constexpr int TW_SMEM_DOUBLES =
    2 * 15 * 64; // 1920 doubles = 15360 bytes
static constexpr int XPOSE_SMEM_DOUBLES =
    2 * 69 * 16; // 2208 doubles = 17664 bytes
static constexpr int XPOSE_SPLIT_SMEM_DOUBLES =
    69 * 16; // 1104 doubles = 8832 bytes
static constexpr int COMPACT_TW_SMEM_OFFSET =
    TW_SMEM_DOUBLES + XPOSE_SMEM_DOUBLES; // 4128 doubles
static constexpr int COMPACT_TW_SMEM_DOUBLES =
    6 * 17; // 102 doubles = 816 bytes
static constexpr int TWIST_HALF_SMEM_OFFSET =
    COMPACT_TW_SMEM_OFFSET + COMPACT_TW_SMEM_DOUBLES; // 4230 doubles

struct alignas(8) FFT16x4x16MBarrierStorage {
  unsigned long long barrier;
};

static_assert(sizeof(FFT16x4x16MBarrierStorage) % sizeof(double) == 0,
              "FFT16x4x16MBarrierStorage must stay double-aligned");

static constexpr int FFT16x4x16_MBARRIER_STORAGE_DOUBLES =
    sizeof(FFT16x4x16MBarrierStorage) / sizeof(double);

// Dual smem offsets: one shared twiddle table then two independent xpose areas
// + two per-group PONG xpose areas (ping-pong for fwd FFT barrier elimination)
// + two per-group mbarriers + one startup mbarrier.
//
// PONG insertion is between XPOSE1 and BARRIER0 so KB_* (single-FFT keybundle
// layout, built from XPOSE0 only) is unaffected.
static constexpr int FFT16x4x16_DUAL_COMPACT_TW_OFFSET = TW_SMEM_DOUBLES;
static constexpr int FFT16x4x16_DUAL_XPOSE0_OFFSET =
    FFT16x4x16_DUAL_COMPACT_TW_OFFSET + COMPACT_TW_SMEM_DOUBLES;
static constexpr int FFT16x4x16_DUAL_XPOSE1_OFFSET =
    FFT16x4x16_DUAL_XPOSE0_OFFSET + XPOSE_SMEM_DOUBLES;
// PONG xpose buffers for ping-pong fwd FFT (1 per y-group, same size as ping).
// Used to eliminate the explicit mbarrier between mul_twiddles_4x4_regs and
// permute_4x4 and the post-FFT mbarrier before smem_comm publish.
static constexpr int FFT16x4x16_DUAL_XPOSE0_PONG_OFFSET =
    FFT16x4x16_DUAL_XPOSE1_OFFSET + XPOSE_SMEM_DOUBLES;
static constexpr int FFT16x4x16_DUAL_XPOSE1_PONG_OFFSET =
    FFT16x4x16_DUAL_XPOSE0_PONG_OFFSET + XPOSE_SMEM_DOUBLES;
static constexpr int FFT16x4x16_DUAL_BARRIER0_OFFSET =
    FFT16x4x16_DUAL_XPOSE1_PONG_OFFSET + XPOSE_SMEM_DOUBLES;
static constexpr int FFT16x4x16_DUAL_BARRIER1_OFFSET =
    FFT16x4x16_DUAL_BARRIER0_OFFSET + FFT16x4x16_MBARRIER_STORAGE_DOUBLES;
static constexpr int FFT16x4x16_DUAL_STARTUP_BARRIER_OFFSET =
    FFT16x4x16_DUAL_BARRIER1_OFFSET + FFT16x4x16_MBARRIER_STORAGE_DOUBLES;
// One padding double after the startup barrier so the negacyclic twist table
// (double2 = 16 bytes) lands on a 16-byte boundary.
// Without padding: (6440+1)*8 = 51528 bytes; 51528 % 16 = 8  → misaligned.
// With padding:    (6440+1+1)*8 = 51536 bytes; 51536 % 16 = 0 → aligned.
static constexpr int FFT16x4x16_DUAL_TWIST_OFFSET =
    FFT16x4x16_DUAL_STARTUP_BARRIER_OFFSET +
    FFT16x4x16_MBARRIER_STORAGE_DOUBLES + 1;

static __device__ __forceinline__ FFT16x4x16MBarrierStorage *
fft16x4x16_dual_mbarrier_storage(double *smem, int fft_id) {
  const int offset = (fft_id == 0) ? FFT16x4x16_DUAL_BARRIER0_OFFSET
                                   : FFT16x4x16_DUAL_BARRIER1_OFFSET;
  return reinterpret_cast<FFT16x4x16MBarrierStorage *>(smem + offset);
}

static __device__ __forceinline__ FFT16x4x16MBarrierStorage *
fft16x4x16_dual_startup_mbarrier_storage(double *smem) {
  return reinterpret_cast<FFT16x4x16MBarrierStorage *>(
      smem + FFT16x4x16_DUAL_STARTUP_BARRIER_OFFSET);
}

// Dual ping-pong smem offsets: one shared twiddle table, two xpose areas,
// and one dedicated CTA-wide communication area. The xpose scratch and the
// cross-group exchange buffer are separated, but the exchange buffer itself is
// reused every iteration.
static constexpr int FFT16x4x16_DUAL_PINGPONG_COMPACT_TW_OFFSET =
    TW_SMEM_DOUBLES;
static constexpr int FFT16x4x16_DUAL_PINGPONG_XPOSE0_OFFSET =
    FFT16x4x16_DUAL_PINGPONG_COMPACT_TW_OFFSET + COMPACT_TW_SMEM_DOUBLES;
static constexpr int FFT16x4x16_DUAL_PINGPONG_XPOSE1_OFFSET =
    FFT16x4x16_DUAL_PINGPONG_XPOSE0_OFFSET + XPOSE_SMEM_DOUBLES;
static constexpr int FFT16x4x16_DUAL_PINGPONG_COMM_SMEM_DOUBLES = 2048;
static constexpr int FFT16x4x16_DUAL_PINGPONG_COMM_OFFSET =
    FFT16x4x16_DUAL_PINGPONG_XPOSE1_OFFSET + XPOSE_SMEM_DOUBLES;
static constexpr int FFT16x4x16_DUAL_PINGPONG_BARRIER0_OFFSET =
    FFT16x4x16_DUAL_PINGPONG_COMM_OFFSET +
    2 * FFT16x4x16_DUAL_PINGPONG_COMM_SMEM_DOUBLES;
static constexpr int FFT16x4x16_DUAL_PINGPONG_BARRIER1_OFFSET =
    FFT16x4x16_DUAL_PINGPONG_BARRIER0_OFFSET +
    FFT16x4x16_MBARRIER_STORAGE_DOUBLES;
static constexpr int FFT16x4x16_DUAL_PINGPONG_STARTUP_BARRIER_OFFSET =
    FFT16x4x16_DUAL_PINGPONG_BARRIER1_OFFSET +
    FFT16x4x16_MBARRIER_STORAGE_DOUBLES;
// One padding double after the startup barrier keeps the twist table aligned
// for double2 access.
static constexpr int FFT16x4x16_DUAL_PINGPONG_TWIST_OFFSET =
    FFT16x4x16_DUAL_PINGPONG_STARTUP_BARRIER_OFFSET +
    FFT16x4x16_MBARRIER_STORAGE_DOUBLES + 1;

static __device__ __forceinline__ FFT16x4x16MBarrierStorage *
fft16x4x16_dual_pingpong_mbarrier_storage(double *smem, int fft_id) {
  const int offset = (fft_id == 0) ? FFT16x4x16_DUAL_PINGPONG_BARRIER0_OFFSET
                                   : FFT16x4x16_DUAL_PINGPONG_BARRIER1_OFFSET;
  return reinterpret_cast<FFT16x4x16MBarrierStorage *>(smem + offset);
}

static __device__ __forceinline__ FFT16x4x16MBarrierStorage *
fft16x4x16_dual_pingpong_startup_mbarrier_storage(double *smem) {
  return reinterpret_cast<FFT16x4x16MBarrierStorage *>(
      smem + FFT16x4x16_DUAL_PINGPONG_STARTUP_BARRIER_OFFSET);
}

static __device__ __forceinline__ double2 *
fft16x4x16_dual_pingpong_comm_buffer(double *smem, int buffer_id) {
  const int offset = FFT16x4x16_DUAL_PINGPONG_COMM_OFFSET +
                     buffer_id * FFT16x4x16_DUAL_PINGPONG_COMM_SMEM_DOUBLES;
  return reinterpret_cast<double2 *>(smem + offset);
}

// Split-real/imag ping-pong offsets: same rollback-safe layout as the regular
// ping-pong variant, but each xpose scratch stores one double plane at a time.
static constexpr int FFT16x4x16_DUAL_PINGPONG_SPLIT_COMPACT_TW_OFFSET =
    TW_SMEM_DOUBLES;
static constexpr int FFT16x4x16_DUAL_PINGPONG_SPLIT_XPOSE0_OFFSET =
    FFT16x4x16_DUAL_PINGPONG_SPLIT_COMPACT_TW_OFFSET + COMPACT_TW_SMEM_DOUBLES;
static constexpr int FFT16x4x16_DUAL_PINGPONG_SPLIT_XPOSE1_OFFSET =
    FFT16x4x16_DUAL_PINGPONG_SPLIT_XPOSE0_OFFSET + XPOSE_SPLIT_SMEM_DOUBLES;
static constexpr int FFT16x4x16_DUAL_PINGPONG_SPLIT_COMM_OFFSET =
    FFT16x4x16_DUAL_PINGPONG_SPLIT_XPOSE1_OFFSET + XPOSE_SPLIT_SMEM_DOUBLES;
static constexpr int FFT16x4x16_DUAL_PINGPONG_SPLIT_BARRIER0_OFFSET =
    FFT16x4x16_DUAL_PINGPONG_SPLIT_COMM_OFFSET +
    2 * FFT16x4x16_DUAL_PINGPONG_COMM_SMEM_DOUBLES;
static constexpr int FFT16x4x16_DUAL_PINGPONG_SPLIT_BARRIER1_OFFSET =
    FFT16x4x16_DUAL_PINGPONG_SPLIT_BARRIER0_OFFSET +
    FFT16x4x16_MBARRIER_STORAGE_DOUBLES;
static constexpr int FFT16x4x16_DUAL_PINGPONG_SPLIT_STARTUP_BARRIER_OFFSET =
    FFT16x4x16_DUAL_PINGPONG_SPLIT_BARRIER1_OFFSET +
    FFT16x4x16_MBARRIER_STORAGE_DOUBLES;
// One padding double after the startup barrier keeps the twist table aligned
// for double2 access.
static constexpr int FFT16x4x16_DUAL_PINGPONG_SPLIT_TWIST_OFFSET =
    FFT16x4x16_DUAL_PINGPONG_SPLIT_STARTUP_BARRIER_OFFSET +
    FFT16x4x16_MBARRIER_STORAGE_DOUBLES + 1;

static __device__ __forceinline__ FFT16x4x16MBarrierStorage *
fft16x4x16_dual_pingpong_split_mbarrier_storage(double *smem, int fft_id) {
  const int offset = (fft_id == 0)
                         ? FFT16x4x16_DUAL_PINGPONG_SPLIT_BARRIER0_OFFSET
                         : FFT16x4x16_DUAL_PINGPONG_SPLIT_BARRIER1_OFFSET;
  return reinterpret_cast<FFT16x4x16MBarrierStorage *>(smem + offset);
}

static __device__ __forceinline__ FFT16x4x16MBarrierStorage *
fft16x4x16_dual_pingpong_split_startup_mbarrier_storage(double *smem) {
  return reinterpret_cast<FFT16x4x16MBarrierStorage *>(
      smem + FFT16x4x16_DUAL_PINGPONG_SPLIT_STARTUP_BARRIER_OFFSET);
}

static __device__ __forceinline__ double2 *
fft16x4x16_dual_pingpong_split_comm_buffer(double *smem, int buffer_id) {
  const int offset = FFT16x4x16_DUAL_PINGPONG_SPLIT_COMM_OFFSET +
                     buffer_id * FFT16x4x16_DUAL_PINGPONG_COMM_SMEM_DOUBLES;
  return reinterpret_cast<double2 *>(smem + offset);
}

// Quad smem offsets: one shared twiddle table then four independent xpose areas
// + four per-group mbarriers + one startup mbarrier.
static constexpr int FFT16x4x16_QUAD_COMPACT_TW_OFFSET = TW_SMEM_DOUBLES;
static constexpr int FFT16x4x16_QUAD_XPOSE0_OFFSET =
    FFT16x4x16_QUAD_COMPACT_TW_OFFSET + COMPACT_TW_SMEM_DOUBLES;
static constexpr int FFT16x4x16_QUAD_XPOSE1_OFFSET =
    FFT16x4x16_QUAD_XPOSE0_OFFSET + XPOSE_SMEM_DOUBLES;
static constexpr int FFT16x4x16_QUAD_XPOSE2_OFFSET =
    FFT16x4x16_QUAD_XPOSE1_OFFSET + XPOSE_SMEM_DOUBLES;
static constexpr int FFT16x4x16_QUAD_XPOSE3_OFFSET =
    FFT16x4x16_QUAD_XPOSE2_OFFSET + XPOSE_SMEM_DOUBLES;
static constexpr int FFT16x4x16_QUAD_BARRIER0_OFFSET =
    FFT16x4x16_QUAD_XPOSE3_OFFSET + XPOSE_SMEM_DOUBLES;
static constexpr int FFT16x4x16_QUAD_BARRIER1_OFFSET =
    FFT16x4x16_QUAD_BARRIER0_OFFSET + FFT16x4x16_MBARRIER_STORAGE_DOUBLES;
static constexpr int FFT16x4x16_QUAD_BARRIER2_OFFSET =
    FFT16x4x16_QUAD_BARRIER1_OFFSET + FFT16x4x16_MBARRIER_STORAGE_DOUBLES;
static constexpr int FFT16x4x16_QUAD_BARRIER3_OFFSET =
    FFT16x4x16_QUAD_BARRIER2_OFFSET + FFT16x4x16_MBARRIER_STORAGE_DOUBLES;
static constexpr int FFT16x4x16_QUAD_STARTUP_BARRIER_OFFSET =
    FFT16x4x16_QUAD_BARRIER3_OFFSET + FFT16x4x16_MBARRIER_STORAGE_DOUBLES;
// One padding double after the startup barrier so the negacyclic twist table
// (double2 = 16 bytes) lands on a 16-byte boundary.
static constexpr int FFT16x4x16_QUAD_TWIST_OFFSET =
    FFT16x4x16_QUAD_STARTUP_BARRIER_OFFSET +
    FFT16x4x16_MBARRIER_STORAGE_DOUBLES + 1;

// ============================================================================
//  mbarrier helpers — SM90+ uses hardware mbarrier for intra-warp-group sync;
//  older architectures fall back to __syncthreads().
// ============================================================================
static __device__ __forceinline__ void
fft16x4x16_mbarrier_init_raw(FFT16x4x16MBarrierStorage *storage,
                             unsigned expected_count) {
#if defined(__CUDA_ARCH__) && __CUDA_ARCH__ >= 900
  asm volatile(
      "mbarrier.init.shared.b64 [%0], %1;"
      :
      : "r"(static_cast<unsigned>(__cvta_generic_to_shared(&storage->barrier))),
        "r"(expected_count)
      : "memory");
#else
  (void)storage;
  (void)expected_count;
#endif
}

static __device__ __forceinline__ void
fft16x4x16_named_barrier_sync(unsigned barrier_id, unsigned thread_count) {
#if defined(__CUDA_ARCH__)
  __barrier_sync_count(barrier_id, thread_count);
#else
  (void)barrier_id;
  (void)thread_count;
#endif
}

// Partial named-barrier sync over one 64-thread FFT y-group (2 warps). Drop-in
// replacement for the mbarrier arrive/test_wait spin used by the production
// ping-pong cores. y-group g (= threadIdx.y) uses named barrier id (g+1):
// groups use ids 1 and 2 — id 0 is reserved for __syncthreads() (== bar.sync
// 0). 64 = 2 warps; bar.sync carries the CTA-scope shared-memory fence the
// transpose store -> sibling-warp-load relies on.
static __device__ __forceinline__ void sync_coupled_warps() {
  fft16x4x16_named_barrier_sync(threadIdx.y + 1u, 64u);
}

// Barrier synchronization between two warps of the same 64-thread FFT group.
// On SM90+ uses the mbarrier arrive/wait protocol to avoid full __syncthreads()
// (which would stall all 128 threads in the block).
static __device__ __forceinline__ void
fft16x4x16_mbarrier_sync(FFT16x4x16MBarrierStorage *storage) {
#if defined(__CUDA_ARCH__) && __CUDA_ARCH__ >= 900
  constexpr unsigned warp_mask = 0xffffffffu;
  const int lane = threadIdx.x & 31;
  const unsigned barrier_addr =
      static_cast<unsigned>(__cvta_generic_to_shared(&storage->barrier));

  __syncwarp(warp_mask);

  unsigned long long token = 0;
  if (lane == 0) {
    asm volatile("mbarrier.arrive.release.cta.shared::cta.b64 %0, [%1];"
                 : "=l"(token)
                 : "r"(barrier_addr)
                 : "memory");
  }

  int ready = 0;
  do {
    if (lane == 0) {
      asm volatile(
          "{\n\t"
          ".reg .pred p;\n\t"
          "mbarrier.test_wait.acquire.cta.shared::cta.b64 p, [%1], %2;\n\t"
          "selp.b32 %0, 1, 0, p;\n\t"
          "}"
          : "=r"(ready)
          : "r"(barrier_addr), "l"(token)
          : "memory");
    }
    ready = __shfl_sync(warp_mask, ready, 0);
  } while (!ready);

  __syncwarp(warp_mask);
#else
  (void)storage;
  __syncthreads();
#endif
}

// ============================================================================
//  Transpose helpers (shared-memory shuffles between FFT stages)
//
//  permute_16x64_mbarrier: 16×64 matrix transpose after the first FFT16 pass.
//    Store pitch 65, stride 4 → smem[lo4*65 + hi4 + i*4]; read indirect.
//  permute_4x4_mbarrier: 4×4 block transpose after the FFT4x4 pass.
//    Store pitch 69; read stride 1.
//  Both variants use fft16x4x16_mbarrier_sync (per-group) instead of
//  __syncthreads.
// ============================================================================
static inline __device__ void
permute_16x64_mbarrier(double2 *a, double *smem,
                       FFT16x4x16MBarrierStorage *barrier) {
  double *smem_re = smem, *smem_im = smem + 69 * 16;
  int lo4 = threadIdx.x & 15;
  int hi4 = threadIdx.x >> 4;
  int sb = lo4 * 65 + hi4;
  int lb = lo4 * 65 + (hi4 << 2);

#pragma unroll
  for (int i = 0; i < 16; i++) {
    int ri = ((i & 1) << 3) | ((i & 2) << 1) | ((i & 4) >> 1) | ((i & 8) >> 3);
    smem_re[sb + (i << 2)] = a[ri].x;
    smem_im[sb + (i << 2)] = a[ri].y;
  }
  fft16x4x16_mbarrier_sync(barrier);
#pragma unroll
  for (int i = 0; i < 16; i++) {
    int li = lb + (i >> 2) * 16 + (i & 3);
    a[i].x = smem_re[li];
    a[i].y = smem_im[li];
  }
}

static inline __device__ void
permute_4x4_mbarrier(double2 *a, double *smem,
                     FFT16x4x16MBarrierStorage *barrier) {
  double *smem_re = smem, *smem_im = smem + 69 * 16;
  int lo2 = threadIdx.x & 3;
  int mi2 = (threadIdx.x >> 2) & 3;
  int hi2 = threadIdx.x >> 4;
  int sb = hi2 * 17 + (mi2 << 2) + lo2;
  int lb = mi2 * 276 + hi2 * 69 + lo2 * 17;

#pragma unroll
  for (int i = 0; i < 16; i++) {
    int ri = (i & 12) | ((i & 1) << 1) | ((i & 2) >> 1);
    smem_re[sb + i * 69] = a[ri].x;
    smem_im[sb + i * 69] = a[ri].y;
  }
  fft16x4x16_mbarrier_sync(barrier);
#pragma unroll
  for (int i = 0; i < 16; i++) {
    a[i].x = smem_re[lb + i];
    a[i].y = smem_im[lb + i];
  }
}
// Performs the data permutation using specialized barriers
static inline __device__ void
permute_16x64_optimized(double2 *a, double *smem,
                        FFT16x4x16MBarrierStorage *barrier) {
  (void)barrier;
  double2 *smem_c = reinterpret_cast<double2 *>(smem);
  int lo4 = threadIdx.x & 15;
  int hi4 = threadIdx.x >> 4;
  int sb = lo4 * 65 + hi4;
  int lb = lo4 * 65 + (hi4 << 2);

  // By unrolling it all the logic to calculate the indexing is calculated at
  // compilation time.
#pragma unroll
  for (int i = 0; i < 16; i++) {
    int ri = ((i & 1) << 3) | ((i & 2) << 1) | ((i & 4) >> 1) | ((i & 8) >> 3);
    smem_c[sb + (i << 2)] = a[ri];
  }
  sync_coupled_warps();
#pragma unroll
  for (int i = 0; i < 16; i++) {
    int li = lb + (i >> 2) * 16 + (i & 3);
    a[i] = smem_c[li];
  }
}
// Permutation for the 4xfft-4 using specialized barriers
static inline __device__ void
permute_4x4_optimized(double2 *a, double *smem,
                      FFT16x4x16MBarrierStorage *barrier) {
  (void)barrier;
  double2 *smem_c = reinterpret_cast<double2 *>(smem);
  int lo2 = threadIdx.x & 3;
  int mi2 = (threadIdx.x >> 2) & 3;
  int hi2 = threadIdx.x >> 4;
  int sb = hi2 * 17 + (mi2 << 2) + lo2;
  int lb = mi2 * 276 + hi2 * 69 + lo2 * 17;

#pragma unroll
  for (int i = 0; i < 16; i++) {
    int ri = (i & 12) | ((i & 1) << 1) | ((i & 2) >> 1);
    smem_c[sb + i * 69] = a[ri];
  }
  sync_coupled_warps();
#pragma unroll
  for (int i = 0; i < 16; i++) {
    a[i] = smem_c[lb + i];
  }
}

// ============================================================================
//  FFT16x4x16 core — operates on 16 registers per thread; smem pointers must
//  be the per-group xpose area and barrier, not the full smem base.
//
//  Forward: FFT16 → inter-stage twiddles → 16x64 transpose → FFT4x4 →
//           compact twiddles → sync → 4x4 transpose → FFT16.
//  Inverse: same sequence with IFFT variants and conjugate twiddles.
//
//  NOTE: output registers are in bit-reversed order d_rev<16>(j).  Callers
//  that do not reorder on output get results in "scrambled" order.
// ============================================================================
static __device__ void FFT16x4x16_fwd_core_mbarrier_explicit(
    double2 *a, const double2 *tw, double *smem_xpose,
    const double *compact_twiddles, FFT16x4x16MBarrierStorage *barrier) {
  int tid = threadIdx.x;
  FFT16(a);
  mul_twiddles_16(a, tid, tw);
  permute_16x64_mbarrier(a, smem_xpose, barrier);
  FFT4x4(a);
  mul_twiddles_4x4(a, compact_twiddles);
  fft16x4x16_mbarrier_sync(barrier);
  permute_4x4_mbarrier(a, smem_xpose, barrier);
  FFT16(a);
}

static __device__ void FFT16x4x16_inv_core_mbarrier_explicit(
    double2 *a, const double2 *tw, double *smem_xpose,
    const double *compact_twiddles, FFT16x4x16MBarrierStorage *barrier) {
  int tid = threadIdx.x;
  IFFT16(a);
  mul_itwiddles_16(a, tid, tw);
  permute_16x64_mbarrier(a, smem_xpose, barrier);
  IFFT4x4(a);
  mul_itwiddles_4x4(a, compact_twiddles);
  fft16x4x16_mbarrier_sync(barrier);
  permute_4x4_mbarrier(a, smem_xpose, barrier);
  IFFT16(a);
}

// First fused pre-twist experiment for the ping-pong accumulate path.
// Keep the old forward core unchanged and provide a sibling path that owns the
// negacyclic pre-twist internally before entering the first FFT16 stage.
//
// The split at j=8 is intentional: for k = tid + 64*j we know exactly when the
// half-table reflection kicks in, so this avoids the per-element branch inside
// twist_lookup while preserving the same math.
static __device__ __forceinline__ void
apply_negacyclic_pre_twist_16x64_stage_fused(double2 *a,
                                             const double2 *smem_twist) {
  const int tid = threadIdx.x;
#pragma unroll
  for (int j = 0; j < 8; j++) {
    double2 tw = smem_twist[tid + j * 64];
    a[j] = a[j] * make_double2(tw.x, -tw.y);
  }
#pragma unroll
  for (int j = 8; j < 16; j++) {
    double2 tw = smem_twist[1024 - (tid + j * 64)];
    a[j] = a[j] * make_double2(-tw.y, tw.x);
  }
}

// Ping-pong forward core WITH the negacyclic pre-twist fused in. That helper is
// *mathematically identical* to the twist_lookup loop (branchless half-table
// split at j=8 ⇔ k=512), so the spectrum entering the GGSW multiply is
// unchanged and the inverse path keeps its smem_twist-based untwist with no
// modification. Ping-pong is preserved: PING (smem_xpose_ping) holds the
// permute_16x64 transpose, PONG (smem_xpose_pong) the permute_4x4 transpose,
// and the mid-FFT explicit mbarrier stays dropped (permute_4x4 writes PONG → no
// WAR on PING).
static __device__ void FFT16x4x16_fwd_optimized_for_pbs(
    double2 *a, const double2 *tw, const double2 *smem_twist,
    double *smem_xpose_ping, double *smem_xpose_pong, double2 compact_w1,
    double2 compact_w2, double2 compact_w3, FFT16x4x16MBarrierStorage *barrier,
    double2 tw_r7, double2 tw_r3, double2 tw_r11, double2 tw_r1) {
  int tid = threadIdx.x;
  apply_negacyclic_pre_twist_16x64_stage_fused(a, smem_twist);
  FFT16(a);
  mul_twiddles_16_cached(a, tid, tw, tw_r7, tw_r3, tw_r11, tw_r1);
  permute_16x64_optimized(a, smem_xpose_ping,
                          barrier); // STS→PING, LDS←PING (named bar.sync)
  FFT4x4(a);
  mul_twiddles_4x4_regs(a, compact_w1, compact_w2, compact_w3);
  // [explicit mbarrier dropped — permute_4x4 below writes to PONG, no WAR on
  // PING]
  permute_4x4_optimized(a, smem_xpose_pong,
                        barrier); // STS→PONG, LDS←PONG (named bar.sync)
  FFT16(a);
}

// Branchless negacyclic post-twist (untwist), fused form. Reads the same
// smem_twist table as the kernel's twist_lookup post-twist loop and is
// mathematically identical: after the inverse FFT, a[j] holds the time value at
// position d_rev16(j)*64 + tid, so it is multiplied by ψ_{tid + d_rev16(j)*64}.
// The half-table reflection is resolved statically (d_rev16(j) < 8 ⇔ k < 512),
// so after #pragma unroll there is no runtime branch. This is NOT the
// constant/gamma form — it keeps smem_twist intact so the BSK twist convention
// is unchanged.
//
// NOTE: the 1/N scaling that used to live here (×inv_n on every element — 2
// extra dependent DMULs per element, 32 per IFFT, unfusable: a·t·s needs 3-way
// product) is now baked into the bsk spectrum by
// batch_FFT16x4x16_classical_specialized (bnsmfft.cuh). 1/1024 = 2^-10 is a
// pure exponent shift, so the result is bit-for-bit identical. Keep the two in
// sync.
static __device__ __forceinline__ void
apply_negacyclic_post_twist_16x64_stage_fused(double2 *a,
                                              const double2 *smem_twist) {
  const int tid = threadIdx.x;
#pragma unroll
  for (int j = 0; j < 16; j++) {
    const int r = bitreversal16(j);
    if (r < 8) {
      double2 t = smem_twist[tid + r * 64];
      a[j] = a[j] * t;
    } else {
      double2 t = smem_twist[1024 - (tid + r * 64)];
      a[j] = a[j] * make_double2(-t.y, -t.x);
    }
  }
}

// Ping-pong inverse core WITH the negacyclic post-twist (untwist) + 1/N fused
// in. Identical to FFT16x4x16_inv_core_mbarrier_explicit_compact_regs_pingpong
// except apply_negacyclic_post_twist_16x64_stage_fused is applied to the
// bit-reversed time-domain registers at the end, replacing the kernel's
// separate twist_lookup loop. Mathematically identical, still reads smem_twist;
// ping-pong (PING for permute_16x64, PONG for permute_4x4) and the dropped
// mid-FFT mbarrier unchanged. The post-twist is register-only besides the
// read-only smem_twist loads, so the dropped post-IFFT mbarrier reasoning still
// holds.
static __device__ void FFT16x4x16_inv_optimized_for_pbs(
    double2 *a, const double2 *tw, const double2 *smem_twist,
    double *smem_xpose_ping, double *smem_xpose_pong, double2 compact_w1,
    double2 compact_w2, double2 compact_w3, FFT16x4x16MBarrierStorage *barrier,
    double2 tw_r7, double2 tw_r3, double2 tw_r11, double2 tw_r1) {
  int tid = threadIdx.x;
  IFFT16(a);
  mul_itwiddles_16_cached(a, tid, tw, tw_r7, tw_r3, tw_r11, tw_r1);
  permute_16x64_optimized(a, smem_xpose_ping,
                          barrier); // STS→PING, LDS←PING (named bar.sync)
  IFFT4x4(a);
  mul_itwiddles_4x4_regs(a, compact_w1, compact_w2, compact_w3);
  // [explicit mbarrier dropped — permute_4x4 below writes to PONG, no WAR on
  // PING]
  permute_4x4_optimized(a, smem_xpose_pong,
                        barrier); // STS→PONG, LDS←PONG (named bar.sync)
  IFFT16(a);
  apply_negacyclic_post_twist_16x64_stage_fused(a, smem_twist);
}

// ============================================================================
//  Dual-block twiddle loader (128-thread block: threadIdx.y=0/1 selects group)
//
//  Loads tw_1024[15][64] and compact_twiddles into the shared region that
//  both FFT groups (y=0 and y=1) share.  Callers must synchronize (via the
//  startup mbarrier) before calling the core functions.
// ============================================================================
static __device__ __forceinline__ void
fft16x4x16_load_shared_twiddles_128t(double *smem) {
  double2 *smem_tw = (double2 *)smem;
  double *compact_twiddles = smem + FFT16x4x16_DUAL_COMPACT_TW_OFFSET;
  const int linear_tid = threadIdx.x + (threadIdx.y << 6);

#pragma unroll
  for (int idx = linear_tid; idx < 15 * 64; idx += 128) {
    smem_tw[idx] = tw_1024[idx >> 6][idx & 63];
  }

  // 48 threads load the compact twiddle table (3 rows × 16 entries re + im)
  if (linear_tid < 48) {
    int r = linear_tid >> 4;
    int col = linear_tid & 15;
    int table_row = (r == 0) ? 7 : (r == 1) ? 3 : 11;
    double2 v = tw_1024[table_row][4 * col];
    compact_twiddles[r * 17 + col] = v.x;
    compact_twiddles[3 * 17 + r * 17 + col] = v.y;
  }
}

// ============================================================================
//  Negacyclic twist lookup (half-table symmetry)
//
//  twisting_twiddles[k] = exp(-i*pi*k / 2048), stored for k=0..512.
//  Entries k=513..1023 are recovered via: ψ_{1024-k} = (-ψ_k.y, -ψ_k.x).
//  Entry k=512 is stored explicitly so the reflection is branchless at k≥512.
// ============================================================================
static inline __device__ double2 twist_lookup(const double2 *smem_twist,
                                              int k) {
  if (k < 512)
    return smem_twist[k];
  double2 t = smem_twist[1024 - k]; // smem_twist[512] valid for k=512
  return make_double2(-t.y, -t.x);
}

// Total shared memory before the barriers
static constexpr int KB_BARRIER_OFFSET =
    FFT16x4x16_DUAL_XPOSE0_OFFSET + XPOSE_SMEM_DOUBLES; // 4230

// Total shared memory before the twisting layer
static constexpr int KB_TWIST_OFFSET =
    KB_BARRIER_OFFSET + FFT16x4x16_MBARRIER_STORAGE_DOUBLES + 1; // 4232
