#ifndef GPU_BOOTSTRAP_FFT_CUH
#define GPU_BOOTSTRAP_FFT_CUH

#include "fft/fft16x4x16.cuh"
#include "polynomial/functions.cuh"
#include "polynomial/parameters.cuh"
#include "twiddles.cuh"
#include "types/complex/operations.cuh"

using Index = unsigned;
/*
 * Direct negacyclic FFT:
 *   - before the FFT the N real coefficients are stored into a
 *     N/2 sized complex with the even coefficients in the real part
 *     and the odd coefficients in the imaginary part. This is referred to
 *     as the half-size FFT
 *   - when calling BNSMFFT_direct for the forward negacyclic FFT of PBS,
 *     opt is divided by 2 because the butterfly pattern is always applied
 *     between pairs of coefficients
 *   - instead of twisting each coefficient A_j before the FFT by
 *     multiplying by the w^j roots of unity (aka twiddles, w=exp(-i pi /N)),
 *     the FFT is modified, and for each level k of the FFT the twiddle:
 *     w_j,k = exp(-i pi j/2^k)
 *     is replaced with:
 *     \zeta_j,k = exp(-i pi (2j-1)/2^k)
 */
template <class params> __device__ void NSMFFT_direct(double2 *A) {

  /* We don't make bit reverse here, since twiddles are already reversed
   *  Each thread is always in charge of "opt/2" pairs of coefficients,
   *  which is why we always loop through N/2 by N/opt strides
   *  The pragma unroll instruction tells the compiler to unroll the
   *  full loop, which should increase performance
   */

  __syncthreads();
  constexpr Index BUTTERFLY_DEPTH = params::opt >> 1;
  constexpr Index LOG2_DEGREE = params::log2_degree;
  constexpr Index HALF_DEGREE = params::degree >> 1;
  constexpr Index STRIDE = params::degree / params::opt;

  Index tid = threadIdx.x;
  double2 u[BUTTERFLY_DEPTH], v[BUTTERFLY_DEPTH], w;

  // load into registers
#pragma unroll
  for (Index i = 0; i < BUTTERFLY_DEPTH; ++i) {
    u[i] = A[tid];
    v[i] = A[tid + HALF_DEGREE];

    tid += STRIDE;
  }

  // level 1
  // we don't make actual complex multiplication on level1 since we have only
  // one twiddle, it's real and image parts are equal, so we can multiply
  // it with simpler operations
#pragma unroll
  for (Index i = 0; i < BUTTERFLY_DEPTH; ++i) {
    w = v[i] * (double2){0.707106781186547461715008466854,
                         0.707106781186547461715008466854};
    v[i] = u[i] - w;
    u[i] = u[i] + w;
  }

  Index twiddle_shift = 1;
  for (Index l = LOG2_DEGREE - 1; l >= 5; --l) {
    Index lane_mask = 1 << (l - 1);
    Index thread_mask = (1 << l) - 1;
    twiddle_shift <<= 1;

    tid = threadIdx.x;
    __syncthreads();
#pragma unroll
    for (Index i = 0; i < BUTTERFLY_DEPTH; i++) {
      Index rank = tid & thread_mask;
      bool u_stays_in_register = rank < lane_mask;
      A[tid] = (u_stays_in_register) ? v[i] : u[i];
      tid = tid + STRIDE;
    }
    __syncthreads();

    tid = threadIdx.x;
#pragma unroll
    for (Index i = 0; i < BUTTERFLY_DEPTH; i++) {
      Index rank = tid & thread_mask;
      bool u_stays_in_register = rank < lane_mask;
      w = A[tid ^ lane_mask];
      u[i] = (u_stays_in_register) ? u[i] : w;
      v[i] = (u_stays_in_register) ? w : v[i];
      w = negtwiddles[tid / lane_mask + twiddle_shift];

      w *= v[i];

      v[i] = u[i] - w;
      u[i] = u[i] + w;
      tid = tid + STRIDE;
    }
  }

  for (Index l = 4; l >= 1; --l) {
    Index lane_mask = 1 << (l - 1);
    Index thread_mask = (1 << l) - 1;
    twiddle_shift <<= 1;

    tid = threadIdx.x;
    __syncwarp();
    double2 reg_A[BUTTERFLY_DEPTH];
#pragma unroll
    for (Index i = 0; i < BUTTERFLY_DEPTH; i++) {
      Index rank = tid & thread_mask;
      bool u_stays_in_register = rank < lane_mask;
      reg_A[i] = (u_stays_in_register) ? v[i] : u[i];
      tid = tid + STRIDE;
    }
    __syncwarp();

    tid = threadIdx.x;
#pragma unroll
    for (Index i = 0; i < BUTTERFLY_DEPTH; i++) {
      Index rank = tid & thread_mask;
      bool u_stays_in_register = rank < lane_mask;
      w = shfl_xor_double2(reg_A[i], 1 << (l - 1), 0xFFFFFFFF);
      u[i] = (u_stays_in_register) ? u[i] : w;
      v[i] = (u_stays_in_register) ? w : v[i];
      w = negtwiddles[tid / lane_mask + twiddle_shift];

      w *= v[i];

      v[i] = u[i] - w;
      u[i] = u[i] + w;
      tid = tid + STRIDE;
    }
  }

  __syncthreads();
  // store registers in SM
  tid = threadIdx.x;
#pragma unroll
  for (Index i = 0; i < BUTTERFLY_DEPTH; i++) {
    A[tid * 2] = u[i];
    A[tid * 2 + 1] = v[i];
    tid = tid + STRIDE;
  }
  __syncthreads();
}

/*
 * negacyclic fft optimized for 2_2 params
   it uses the twiddles from shared memory for extra performance
   this is possible cause we know for 2_2 params will have memory available
   the fft is returned in registers to avoid extra synchronizations
 */
template <class params>
__device__ void NSMFFT_direct_2_2_params(double2 *A, double2 *fft_out,
                                         double2 *shared_twiddles) {

  /* We don't make bit reverse here, since twiddles are already reversed
   *  Each thread is always in charge of "opt/2" pairs of coefficients,
   *  which is why we always loop through N/2 by N/opt strides
   *  The pragma unroll instruction tells the compiler to unroll the
   *  full loop, which should increase performance
   */

  constexpr Index BUTTERFLY_DEPTH = params::opt >> 1;
  constexpr Index LOG2_DEGREE = params::log2_degree;
  constexpr Index HALF_DEGREE = params::degree >> 1;
  constexpr Index STRIDE = params::degree / params::opt;

  Index tid = threadIdx.x;
  double2 u[BUTTERFLY_DEPTH], v[BUTTERFLY_DEPTH], w;

  // switch register order
  for (Index i = 0; i < BUTTERFLY_DEPTH; ++i) {
    u[i] = fft_out[i];
    v[i] = fft_out[i + params::opt / 2];
  }

  // level 1
  // we don't make actual complex multiplication on level1 since we have only
  // one twiddle, it's real and image parts are equal, so we can multiply
  // it with simpler operations
#pragma unroll
  for (Index i = 0; i < BUTTERFLY_DEPTH; ++i) {
    w = v[i] * (double2){0.707106781186547461715008466854,
                         0.707106781186547461715008466854};
    v[i] = u[i] - w;
    u[i] = u[i] + w;
  }

  Index twiddle_shift = 1;
  for (Index l = LOG2_DEGREE - 1; l > 5; --l) {
    Index lane_mask = 1 << (l - 1);
    Index thread_mask = (1 << l) - 1;
    twiddle_shift <<= 1;

    tid = threadIdx.x;
    __syncthreads();
#pragma unroll
    for (Index i = 0; i < BUTTERFLY_DEPTH; i++) {
      Index rank = tid & thread_mask;
      bool u_stays_in_register = rank < lane_mask;
      A[tid] = (u_stays_in_register) ? v[i] : u[i];
      tid = tid + STRIDE;
    }
    __syncthreads();

    tid = threadIdx.x;
#pragma unroll
    for (Index i = 0; i < BUTTERFLY_DEPTH; i++) {
      Index rank = tid & thread_mask;
      bool u_stays_in_register = rank < lane_mask;
      w = A[tid ^ lane_mask];
      u[i] = (u_stays_in_register) ? u[i] : w;
      v[i] = (u_stays_in_register) ? w : v[i];
      w = shared_twiddles[tid / lane_mask + twiddle_shift];

      w *= v[i];

      v[i] = u[i] - w;
      u[i] = u[i] + w;
      tid = tid + STRIDE;
    }
  }
  __syncthreads();
  for (Index l = 5; l >= 1; --l) {
    Index lane_mask = 1 << (l - 1);
    Index thread_mask = (1 << l) - 1;
    twiddle_shift <<= 1;

    tid = threadIdx.x;
    double2 reg_A[BUTTERFLY_DEPTH];

    tid = threadIdx.x;
#pragma unroll
    for (Index i = 0; i < BUTTERFLY_DEPTH; i++) {
      Index rank = tid & thread_mask;
      bool u_stays_in_register = rank < lane_mask;
      reg_A[i] = (u_stays_in_register) ? v[i] : u[i];
      w = shfl_xor_double2(reg_A[i], 1 << (l - 1), 0xFFFFFFFF);
      u[i] = (u_stays_in_register) ? u[i] : w;
      v[i] = (u_stays_in_register) ? w : v[i];
      w = shared_twiddles[tid / lane_mask + twiddle_shift];

      w *= v[i];

      v[i] = u[i] - w;
      u[i] = u[i] + w;
      tid = tid + STRIDE;
    }
  }

  // Return result in registers, no need to synchronize here
  // only with we need to use the same shared memory afterwards
  for (Index i = 0; i < BUTTERFLY_DEPTH; i++) {
    fft_out[i] = u[i];
    fft_out[i + params::opt / 2] = v[i];
  }
}

/*
 * negacyclic inverse fft
 */
template <class params> __device__ void NSMFFT_inverse(double2 *A) {

  /* We don't make bit reverse here, since twiddles are already reversed
   *  Each thread is always in charge of "opt/2" pairs of coefficients,
   *  which is why we always loop through N/2 by N/opt strides
   *  The pragma unroll instruction tells the compiler to unroll the
   *  full loop, which should increase performance
   */

  __syncthreads();
  constexpr Index BUTTERFLY_DEPTH = params::opt >> 1;
  constexpr Index LOG2_DEGREE = params::log2_degree;
  constexpr Index DEGREE = params::degree;
  constexpr Index HALF_DEGREE = params::degree >> 1;
  constexpr Index STRIDE = params::degree / params::opt;

  size_t tid = threadIdx.x;
  double2 u[BUTTERFLY_DEPTH], v[BUTTERFLY_DEPTH], w;

  // load into registers and divide by compressed polynomial size
#pragma unroll
  for (Index i = 0; i < BUTTERFLY_DEPTH; ++i) {
    u[i] = A[2 * tid];
    v[i] = A[2 * tid + 1];

    u[i] /= DEGREE;
    v[i] /= DEGREE;

    tid += STRIDE;
  }

  Index twiddle_shift = DEGREE;
  for (Index l = 1; l <= 4; ++l) {
    Index lane_mask = 1 << (l - 1);
    Index thread_mask = (1 << l) - 1;
    tid = threadIdx.x;
    twiddle_shift >>= 1;

    // at this point registers are ready for the  butterfly
    tid = threadIdx.x;
    __syncwarp();
    double2 reg_A[BUTTERFLY_DEPTH];
#pragma unroll
    for (Index i = 0; i < BUTTERFLY_DEPTH; ++i) {
      w = (u[i] - v[i]);
      u[i] += v[i];
      v[i] = w * conjugate(negtwiddles[tid / lane_mask + twiddle_shift]);

      // keep one of the register for next iteration and store another one in sm
      Index rank = tid & thread_mask;
      bool u_stays_in_register = rank < lane_mask;
      reg_A[i] = (u_stays_in_register) ? v[i] : u[i];

      tid = tid + STRIDE;
    }
    __syncwarp();

    // prepare registers for next butterfly iteration
    tid = threadIdx.x;
#pragma unroll
    for (Index i = 0; i < BUTTERFLY_DEPTH; ++i) {
      Index rank = tid & thread_mask;
      bool u_stays_in_register = rank < lane_mask;
      w = shfl_xor_double2(reg_A[i], 1 << (l - 1), 0xFFFFFFFF);
      u[i] = (u_stays_in_register) ? u[i] : w;
      v[i] = (u_stays_in_register) ? w : v[i];

      tid = tid + STRIDE;
    }
  }

  for (Index l = 5; l <= LOG2_DEGREE - 1; ++l) {
    Index lane_mask = 1 << (l - 1);
    Index thread_mask = (1 << l) - 1;
    tid = threadIdx.x;
    twiddle_shift >>= 1;

    // at this point registers are ready for the  butterfly
    tid = threadIdx.x;
    __syncthreads();
#pragma unroll
    for (Index i = 0; i < BUTTERFLY_DEPTH; ++i) {
      w = (u[i] - v[i]);
      u[i] += v[i];
      v[i] = w * conjugate(negtwiddles[tid / lane_mask + twiddle_shift]);

      // keep one of the register for next iteration and store another one in sm
      Index rank = tid & thread_mask;
      bool u_stays_in_register = rank < lane_mask;
      A[tid] = (u_stays_in_register) ? v[i] : u[i];

      tid = tid + STRIDE;
    }
    __syncthreads();

    // prepare registers for next butterfly iteration
    tid = threadIdx.x;
#pragma unroll
    for (Index i = 0; i < BUTTERFLY_DEPTH; ++i) {
      Index rank = tid & thread_mask;
      bool u_stays_in_register = rank < lane_mask;
      w = A[tid ^ lane_mask];
      u[i] = (u_stays_in_register) ? u[i] : w;
      v[i] = (u_stays_in_register) ? w : v[i];

      tid = tid + STRIDE;
    }
  }

  // last iteration
  for (Index i = 0; i < BUTTERFLY_DEPTH; ++i) {
    w = (u[i] - v[i]);
    u[i] = u[i] + v[i];
    v[i] = w * (double2){0.707106781186547461715008466854,
                         -0.707106781186547461715008466854};
  }
  __syncthreads();
  // store registers in SM
  tid = threadIdx.x;
#pragma unroll
  for (Index i = 0; i < BUTTERFLY_DEPTH; i++) {
    A[tid] = u[i];
    A[tid + HALF_DEGREE] = v[i];
    tid = tid + STRIDE;
  }
  __syncthreads();
}

/*
 * negacyclic inverse fft optimized for 2_2 params
 * it uses the twiddles from shared memory for extra performance
 * this is possible cause we know for 2_2 params will have memory available
 * the input comes from registers to avoid some synchronizations and shared mem
 * usage
 */
template <class params>
__device__ void NSMFFT_inverse_2_2_params(double2 *A, double2 *buffer_regs,
                                          double2 *shared_twiddles) {

  /* We don't make bit reverse here, since twiddles are already reversed
   *  Each thread is always in charge of "opt/2" pairs of coefficients,
   *  which is why we always loop through N/2 by N/opt strides
   *  The pragma unroll instruction tells the compiler to unroll the
   *  full loop, which should increase performance
   */

  constexpr Index BUTTERFLY_DEPTH = params::opt >> 1;
  constexpr Index LOG2_DEGREE = params::log2_degree;
  constexpr Index DEGREE = params::degree;
  constexpr Index HALF_DEGREE = params::degree >> 1;
  constexpr Index STRIDE = params::degree / params::opt;

  size_t tid = threadIdx.x;
  double2 u[BUTTERFLY_DEPTH], v[BUTTERFLY_DEPTH], w;

  // load into registers and divide by compressed polynomial size
  for (Index i = 0; i < BUTTERFLY_DEPTH; ++i) {
    u[i] = buffer_regs[i];
    v[i] = buffer_regs[i + params::opt / 2];

    u[i] /= DEGREE;
    v[i] /= DEGREE;
  }

  Index twiddle_shift = DEGREE;
  for (Index l = 1; l <= 5; ++l) {
    Index lane_mask = 1 << (l - 1);
    Index thread_mask = (1 << l) - 1;
    tid = threadIdx.x;
    twiddle_shift >>= 1;

    // at this point registers are ready for the  butterfly
    tid = threadIdx.x;
    double2 reg_A[BUTTERFLY_DEPTH];
#pragma unroll
    for (Index i = 0; i < BUTTERFLY_DEPTH; ++i) {
      w = (u[i] - v[i]);
      u[i] += v[i];
      v[i] = w * conjugate(shared_twiddles[tid / lane_mask + twiddle_shift]);

      tid = tid + STRIDE;
    }
    __syncwarp();

    // prepare registers for next butterfly iteration
    tid = threadIdx.x;
#pragma unroll
    for (Index i = 0; i < BUTTERFLY_DEPTH; ++i) {
      Index rank = tid & thread_mask;
      bool u_stays_in_register = rank < lane_mask;
      reg_A[i] = (u_stays_in_register) ? v[i] : u[i];
      w = shfl_xor_double2(reg_A[i], 1 << (l - 1), 0xFFFFFFFF);
      u[i] = (u_stays_in_register) ? u[i] : w;
      v[i] = (u_stays_in_register) ? w : v[i];

      tid = tid + STRIDE;
    }
  }

  for (Index l = 6; l <= LOG2_DEGREE - 1; ++l) {
    Index lane_mask = 1 << (l - 1);
    Index thread_mask = (1 << l) - 1;
    tid = threadIdx.x;
    twiddle_shift >>= 1;

    // at this point registers are ready for the  butterfly
    tid = threadIdx.x;

#pragma unroll
    for (Index i = 0; i < BUTTERFLY_DEPTH; ++i) {
      w = (u[i] - v[i]);
      u[i] += v[i];
      v[i] = w * conjugate(shared_twiddles[tid / lane_mask + twiddle_shift]);

      // keep one of the register for next iteration and store another one in sm
      Index rank = tid & thread_mask;
      bool u_stays_in_register = rank < lane_mask;
      A[tid] = (u_stays_in_register) ? v[i] : u[i];

      tid = tid + STRIDE;
    }
    __syncthreads();

    // prepare registers for next butterfly iteration
    tid = threadIdx.x;
#pragma unroll
    for (Index i = 0; i < BUTTERFLY_DEPTH; ++i) {
      Index rank = tid & thread_mask;
      bool u_stays_in_register = rank < lane_mask;
      w = A[tid ^ lane_mask];
      u[i] = (u_stays_in_register) ? u[i] : w;
      v[i] = (u_stays_in_register) ? w : v[i];

      tid = tid + STRIDE;
    }
    __syncthreads();
  }

// last iteration
#pragma unroll
  for (Index i = 0; i < BUTTERFLY_DEPTH; ++i) {
    w = (u[i] - v[i]);
    buffer_regs[i] = u[i] + v[i];
    buffer_regs[i + params::opt / 2] =
        w * (double2){0.707106781186547461715008466854,
                      -0.707106781186547461715008466854};
  }
}

/*
 * global batch fft
 * does fft in half size
 * this function must be called with actual degree
 * function takes as input already compressed input
 */
template <class params, sharedMemDegree SMD>
__global__ void batch_NSMFFT(double2 *d_input, double2 *d_output,
                             double2 *buffer) {
  extern __shared__ double2 sharedMemoryFFT[];
  double2 *fft = (SMD == NOSM) ? &buffer[blockIdx.x * params::degree / 2]
                               : sharedMemoryFFT;
  int tid = threadIdx.x;

#pragma unroll
  for (int i = 0; i < params::opt / 2; i++) {
    fft[tid] = d_input[blockIdx.x * (params::degree / 2) + tid];
    tid = tid + params::degree / params::opt;
  }
  __syncthreads();
  NSMFFT_direct<HalfDegree<params>>(fft);
  __syncthreads();

  tid = threadIdx.x;
#pragma unroll
  for (int i = 0; i < params::opt / 2; i++) {
    d_output[blockIdx.x * (params::degree / 2) + tid] = fft[tid];
    tid = tid + params::degree / params::opt;
  }
}

/*
 * global batch fft
 * does fft in half size
 * this function must be called with actual degree
 * function takes as input already compressed input
 * this function is optimized for 2_2 params, it uses shared memory for
 * twiddles, and for the fft exchanges between threads. Only 32768 bytes are
 * needed, and we know in the 2_2 params cases we will always have enough shared
 * memory.
 */
template <class params>
__global__ void batch_NSMFFT_classical_specialized(double2 *d_input,
                                                   double2 *d_output) {
  extern __shared__ double2 sharedMemoryFFT[];
  // For specialized we will always have enough shared memory
  double2 *fft = sharedMemoryFFT;
  int tid = threadIdx.x;

  double2 *shared_twiddles = fft + params::degree / 2;

  double2 fft_regs[params::opt / 2];
#pragma unroll
  for (int i = 0; i < params::opt / 2; i++) {
    shared_twiddles[tid] = negtwiddles[tid];
    fft_regs[i] = d_input[blockIdx.x * (params::degree / 2) + tid];
    tid = tid + params::degree / params::opt;
  }
  __syncthreads();

  NSMFFT_direct_2_2_params<HalfDegree<params>>(fft, fft_regs, shared_twiddles);
  __syncthreads();

  tid = threadIdx.x;
#pragma unroll
  for (int i = 0; i < params::opt / 2; i++) {
    d_output[blockIdx.x * (params::degree / 2) + tid] = fft_regs[i];
    tid = tid + params::degree / params::opt;
  }
}

// FFT16x4x16-based batch BSK forward transform for the specialized 2_2 path.
//
// Replacement for batch_NSMFFT_classical_specialized that converts each
// bootstrapping-key polynomial into the same bit-reversed-frequency layout the
// FFT16x4x16-based accumulate kernel produces and reads. Both sides therefore
// pair identical frequencies during the GGSW pointwise multiply without any
// per-iteration register permutation.
//
// Layout convention
// ─────────────────
//   For an N=2048 real polynomial encoded as N/2=1024 complex doubles via the
//   compressed real layout (input[k].x = poly[k], input[k].y = poly[k+1024]):
//
//     d_output[blockIdx.x*(N/2) + tid + j*64]  =  Â_bsk[bitreversal16(j)*64 +
//     tid]
//
//   tid ∈ [0,64), j ∈ [0,16).  The accumulate kernel's FFT16x4x16 forward
//   leaves register a[j] holding Â_acc[bitreversal16(j)*64+tid]; reading bsk at
//   physical index tid+j*64 picks the matching frequency.
//
// SMEM layout (≈41 KB, single 64-thread FFT — Strategy A from the keybundle
// migration plan, no monomial precalc needed for the classic bsk):
//   [0 .. TW_SMEM_DOUBLES-1]                   tw_1024 twiddle table (1920)
//   [FFT16x4x16_DUAL_COMPACT_TW_OFFSET .. +101] compact_twiddles (102)
//   [FFT16x4x16_DUAL_XPOSE0_OFFSET .. +2207]   xpose scratch (2208)
//   [KB_BARRIER_OFFSET]                         mbarrier (1 storage double)
//   [KB_TWIST_OFFSET .. +1025]                  negacyclic twist half-table
template <class params>
__global__ void batch_FFT16x4x16_classical_specialized(double2 *d_input,
                                                       double2 *d_output) {
  extern __shared__ int8_t batch_fft16_sharedmem[];
  double *smem = reinterpret_cast<double *>(batch_fft16_sharedmem);

  const double2 *tw_shared = reinterpret_cast<const double2 *>(smem);
  const double *compact_twiddles = smem + FFT16x4x16_DUAL_COMPACT_TW_OFFSET;
  double *smem_xpose = smem + FFT16x4x16_DUAL_XPOSE0_OFFSET;
  double2 *smem_twist = reinterpret_cast<double2 *>(smem + KB_TWIST_OFFSET);
  FFT16x4x16MBarrierStorage *barrier =
      reinterpret_cast<FFT16x4x16MBarrierStorage *>(smem + KB_BARRIER_OFFSET);

  // 64 threads / 32 lanes = 2 warps participate in each per-FFT barrier.
  if (threadIdx.x == 0)
    fft16x4x16_mbarrier_init_raw(barrier, 2u);

  // Load FFT twiddle table cooperatively (64 threads × 15 iters = 960 d2's).
  double2 *tw_shared_w = reinterpret_cast<double2 *>(smem);
#pragma unroll
  for (int idx = threadIdx.x; idx < 15 * 64; idx += 64)
    tw_shared_w[idx] = tw_1024[idx >> 6][idx & 63];

  // Compact twiddles: 3 rows × 16 columns of (re, im).  First 48 threads each
  // load one (row, col) entry; matches the convention used by the dual-FFT
  // 128-thread loader in fft16x4x16_load_shared_twiddles_128t.
  double *compact_twiddles_w = smem + FFT16x4x16_DUAL_COMPACT_TW_OFFSET;
  if (threadIdx.x < 48) {
    int r = threadIdx.x >> 4;
    int col = threadIdx.x & 15;
    int table_row = (r == 0) ? 7 : (r == 1) ? 3 : 11;
    double2 v = tw_1024[table_row][4 * col];
    compact_twiddles_w[r * 17 + col] = v.x;
    compact_twiddles_w[3 * 17 + r * 17 + col] = v.y;
  }

  // Negacyclic twist half-table (513 entries; symmetric reflection for k>512).
  for (int idx = threadIdx.x; idx < 512; idx += 64)
    smem_twist[idx] = twisting_twiddles[idx];
  if (threadIdx.x == 0)
    smem_twist[512] = twisting_twiddles[512];

  __syncthreads();

  // Read this block's compressed bsk polynomial (16 complex per thread).
  double2 a[16];
#pragma unroll
  for (int j = 0; j < 16; j++)
    a[j] = d_input[blockIdx.x * (params::degree / 2) + threadIdx.x + j * 64];

    // Negacyclic pre-twist: multiply each element by conj(ψ_{tid+j*64}). This
    // is the same convention applied on the accumulator side, so both Â_bsk and
    // Â_acc are produced with the matching negacyclic embedding.
#pragma unroll
  for (int j = 0; j < 16; j++) {
    double2 tw = twist_lookup(smem_twist, threadIdx.x + j * 64);
    a[j] = a[j] * make_double2(tw.x, -tw.y);
  }

  // Standard 1024-point FFT; output is in bit-reversed register order.
  FFT16x4x16_fwd_core_mbarrier_explicit(a, tw_shared, smem_xpose,
                                        compact_twiddles, barrier);
  fft16x4x16_mbarrier_sync(barrier);

  // Persist a[j] at physical index tid + j*64 — see layout comment at the top.
  //
  // Scaled by 1/N (N = 1024, the FFT length): the PBS inverse path's fused
  // post-twist no longer multiplies by inv_n — the bsk spectrum carries the
  // 1/N instead, saving 32 dependent DMULs per IFFT per PBS iteration.
  constexpr double inv_n = 1.0 / 1024.0;
#pragma unroll
  for (int j = 0; j < 16; j++)
    d_output[blockIdx.x * (params::degree / 2) + threadIdx.x + j * 64] =
        a[j] * inv_n;
}

// Shared-memory footprint of batch_FFT16x4x16_classical_specialized.
//   KB_TWIST_OFFSET doubles + 513 double2 entries
//   = 4232 * 8 + 513 * 16 = 33856 + 8208 = 42064 bytes  (≈41 KB)
static constexpr size_t BATCH_FFT16X4X16_BSK_SMEM_BYTES =
    static_cast<size_t>(KB_TWIST_OFFSET) * sizeof(double) +
    513 * sizeof(double2);

/*
 * global batch polynomial multiplication
 * only used for fft tests
 * d_input1 and d_output must not have the same pointer
 * d_input1 can be modified inside the function
 */
template <class params, sharedMemDegree SMD>
__global__ void batch_polynomial_mul(double2 *d_input1, double2 *d_input2,
                                     double2 *d_output, double2 *buffer) {
  extern __shared__ double2 sharedMemoryFFT[];
  double2 *fft = (SMD == NOSM) ? &buffer[blockIdx.x * params::degree / 2]
                               : sharedMemoryFFT;

  // Move first polynomial into shared memory(if possible otherwise it will
  // be moved in device buffer)
  int tid = threadIdx.x;
#pragma unroll
  for (int i = 0; i < params::opt / 2; i++) {
    fft[tid] = d_input1[blockIdx.x * (params::degree / 2) + tid];
    tid = tid + params::degree / params::opt;
  }

  // Perform direct negacyclic fourier transform
  __syncthreads();
  NSMFFT_direct<HalfDegree<params>>(fft);
  __syncthreads();

  // Put the result of direct fft inside input1
  tid = threadIdx.x;
#pragma unroll
  for (int i = 0; i < params::opt / 2; i++) {
    d_input1[blockIdx.x * (params::degree / 2) + tid] = fft[tid];
    tid = tid + params::degree / params::opt;
  }
  __syncthreads();

  // Move first polynomial into shared memory(if possible otherwise it will
  // be moved in device buffer)
  tid = threadIdx.x;
#pragma unroll
  for (int i = 0; i < params::opt / 2; i++) {
    fft[tid] = d_input2[blockIdx.x * (params::degree / 2) + tid];
    tid = tid + params::degree / params::opt;
  }

  // Perform direct negacyclic fourier transform on the second polynomial
  __syncthreads();
  NSMFFT_direct<HalfDegree<params>>(fft);
  __syncthreads();

  // calculate pointwise multiplication inside fft buffer
  tid = threadIdx.x;
#pragma unroll
  for (int i = 0; i < params::opt / 2; i++) {
    fft[tid] *= d_input1[blockIdx.x * (params::degree / 2) + tid];
    tid = tid + params::degree / params::opt;
  }

  // Perform backward negacyclic fourier transform
  __syncthreads();
  NSMFFT_inverse<HalfDegree<params>>(fft);
  __syncthreads();

  // copy results in output buffer
  tid = threadIdx.x;
#pragma unroll
  for (int i = 0; i < params::opt / 2; i++) {
    d_output[blockIdx.x * (params::degree / 2) + tid] = fft[tid];
    tid = tid + params::degree / params::opt;
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Test-only negacyclic polynomial multiplication using the FFT16x4x16 path.
//
// Analog of batch_polynomial_mul, but exercises the throughput-oriented
// FFT16x4x16 forward/inverse cores actually used by the specialized 2_2_params
// PBS (FFT16x4x16_fwd/inv_optimized_for_pbs). Hardcoded to N = 2048
// (N/2 = 1024 = 16×64) and to a single 64-thread FFT group per block.
//
// REQUIRES sm_90 (H100): the optimized cores rely on named-barrier / mbarrier
// primitives only available there.
//
// Data flow (mirrors the production PBS exactly):
//   - both operands get the fused negacyclic pre-twist inside the forward core;
//   - their spectra are produced in bit-reversed frequency order
//     (a[j] ↔ frequency bitreversal16(j)*64 + tid), so the pointwise product is
//     a register-wise a[j]*b[j];
//   - the 1/N (N = 1024) scaling — which production bakes into the BSK spectrum
//     via batch_FFT16x4x16_classical_specialized, NOT into the inverse core —
//     is applied here on the product;
//   - the inverse core expects natural-order input, so we unscramble once
//     (nat[j] = prod[bitreversal16(j)]) before calling it;
//   - after the inverse, nat[j] holds the time value at position
//     bitreversal16(j)*64 + tid in the compressed real layout (.x = coeff k,
//     .y = coeff k+1024).
//
// Smem: reuses the dual-FFT layout offsets (group 0 only) so the pointers
// handed to the cores stay consistent; allocate FFT16x4x16_DUAL_SMEM_BYTES.
template <class params>
__global__ void
batch_polynomial_mul_fft16x4x16(const double2 *__restrict__ d_input1,
                                const double2 *__restrict__ d_input2,
                                double2 *__restrict__ d_output) {
  extern __shared__ int8_t batch_fft16_mul_sharedmem[];
  double *smem = reinterpret_cast<double *>(batch_fft16_mul_sharedmem);

  const double2 *tw_shared = reinterpret_cast<const double2 *>(smem);
  const double *compact_twiddles = smem + FFT16x4x16_DUAL_COMPACT_TW_OFFSET;
  double *smem_xpose = smem + FFT16x4x16_DUAL_XPOSE0_OFFSET;
  double *smem_xpose_pong = smem + FFT16x4x16_DUAL_XPOSE0_PONG_OFFSET;
  double2 *smem_twist =
      reinterpret_cast<double2 *>(smem + FFT16x4x16_DUAL_TWIST_OFFSET);

  // Cooperative twiddle table load (64 threads × 15 iters = 960 double2's).
  double2 *tw_shared_w = reinterpret_cast<double2 *>(smem);
#pragma unroll
  for (int idx = threadIdx.x; idx < 15 * 64; idx += 64)
    tw_shared_w[idx] = tw_1024[idx >> 6][idx & 63];

  // Compact twiddles: 3 rows × 16 columns of (re, im).
  double *compact_twiddles_w = smem + FFT16x4x16_DUAL_COMPACT_TW_OFFSET;
  if (threadIdx.x < 48) {
    int r = threadIdx.x >> 4;
    int col = threadIdx.x & 15;
    int table_row = (r == 0) ? 7 : (r == 1) ? 3 : 11;
    double2 v = tw_1024[table_row][4 * col];
    compact_twiddles_w[r * 17 + col] = v.x;
    compact_twiddles_w[3 * 17 + r * 17 + col] = v.y;
  }

  // Negacyclic twist half-table (513 entries; reflection recovers k > 512).
  for (int idx = threadIdx.x; idx < 512; idx += 64)
    smem_twist[idx] = twisting_twiddles[idx];
  if (threadIdx.x == 0)
    smem_twist[512] = twisting_twiddles[512];

  __syncthreads();

  // Register-cached twiddles — same preload the PBS kernel performs.
  const double2 tw_cache_r7 = tw_shared[7 * 64 + threadIdx.x];
  const double2 tw_cache_r3 = tw_shared[3 * 64 + threadIdx.x];
  const double2 tw_cache_r11 = tw_shared[11 * 64 + threadIdx.x];
  const double2 tw_cache_r1 = tw_shared[1 * 64 + threadIdx.x];
  const int lo4 = threadIdx.x & 15;
  double2 compact_w1 =
      make_double2(compact_twiddles[lo4], compact_twiddles[3 * 17 + lo4]);
  double2 compact_w2 = make_double2(compact_twiddles[17 + lo4],
                                    compact_twiddles[3 * 17 + 17 + lo4]);
  double2 compact_w3 = make_double2(compact_twiddles[34 + lo4],
                                    compact_twiddles[3 * 17 + 34 + lo4]);

  constexpr int half_degree = params::degree / 2; // 1024
  double2 a[16];
  double2 b[16];
#pragma unroll
  for (int j = 0; j < 16; j++) {
    a[j] = d_input1[blockIdx.x * half_degree + threadIdx.x + j * 64];
    b[j] = d_input2[blockIdx.x * half_degree + threadIdx.x + j * 64];
  }

  // Forward FFT (fused pre-twist) on both operands.
  FFT16x4x16_fwd_optimized_for_pbs(a, tw_shared, smem_twist, smem_xpose,
                                   smem_xpose_pong, compact_w1, compact_w2,
                                   compact_w3, tw_cache_r7, tw_cache_r3,
                                   tw_cache_r11, tw_cache_r1);
  FFT16x4x16_fwd_optimized_for_pbs(b, tw_shared, smem_twist, smem_xpose,
                                   smem_xpose_pong, compact_w1, compact_w2,
                                   compact_w3, tw_cache_r7, tw_cache_r3,
                                   tw_cache_r11, tw_cache_r1);

  // Pointwise product in matching bit-reversed layout, fold in 1/N.
  constexpr double inv_n = 1.0 / 1024.0;
  double2 prod[16];
#pragma unroll
  for (int j = 0; j < 16; j++)
    prod[j] = (a[j] * b[j]) * inv_n;

  // Inverse core expects natural-order input → unscramble once.
  double2 nat[16];
#pragma unroll
  for (int j = 0; j < 16; j++)
    nat[j] = prod[bitreversal16(j)];

  FFT16x4x16_inv_optimized_for_pbs(nat, tw_shared, smem_twist, smem_xpose,
                                   smem_xpose_pong, compact_w1, compact_w2,
                                   compact_w3, tw_cache_r7, tw_cache_r3,
                                   tw_cache_r11, tw_cache_r1);

#pragma unroll
  for (int j = 0; j < 16; j++) {
    int k = bitreversal16(j);
    d_output[blockIdx.x * half_degree + threadIdx.x + k * 64] = nat[j];
  }
}

#endif // GPU_BOOTSTRAP_FFT_CUH
