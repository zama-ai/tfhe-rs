#ifndef GPU_BOOTSTRAP_FFT_CUH
#define GPU_BOOTSTRAP_FFT_CUH

#include "fft/fft16x16x4.cuh"
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

// Block startup shared by the key conversion and the test kernels, as in the
// PBS kernel: folded twiddles in shared memory, roots and rows in registers.
struct fft16x16x4_block_context {
  const double2 *tw;
  double *xpose, *xpose_other, *xpose_pong, *xpose0_pong, *xpose1_pong;
  double2 small_w[6];
  double2 r0, r7, r3, r11, r1;
};

static __device__ __forceinline__ void
fft16x16x4_block_setup(double *smem, fft16x16x4_block_context &c) {
  double *xpose0 = smem + FFT16x16x4_DUAL_XPOSE0_OFFSET;
  double *xpose1 = smem + FFT16x16x4_DUAL_XPOSE1_OFFSET;
  c.tw = reinterpret_cast<const double2 *>(smem);
  c.xpose0_pong = smem + FFT16x16x4_DUAL_XPOSE0_PONG_OFFSET;
  c.xpose1_pong = smem + FFT16x16x4_DUAL_XPOSE1_PONG_OFFSET;
  c.xpose = threadIdx.y == 0 ? xpose0 : xpose1;
  c.xpose_other = threadIdx.y == 0 ? xpose1 : xpose0;
  c.xpose_pong = threadIdx.y == 0 ? c.xpose0_pong : c.xpose1_pong;

  fft16x16x4_load_shared_twiddles_folded_128t(smem);
  __syncthreads();
  fft16x16x4_load_small_twiddles(c.small_w);
  c.r0 = conjugate(twisting_twiddles[threadIdx.x]);
  c.r7 = c.tw[7 * 64 + threadIdx.x];
  c.r3 = c.tw[3 * 64 + threadIdx.x];
  c.r11 = c.tw[11 * 64 + threadIdx.x];
  c.r1 = c.tw[1 * 64 + threadIdx.x];
}

// Bootstrapping-key forward transform of the specialized 2_2 path: the paired
// FFT16x16x4 forward of the PBS kernel, run on pairs of key polynomials, with
// the spectra stored in the slot order the PBS kernel reads them back.
//
// Layout
//   After the paired forward, register j of thread (tid, y) holds, for both
//   polynomials of the pair, the frequency the PBS kernel consumes from slot
//   tid + 64*(j + 8*y) of its key slice (see fft16x16x4.cuh). Storing register
//   j (polynomial 0) and register 8 + j (polynomial 1) at that slot pairs
//   identical frequencies in the GGSW product without any permutation.
//
//   The spectra carry the 1/N of the inverse transform (N = 1024), which the
//   PBS inverse path does not apply itself.
//
// One (64, 2, 1) block per pair of polynomials (so the count must be even),
// FFT16x16x4_DUAL_SMEM_BYTES of shared memory.
template <class params>
__global__ void
batch_FFT16x16x4_classical_2_2_specialized(const double2 *__restrict__ d_input,
                                           double2 *__restrict__ d_output) {
  extern __shared__ int8_t batch_fft16x16x4_bsk_sharedmem[];
  double *smem = reinterpret_cast<double *>(batch_fft16x16x4_bsk_sharedmem);
  fft16x16x4_block_context c;
  fft16x16x4_block_setup(smem, c);

  constexpr int half_degree = params::degree / 2; // 1024
  const double2 *in =
      d_input + (2 * blockIdx.x + threadIdx.y) * half_degree; // own polynomial
  double2 *out0 = d_output + (2 * blockIdx.x) * half_degree;
  double2 *out1 = out0 + half_degree;

  double2 a[16];
#pragma unroll
  for (int j = 0; j < 16; j++)
    a[j] = in[threadIdx.x + j * 64];

  FFT16x16x4_fwd_paired_for_pbs(a, c.tw, c.r0, c.xpose, c.xpose_pong,
                                c.xpose0_pong, c.xpose1_pong, c.small_w, c.r7,
                                c.r3, c.r11, c.r1);

  constexpr double inv_n = 1.0 / 1024.0;
  const int slot = threadIdx.x + 64 * 8 * threadIdx.y;
#pragma unroll
  for (int j = 0; j < 8; j++) {
    out0[slot + 64 * j] = a[j] * inv_n;
    out1[slot + 64 * j] = a[8 + j] * inv_n;
  }
}

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

// Test-only kernels for the paired FFT16x16x4 transforms: PBS block shape
// (64, 2, 1), group y owns polynomial 2*blockIdx.x + y, no 1/N applied.

// Natural-order frequency held by thread T in register 4*h + v.
static __device__ __forceinline__ int fft16x16x4_paired_frequency(int T, int h,
                                                                  int v) {
  return T + 128 * h + 256 * bitreversal4(v);
}

// Forward paired transform of polynomials 2*blockIdx.x and 2*blockIdx.x + 1.
// Input: natural time order, element i of a polynomial at slot i of its
// N/2-slot block. Output: natural frequency order, same slotting.
template <class params>
__global__ void batch_forward_fft16x16x4(const double2 *__restrict__ d_input,
                                         double2 *__restrict__ d_output) {
  extern __shared__ int8_t batch_fft16x16x4_fwd_sharedmem[];
  double *smem = reinterpret_cast<double *>(batch_fft16x16x4_fwd_sharedmem);
  fft16x16x4_block_context c;
  fft16x16x4_block_setup(smem, c);

  constexpr int half_degree = params::degree / 2; // 1024
  const int T = threadIdx.x + 64 * threadIdx.y;
  const double2 *in =
      d_input + (2 * blockIdx.x + threadIdx.y) * half_degree; // own polynomial
  double2 *out0 = d_output + (2 * blockIdx.x) * half_degree;
  double2 *out1 = out0 + half_degree;

  double2 a[16];
#pragma unroll
  for (int j = 0; j < 16; j++)
    a[j] = in[threadIdx.x + j * 64];

  FFT16x16x4_fwd_paired_for_pbs(a, c.tw, c.r0, c.xpose, c.xpose_pong,
                                c.xpose0_pong, c.xpose1_pong, c.small_w, c.r7,
                                c.r3, c.r11, c.r1);

  // Paired layout: a[0..7] holds polynomial 0, a[8..15] polynomial 1.
#pragma unroll
  for (int h = 0; h < 2; h++) {
#pragma unroll
    for (int v = 0; v < 4; v++) {
      const int f = fft16x16x4_paired_frequency(T, h, v);
      out0[f] = a[4 * h + v];
      out1[f] = a[8 + 4 * h + v];
    }
  }
}

// Inverse paired transform, the clean inverse of batch_forward_fft16x16x4:
// natural-order spectra of polynomials 2*blockIdx.x and 2*blockIdx.x + 1 in,
// natural time order out, no 1/N.
template <class params>
__global__ void batch_backward_fft16x16x4(const double2 *__restrict__ d_input,
                                          double2 *__restrict__ d_output) {
  extern __shared__ int8_t batch_fft16x16x4_inv_sharedmem[];
  double *smem = reinterpret_cast<double *>(batch_fft16x16x4_inv_sharedmem);
  fft16x16x4_block_context c;
  fft16x16x4_block_setup(smem, c);

  constexpr int half_degree = params::degree / 2; // 1024
  const int T = threadIdx.x + 64 * threadIdx.y;
  // The inverse wants the paired layout owner-relative: this group's
  // polynomial in the first register half, the other group's in the second.
  const double2 *in_own =
      d_input + (2 * blockIdx.x + threadIdx.y) * half_degree;
  const double2 *in_other =
      d_input + (2 * blockIdx.x + 1 - threadIdx.y) * half_degree;
  double2 *out = d_output + (2 * blockIdx.x + threadIdx.y) * half_degree;

  double2 a[16];
#pragma unroll
  for (int h = 0; h < 2; h++) {
#pragma unroll
    for (int v = 0; v < 4; v++) {
      const int f = fft16x16x4_paired_frequency(T, h, v);
      a[4 * h + v] = in_own[f];
      a[8 + 4 * h + v] = in_other[f];
    }
  }

  FFT16x16x4_inv_paired_for_pbs(a, c.tw, c.r0, c.xpose, c.xpose_other,
                                c.xpose_pong, c.small_w, c.r7, c.r3, c.r11,
                                c.r1);

  // Register j holds time position bitreversal16(j)*64 + tid of this group's
  // polynomial.
#pragma unroll
  for (int j = 0; j < 16; j++)
    out[bitreversal16(j) * 64 + threadIdx.x] = a[j];
}

// Negacyclic polynomial multiplication through the paired transforms, the data
// flow of the PBS external product: both inputs forward, pointwise product in
// registers (with the 1/N of the inverse), inverse back to each group's own
// polynomial. Polynomial p of d_input1 is multiplied by polynomial p of
// d_input2, two pairs per block. d_output may alias d_input2 (the test
// multiplies in place), so neither of those carries __restrict__.
template <class params>
__global__ void
batch_polynomial_mul_fft16x16x4(const double2 *__restrict__ d_input1,
                                const double2 *d_input2, double2 *d_output) {
  extern __shared__ int8_t batch_fft16x16x4_mul_sharedmem[];
  double *smem = reinterpret_cast<double *>(batch_fft16x16x4_mul_sharedmem);
  fft16x16x4_block_context c;
  fft16x16x4_block_setup(smem, c);

  constexpr int half_degree = params::degree / 2; // 1024
  const int own = (2 * blockIdx.x + threadIdx.y) * half_degree;
  const double2 *in1 = d_input1 + own;
  const double2 *in2 = d_input2 + own;
  double2 *out = d_output + own;

  double2 a[16];
  double2 b[16];
#pragma unroll
  for (int j = 0; j < 16; j++) {
    a[j] = in1[threadIdx.x + j * 64];
    b[j] = in2[threadIdx.x + j * 64];
  }

  FFT16x16x4_fwd_paired_for_pbs(a, c.tw, c.r0, c.xpose, c.xpose_pong,
                                c.xpose0_pong, c.xpose1_pong, c.small_w, c.r7,
                                c.r3, c.r11, c.r1);
  // The second transform rewrites the pong regions both groups just read.
  __syncthreads();
  FFT16x16x4_fwd_paired_for_pbs(b, c.tw, c.r0, c.xpose, c.xpose_pong,
                                c.xpose0_pong, c.xpose1_pong, c.small_w, c.r7,
                                c.r3, c.r11, c.r1);

  // Owner-relative layout for the inverse: group 1 takes the second half first.
  // The condition is uniform within a group, so the warps stay converged.
  constexpr double inv_n = 1.0 / 1024.0;
  double2 prod[16];
#pragma unroll
  for (int j = 0; j < 16; j++)
    prod[j] = (a[j] * b[j]) * inv_n;
  double2 r[16];
  if (threadIdx.y == 0) {
#pragma unroll
    for (int j = 0; j < 16; j++)
      r[j] = prod[j];
  } else {
#pragma unroll
    for (int j = 0; j < 8; j++) {
      r[j] = prod[8 + j];
      r[8 + j] = prod[j];
    }
  }

  FFT16x16x4_inv_paired_for_pbs(r, c.tw, c.r0, c.xpose, c.xpose_other,
                                c.xpose_pong, c.small_w, c.r7, c.r3, c.r11,
                                c.r1);

#pragma unroll
  for (int j = 0; j < 16; j++)
    out[bitreversal16(j) * 64 + threadIdx.x] = r[j];
}

#endif // GPU_BOOTSTRAP_FFT_CUH
