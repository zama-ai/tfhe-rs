#ifndef GPU_BOOTSTRAP_FFT_CUH
#define GPU_BOOTSTRAP_FFT_CUH

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
 * unrolling half size fft result in half size + 1 elements
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
 * unrolling half size fft result in half size + 1 elements
 * this function must be called with actual degree
 * function takes as input already compressed input
 */
template <class params, sharedMemDegree SMD>
__global__ void batch_NSMFFT_classical_specialized(double2 *d_input,
                                                   double2 *d_output,
                                                   double2 *buffer) {
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

#endif // GPU_BOOTSTRAP_FFT_CUH
