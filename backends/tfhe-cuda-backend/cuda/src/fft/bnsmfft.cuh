#ifndef GPU_BOOTSTRAP_FFT_CUH
#define GPU_BOOTSTRAP_FFT_CUH

#include "polynomial/functions.cuh"
#include "polynomial/parameters.cuh"
#include "twiddles.cuh"
#include "types/complex/operations.cuh"

using Index = unsigned;

constexpr inline Index warpsize() { return 32; }

template <Index SIZE> __device__ inline void sync_fft_step() {
  if constexpr (SIZE < warpsize()) {
    __syncwarp();
  } else {
    __syncthreads();
  }
}

__device__ constexpr bool coalesce_mem_access() { return false; }

__device__ inline void direct_butterfly(double2 *a0, double2 *a1, double2 w) {
  double2 b0 = *a0;
  double2 b1 = *a1 * w;

  *a0 = b0 + b1;
  *a1 = b0 - b1;
}

__device__ inline void inverse_butterfly(double2 *a0, double2 *a1, double2 w) {
  double2 b0 = *a0 + *a1;
  double2 b1 = *a0 - *a1;

  *a0 = b0;
  *a1 = mul_conj(b1, w);
}

template <Index M, Index T>
__device__ inline void NSMFFT_direct_2warpsize(double2 *a0, double2 *a1,
                                               Index const tid) {
  if constexpr (T > 0) {
    if constexpr (T < warpsize()) {
      // thread 0:
      // a0: 0 * T
      // a1: 2 * T
      // thread 1:
      // a0: 1 * T
      // a1: 3 * T

      bool is_lower = ((tid >> tfhe_log2(T)) & 1) == 0;
      double2 tmp = is_lower ? *a1 : *a0;
      // thread 0:
      // tmp: 2 * T
      // thread 1:
      // tmp: 1 * T

      tmp.x = __shfl_xor_sync(0xFFFFFFFF, tmp.x, T, 2 * T);
      tmp.y = __shfl_xor_sync(0xFFFFFFFF, tmp.y, T, 2 * T);
      // thread 0:
      // tmp: 1 * T
      // thread 1:
      // tmp: 2 * T

      *a0 = is_lower ? *a0 : tmp;
      *a1 = is_lower ? tmp : *a1;

      // thread 0:
      // a0: 0 * T
      // a1: 1 * T
      // thread 1:
      // a0: 2 * T
      // a1: 3 * T
    }
    double2 w1 = negtwiddles[M + (tid / T)];
    direct_butterfly(a0, a1, w1);
    NSMFFT_direct_2warpsize<M * 2, T / 2>(a0, a1, tid);
  }
}

template <Index M, Index T>
__device__ inline void NSMFFT_inverse_2warpsize(double2 *a0, double2 *a1,
                                                Index const tid) {
  if constexpr (T > 0) {
    NSMFFT_inverse_2warpsize<M * 2, T / 2>(a0, a1, tid);
    double2 w1 = negtwiddles[M + (tid / T)];
    inverse_butterfly(a0, a1, w1);

    if constexpr (T < warpsize()) {
      // thread 0:
      // a0: 0 * T
      // a1: 1 * T
      // thread 1:
      // a0: 2 * T
      // a1: 3 * T

      bool is_lower = ((tid >> tfhe_log2(T)) & 1) == 0;
      double2 tmp = is_lower ? *a1 : *a0;
      // thread 0:
      // tmp: 1 * T
      // thread 1:
      // tmp: 2 * T

      tmp.x = __shfl_xor_sync(0xFFFFFFFF, tmp.x, T, 2 * T);
      tmp.y = __shfl_xor_sync(0xFFFFFFFF, tmp.y, T, 2 * T);
      // thread 0:
      // tmp: 2 * T
      // thread 1:
      // tmp: 1 * T

      *a0 = is_lower ? *a0 : tmp;
      *a1 = is_lower ? tmp : *a1;

      // thread 0:
      // a0: 0 * T
      // a1: 2 * T
      // thread 1:
      // a0: 1 * T
      // a1: 3 * T
    }
  }
}

template <Index RADIX, Index DEGREE, Index M>
__device__ inline void NSMFFT_direct_step(double2 *A, Index const tid) {
  constexpr Index SIZE = DEGREE / M;
  constexpr Index T = SIZE / RADIX;

  Index i;
  double2 w1;

  if constexpr (M == 1) {
    i = 0;
    w1 = (double2){
        0.707106781186547461715008466854,
        0.707106781186547461715008466854,
    };
  } else {
    i = tid / T;
    w1 = negtwiddles[M + i];
  }

  Index j = i * SIZE + (tid % T);

  if constexpr (RADIX == 4) {
    double2 w2 = negtwiddles[2 * (M + i) + 0];
    double2 w3 = negtwiddles[2 * (M + i) + 1];

    Index j0 = j + 0 * T;
    Index j1 = j + 1 * T;
    Index j2 = j + 2 * T;
    Index j3 = j + 3 * T;

    double2 a0 = A[j0];
    double2 a1 = A[j1];
    double2 a2 = A[j2];
    double2 a3 = A[j3];

    direct_butterfly(&a0, &a2, w1);
    direct_butterfly(&a1, &a3, w1);
    direct_butterfly(&a0, &a1, w2);
    direct_butterfly(&a2, &a3, w3);

    A[j0] = a0;
    A[j1] = a1;
    A[j2] = a2;
    A[j3] = a3;
  } else if constexpr (RADIX == 2) {
    Index j0 = j + 0 * T;
    Index j1 = j + 1 * T;

    double2 a0 = A[j0];
    double2 a1 = A[j1];

    direct_butterfly(&a0, &a1, w1);

    A[j0] = a0;
    A[j1] = a1;
  }
}

template <Index RADIX, Index DEGREE, Index M>
__device__ inline void NSMFFT_inverse_step(double2 *A, Index const tid) {
  constexpr Index SIZE = DEGREE / M;
  constexpr Index T = SIZE / RADIX;

  Index i;
  double2 w1;

  if constexpr (M == 1) {
    i = 0;
    w1 = (double2){
        0.707106781186547461715008466854,
        0.707106781186547461715008466854,
    };
  } else {
    i = tid / T;
    w1 = negtwiddles[M + i];
  }

  Index j = i * SIZE + (tid % T);

  if constexpr (RADIX == 4) {
    double2 w2 = negtwiddles[2 * (M + i) + 0];
    double2 w3 = negtwiddles[2 * (M + i) + 1];

    Index j0 = j + 0 * T;
    Index j1 = j + 1 * T;
    Index j2 = j + 2 * T;
    Index j3 = j + 3 * T;

    double2 a0 = A[j0];
    double2 a1 = A[j1];
    double2 a2 = A[j2];
    double2 a3 = A[j3];

    if constexpr (M == 1) {
      a0 *= 1.0 / double(DEGREE);
      a1 *= 1.0 / double(DEGREE);
      a2 *= 1.0 / double(DEGREE);
      a3 *= 1.0 / double(DEGREE);
    }

    inverse_butterfly(&a0, &a1, w2);
    inverse_butterfly(&a2, &a3, w3);
    inverse_butterfly(&a0, &a2, w1);
    inverse_butterfly(&a1, &a3, w1);

    A[j0] = a0;
    A[j1] = a1;
    A[j2] = a2;
    A[j3] = a3;
  } else if constexpr (RADIX == 2) {
    Index j0 = j + 0 * T;
    Index j1 = j + 1 * T;

    double2 a0 = A[j0];
    double2 a1 = A[j1];

    if constexpr (M == 1) {
      a0 *= 1.0 / double(DEGREE);
      a1 *= 1.0 / double(DEGREE);
    }

    inverse_butterfly(&a0, &a1, w1);

    A[j0] = a0;
    A[j1] = a1;
  }
}

template <Index RADIX, Index DEGREE, Index OPT, Index M>
__device__ inline void NSMFFT_direct_impl(double2 *A, Index const tid) {
  static_assert(OPT >= RADIX,
                "params::opt should be larger than or equal to the fft radix");

  constexpr Index SIZE = DEGREE / M;

  if constexpr (coalesce_mem_access()) {
    constexpr Index WARPSIZE = warpsize();

    if constexpr (SIZE >= 2 * WARPSIZE) {
      constexpr Index radix = (SIZE == 2 * WARPSIZE)                   ? 2
                              : ((SIZE / (2 * WARPSIZE)) % RADIX != 0) ? 2
                                                                       : RADIX;

      __syncthreads();

#pragma unroll
      for (Index k = 0; k < OPT / radix; ++k) {
        if constexpr (SIZE == 2 * WARPSIZE) {
          static_assert(radix == 2, "");

          Index i = tid / WARPSIZE;
          Index j = i * SIZE + (tid % WARPSIZE);
          Index j0 = j + 0 * WARPSIZE;
          Index j1 = j + 1 * WARPSIZE;

          double2 a0 = A[j0];
          double2 a1 = A[j1];
          NSMFFT_direct_2warpsize<M, WARPSIZE>(&a0, &a1, tid);
          A[j0] = a0;
          A[j1] = a1;
        } else {
          static_assert(SIZE > 2 * WARPSIZE, "");
          NSMFFT_direct_step<radix, DEGREE, M>(A, tid + k * (DEGREE / OPT));
        }
      }

      NSMFFT_direct_impl<RADIX, DEGREE, OPT, radix * M>(A, tid);
    }
  } else {
    if constexpr (SIZE > 1) {
      constexpr Index radix = (SIZE % RADIX != 0) ? 2 : RADIX;
      sync_fft_step<SIZE>();

#pragma unroll
      for (Index k = 0; k < OPT / radix; ++k) {
        NSMFFT_direct_step<radix, DEGREE, M>(A, tid + k * (DEGREE / OPT));
      }

      NSMFFT_direct_impl<RADIX, DEGREE, OPT, radix * M>(A, tid);
    }
  }
}

template <Index RADIX, Index DEGREE, Index OPT, Index M>
__device__ inline void NSMFFT_inverse_impl(double2 *A, Index const tid) {
  static_assert(OPT >= RADIX,
                "params::opt should be larger than or equal to the fft radix");

  constexpr Index SIZE = DEGREE / M;

  if constexpr (coalesce_mem_access()) {
    constexpr Index WARPSIZE = warpsize();

    if constexpr (SIZE >= 2 * WARPSIZE) {
      constexpr Index radix = (SIZE == 2 * WARPSIZE)                   ? 2
                              : ((SIZE / (2 * WARPSIZE)) % RADIX != 0) ? 2
                                                                       : RADIX;

      NSMFFT_inverse_impl<RADIX, DEGREE, OPT, radix * M>(A, tid);

#pragma unroll
      for (Index k = 0; k < OPT / radix; ++k) {
        if constexpr (SIZE == 2 * WARPSIZE) {
          static_assert(radix == 2, "");

          Index i = tid / WARPSIZE;
          Index j = i * SIZE + (tid % WARPSIZE);
          Index j0 = j + 0 * WARPSIZE;
          Index j1 = j + 1 * WARPSIZE;

          double2 a0 = A[j0];
          double2 a1 = A[j1];
          NSMFFT_inverse_2warpsize<M, WARPSIZE>(&a0, &a1, tid);
          A[j0] = a0;
          A[j1] = a1;
        } else {
          static_assert(SIZE > 2 * WARPSIZE, "");
          NSMFFT_inverse_step<radix, DEGREE, M>(A, tid + k * (DEGREE / OPT));
        }
      }

      __syncthreads();
    }
  } else {
    if constexpr (SIZE > 1) {
      constexpr Index radix = (SIZE % RADIX != 0) ? 2 : RADIX;

      NSMFFT_inverse_impl<RADIX, DEGREE, OPT, radix * M>(A, tid);

#pragma unroll
      for (Index k = 0; k < OPT / radix; ++k) {
        NSMFFT_inverse_step<radix, DEGREE, M>(A, tid + k * (DEGREE / OPT));
      }

      sync_fft_step<SIZE>();
    }
  }
}

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
template <class params, int radix = tfhe_fft_default_radix()>
__device__ void NSMFFT_direct(double2 *A) {
  NSMFFT_direct_impl<radix, params::degree, params::opt, 1>(A, threadIdx.x);
  __syncthreads();
}

/*
 * negacyclic inverse fft
 */
template <class params, int radix = tfhe_fft_default_radix()>
__device__ void NSMFFT_inverse(double2 *A) {
  __syncthreads();
  NSMFFT_inverse_impl<radix, params::degree, params::opt, 1>(A, threadIdx.x);
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
