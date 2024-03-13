#ifndef GPU_BOOTSTRAP_FFT_CUH
#define GPU_BOOTSTRAP_FFT_CUH

#include "polynomial/functions.cuh"
#include "polynomial/parameters.cuh"
#include "twiddles.cuh"
#include "types/complex/operations.cuh"

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

  size_t tid = threadIdx.x;
  size_t twid_id;
  size_t i1, i2;
  double2 u, v, w;
  // level 1
  // we don't make actual complex multiplication on level1 since we have only
  // one twiddle, it's real and image parts are equal, so we can multiply
  // it with simpler operations
#pragma unroll
  for (size_t i = 0; i < params::opt / 2; ++i) {
    i1 = tid;
    i2 = tid + params::degree / 2;

    u = A[i1];
    v = A[i2] * (double2){0.707106781186547461715008466854,
                          0.707106781186547461715008466854};

    A[i1] += v;
    A[i2] = u - v;

    tid += params::degree / params::opt;
  }
  __syncthreads();

  // level 2
  // from this level there are more than one twiddles and none of them has equal
  // real and imag parts, so complete complex multiplication is needed
  // for each level params::degree / 2^level represents number of coefficients
  // inside divided chunk of specific level
  //
  tid = threadIdx.x;
#pragma unroll
  for (size_t i = 0; i < params::opt / 2; ++i) {
    twid_id = tid / (params::degree / 4);
    i1 = 2 * (params::degree / 4) * twid_id + (tid & (params::degree / 4 - 1));
    i2 = i1 + params::degree / 4;

    w = negtwiddles[twid_id + 2];
    u = A[i1];
    v = A[i2] * w;

    A[i1] += v;
    A[i2] = u - v;

    tid += params::degree / params::opt;
  }
  __syncthreads();

  // level 3
  tid = threadIdx.x;
#pragma unroll
  for (size_t i = 0; i < params::opt / 2; ++i) {
    twid_id = tid / (params::degree / 8);
    i1 = 2 * (params::degree / 8) * twid_id + (tid & (params::degree / 8 - 1));
    i2 = i1 + params::degree / 8;

    w = negtwiddles[twid_id + 4];
    u = A[i1];
    v = A[i2] * w;

    A[i1] += v;
    A[i2] = u - v;

    tid += params::degree / params::opt;
  }
  __syncthreads();

  // level 4
  tid = threadIdx.x;
#pragma unroll
  for (size_t i = 0; i < params::opt / 2; ++i) {
    twid_id = tid / (params::degree / 16);
    i1 =
        2 * (params::degree / 16) * twid_id + (tid & (params::degree / 16 - 1));
    i2 = i1 + params::degree / 16;

    w = negtwiddles[twid_id + 8];
    u = A[i1];
    v = A[i2] * w;

    A[i1] += v;
    A[i2] = u - v;

    tid += params::degree / params::opt;
  }
  __syncthreads();

  // level 5
  tid = threadIdx.x;
#pragma unroll
  for (size_t i = 0; i < params::opt / 2; ++i) {
    twid_id = tid / (params::degree / 32);
    i1 =
        2 * (params::degree / 32) * twid_id + (tid & (params::degree / 32 - 1));
    i2 = i1 + params::degree / 32;

    w = negtwiddles[twid_id + 16];
    u = A[i1];
    v = A[i2] * w;

    A[i1] += v;
    A[i2] = u - v;

    tid += params::degree / params::opt;
  }
  __syncthreads();

  // level 6
  tid = threadIdx.x;
#pragma unroll
  for (size_t i = 0; i < params::opt / 2; ++i) {
    twid_id = tid / (params::degree / 64);
    i1 =
        2 * (params::degree / 64) * twid_id + (tid & (params::degree / 64 - 1));
    i2 = i1 + params::degree / 64;

    w = negtwiddles[twid_id + 32];
    u = A[i1];
    v = A[i2] * w;

    A[i1] += v;
    A[i2] = u - v;

    tid += params::degree / params::opt;
  }
  __syncthreads();

  // level 7
  tid = threadIdx.x;
#pragma unroll
  for (size_t i = 0; i < params::opt / 2; ++i) {
    twid_id = tid / (params::degree / 128);
    i1 = 2 * (params::degree / 128) * twid_id +
         (tid & (params::degree / 128 - 1));
    i2 = i1 + params::degree / 128;

    w = negtwiddles[twid_id + 64];
    u = A[i1];
    v = A[i2] * w;

    A[i1] += v;
    A[i2] = u - v;

    tid += params::degree / params::opt;
  }
  __syncthreads();

  // from level 8, we need to check size of params degree, because we support
  // minimum actual polynomial size = 256,  when compressed size is halfed and
  // minimum supported compressed size is 128, so we always need first 7
  // levels of butterfly operation, since butterfly levels are hardcoded
  // we need to check if polynomial size is big enough to require specific level
  // of butterfly.
  if constexpr (params::degree >= 256) {
    // level 8
    tid = threadIdx.x;
#pragma unroll
    for (size_t i = 0; i < params::opt / 2; ++i) {
      twid_id = tid / (params::degree / 256);
      i1 = 2 * (params::degree / 256) * twid_id +
           (tid & (params::degree / 256 - 1));
      i2 = i1 + params::degree / 256;

      w = negtwiddles[twid_id + 128];
      u = A[i1];
      v = A[i2] * w;

      A[i1] += v;
      A[i2] = u - v;

      tid += params::degree / params::opt;
    }
    __syncthreads();
  }

  if constexpr (params::degree >= 512) {
    // level 9
    tid = threadIdx.x;
#pragma unroll
    for (size_t i = 0; i < params::opt / 2; ++i) {
      twid_id = tid / (params::degree / 512);
      i1 = 2 * (params::degree / 512) * twid_id +
           (tid & (params::degree / 512 - 1));
      i2 = i1 + params::degree / 512;

      w = negtwiddles[twid_id + 256];
      u = A[i1];
      v = A[i2] * w;

      A[i1] += v;
      A[i2] = u - v;

      tid += params::degree / params::opt;
    }
    __syncthreads();
  }

  if constexpr (params::degree >= 1024) {
    // level 10
    tid = threadIdx.x;
#pragma unroll
    for (size_t i = 0; i < params::opt / 2; ++i) {
      twid_id = tid / (params::degree / 1024);
      i1 = 2 * (params::degree / 1024) * twid_id +
           (tid & (params::degree / 1024 - 1));
      i2 = i1 + params::degree / 1024;

      w = negtwiddles[twid_id + 512];
      u = A[i1];
      v = A[i2] * w;

      A[i1] += v;
      A[i2] = u - v;

      tid += params::degree / params::opt;
    }
    __syncthreads();
  }

  if constexpr (params::degree >= 2048) {
    // level 11
    tid = threadIdx.x;
#pragma unroll
    for (size_t i = 0; i < params::opt / 2; ++i) {
      twid_id = tid / (params::degree / 2048);
      i1 = 2 * (params::degree / 2048) * twid_id +
           (tid & (params::degree / 2048 - 1));
      i2 = i1 + params::degree / 2048;

      w = negtwiddles[twid_id + 1024];
      u = A[i1];
      v = A[i2] * w;

      A[i1] += v;
      A[i2] = u - v;

      tid += params::degree / params::opt;
    }
    __syncthreads();
  }

  if constexpr (params::degree >= 4096) {
    // level 12
    tid = threadIdx.x;
#pragma unroll
    for (size_t i = 0; i < params::opt / 2; ++i) {
      twid_id = tid / (params::degree / 4096);
      i1 = 2 * (params::degree / 4096) * twid_id +
           (tid & (params::degree / 4096 - 1));
      i2 = i1 + params::degree / 4096;

      w = negtwiddles[twid_id + 2048];
      u = A[i1];
      v = A[i2] * w;

      A[i1] += v;
      A[i2] = u - v;

      tid += params::degree / params::opt;
    }
    __syncthreads();
  }

  // compressed size = 8192 is actual polynomial size = 16384.
  // from this size, twiddles can't fit in constant memory,
  // so from here, butterfly operation access device memory.
  if constexpr (params::degree >= 8192) {
    // level 13
    tid = threadIdx.x;
#pragma unroll
    for (size_t i = 0; i < params::opt / 2; ++i) {
      twid_id = tid / (params::degree / 8192);
      i1 = 2 * (params::degree / 8192) * twid_id +
           (tid & (params::degree / 8192 - 1));
      i2 = i1 + params::degree / 8192;

      w = negtwiddles13[twid_id];
      u = A[i1];
      v = A[i2] * w;

      A[i1] += v;
      A[i2] = u - v;

      tid += params::degree / params::opt;
    }
    __syncthreads();
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

  size_t tid = threadIdx.x;
  size_t twid_id;
  size_t i1, i2;
  double2 u, w;

  // divide input by compressed polynomial size
  tid = threadIdx.x;
  for (size_t i = 0; i < params::opt; ++i) {
    A[tid] /= params::degree;
    tid += params::degree / params::opt;
  }
  __syncthreads();

  // none of the twiddles have equal real and imag part, so
  // complete complex multiplication has to be done
  // here we have more than one twiddle
  // mapping in backward fft is reversed
  // butterfly operation is started from last level

  // compressed size = 8192 is actual polynomial size = 16384.
  // twiddles for this size can't fit in constant memory so
  // butterfly operation for this level access device memory to fetch
  // twiddles
  if constexpr (params::degree >= 8192) {
    // level 13
    tid = threadIdx.x;
#pragma unroll
    for (size_t i = 0; i < params::opt / 2; ++i) {
      twid_id = tid / (params::degree / 8192);
      i1 = 2 * (params::degree / 8192) * twid_id +
           (tid & (params::degree / 8192 - 1));
      i2 = i1 + params::degree / 8192;

      w = negtwiddles13[twid_id];
      u = A[i1] - A[i2];

      A[i1] += A[i2];
      A[i2] = u * conjugate(w);

      tid += params::degree / params::opt;
    }
    __syncthreads();
  }

  if constexpr (params::degree >= 4096) {
    // level 12
    tid = threadIdx.x;
#pragma unroll
    for (size_t i = 0; i < params::opt / 2; ++i) {
      twid_id = tid / (params::degree / 4096);
      i1 = 2 * (params::degree / 4096) * twid_id +
           (tid & (params::degree / 4096 - 1));
      i2 = i1 + params::degree / 4096;

      w = negtwiddles[twid_id + 2048];
      u = A[i1] - A[i2];

      A[i1] += A[i2];
      A[i2] = u * conjugate(w);

      tid += params::degree / params::opt;
    }
    __syncthreads();
  }

  if constexpr (params::degree >= 2048) {
    // level 11
    tid = threadIdx.x;
#pragma unroll
    for (size_t i = 0; i < params::opt / 2; ++i) {
      twid_id = tid / (params::degree / 2048);
      i1 = 2 * (params::degree / 2048) * twid_id +
           (tid & (params::degree / 2048 - 1));
      i2 = i1 + params::degree / 2048;

      w = negtwiddles[twid_id + 1024];
      u = A[i1] - A[i2];

      A[i1] += A[i2];
      A[i2] = u * conjugate(w);

      tid += params::degree / params::opt;
    }
    __syncthreads();
  }

  if constexpr (params::degree >= 1024) {
    // level 10
    tid = threadIdx.x;
#pragma unroll
    for (size_t i = 0; i < params::opt / 2; ++i) {
      twid_id = tid / (params::degree / 1024);
      i1 = 2 * (params::degree / 1024) * twid_id +
           (tid & (params::degree / 1024 - 1));
      i2 = i1 + params::degree / 1024;

      w = negtwiddles[twid_id + 512];
      u = A[i1] - A[i2];

      A[i1] += A[i2];
      A[i2] = u * conjugate(w);

      tid += params::degree / params::opt;
    }
    __syncthreads();
  }

  if constexpr (params::degree >= 512) {
    // level 9
    tid = threadIdx.x;
#pragma unroll
    for (size_t i = 0; i < params::opt / 2; ++i) {
      twid_id = tid / (params::degree / 512);
      i1 = 2 * (params::degree / 512) * twid_id +
           (tid & (params::degree / 512 - 1));
      i2 = i1 + params::degree / 512;

      w = negtwiddles[twid_id + 256];
      u = A[i1] - A[i2];

      A[i1] += A[i2];
      A[i2] = u * conjugate(w);

      tid += params::degree / params::opt;
    }
    __syncthreads();
  }

  if constexpr (params::degree >= 256) {
    // level 8
    tid = threadIdx.x;
#pragma unroll
    for (size_t i = 0; i < params::opt / 2; ++i) {
      twid_id = tid / (params::degree / 256);
      i1 = 2 * (params::degree / 256) * twid_id +
           (tid & (params::degree / 256 - 1));
      i2 = i1 + params::degree / 256;

      w = negtwiddles[twid_id + 128];
      u = A[i1] - A[i2];

      A[i1] += A[i2];
      A[i2] = u * conjugate(w);

      tid += params::degree / params::opt;
    }
    __syncthreads();
  }

  // below level 8, we don't need to check size of params degree, because we
  // support minimum actual polynomial size = 256,  when compressed size is
  // halfed and minimum supported compressed size is 128, so we always need
  // last 7 levels of butterfly operation, since butterfly levels are hardcoded
  // we don't need to check if polynomial size is big enough to require
  // specific level of butterfly.
  // level 7
  tid = threadIdx.x;
#pragma unroll
  for (size_t i = 0; i < params::opt / 2; ++i) {
    twid_id = tid / (params::degree / 128);
    i1 = 2 * (params::degree / 128) * twid_id +
         (tid & (params::degree / 128 - 1));
    i2 = i1 + params::degree / 128;

    w = negtwiddles[twid_id + 64];
    u = A[i1] - A[i2];

    A[i1] += A[i2];
    A[i2] = u * conjugate(w);

    tid += params::degree / params::opt;
  }
  __syncthreads();

  // level 6
  tid = threadIdx.x;
#pragma unroll
  for (size_t i = 0; i < params::opt / 2; ++i) {
    twid_id = tid / (params::degree / 64);
    i1 =
        2 * (params::degree / 64) * twid_id + (tid & (params::degree / 64 - 1));
    i2 = i1 + params::degree / 64;

    w = negtwiddles[twid_id + 32];
    u = A[i1] - A[i2];

    A[i1] += A[i2];
    A[i2] = u * conjugate(w);

    tid += params::degree / params::opt;
  }
  __syncthreads();

  // level 5
  tid = threadIdx.x;
#pragma unroll
  for (size_t i = 0; i < params::opt / 2; ++i) {
    twid_id = tid / (params::degree / 32);
    i1 =
        2 * (params::degree / 32) * twid_id + (tid & (params::degree / 32 - 1));
    i2 = i1 + params::degree / 32;

    w = negtwiddles[twid_id + 16];
    u = A[i1] - A[i2];

    A[i1] += A[i2];
    A[i2] = u * conjugate(w);

    tid += params::degree / params::opt;
  }
  __syncthreads();

  // level 4
  tid = threadIdx.x;
#pragma unroll
  for (size_t i = 0; i < params::opt / 2; ++i) {
    twid_id = tid / (params::degree / 16);
    i1 =
        2 * (params::degree / 16) * twid_id + (tid & (params::degree / 16 - 1));
    i2 = i1 + params::degree / 16;

    w = negtwiddles[twid_id + 8];
    u = A[i1] - A[i2];

    A[i1] += A[i2];
    A[i2] = u * conjugate(w);

    tid += params::degree / params::opt;
  }
  __syncthreads();

  // level 3
  tid = threadIdx.x;
#pragma unroll
  for (size_t i = 0; i < params::opt / 2; ++i) {
    twid_id = tid / (params::degree / 8);
    i1 = 2 * (params::degree / 8) * twid_id + (tid & (params::degree / 8 - 1));
    i2 = i1 + params::degree / 8;

    w = negtwiddles[twid_id + 4];
    u = A[i1] - A[i2];

    A[i1] += A[i2];
    A[i2] = u * conjugate(w);

    tid += params::degree / params::opt;
  }
  __syncthreads();

  // level 2
  tid = threadIdx.x;
#pragma unroll
  for (size_t i = 0; i < params::opt / 2; ++i) {
    twid_id = tid / (params::degree / 4);
    i1 = 2 * (params::degree / 4) * twid_id + (tid & (params::degree / 4 - 1));
    i2 = i1 + params::degree / 4;

    w = negtwiddles[twid_id + 2];
    u = A[i1] - A[i2];

    A[i1] += A[i2];
    A[i2] = u * conjugate(w);

    tid += params::degree / params::opt;
  }
  __syncthreads();

  // level 1
  tid = threadIdx.x;
#pragma unroll
  for (size_t i = 0; i < params::opt / 2; ++i) {
    twid_id = tid / (params::degree / 2);
    i1 = 2 * (params::degree / 2) * twid_id + (tid & (params::degree / 2 - 1));
    i2 = i1 + params::degree / 2;

    w = negtwiddles[twid_id + 1];
    u = A[i1] - A[i2];

    A[i1] += A[i2];
    A[i2] = u * conjugate(w);

    tid += params::degree / params::opt;
  }
  __syncthreads();
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
