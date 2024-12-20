#ifndef TFHE_RS_BACKENDS_TFHE_CUDA_BACKEND_CUDA_SRC_FFT128_FFT128_CUH_
#define TFHE_RS_BACKENDS_TFHE_CUDA_BACKEND_CUDA_SRC_FFT128_FFT128_CUH_

#include "f128.cuh"
#include "pbs/fft.h"
#include "polynomial/functions.cuh"
#include "polynomial/parameters.cuh"
#include "twiddles.cuh"
#include "types/complex/operations.cuh"
#include <iostream>

using Index = unsigned;

#define NEG_TWID(i)                                                            \
  f128x2(f128(neg_twiddles_re_hi[(i)], neg_twiddles_re_lo[(i)]),               \
         f128(neg_twiddles_im_hi[(i)], neg_twiddles_im_lo[(i)]))

#define F64x4_TO_F128x2(f128x2_reg, ind)                                       \
  f128x2_reg.re.hi = dt_re_hi[ind];                                            \
  f128x2_reg.re.lo = dt_re_lo[ind];                                            \
  f128x2_reg.im.hi = dt_im_hi[ind];                                            \
  f128x2_reg.im.lo = dt_im_lo[ind];

#define F128x2_TO_F64x4(f128x2_reg, ind)                                       \
  dt_re_hi[ind] = f128x2_reg.re.hi;                                            \
  dt_re_lo[ind] = f128x2_reg.re.lo;                                            \
  dt_im_hi[ind] = f128x2_reg.im.hi;                                            \
  dt_im_lo[ind] = f128x2_reg.im.lo;

// zl - left part of butterfly operation
// zr - right part of butterfly operation
// re - real part
// im - imaginary part
// hi - high bits
// lo - low bits
// dt - list
// cf - single coefficient
template <class params>
__device__ void negacyclic_forward_fft_f128(double *dt_re_hi, double *dt_re_lo,
                                            double *dt_im_hi,
                                            double *dt_im_lo) {

  __syncthreads();
  constexpr Index BUTTERFLY_DEPTH = params::opt >> 1;
  constexpr Index LOG2_DEGREE = params::log2_degree;
  constexpr Index HALF_DEGREE = params::degree >> 1;
  constexpr Index STRIDE = params::degree / params::opt;

  f128x2 u[BUTTERFLY_DEPTH], v[BUTTERFLY_DEPTH], w;

  Index tid = threadIdx.x;

  // load into registers
#pragma unroll
  for (Index i = 0; i < BUTTERFLY_DEPTH; ++i) {
    F64x4_TO_F128x2(u[i], tid);
    F64x4_TO_F128x2(v[i], tid + HALF_DEGREE);
    tid += STRIDE;
  }

  // level 1
  // we don't make actual complex multiplication on level1 since we have only
  // one twiddle, it's real and image parts are equal, so we can multiply
  // it with simpler operations

#pragma unroll
  for (Index i = 0; i < BUTTERFLY_DEPTH; ++i) {
    w = v[i] * NEG_TWID(1);
    v[i] = u[i] - w;
    u[i] = u[i] + w;
  }

  Index twiddle_shift = 1;
  for (Index l = LOG2_DEGREE - 1; l >= 1; --l) {
    Index lane_mask = 1 << (l - 1);
    Index thread_mask = (1 << l) - 1;
    twiddle_shift <<= 1;

    tid = threadIdx.x;
    __syncthreads();
#pragma unroll
    for (Index i = 0; i < BUTTERFLY_DEPTH; i++) {
      Index rank = tid & thread_mask;
      bool u_stays_in_register = rank < lane_mask;
      F128x2_TO_F64x4((u_stays_in_register) ? v[i] : u[i], tid);
      tid = tid + STRIDE;
    }
    __syncthreads();

    tid = threadIdx.x;
#pragma unroll
    for (Index i = 0; i < BUTTERFLY_DEPTH; i++) {
      Index rank = tid & thread_mask;
      bool u_stays_in_register = rank < lane_mask;
      F64x4_TO_F128x2(w, tid ^ lane_mask);
      u[i] = (u_stays_in_register) ? u[i] : w;
      v[i] = (u_stays_in_register) ? w : v[i];
      w = NEG_TWID(tid / lane_mask + twiddle_shift);

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
    F128x2_TO_F64x4(u[i], tid * 2);
    F128x2_TO_F64x4(v[i], tid * 2 + 1);
    tid = tid + STRIDE;
  }
  __syncthreads();
}

template <class params>
__device__ void negacyclic_inverse_fft_f128(double *dt_re_hi, double *dt_re_lo,
                                            double *dt_im_hi,
                                            double *dt_im_lo) {
  __syncthreads();
  constexpr Index BUTTERFLY_DEPTH = params::opt >> 1;
  constexpr Index LOG2_DEGREE = params::log2_degree;
  constexpr Index DEGREE = params::degree;
  constexpr Index HALF_DEGREE = params::degree >> 1;
  constexpr Index STRIDE = params::degree / params::opt;

  size_t tid = threadIdx.x;
  f128x2 u[BUTTERFLY_DEPTH], v[BUTTERFLY_DEPTH], w;

  // load into registers and divide by compressed polynomial size
#pragma unroll
  for (Index i = 0; i < BUTTERFLY_DEPTH; ++i) {

    F64x4_TO_F128x2(u[i], 2 * tid);
    F64x4_TO_F128x2(v[i], 2 * tid + 1);

    // TODO f128 / double and f128x2/double
    //    u[i] /= DEGREE;
    //    v[i] /= DEGREE;

    tid += STRIDE;
  }

  Index twiddle_shift = DEGREE;
  for (Index l = 1; l <= LOG2_DEGREE - 1; ++l) {
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
      v[i] = w * NEG_TWID(tid / lane_mask + twiddle_shift).conjugate();

      // keep one of the register for next iteration and store another one in sm
      Index rank = tid & thread_mask;
      bool u_stays_in_register = rank < lane_mask;
      F128x2_TO_F64x4((u_stays_in_register) ? v[i] : u[i], tid);

      tid = tid + STRIDE;
    }
    __syncthreads();

    // prepare registers for next butterfly iteration
    tid = threadIdx.x;
#pragma unroll
    for (Index i = 0; i < BUTTERFLY_DEPTH; ++i) {
      Index rank = tid & thread_mask;
      bool u_stays_in_register = rank < lane_mask;
      F64x4_TO_F128x2(w, tid ^ lane_mask);

      u[i] = (u_stays_in_register) ? u[i] : w;
      v[i] = (u_stays_in_register) ? w : v[i];

      tid = tid + STRIDE;
    }
  }

  // last iteration
  for (Index i = 0; i < BUTTERFLY_DEPTH; ++i) {
    w = (u[i] - v[i]);
    u[i] = u[i] + v[i];
    v[i] = w * NEG_TWID(1).conjugate();
  }
  __syncthreads();
  // store registers in SM
  tid = threadIdx.x;
#pragma unroll
  for (Index i = 0; i < BUTTERFLY_DEPTH; i++) {
    F128x2_TO_F64x4(u[i], tid);
    F128x2_TO_F64x4(v[i], tid + HALF_DEGREE);

    tid = tid + STRIDE;
  }
  __syncthreads();
}

void print_uint128_bits(__uint128_t value) {
  char buffer[129];   // 128 bits + null terminator
  buffer[128] = '\0'; // Null-terminate the string

  for (int i = 127; i >= 0; --i) {
    buffer[i] = (value & 1) ? '1' : '0'; // Extract the least significant bit
    value >>= 1;                         // Shift right by 1 bit
  }

  printf("%s\n", buffer);
}

template <class params>
__host__ void host_fourier_transform_forward_f128_split_input(
    cudaStream_t stream, uint32_t gpu_index, double *re0, double *re1,
    double *im0, double *im1, __uint128_t const *standard, uint32_t const N) {

  printf("cpp_poly_host\n");
  for (int i = 0; i < N; i++) {
    print_uint128_bits(standard[i]);
  }
  printf("check #1\n");

  double *d_re0, *d_re1, *d_im0, *d_im1;
  __uint128_t *d_standard;

  check_cuda_error(cudaMalloc((void **)&d_re0, N * sizeof(double)));
  check_cuda_error(cudaMalloc((void **)&d_re1, N * sizeof(double)));
  check_cuda_error(cudaMalloc((void **)&d_im0, N * sizeof(double)));
  check_cuda_error(cudaMalloc((void **)&d_im1, N * sizeof(double)));

  check_cuda_error(cudaMalloc((void **)&d_standard, N * sizeof(__uint128_t)));

  check_cuda_error(cudaFree(d_re0));
  check_cuda_error(cudaFree(d_re1));
  check_cuda_error(cudaFree(d_im0));
  check_cuda_error(cudaFree(d_im1));

  cudaFree(d_standard);
}

#endif // TFHE_RS_BACKENDS_TFHE_CUDA_BACKEND_CUDA_SRC_FFT128_FFT128_CUH_
