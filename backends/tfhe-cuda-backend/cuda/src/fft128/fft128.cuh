#ifndef CUDA_FFT128_CUH
#define CUDA_FFT128_CUH

#include "checked_arithmetic.h"
#include "f128.cuh"
#include "fft/fft128.h"
#include "polynomial/functions.cuh"
#include "polynomial/parameters.cuh"
#include "twiddles.cuh"
#include "types/complex/operations.cuh"
#include <iostream>

using Index = unsigned;

#define NEG_TWID(i)                                                            \
  f128x2(                                                                      \
      f128(__ldg(&neg_twiddles_re_hi[(i)]), __ldg(&neg_twiddles_re_lo[(i)])),  \
      f128(__ldg(&neg_twiddles_im_hi[(i)]), __ldg(&neg_twiddles_im_lo[(i)])))

#define F64x4_TO_F128x2(f128x2_reg, ind)                                       \
  f128x2_reg.re.hi = dt_re_hi[ind];                                            \
  f128x2_reg.re.lo = dt_re_lo[ind];                                            \
  f128x2_reg.im.hi = dt_im_hi[ind];                                            \
  f128x2_reg.im.lo = dt_im_lo[ind]

#define F128x2_TO_F64x4(f128x2_reg, ind)                                       \
  dt_re_hi[ind] = f128x2_reg.re.hi;                                            \
  dt_re_lo[ind] = f128x2_reg.re.lo;                                            \
  dt_im_hi[ind] = f128x2_reg.im.hi;                                            \
  dt_im_lo[ind] = f128x2_reg.im.lo

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
    auto ww = NEG_TWID(1);
    f128::cplx_f128_mul_assign(w.re, w.im, v[i].re, v[i].im, NEG_TWID(1).re,
                               NEG_TWID(1).im);
    f128::cplx_f128_sub_assign(v[i].re, v[i].im, u[i].re, u[i].im, w.re, w.im);
    f128::cplx_f128_add_assign(u[i].re, u[i].im, u[i].re, u[i].im, w.re, w.im);
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
      if (u_stays_in_register) {
        F128x2_TO_F64x4(v[i], tid);
      } else {
        F128x2_TO_F64x4(u[i], tid);
      }
      tid = tid + STRIDE;
    }
    __syncthreads();

    tid = threadIdx.x;
#pragma unroll
    for (Index i = 0; i < BUTTERFLY_DEPTH; i++) {
      Index rank = tid & thread_mask;
      bool u_stays_in_register = rank < lane_mask;
      F64x4_TO_F128x2(w, tid ^ lane_mask);
      if (u_stays_in_register) {
        v[i] = w;
      } else {
        u[i] = w;
      }
      w = NEG_TWID(tid / lane_mask + twiddle_shift);
      f128::cplx_f128_mul_assign(w.re, w.im, v[i].re, v[i].im, w.re, w.im);
      f128::cplx_f128_sub_assign(v[i].re, v[i].im, u[i].re, u[i].im, w.re,
                                 w.im);
      f128::cplx_f128_add_assign(u[i].re, u[i].im, u[i].re, u[i].im, w.re,
                                 w.im);
      tid = tid + STRIDE;
    }
  }
  __syncthreads();

  //   store registers in SM
  tid = threadIdx.x;
#pragma unroll
  for (Index i = 0; i < BUTTERFLY_DEPTH; i++) {
    F128x2_TO_F64x4(u[i], tid * 2);
    F128x2_TO_F64x4(v[i], (tid * 2 + 1));
    tid = tid + STRIDE;
  }
  __syncthreads();
}

template <class params>
__device__ void negacyclic_backward_fft_f128(double *dt_re_hi, double *dt_re_lo,
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
      if (u_stays_in_register) {
        F128x2_TO_F64x4(v[i], tid);
      } else {
        F128x2_TO_F64x4(u[i], tid);
      }

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

      if (u_stays_in_register) {
        v[i] = w;
      } else {
        u[i] = w;
      }

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

// params is expected to be full degree not half degree
template <class params>
__device__ void convert_u128_to_f128_as_integer(
    double *out_re_hi, double *out_re_lo, double *out_im_hi, double *out_im_lo,
    const __uint128_t *in_re, const __uint128_t *in_im) {

  Index tid = threadIdx.x;
  // #pragma unroll
  for (Index i = 0; i < params::opt / 2; i++) {
    auto out_re = u128_to_signed_to_f128(in_re[tid]);
    auto out_im = u128_to_signed_to_f128(in_im[tid]);

    out_re_hi[tid] = out_re.hi;
    out_re_lo[tid] = out_re.lo;
    out_im_hi[tid] = out_im.hi;
    out_im_lo[tid] = out_im.lo;

    tid += params::degree / params::opt;
  }
}

// params is expected to be full degree not half degree
template <class params>
__device__ void convert_u128_to_f128_as_torus(
    double *out_re_hi, double *out_re_lo, double *out_im_hi, double *out_im_lo,
    const __uint128_t *in_re, const __uint128_t *in_im) {

  const double normalization = __longlong_as_double(0x37f0000000000000ULL);
  Index tid = threadIdx.x;
  // #pragma unroll
  for (Index i = 0; i < params::opt / 2; i++) {
    auto out_re = u128_to_signed_to_f128(in_re[tid]);
    auto out_im = u128_to_signed_to_f128(in_im[tid]);

    out_re_hi[tid] = out_re.hi * normalization;
    out_re_lo[tid] = out_re.lo * normalization;
    out_im_hi[tid] = out_im.hi * normalization;
    out_im_lo[tid] = out_im.lo * normalization;

    tid += params::degree / params::opt;
  }
}

// params is expected to be full degree not half degree
// same as convert_u128_to_f128_as_torus() but expects input to be on registers
template <class params>
__device__ void convert_u128_on_regs_to_f128_as_torus(
    double *out_re_hi, double *out_re_lo, double *out_im_hi, double *out_im_lo,
    const __uint128_t *in_re_on_regs, const __uint128_t *in_im_on_regs) {

  const double normalization = __longlong_as_double(0x37f0000000000000ULL);
  Index tid = threadIdx.x;
  // #pragma unroll
  for (Index i = 0; i < params::opt / 2; i++) {
    auto out_re = u128_to_signed_to_f128(in_re_on_regs[i]);
    auto out_im = u128_to_signed_to_f128(in_im_on_regs[i]);

    out_re_hi[tid] = out_re.hi * normalization;
    out_re_lo[tid] = out_re.lo * normalization;
    out_im_hi[tid] = out_im.hi * normalization;
    out_im_lo[tid] = out_im.lo * normalization;

    tid += params::degree / params::opt;
  }
}

template <class params>
__device__ void
convert_f128_to_u128_as_torus(__uint128_t *out_re, __uint128_t *out_im,
                              const double *in_re_hi, const double *in_re_lo,
                              const double *in_im_hi, const double *in_im_lo) {

  const double normalization = 1. / (params::degree / 2);
  Index tid = threadIdx.x;
  // #pragma unroll
  for (Index i = 0; i < params::opt / 2; i++) {

    f128 in_re(in_re_hi[tid] * normalization, in_re_lo[tid] * normalization);
    f128 in_im(in_im_hi[tid] * normalization, in_im_lo[tid] * normalization);

    out_re[tid] = u128_from_torus_f128(in_re);
    out_im[tid] = u128_from_torus_f128(in_im);

    tid += params::degree / params::opt;
  }
}

// params is expected to be full degree not half degree
template <class params>
__global__ void
batch_convert_u128_to_f128_as_integer(double *out_re_hi, double *out_re_lo,
                                      double *out_im_hi, double *out_im_lo,
                                      const __uint128_t *in) {

  convert_u128_to_f128_as_integer<params>(
      &out_re_hi[blockIdx.x * params::degree / 2],
      &out_re_lo[blockIdx.x * params::degree / 2],
      &out_im_hi[blockIdx.x * params::degree / 2],
      &out_im_lo[blockIdx.x * params::degree / 2],
      &in[blockIdx.x * params::degree],
      &in[blockIdx.x * params::degree + params::degree / 2]);
}

// params is expected to be full degree not half degree
// converts standard input into complex<128> represented by 4 double
// with following pattern: [re_hi_0, re_hi_1, ... re_hi_n, re_lo_0, re_lo_1,
// ... re_lo_n, im_hi_0, im_hi_1, ..., im_hi_n,  im_lo_0, im_lo_1, ..., im_lo_n]
template <class params>
__global__ void
batch_convert_u128_to_f128_as_torus(double *out_re_hi, double *out_re_lo,
                                    double *out_im_hi, double *out_im_lo,
                                    const __uint128_t *in) {

  convert_u128_to_f128_as_torus<params>(
      &out_re_hi[blockIdx.x * params::degree / 2],
      &out_re_lo[blockIdx.x * params::degree / 2],
      &out_im_hi[blockIdx.x * params::degree / 2],
      &out_im_lo[blockIdx.x * params::degree / 2],
      &in[blockIdx.x * params::degree],
      &in[blockIdx.x * params::degree + params::degree / 2]);
}

// params is expected to be full degree not half degree
// converts standard input into complex<128> represented by 4 double
// with following pattern: [re_hi_0, re_lo_0, im_hi_0, im_lo_0, re_hi_1,
// re_lo_1, im_hi_1, im_lo_1,
// ...,re_hi_n, re_lo_n, im_hi_n, im_lo_n, ]
template <class params>
__global__ void
batch_convert_u128_to_f128_strided_as_torus(double *d_out,
                                            const __uint128_t *d_in) {

  constexpr size_t chunk_size = params::degree / 2 * 4;
  double *chunk = &d_out[blockIdx.x * chunk_size];
  double *out_re_hi = &chunk[0 * params::degree / 2];
  double *out_re_lo = &chunk[1 * params::degree / 2];
  double *out_im_hi = &chunk[2 * params::degree / 2];
  double *out_im_lo = &chunk[3 * params::degree / 2];

  convert_u128_to_f128_as_torus<params>(
      out_re_hi, out_re_lo, out_im_hi, out_im_lo,
      &d_in[blockIdx.x * params::degree],
      &d_in[blockIdx.x * params::degree + params::degree / 2]);
}

// params is expected to be full degree not half degree
template <class params>
__global__ void batch_convert_f128_to_u128_as_torus(__uint128_t *out,
                                                    const double *in_re_hi,
                                                    const double *in_re_lo,
                                                    const double *in_im_hi,
                                                    const double *in_im_lo) {

  convert_f128_to_u128_as_torus<params>(
      &out[blockIdx.x * params::degree],
      &out[blockIdx.x * params::degree + params::degree / 2],
      &in_re_hi[blockIdx.x * params::degree / 2],
      &in_re_lo[blockIdx.x * params::degree / 2],
      &in_im_hi[blockIdx.x * params::degree / 2],
      &in_im_lo[blockIdx.x * params::degree / 2]);
}

template <class params, sharedMemDegree SMD>
__global__ void
batch_NSMFFT_128(double *in_re_hi, double *in_re_lo, double *in_im_hi,
                 double *in_im_lo, double *out_re_hi, double *out_re_lo,
                 double *out_im_hi, double *out_im_lo, double *buffer) {
  extern __shared__ double sharedMemoryFFT128[];
  double *re_hi, *re_lo, *im_hi, *im_lo;

  if (SMD == NOSM) {
    re_hi =
        &buffer[blockIdx.x * params::degree / 2 * 4 + params::degree / 2 * 0];
    re_lo =
        &buffer[blockIdx.x * params::degree / 2 * 4 + params::degree / 2 * 1];
    im_hi =
        &buffer[blockIdx.x * params::degree / 2 * 4 + params::degree / 2 * 2];
    im_lo =
        &buffer[blockIdx.x * params::degree / 2 * 4 + params::degree / 2 * 3];
  } else {
    re_hi = &sharedMemoryFFT128[params::degree / 2 * 0];
    re_lo = &sharedMemoryFFT128[params::degree / 2 * 1];
    im_hi = &sharedMemoryFFT128[params::degree / 2 * 2];
    im_lo = &sharedMemoryFFT128[params::degree / 2 * 3];
  }

  Index tid = threadIdx.x;
#pragma unroll
  for (Index i = 0; i < params::opt / 2; ++i) {
    re_hi[tid] = in_re_hi[blockIdx.x * (params::degree / 2) + tid];
    re_lo[tid] = in_re_lo[blockIdx.x * (params::degree / 2) + tid];
    im_hi[tid] = in_im_hi[blockIdx.x * (params::degree / 2) + tid];
    im_lo[tid] = in_im_lo[blockIdx.x * (params::degree / 2) + tid];
    tid += params::degree / params::opt;
  }
  __syncthreads();
  if constexpr (params::fft_direction == 1) {
    negacyclic_backward_fft_f128<HalfDegree<params>>(re_hi, re_lo, im_hi,
                                                     im_lo);
  } else {
    negacyclic_forward_fft_f128<HalfDegree<params>>(re_hi, re_lo, im_hi, im_lo);
  }
  __syncthreads();
  tid = threadIdx.x;
#pragma unroll
  for (Index i = 0; i < params::opt / 2; ++i) {
    out_re_hi[blockIdx.x * (params::degree / 2) + tid] = re_hi[tid];
    out_re_lo[blockIdx.x * (params::degree / 2) + tid] = re_lo[tid];
    out_im_hi[blockIdx.x * (params::degree / 2) + tid] = im_hi[tid];
    out_im_lo[blockIdx.x * (params::degree / 2) + tid] = im_lo[tid];
    tid += params::degree / params::opt;
  }
}

template <class params, sharedMemDegree SMD>
__global__ void batch_NSMFFT_strided_128(double *d_in, double *d_out,
                                         double *buffer) {
  extern __shared__ double sharedMemoryFFT128[];
  double *re_hi, *re_lo, *im_hi, *im_lo;

  if (SMD == NOSM) {
    re_hi =
        &buffer[blockIdx.x * params::degree / 2 * 4 + params::degree / 2 * 0];
    re_lo =
        &buffer[blockIdx.x * params::degree / 2 * 4 + params::degree / 2 * 1];
    im_hi =
        &buffer[blockIdx.x * params::degree / 2 * 4 + params::degree / 2 * 2];
    im_lo =
        &buffer[blockIdx.x * params::degree / 2 * 4 + params::degree / 2 * 3];
  } else {
    re_hi = &sharedMemoryFFT128[params::degree / 2 * 0];
    re_lo = &sharedMemoryFFT128[params::degree / 2 * 1];
    im_hi = &sharedMemoryFFT128[params::degree / 2 * 2];
    im_lo = &sharedMemoryFFT128[params::degree / 2 * 3];
  }

  constexpr size_t chunk_size = params::degree / 2 * 4;
  double *chunk = &d_in[blockIdx.x * chunk_size];
  double *tmp_re_hi = &chunk[0 * params::degree / 2];
  double *tmp_re_lo = &chunk[1 * params::degree / 2];
  double *tmp_im_hi = &chunk[2 * params::degree / 2];
  double *tmp_im_lo = &chunk[3 * params::degree / 2];

  Index tid = threadIdx.x;
#pragma unroll
  for (Index i = 0; i < params::opt / 2; ++i) {
    re_hi[tid] = tmp_re_hi[tid];
    re_lo[tid] = tmp_re_lo[tid];
    im_hi[tid] = tmp_im_hi[tid];
    im_lo[tid] = tmp_im_lo[tid];
    tid += params::degree / params::opt;
  }
  __syncthreads();
  if constexpr (params::fft_direction == 1) {
    negacyclic_backward_fft_f128<HalfDegree<params>>(re_hi, re_lo, im_hi,
                                                     im_lo);
  } else {
    negacyclic_forward_fft_f128<HalfDegree<params>>(re_hi, re_lo, im_hi, im_lo);
  }
  __syncthreads();

  chunk = &d_out[blockIdx.x * chunk_size];
  tmp_re_hi = &chunk[0 * params::degree / 2];
  tmp_re_lo = &chunk[1 * params::degree / 2];
  tmp_im_hi = &chunk[2 * params::degree / 2];
  tmp_im_lo = &chunk[3 * params::degree / 2];

  tid = threadIdx.x;
#pragma unroll
  for (Index i = 0; i < params::opt / 2; ++i) {
    tmp_re_hi[tid] = re_hi[tid];
    tmp_re_lo[tid] = re_lo[tid];
    tmp_im_hi[tid] = im_hi[tid];
    tmp_im_lo[tid] = im_lo[tid];
    tid += params::degree / params::opt;
  }
}

template <class params>
__host__ void host_fourier_transform_forward_as_integer_f128(
    cudaStream_t stream, uint32_t gpu_index, double *re0, double *re1,
    double *im0, double *im1, const __uint128_t *standard, const uint32_t N,
    const uint32_t number_of_samples) {

  // allocate device buffers
  double *d_re0 = (double *)cuda_malloc_async(safe_mul_sizeof<double>(N / 2),
                                              stream, gpu_index);
  double *d_re1 = (double *)cuda_malloc_async(safe_mul_sizeof<double>(N / 2),
                                              stream, gpu_index);
  double *d_im0 = (double *)cuda_malloc_async(safe_mul_sizeof<double>(N / 2),
                                              stream, gpu_index);
  double *d_im1 = (double *)cuda_malloc_async(safe_mul_sizeof<double>(N / 2),
                                              stream, gpu_index);
  __uint128_t *d_standard = (__uint128_t *)cuda_malloc_async(
      safe_mul_sizeof<__uint128_t>(N), stream, gpu_index);

  // copy input into device
  cuda_memcpy_async_to_gpu(d_standard, standard,
                           safe_mul_sizeof<__uint128_t>(N), stream, gpu_index);

  // setup launch parameters
  size_t required_shared_memory_size =
      safe_mul_sizeof<double>((size_t)(N / 2), (size_t)4);
  int grid_size = number_of_samples;
  int block_size = params::degree / params::opt;
  bool full_sm =
      (required_shared_memory_size <= cuda_get_max_shared_memory(gpu_index));
  size_t buffer_size =
      full_sm ? 0
              : safe_mul((size_t)number_of_samples, (size_t)(N / 2), (size_t)4);
  size_t shared_memory_size = full_sm ? required_shared_memory_size : 0;
  double *buffer = (double *)cuda_malloc_async(buffer_size, stream, gpu_index);

  // configure shared memory for batch fft kernel
  if (full_sm) {
    check_cuda_error(cudaFuncSetAttribute(
        batch_NSMFFT_128<FFTDegree<params, ForwardFFT>, FULLSM>,
        cudaFuncAttributeMaxDynamicSharedMemorySize, shared_memory_size));
    check_cuda_error(cudaFuncSetCacheConfig(
        batch_NSMFFT_128<FFTDegree<params, ForwardFFT>, FULLSM>,
        cudaFuncCachePreferShared));
  }

  // convert u128 into 4 x double
  batch_convert_u128_to_f128_as_integer<params>
      <<<grid_size, block_size, 0, stream>>>(d_re0, d_re1, d_im0, d_im1,
                                             d_standard);
  check_cuda_error(cudaGetLastError());

  // call negacyclic 128 bit forward fft.
  if (full_sm) {
    batch_NSMFFT_128<FFTDegree<params, ForwardFFT>, FULLSM>
        <<<grid_size, block_size, shared_memory_size, stream>>>(
            d_re0, d_re1, d_im0, d_im1, d_re0, d_re1, d_im0, d_im1, buffer);
  } else {
    batch_NSMFFT_128<FFTDegree<params, ForwardFFT>, NOSM>
        <<<grid_size, block_size, shared_memory_size, stream>>>(
            d_re0, d_re1, d_im0, d_im1, d_re0, d_re1, d_im0, d_im1, buffer);
  }
  check_cuda_error(cudaGetLastError());

  cuda_memcpy_async_to_cpu(re0, d_re0, safe_mul_sizeof<double>(N / 2), stream,
                           gpu_index);
  cuda_memcpy_async_to_cpu(re1, d_re1, safe_mul_sizeof<double>(N / 2), stream,
                           gpu_index);
  cuda_memcpy_async_to_cpu(im0, d_im0, safe_mul_sizeof<double>(N / 2), stream,
                           gpu_index);
  cuda_memcpy_async_to_cpu(im1, d_im1, safe_mul_sizeof<double>(N / 2), stream,
                           gpu_index);

  cuda_drop_async(d_standard, stream, gpu_index);
  cuda_drop_async(d_re0, stream, gpu_index);
  cuda_drop_async(d_re1, stream, gpu_index);
  cuda_drop_async(d_im0, stream, gpu_index);
  cuda_drop_async(d_im1, stream, gpu_index);
}

template <class params>
__host__ void host_fourier_transform_forward_as_torus_f128(
    cudaStream_t stream, uint32_t gpu_index, double *re0, double *re1,
    double *im0, double *im1, const __uint128_t *standard, const uint32_t N,
    const uint32_t number_of_samples) {

  // allocate device buffers
  double *d_re0 = (double *)cuda_malloc_async(safe_mul_sizeof<double>(N / 2),
                                              stream, gpu_index);
  double *d_re1 = (double *)cuda_malloc_async(safe_mul_sizeof<double>(N / 2),
                                              stream, gpu_index);
  double *d_im0 = (double *)cuda_malloc_async(safe_mul_sizeof<double>(N / 2),
                                              stream, gpu_index);
  double *d_im1 = (double *)cuda_malloc_async(safe_mul_sizeof<double>(N / 2),
                                              stream, gpu_index);
  __uint128_t *d_standard = (__uint128_t *)cuda_malloc_async(
      safe_mul_sizeof<__uint128_t>(N), stream, gpu_index);

  // copy input into device
  cuda_memcpy_async_to_gpu(d_standard, standard,
                           safe_mul_sizeof<__uint128_t>(N), stream, gpu_index);

  // setup launch parameters
  size_t required_shared_memory_size =
      safe_mul_sizeof<double>((size_t)(N / 2), (size_t)4);
  int grid_size = number_of_samples;
  int block_size = params::degree / params::opt;
  bool full_sm =
      (required_shared_memory_size <= cuda_get_max_shared_memory(gpu_index));
  size_t buffer_size =
      full_sm ? 0
              : safe_mul((size_t)number_of_samples, (size_t)(N / 2), (size_t)4);
  size_t shared_memory_size = full_sm ? required_shared_memory_size : 0;
  double *buffer = (double *)cuda_malloc_async(buffer_size, stream, gpu_index);

  // configure shared memory for batch fft kernel
  if (full_sm) {
    check_cuda_error(cudaFuncSetAttribute(
        batch_NSMFFT_128<FFTDegree<params, ForwardFFT>, FULLSM>,
        cudaFuncAttributeMaxDynamicSharedMemorySize, shared_memory_size));
    check_cuda_error(cudaFuncSetCacheConfig(
        batch_NSMFFT_128<FFTDegree<params, ForwardFFT>, FULLSM>,
        cudaFuncCachePreferShared));
  }

  // convert u128 into 4 x double
  batch_convert_u128_to_f128_as_torus<params>
      <<<grid_size, block_size, 0, stream>>>(d_re0, d_re1, d_im0, d_im1,
                                             d_standard);

  // call negacyclic 128 bit forward fft.
  if (full_sm) {
    batch_NSMFFT_128<FFTDegree<params, ForwardFFT>, FULLSM>
        <<<grid_size, block_size, shared_memory_size, stream>>>(
            d_re0, d_re1, d_im0, d_im1, d_re0, d_re1, d_im0, d_im1, buffer);
  } else {
    batch_NSMFFT_128<FFTDegree<params, ForwardFFT>, NOSM>
        <<<grid_size, block_size, shared_memory_size, stream>>>(
            d_re0, d_re1, d_im0, d_im1, d_re0, d_re1, d_im0, d_im1, buffer);
  }

  cuda_memcpy_async_to_cpu(re0, d_re0, safe_mul_sizeof<double>(N / 2), stream,
                           gpu_index);
  cuda_memcpy_async_to_cpu(re1, d_re1, safe_mul_sizeof<double>(N / 2), stream,
                           gpu_index);
  cuda_memcpy_async_to_cpu(im0, d_im0, safe_mul_sizeof<double>(N / 2), stream,
                           gpu_index);
  cuda_memcpy_async_to_cpu(im1, d_im1, safe_mul_sizeof<double>(N / 2), stream,
                           gpu_index);

  cuda_drop_async(d_standard, stream, gpu_index);
  cuda_drop_async(d_re0, stream, gpu_index);
  cuda_drop_async(d_re1, stream, gpu_index);
  cuda_drop_async(d_im0, stream, gpu_index);
  cuda_drop_async(d_im1, stream, gpu_index);
}

template <class params>
__host__ void host_fourier_transform_backward_as_torus_f128(
    cudaStream_t stream, uint32_t gpu_index, __uint128_t *standard,
    double const *re0, double const *re1, double const *im0, double const *im1,
    const uint32_t N, const uint32_t number_of_samples) {

  // allocate device buffers
  double *d_re0 = (double *)cuda_malloc_async(safe_mul_sizeof<double>(N / 2),
                                              stream, gpu_index);
  double *d_re1 = (double *)cuda_malloc_async(safe_mul_sizeof<double>(N / 2),
                                              stream, gpu_index);
  double *d_im0 = (double *)cuda_malloc_async(safe_mul_sizeof<double>(N / 2),
                                              stream, gpu_index);
  double *d_im1 = (double *)cuda_malloc_async(safe_mul_sizeof<double>(N / 2),
                                              stream, gpu_index);
  __uint128_t *d_standard = (__uint128_t *)cuda_malloc_async(
      safe_mul_sizeof<__uint128_t>(N), stream, gpu_index);

  //  // copy input into device
  cuda_memcpy_async_to_gpu(d_re0, re0, safe_mul_sizeof<double>(N / 2), stream,
                           gpu_index);
  cuda_memcpy_async_to_gpu(d_re1, re1, safe_mul_sizeof<double>(N / 2), stream,
                           gpu_index);
  cuda_memcpy_async_to_gpu(d_im0, im0, safe_mul_sizeof<double>(N / 2), stream,
                           gpu_index);
  cuda_memcpy_async_to_gpu(d_im1, im1, safe_mul_sizeof<double>(N / 2), stream,
                           gpu_index);

  // setup launch parameters
  size_t required_shared_memory_size =
      safe_mul_sizeof<double>((size_t)(N / 2), (size_t)4);
  int grid_size = number_of_samples;
  int block_size = params::degree / params::opt;
  bool full_sm =
      (required_shared_memory_size <= cuda_get_max_shared_memory(gpu_index));
  size_t buffer_size =
      full_sm ? 0
              : safe_mul((size_t)number_of_samples, (size_t)(N / 2), (size_t)4);
  size_t shared_memory_size = full_sm ? required_shared_memory_size : 0;
  double *buffer = (double *)cuda_malloc_async(buffer_size, stream, gpu_index);

  // configure shared memory for batch fft kernel
  if (full_sm) {
    check_cuda_error(cudaFuncSetAttribute(
        batch_NSMFFT_128<FFTDegree<params, BackwardFFT>, FULLSM>,
        cudaFuncAttributeMaxDynamicSharedMemorySize, shared_memory_size));
    check_cuda_error(cudaFuncSetCacheConfig(
        batch_NSMFFT_128<FFTDegree<params, BackwardFFT>, FULLSM>,
        cudaFuncCachePreferShared));
    batch_NSMFFT_128<FFTDegree<params, BackwardFFT>, FULLSM>
        <<<grid_size, block_size, shared_memory_size, stream>>>(
            d_re0, d_re1, d_im0, d_im1, d_re0, d_re1, d_im0, d_im1, buffer);
  } else {
    batch_NSMFFT_128<FFTDegree<params, BackwardFFT>, NOSM>
        <<<grid_size, block_size, shared_memory_size, stream>>>(
            d_re0, d_re1, d_im0, d_im1, d_re0, d_re1, d_im0, d_im1, buffer);
  }

  batch_convert_f128_to_u128_as_torus<params>
      <<<grid_size, block_size, 0, stream>>>(d_standard, d_re0, d_re1, d_im0,
                                             d_im1);

  cuda_memcpy_async_to_cpu(standard, d_standard,
                           safe_mul_sizeof<__uint128_t>(N), stream, gpu_index);
  cuda_drop_async(d_standard, stream, gpu_index);
  cuda_drop_async(d_re0, stream, gpu_index);
  cuda_drop_async(d_re1, stream, gpu_index);
  cuda_drop_async(d_im0, stream, gpu_index);
  cuda_drop_async(d_im1, stream, gpu_index);
}

#undef NEG_TWID
#undef F64x4_TO_F128x2
#undef F128x2_TO_F64x4

#endif // TFHE_RS_BACKENDS_TFHE_CUDA_BACKEND_CUDA_SRC_FFT128_FFT128_CUH_
