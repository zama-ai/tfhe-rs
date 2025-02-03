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
  f128x2_reg.im.lo = dt_im_lo[ind]

#define F128x2_TO_F64x4(f128x2_reg, ind)                                       \
  dt_re_hi[ind] = f128x2_reg.re.hi;                                            \
  dt_re_lo[ind] = f128x2_reg.re.lo;                                            \
  dt_im_hi[ind] = f128x2_reg.im.hi;                                            \
  dt_im_lo[ind] = f128x2_reg.im.lo

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

  // debug
  __syncthreads();
  if (threadIdx.x == 0 && blockIdx.x == 0) {
    printf("BUTTERFLY_DEPTH %d\n", BUTTERFLY_DEPTH);
    printf("LOG2_DEGREE %d\n", LOG2_DEGREE);
    printf("HALF_DEGREE %d\n", HALF_DEGREE);
    printf("STRIDE %d\n", STRIDE);
    printf("Params::degree %d\n", params::degree);
    printf("opt %d\n", params::opt);
  }
  __syncthreads();

  // load into registers
#pragma unroll
  for (Index i = 0; i < BUTTERFLY_DEPTH; ++i) {
    F64x4_TO_F128x2(u[i], tid);
    F64x4_TO_F128x2(v[i], tid + HALF_DEGREE);
//    u[i].re.hi = dt_re_hi[tid];
//    u[i].re.lo = dt_re_lo[tid];
//    u[i].im.hi = dt_im_hi[tid];
//    u[i].im.lo = dt_im_lo[tid];

//    v[i].re.hi = dt_re_hi[tid + HALF_DEGREE];
//    v[i].re.lo = dt_re_lo[tid + HALF_DEGREE];
//    v[i].im.hi = dt_im_hi[tid + HALF_DEGREE];
//    v[i].im.lo = dt_im_lo[tid + HALF_DEGREE];

//    F64x4_TO_F128x2(u[i], tid);
//    F64x4_TO_F128x2(v[i], tid + HALF_DEGREE);
    tid += STRIDE;
  }

  // level 1
  // we don't make actual complex multiplication on level1 since we have only
  // one twiddle, it's real and image parts are equal, so we can multiply
  // it with simpler operations

#pragma unroll
  for (Index i = 0; i < BUTTERFLY_DEPTH; ++i) {
    auto ww = NEG_TWID(1);
    f128::cplx_f128_mul_assign(w.re, w.im, v[i].re, v[i].im, NEG_TWID(1).re, NEG_TWID(1).im);
    w = v[i] * NEG_TWID(1);

//    __syncthreads();
//    if (threadIdx.x == 0 && blockIdx.x == 0) {
//      printf("w = %.5f %.5f %.5f %.5f\n", ww.re.hi, ww.re.lo, ww.im.hi, ww.im.lo);
//      printf("u = %.5f %.5f %.5f %.5f\n", u[i].re.hi, u[i].re.lo, u[i].im.hi, u[i].im.lo);
//      printf("v = %.5f %.5f %.5f %.5f\n", v[i].re.hi, v[i].re.lo, v[i].im.hi, v[i].im.lo);
//      printf("wv = %.5f %.5f %.5f %.5f\n", w.re.hi, w.re.lo, w.im.hi, w.im.lo);
//    }
//    __syncthreads();
    v[i] = u[i] - w;
    u[i] = u[i] + w;
  }


//  tid = threadIdx.x;
//#pragma unroll
//  for (Index i = 0; i < BUTTERFLY_DEPTH; i++) {
//    F128x2_TO_F64x4(u[i], (tid));
//    F128x2_TO_F64x4(v[i], (tid + HALF_DEGREE));
//    tid = tid + STRIDE;
//  }
//  __syncthreads();


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
      F128x2_TO_F64x4(((u_stays_in_register) ? v[i] : u[i]), tid);
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

// params is expected to be full degree not half degree
template <class params>
__device__ void convert_u128_to_f128_as_integer(
    double *out_re_hi, double *out_re_lo,
    double *out_im_hi, double *out_im_lo,
    const __uint128_t *in_re, const __uint128_t *in_im) {

  Index tid = threadIdx.x;
//#pragma unroll
  for (Index i = 0; i < params::opt / 2; i++) {
    __syncthreads();
    auto out_re = u128_to_signed_to_f128(in_re[tid]);
    __syncthreads();
    auto out_im = u128_to_signed_to_f128(in_im[tid]);
    __syncthreads();

    out_re_hi[tid] = out_re.hi;
    out_re_lo[tid] = out_re.lo;
    out_im_hi[tid] = out_im.hi;
    out_im_lo[tid] = out_im.lo;

//    __syncthreads();
//    if (threadIdx.x == 0 && blockIdx.x == 0) {
//      printf("%.5f %.5f %.5f %.5f\n", out_re_hi[tid], out_re_lo[tid], out_im_hi[tid],
//             out_im_lo[tid]);
//    }
//    __syncthreads();
    tid += params::degree / params::opt;
  }
}

// params is expected to be full degree not half degree
template <class params>
__device__ void convert_u128_to_f128_as_torus(
    double *out_re_hi, double *out_re_lo,
    double *out_im_hi, double *out_im_lo,
    const __uint128_t *in_re, const __uint128_t *in_im) {

  const double normalization = pow(2., -128.);
  Index tid = threadIdx.x;
//#pragma unroll
  for (Index i = 0; i < params::opt / 2; i++) {
    __syncthreads();
    auto out_re = u128_to_signed_to_f128(in_re[tid]);
    __syncthreads();
    auto out_im = u128_to_signed_to_f128(in_im[tid]);
    __syncthreads();

    out_re_hi[tid] = out_re.hi * normalization;
    out_re_lo[tid] = out_re.lo * normalization;
    out_im_hi[tid] = out_im.hi * normalization;
    out_im_lo[tid] = out_im.lo * normalization;

//    __syncthreads();
//    if (threadIdx.x == 0 && blockIdx.x == 0) {
//      printf("%.5f %.5f %.5f %.5f\n", out_re_hi[tid], out_re_lo[tid], out_im_hi[tid],
//             out_im_lo[tid]);
//    }
//    __syncthreads();
    tid += params::degree / params::opt;
  }
}

// params is expected to be full degree not half degree
template <class params>
__global__ void batch_convert_u128_to_f128_as_integer(
    double *out_re_hi, double *out_re_lo,
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
template <class params>
__global__ void batch_convert_u128_to_f128_as_torus(
    double *out_re_hi, double *out_re_lo,
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

template <class params, sharedMemDegree SMD>
__global__ void batch_NSMFFT_128(double *in_re_hi, double *in_re_lo,
                            double *in_im_hi,
                            double *in_im_lo,
                            double *out_re_hi, double *out_re_lo,
                            double *out_im_hi,
                            double *out_im_lo,
                            double *buffer) {
  extern __shared__ double sharedMemoryFFT[];
  double *re_hi, *re_lo, *im_hi, *im_lo;

  // debug
  __syncthreads();
  if (threadIdx.x == 0 && blockIdx.x == 0) {
    printf("Params::degree %d\n", params::degree);
    printf("opt %d\n", params::opt);
  }
  __syncthreads();

  if (SMD == NOSM) {
    re_hi = &buffer[blockIdx.x * params::degree / 2 * 4 + params::degree / 2 * 0];
    re_lo = &buffer[blockIdx.x * params::degree / 2 * 4 + params::degree / 2 * 1];
    im_hi = &buffer[blockIdx.x * params::degree / 2 * 4 + params::degree / 2 * 2];
    im_lo = &buffer[blockIdx.x * params::degree / 2 * 4 + params::degree / 2 * 3];
  } else {
    re_hi = &sharedMemoryFFT[params::degree / 2 * 0];
    re_lo = &sharedMemoryFFT[params::degree / 2 * 1];
    im_hi = &sharedMemoryFFT[params::degree / 2 * 2];
    im_lo = &sharedMemoryFFT[params::degree / 2 * 3];
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
  negacyclic_forward_fft_f128<HalfDegree<params>>(re_hi, re_lo, im_hi, im_lo);
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
__host__ void host_fourier_transform_forward_as_integer_f128(
    cudaStream_t stream, uint32_t gpu_index, double *re0, double *re1,
    double *im0, double *im1, const __uint128_t *standard, const uint32_t N,
    const uint32_t number_of_samples) {

//  for (int i = 0; i < N / 2; i++)
//  {
//    printf("%.10f\n", re0[i]);
//  }
//  printf("cpp_poly_host\n");
//  for (int i = 0; i < N; i++) {
//    print_uint128_bits(standard[i]);
//  }
//  printf("check #1\n");

//  for (int i = 0; i < 32; i++) {
//    standard[i + 32] = standard[i];
//  }

  // allocate device buffers
  double *d_re0 = (double *)cuda_malloc_async(N / 2 * sizeof(double), stream, gpu_index);
  double *d_re1 = (double *)cuda_malloc_async(N / 2 * sizeof(double), stream, gpu_index);
  double *d_im0 = (double *)cuda_malloc_async(N / 2 * sizeof(double), stream, gpu_index);
  double *d_im1 = (double *)cuda_malloc_async(N / 2 * sizeof(double), stream, gpu_index);
  __uint128_t *d_standard = (__uint128_t *)cuda_malloc_async(N * sizeof(__uint128_t), stream, gpu_index);

  // copy input into device
  cuda_memcpy_async_to_gpu(d_standard, standard, N * sizeof(__uint128_t), stream, gpu_index);

  // setup launch parameters
  size_t required_shared_memory_size = sizeof(double) * N / 2 * 4;
  int grid_size = number_of_samples;
  int block_size = params::degree / params::opt;
  bool full_sm = (required_shared_memory_size <= cuda_get_max_shared_memory(gpu_index));
  size_t buffer_size = full_sm ? 0 : (size_t)number_of_samples * N / 2  * 4;
  size_t shared_memory_size = full_sm ? required_shared_memory_size : 0;
  double *buffer = (double*)cuda_malloc_async(buffer_size, stream, gpu_index);

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
  batch_convert_u128_to_f128_as_integer<params><<<grid_size, block_size, 0, stream>>>(
      d_re0, d_re1, d_im0, d_im1, d_standard);

  // call negacyclic 128 bit forward fft.
  if (full_sm) {
    batch_NSMFFT_128<FFTDegree<params, ForwardFFT>, FULLSM><<<grid_size, block_size,
    shared_memory_size, stream>>>
        (d_re0, d_re1, d_im0, d_im1, d_re0, d_re1, d_im0, d_im1, buffer);
  } else {
    batch_NSMFFT_128<FFTDegree<params, ForwardFFT>, NOSM><<<grid_size, block_size,
    shared_memory_size, stream>>>
        (d_re0, d_re1, d_im0, d_im1, d_re0, d_re1, d_im0, d_im1, buffer);

  }

  cudaDeviceSynchronize();

//  print_debug("re_hi", d_re0, 32);
//  print_debug("d_re_lo", d_re1, 32);
//  print_debug("d_im_hi", d_im0, 32);
//  print_debug("d_im_lo", d_im1, 32);

  cuda_memcpy_async_to_cpu(re0, d_re0, N / 2 * sizeof(double), stream, gpu_index);
  cuda_memcpy_async_to_cpu(re1, d_re1, N / 2 * sizeof(double), stream, gpu_index);
  cuda_memcpy_async_to_cpu(im0, d_im0, N / 2 * sizeof(double), stream, gpu_index);
  cuda_memcpy_async_to_cpu(im1, d_im1, N / 2 * sizeof(double), stream, gpu_index);





  cuda_drop_async(d_standard, stream, gpu_index);
  cuda_drop_async(d_re0, stream, gpu_index);
  cuda_drop_async(d_re1, stream, gpu_index);
  cuda_drop_async(d_im0, stream, gpu_index);
  cuda_drop_async(d_im1, stream, gpu_index);

  cudaDeviceSynchronize();

//  printf("params::degree: %d\n", params::degree);
//  printf("params::opt: %d\n", params::opt);
//  printf("N: %d\n", N);
//  for (int i = 0; i < N; i++)
//  {
//    printf("%s\n", to_string_128(standard[i]).c_str());
//  }
//
//  for (int i = 0; i < N / 2; i++) {
////    auto re = u128_to_signed_to_f128(standard[i]);
////    auto im = u128_to_signed_to_f128(standard[i + N / 2]);
////    printf("%.10f %.10f %.10f %.10f\n", re.hi, re.lo, im.hi, im.lo);
//    printf("%.10f %.10f %.10f %.10f\n", re0[i], re1[i], im0[i], im1[i]);
//  }


}

template <class params>
__host__ void host_fourier_transform_forward_as_torus_f128(
    cudaStream_t stream, uint32_t gpu_index, double *re0, double *re1,
    double *im0, double *im1, const __uint128_t *standard, const uint32_t N,
    const uint32_t number_of_samples) {

  for (int i = 0; i < N / 2; i++)
  {
    printf("%.10f\n", re0[i]);
  }
  printf("cpp_poly_host\n");
  for (int i = 0; i < N; i++) {
    print_uint128_bits(standard[i]);
  }
  printf("check #1\n");

//  for (int i = 0; i < 32; i++) {
//    standard[i + 32] = standard[i];
//  }

  // allocate device buffers
  double *d_re0 = (double *)cuda_malloc_async(N / 2 * sizeof(double), stream, gpu_index);
  double *d_re1 = (double *)cuda_malloc_async(N / 2 * sizeof(double), stream, gpu_index);
  double *d_im0 = (double *)cuda_malloc_async(N / 2 * sizeof(double), stream, gpu_index);
  double *d_im1 = (double *)cuda_malloc_async(N / 2 * sizeof(double), stream, gpu_index);
  __uint128_t *d_standard = (__uint128_t *)cuda_malloc_async(N * sizeof(__uint128_t), stream, gpu_index);

  // copy input into device
  cuda_memcpy_async_to_gpu(d_standard, standard, N * sizeof(__uint128_t), stream, gpu_index);

  // setup launch parameters
  size_t required_shared_memory_size = sizeof(double) * N / 2 * 4;
  int grid_size = number_of_samples;
  int block_size = params::degree / params::opt;
  bool full_sm = (required_shared_memory_size <= cuda_get_max_shared_memory(gpu_index));
  size_t buffer_size = full_sm ? 0 : (size_t)number_of_samples * N / 2  * 4;
  size_t shared_memory_size = full_sm ? required_shared_memory_size : 0;
  double *buffer = (double*)cuda_malloc_async(buffer_size, stream, gpu_index);

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
  batch_convert_u128_to_f128_as_torus<params><<<grid_size, block_size, 0, stream>>>(
      d_re0, d_re1, d_im0, d_im1, d_standard);

  // call negacyclic 128 bit forward fft.
  if (full_sm) {
    batch_NSMFFT_128<FFTDegree<params, ForwardFFT>, FULLSM><<<grid_size, block_size,
    shared_memory_size, stream>>>
        (d_re0, d_re1, d_im0, d_im1, d_re0, d_re1, d_im0, d_im1, buffer);
  } else {
    batch_NSMFFT_128<FFTDegree<params, ForwardFFT>, NOSM><<<grid_size, block_size,
    shared_memory_size, stream>>>
        (d_re0, d_re1, d_im0, d_im1, d_re0, d_re1, d_im0, d_im1, buffer);

  }

  cudaDeviceSynchronize();

//  print_debug("re_hi", d_re0, 32);
//  print_debug("d_re_lo", d_re1, 32);
//  print_debug("d_im_hi", d_im0, 32);
//  print_debug("d_im_lo", d_im1, 32);

  cuda_memcpy_async_to_cpu(re0, d_re0, N / 2 * sizeof(double), stream, gpu_index);
  cuda_memcpy_async_to_cpu(re1, d_re1, N / 2 * sizeof(double), stream, gpu_index);
  cuda_memcpy_async_to_cpu(im0, d_im0, N / 2 * sizeof(double), stream, gpu_index);
  cuda_memcpy_async_to_cpu(im1, d_im1, N / 2 * sizeof(double), stream, gpu_index);





  cuda_drop_async(d_standard, stream, gpu_index);
  cuda_drop_async(d_re0, stream, gpu_index);
  cuda_drop_async(d_re1, stream, gpu_index);
  cuda_drop_async(d_im0, stream, gpu_index);
  cuda_drop_async(d_im1, stream, gpu_index);

  cudaDeviceSynchronize();

  printf("params::degree: %d\n", params::degree);
  printf("params::opt: %d\n", params::opt);
  printf("N: %d\n", N);
  for (int i = 0; i < N; i++)
  {
    printf("%s\n", to_string_128(standard[i]).c_str());
  }

  for (int i = 0; i < N / 2; i++) {
//    auto re = u128_to_signed_to_f128(standard[i]);
//    auto im = u128_to_signed_to_f128(standard[i + N / 2]);
//    printf("%.10f %.10f %.10f %.10f\n", re.hi, re.lo, im.hi, im.lo);
    printf("%.10f %.10f %.10f %.10f\n", re0[i], re1[i], im0[i], im1[i]);
  }


}

template <class params>
__host__ void host_fourier_transform_backward_as_torus_f128(
    cudaStream_t stream, uint32_t gpu_index, __uint128_t *standard, double const *re0, double const
    *re1,
    double const *im0, double const  *im1, const uint32_t N,
    const uint32_t number_of_samples) {

    // allocate device buffers
  double *d_re0 = (double *)cuda_malloc_async(N / 2 * sizeof(double), stream, gpu_index);
  double *d_re1 = (double *)cuda_malloc_async(N / 2 * sizeof(double), stream, gpu_index);
  double *d_im0 = (double *)cuda_malloc_async(N / 2 * sizeof(double), stream, gpu_index);
  double *d_im1 = (double *)cuda_malloc_async(N / 2 * sizeof(double), stream, gpu_index);
  __uint128_t *d_standard = (__uint128_t *)cuda_malloc_async(N * sizeof(__uint128_t), stream, gpu_index);

//  // copy input into device
  cuda_memcpy_async_to_gpu(d_re0, standard, N / 2 * sizeof(double), stream, gpu_index);
  cuda_memcpy_async_to_gpu(d_re1, standard, N / 2 * sizeof(double), stream, gpu_index);
  cuda_memcpy_async_to_gpu(d_im0, standard, N / 2 * sizeof(double), stream, gpu_index);
  cuda_memcpy_async_to_gpu(d_im1, standard, N / 2 * sizeof(double), stream, gpu_index);



  // setup launch parameters
  size_t required_shared_memory_size = sizeof(double) * N / 2 * 4;
  int grid_size = number_of_samples;
  int block_size = params::degree / params::opt;
  bool full_sm = (required_shared_memory_size <= cuda_get_max_shared_memory(gpu_index));
  size_t buffer_size = full_sm ? 0 : (size_t)number_of_samples * N / 2  * 4;
  size_t shared_memory_size = full_sm ? required_shared_memory_size : 0;
  double *buffer = (double*)cuda_malloc_async(buffer_size, stream, gpu_index);

  // configure shared memory for batch fft kernel
  if (full_sm) {
    check_cuda_error(cudaFuncSetAttribute(
        batch_NSMFFT_128<FFTDegree<params, ForwardFFT>, FULLSM>,
        cudaFuncAttributeMaxDynamicSharedMemorySize, shared_memory_size));
    check_cuda_error(cudaFuncSetCacheConfig(
        batch_NSMFFT_128<FFTDegree<params, ForwardFFT>, FULLSM>,
        cudaFuncCachePreferShared));
  }

//  // convert u128 into 4 x double
//  batch_convert_u128_to_f128_as_torus<params><<<grid_size, block_size, 0, stream>>>(
//      d_re0, d_re1, d_im0, d_im1, d_standard);

  // call negacyclic 128 bit forward fft.
//  if (full_sm) {
//    negacyclic_inverse_fft_f128<FFTDegree<params, ForwardFFT>, FULLSM><<<grid_size, block_size,
//    shared_memory_size, stream>>>
//        (d_re0, d_re1, d_im0, d_im1, d_re0, d_re1, d_im0, d_im1, buffer);
//  } else {
//    batch_NSMFFT_128<FFTDegree<params, ForwardFFT>, NOSM><<<grid_size, block_size,
//    shared_memory_size, stream>>>
//        (d_re0, d_re1, d_im0, d_im1, d_re0, d_re1, d_im0, d_im1, buffer);
//
//  }
//
//  cudaDeviceSynchronize();

////  print_debug("re_hi", d_re0, 32);
////  print_debug("d_re_lo", d_re1, 32);
////  print_debug("d_im_hi", d_im0, 32);
////  print_debug("d_im_lo", d_im1, 32);
//

  cuda_memcpy_async_to_cpu(standard, d_standard, N * sizeof(__uint128_t), stream, gpu_index);
  cuda_drop_async(d_standard, stream, gpu_index);
  cuda_drop_async(d_re0, stream, gpu_index);
  cuda_drop_async(d_re1, stream, gpu_index);
  cuda_drop_async(d_im0, stream, gpu_index);
  cuda_drop_async(d_im1, stream, gpu_index);

  cudaDeviceSynchronize();
//
//  printf("params::degree: %d\n", params::degree);
//  printf("params::opt: %d\n", params::opt);
//  printf("N: %d\n", N);
//  for (int i = 0; i < N; i++)
//  {
//    printf("%s\n", to_string_128(standard[i]).c_str());
//  }
//
//  for (int i = 0; i < N / 2; i++) {
////    auto re = u128_to_signed_to_f128(standard[i]);
////    auto im = u128_to_signed_to_f128(standard[i + N / 2]);
////    printf("%.10f %.10f %.10f %.10f\n", re.hi, re.lo, im.hi, im.lo);
//    printf("%.10f %.10f %.10f %.10f\n", re0[i], re1[i], im0[i], im1[i]);
//  }
//

}



#endif // TFHE_RS_BACKENDS_TFHE_CUDA_BACKEND_CUDA_SRC_FFT128_FFT128_CUH_
