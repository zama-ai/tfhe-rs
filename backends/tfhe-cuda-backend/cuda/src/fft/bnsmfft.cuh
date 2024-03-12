#ifndef GPU_BOOTSTRAP_FFT_CUH
#define GPU_BOOTSTRAP_FFT_CUH

#include "polynomial/functions.cuh"
#include "polynomial/parameters.cuh"
#include "twiddles.cuh"
#include "types/complex/operations.cuh"

template <class params>
__device__ typename params::FFT::value_type get_neg_twiddle(int i) {
  typename params::FFT::value_type w = {0, 0};
  switch (params::degree) {
  case 128:
    w = neg_twist_128[i];
    break;
  case 256:
    w = neg_twist_256[i];
    break;
  case 512:
    w = neg_twist_512[i];
    break;
  case 1024:
    w = neg_twist_1024[i];
    break;
  case 2048:
    w = neg_twist_2048[i];
    break;
  case 4096:
    w = neg_twist_2048[i];
    break;
  default:
    break;
  }

  return w;
}

/*
 * Direct negacyclic FFT:
 */
template <class params> __device__ void NSMFFT_direct(double2 *A) {
  // twist polynomial
  int tid = threadIdx.x;
  for (int i = 0; i < params::opt; i++) {
    typename params::FFT::value_type w = get_neg_twiddle<params>(tid);
    A[tid] *= w;
    tid += params::degree / params::opt;
  }

  // apply cyclic forward fft
  params::FFT().execute(reinterpret_cast<void *>(A));
}

/*
 * negacyclic inverse fft
 */
template <class params> __device__ void NSMFFT_inverse(double2 *A) {
  double scale = 1.0 / params::degree;

  params::IFFT().execute(reinterpret_cast<void *>(A));

  int tid = threadIdx.x;
  for (int i = 0; i < params::opt; i++) {
    typename params::FFT::value_type w = get_neg_twiddle<params>(tid);
    w.x *= scale;
    w.y *= -scale;
    A[tid] *= w;
    tid += params::degree / params::opt;
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
