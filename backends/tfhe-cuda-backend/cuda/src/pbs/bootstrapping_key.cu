#include "bootstrapping_key.cuh"
#include "checked_arithmetic.h"

void cuda_convert_lwe_programmable_bootstrap_key_32_async(
    void *stream, uint32_t gpu_index, void *dest, void const *src,
    uint32_t input_lwe_dim, uint32_t glwe_dim, uint32_t level_count,
    uint32_t polynomial_size) {
  size_t total_polynomials =
      safe_mul((size_t)input_lwe_dim, (size_t)(glwe_dim + 1),
               (size_t)(glwe_dim + 1), (size_t)level_count);
  cuda_convert_lwe_programmable_bootstrap_key<uint32_t, int32_t>(
      static_cast<cudaStream_t>(stream), gpu_index, (double2 *)dest,
      (const int32_t *)src, polynomial_size, total_polynomials);
}

void cuda_convert_lwe_programmable_bootstrap_key_64_async(
    void *stream, uint32_t gpu_index, void *dest, void const *src,
    uint32_t input_lwe_dim, uint32_t glwe_dim, uint32_t level_count,
    uint32_t polynomial_size) {
  size_t total_polynomials =
      safe_mul((size_t)input_lwe_dim, (size_t)(glwe_dim + 1),
               (size_t)(glwe_dim + 1), (size_t)level_count);
  cuda_convert_lwe_programmable_bootstrap_key<uint64_t, int64_t>(
      static_cast<cudaStream_t>(stream), gpu_index, (double2 *)dest,
      (const int64_t *)src, polynomial_size, total_polynomials);
}

void cuda_convert_lwe_multi_bit_programmable_bootstrap_key_64_async(
    void *stream, uint32_t gpu_index, void *dest, void const *src,
    uint32_t input_lwe_dim, uint32_t glwe_dim, uint32_t level_count,
    uint32_t polynomial_size, uint32_t grouping_factor) {
  size_t total_polynomials =
      safe_mul((size_t)input_lwe_dim, (size_t)(glwe_dim + 1),
               (size_t)(glwe_dim + 1), (size_t)level_count);
  total_polynomials =
      safe_mul(total_polynomials, (size_t)(1 << grouping_factor)) /
      grouping_factor;
  size_t buffer_size =
      safe_mul_sizeof<uint64_t>(total_polynomials, (size_t)polynomial_size);

  cuda_memcpy_async_to_gpu((uint64_t *)dest, (uint64_t *)src, buffer_size,
                           static_cast<cudaStream_t>(stream), gpu_index);
}

void cuda_convert_lwe_multi_bit_programmable_bootstrap_key_128_async(
    void *stream, uint32_t gpu_index, void *dest, void const *src,
    uint32_t input_lwe_dim, uint32_t glwe_dim, uint32_t level_count,
    uint32_t polynomial_size, uint32_t grouping_factor) {
  size_t total_polynomials =
      safe_mul((size_t)input_lwe_dim, (size_t)(glwe_dim + 1),
               (size_t)(glwe_dim + 1), (size_t)level_count);
  total_polynomials =
      safe_mul(total_polynomials, (size_t)(1 << grouping_factor)) /
      grouping_factor;
  size_t buffer_size =
      safe_mul_sizeof<__uint128_t>(total_polynomials, (size_t)polynomial_size);

  cuda_memcpy_async_to_gpu((__uint128_t *)dest, (__uint128_t *)src, buffer_size,
                           static_cast<cudaStream_t>(stream), gpu_index);
}

// We need these lines so the compiler knows how to specialize these functions
template __device__ const uint64_t *
get_ith_mask_kth_block(const uint64_t *ptr, int i, int k, int level,
                       uint32_t polynomial_size, int glwe_dimension,
                       uint32_t level_count);
template __device__ const uint32_t *
get_ith_mask_kth_block(const uint32_t *ptr, int i, int k, int level,
                       uint32_t polynomial_size, int glwe_dimension,
                       uint32_t level_count);
template __device__ const double2 *
get_ith_mask_kth_block(const double2 *ptr, int i, int k, int level,
                       uint32_t polynomial_size, int glwe_dimension,
                       uint32_t level_count);
template __device__ uint64_t *get_ith_mask_kth_block(uint64_t *ptr, int i,
                                                     int k, int level,
                                                     uint32_t polynomial_size,
                                                     int glwe_dimension,
                                                     uint32_t level_count);
template __device__ uint32_t *get_ith_mask_kth_block(uint32_t *ptr, int i,
                                                     int k, int level,
                                                     uint32_t polynomial_size,
                                                     int glwe_dimension,
                                                     uint32_t level_count);
template __device__ double2 *get_ith_mask_kth_block(double2 *ptr, int i, int k,
                                                    int level,
                                                    uint32_t polynomial_size,
                                                    int glwe_dimension,
                                                    uint32_t level_count);

template __device__ uint64_t *get_ith_body_kth_block(uint64_t *ptr, int i,
                                                     int k, int level,
                                                     uint32_t polynomial_size,
                                                     int glwe_dimension,
                                                     uint32_t level_count);
template __device__ uint32_t *get_ith_body_kth_block(uint32_t *ptr, int i,
                                                     int k, int level,
                                                     uint32_t polynomial_size,
                                                     int glwe_dimension,
                                                     uint32_t level_count);
template __device__ double2 *get_ith_body_kth_block(double2 *ptr, int i, int k,
                                                    int level,
                                                    uint32_t polynomial_size,
                                                    int glwe_dimension,
                                                    uint32_t level_count);

template __device__ const __uint128_t *
get_multi_bit_ith_lwe_gth_group_kth_block(const __uint128_t *ptr, int g, int i,
                                          int k, int level,
                                          uint32_t grouping_factor,
                                          uint32_t polynomial_size,
                                          uint32_t glwe_dimension,
                                          uint32_t level_count);

template __device__ const uint64_t *get_multi_bit_ith_lwe_gth_group_kth_block(
    const uint64_t *ptr, int g, int i, int k, int level,
    uint32_t grouping_factor, uint32_t polynomial_size, uint32_t glwe_dimension,
    uint32_t level_count);

template __device__ const double2 *get_multi_bit_ith_lwe_gth_group_kth_block(
    const double2 *ptr, int g, int i, int k, int level,
    uint32_t grouping_factor, uint32_t polynomial_size, uint32_t glwe_dimension,
    uint32_t level_count);

void cuda_fourier_polynomial_mul_async(void *stream_v, uint32_t gpu_index,
                                       void const *_input1, void const *_input2,
                                       void *_output, uint32_t polynomial_size,
                                       uint32_t total_polynomials) {

  auto stream = static_cast<cudaStream_t>(stream_v);
  cuda_set_device(gpu_index);
  auto input1 = (double2 *)_input1;
  auto input2 = (double2 *)_input2;
  auto output = (double2 *)_output;

  size_t shared_memory_size = safe_mul_sizeof<double2>(polynomial_size / 2);

  int gridSize = total_polynomials;
  int blockSize = polynomial_size / choose_opt_amortized(polynomial_size);

  auto max_shared_memory = cuda_get_max_shared_memory(gpu_index);

  double2 *buffer;
  switch (polynomial_size) {
  case 256:
    if (shared_memory_size <= max_shared_memory) {
      buffer = (double2 *)cuda_malloc_async(0, stream, gpu_index);
      check_cuda_error(cudaFuncSetAttribute(
          batch_polynomial_mul<FFTDegree<AmortizedDegree<256>, ForwardFFT>,
                               FULLSM>,
          cudaFuncAttributeMaxDynamicSharedMemorySize, shared_memory_size));
      check_cuda_error(cudaFuncSetCacheConfig(
          batch_polynomial_mul<FFTDegree<AmortizedDegree<256>, ForwardFFT>,
                               FULLSM>,
          cudaFuncCachePreferShared));
      batch_polynomial_mul<FFTDegree<AmortizedDegree<256>, ForwardFFT>, FULLSM>
          <<<gridSize, blockSize, shared_memory_size, stream>>>(input1, input2,
                                                                output, buffer);
    } else {
      buffer = (double2 *)cuda_malloc_async(
          safe_mul(shared_memory_size, (size_t)total_polynomials), stream,
          gpu_index);
      batch_polynomial_mul<FFTDegree<AmortizedDegree<256>, ForwardFFT>, NOSM>
          <<<gridSize, blockSize, 0, stream>>>(input1, input2, output, buffer);
    }
    break;
  case 512:
    if (shared_memory_size <= max_shared_memory) {
      buffer = (double2 *)cuda_malloc_async(0, stream, gpu_index);
      check_cuda_error(cudaFuncSetAttribute(
          batch_polynomial_mul<FFTDegree<AmortizedDegree<521>, ForwardFFT>,
                               FULLSM>,
          cudaFuncAttributeMaxDynamicSharedMemorySize, shared_memory_size));
      check_cuda_error(cudaFuncSetCacheConfig(
          batch_polynomial_mul<FFTDegree<AmortizedDegree<512>, ForwardFFT>,
                               FULLSM>,
          cudaFuncCachePreferShared));
      batch_polynomial_mul<FFTDegree<AmortizedDegree<512>, ForwardFFT>, FULLSM>
          <<<gridSize, blockSize, shared_memory_size, stream>>>(input1, input2,
                                                                output, buffer);
    } else {
      buffer = (double2 *)cuda_malloc_async(
          safe_mul(shared_memory_size, (size_t)total_polynomials), stream,
          gpu_index);
      batch_polynomial_mul<FFTDegree<AmortizedDegree<512>, ForwardFFT>, NOSM>
          <<<gridSize, blockSize, 0, stream>>>(input1, input2, output, buffer);
    }
    break;
  case 1024:
    if (shared_memory_size <= max_shared_memory) {
      buffer = (double2 *)cuda_malloc_async(0, stream, gpu_index);
      check_cuda_error(cudaFuncSetAttribute(
          batch_polynomial_mul<FFTDegree<AmortizedDegree<1024>, ForwardFFT>,
                               FULLSM>,
          cudaFuncAttributeMaxDynamicSharedMemorySize, shared_memory_size));
      check_cuda_error(cudaFuncSetCacheConfig(
          batch_polynomial_mul<FFTDegree<AmortizedDegree<1024>, ForwardFFT>,
                               FULLSM>,
          cudaFuncCachePreferShared));
      batch_polynomial_mul<FFTDegree<AmortizedDegree<1024>, ForwardFFT>, FULLSM>
          <<<gridSize, blockSize, shared_memory_size, stream>>>(input1, input2,
                                                                output, buffer);
    } else {
      buffer = (double2 *)cuda_malloc_async(
          safe_mul(shared_memory_size, (size_t)total_polynomials), stream,
          gpu_index);
      batch_polynomial_mul<FFTDegree<AmortizedDegree<1024>, ForwardFFT>, NOSM>
          <<<gridSize, blockSize, 0, stream>>>(input1, input2, output, buffer);
    }
    break;
  case 2048:
    if (shared_memory_size <= max_shared_memory) {
      buffer = (double2 *)cuda_malloc_async(0, stream, gpu_index);
      check_cuda_error(cudaFuncSetAttribute(
          batch_polynomial_mul<FFTDegree<AmortizedDegree<2048>, ForwardFFT>,
                               FULLSM>,
          cudaFuncAttributeMaxDynamicSharedMemorySize, shared_memory_size));
      check_cuda_error(cudaFuncSetCacheConfig(
          batch_polynomial_mul<FFTDegree<AmortizedDegree<2048>, ForwardFFT>,
                               FULLSM>,
          cudaFuncCachePreferShared));
      batch_polynomial_mul<FFTDegree<AmortizedDegree<2048>, ForwardFFT>, FULLSM>
          <<<gridSize, blockSize, shared_memory_size, stream>>>(input1, input2,
                                                                output, buffer);
    } else {
      buffer = (double2 *)cuda_malloc_async(
          safe_mul(shared_memory_size, (size_t)total_polynomials), stream,
          gpu_index);
      batch_polynomial_mul<FFTDegree<AmortizedDegree<2048>, ForwardFFT>, NOSM>
          <<<gridSize, blockSize, 0, stream>>>(input1, input2, output, buffer);
    }
    break;
  case 4096:
    if (shared_memory_size <= max_shared_memory) {
      buffer = (double2 *)cuda_malloc_async(0, stream, gpu_index);
      check_cuda_error(cudaFuncSetAttribute(
          batch_polynomial_mul<FFTDegree<AmortizedDegree<4096>, ForwardFFT>,
                               FULLSM>,
          cudaFuncAttributeMaxDynamicSharedMemorySize, shared_memory_size));
      check_cuda_error(cudaFuncSetCacheConfig(
          batch_polynomial_mul<FFTDegree<AmortizedDegree<4096>, ForwardFFT>,
                               FULLSM>,
          cudaFuncCachePreferShared));
      batch_polynomial_mul<FFTDegree<AmortizedDegree<4096>, ForwardFFT>, FULLSM>
          <<<gridSize, blockSize, shared_memory_size, stream>>>(input1, input2,
                                                                output, buffer);
    } else {
      buffer = (double2 *)cuda_malloc_async(
          safe_mul(shared_memory_size, (size_t)total_polynomials), stream,
          gpu_index);
      batch_polynomial_mul<FFTDegree<AmortizedDegree<4096>, ForwardFFT>, NOSM>
          <<<gridSize, blockSize, 0, stream>>>(input1, input2, output, buffer);
    }
    break;
  case 8192:
    if (shared_memory_size <= max_shared_memory) {
      buffer = (double2 *)cuda_malloc_async(0, stream, gpu_index);
      check_cuda_error(cudaFuncSetAttribute(
          batch_polynomial_mul<FFTDegree<AmortizedDegree<8192>, ForwardFFT>,
                               FULLSM>,
          cudaFuncAttributeMaxDynamicSharedMemorySize, shared_memory_size));
      check_cuda_error(cudaFuncSetCacheConfig(
          batch_polynomial_mul<FFTDegree<AmortizedDegree<8192>, ForwardFFT>,
                               FULLSM>,
          cudaFuncCachePreferShared));
      batch_polynomial_mul<FFTDegree<AmortizedDegree<8192>, ForwardFFT>, FULLSM>
          <<<gridSize, blockSize, shared_memory_size, stream>>>(input1, input2,
                                                                output, buffer);
    } else {
      buffer = (double2 *)cuda_malloc_async(
          safe_mul(shared_memory_size, (size_t)total_polynomials), stream,
          gpu_index);
      batch_polynomial_mul<FFTDegree<AmortizedDegree<8192>, ForwardFFT>, NOSM>
          <<<gridSize, blockSize, 0, stream>>>(input1, input2, output, buffer);
    }
    break;
  case 16384:
    if (shared_memory_size <= max_shared_memory) {
      buffer = (double2 *)cuda_malloc_async(0, stream, gpu_index);
      check_cuda_error(cudaFuncSetAttribute(
          batch_polynomial_mul<FFTDegree<AmortizedDegree<16384>, ForwardFFT>,
                               FULLSM>,
          cudaFuncAttributeMaxDynamicSharedMemorySize, shared_memory_size));
      check_cuda_error(cudaFuncSetCacheConfig(
          batch_polynomial_mul<FFTDegree<AmortizedDegree<16384>, ForwardFFT>,
                               FULLSM>,
          cudaFuncCachePreferShared));
      batch_polynomial_mul<FFTDegree<AmortizedDegree<16384>, ForwardFFT>,
                           FULLSM>
          <<<gridSize, blockSize, shared_memory_size, stream>>>(input1, input2,
                                                                output, buffer);
    } else {
      buffer = (double2 *)cuda_malloc_async(
          safe_mul(shared_memory_size, (size_t)total_polynomials), stream,
          gpu_index);
      batch_polynomial_mul<FFTDegree<AmortizedDegree<16384>, ForwardFFT>, NOSM>
          <<<gridSize, blockSize, 0, stream>>>(input1, input2, output, buffer);
    }
    break;
  default:
    break;
  }
  check_cuda_error(cudaGetLastError());

  cuda_drop_async(buffer, stream, gpu_index);
}

void cuda_convert_lwe_programmable_bootstrap_key_u128(
    cudaStream_t stream, uint32_t gpu_index, double *dest,
    __uint128_t const *src, uint32_t polynomial_size,
    uint32_t total_polynomials) {

  // Here the buffer size is the size of double times the number of polynomials
  // time 4 each polynomial is represented with 4 double array with size
  // polynomial_size / 2 into the complex domain to perform the FFT
  size_t buffer_size = safe_mul_sizeof<double>(
      (size_t)total_polynomials, (size_t)(polynomial_size / 2), (size_t)4);

  __uint128_t *d_standard =
      (__uint128_t *)cuda_malloc_async(buffer_size, stream, gpu_index);

  cuda_memcpy_async_to_gpu(d_standard, src, buffer_size, stream, gpu_index);

  switch (polynomial_size) {
  case 256:
    convert_u128_to_f128_and_forward_fft_128<AmortizedDegree<256>>(
        stream, gpu_index, dest, d_standard, total_polynomials);
    break;
  case 512:
    convert_u128_to_f128_and_forward_fft_128<AmortizedDegree<512>>(
        stream, gpu_index, dest, d_standard, total_polynomials);
    break;
  case 1024:
    convert_u128_to_f128_and_forward_fft_128<AmortizedDegree<1024>>(
        stream, gpu_index, dest, d_standard, total_polynomials);
    break;
  case 2048:
    convert_u128_to_f128_and_forward_fft_128<AmortizedDegree<2048>>(
        stream, gpu_index, dest, d_standard, total_polynomials);
    break;
  case 4096:
    convert_u128_to_f128_and_forward_fft_128<AmortizedDegree<4096>>(
        stream, gpu_index, dest, d_standard, total_polynomials);
    break;
  default:
    PANIC("Cuda error (convert BSK): unsupported polynomial size. Supported "
          "N's are powers of two in the interval [256..4096].")
  }

  cuda_drop_async(d_standard, stream, gpu_index);
}

void cuda_convert_lwe_programmable_bootstrap_key_128_async(
    void *stream, uint32_t gpu_index, void *dest, void const *src,
    uint32_t input_lwe_dim, uint32_t glwe_dim, uint32_t level_count,
    uint32_t polynomial_size) {

  size_t total_polynomials =
      safe_mul((size_t)input_lwe_dim, (size_t)(glwe_dim + 1),
               (size_t)(glwe_dim + 1), (size_t)level_count);
  cuda_convert_lwe_programmable_bootstrap_key_u128(
      static_cast<cudaStream_t>(stream), gpu_index, (double *)dest,
      (const __uint128_t *)src, polynomial_size, total_polynomials);
}
