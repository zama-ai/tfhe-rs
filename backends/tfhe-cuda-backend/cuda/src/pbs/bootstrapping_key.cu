#include "bootstrapping_key.cuh"

void cuda_convert_lwe_programmable_bootstrap_key_32(
    void *stream, uint32_t gpu_index, void *dest, void const *src,
    uint32_t input_lwe_dim, uint32_t glwe_dim, uint32_t level_count,
    uint32_t polynomial_size) {
  uint32_t total_polynomials =
      input_lwe_dim * (glwe_dim + 1) * (glwe_dim + 1) * level_count;
  cuda_convert_lwe_programmable_bootstrap_key<uint32_t, int32_t>(
      static_cast<cudaStream_t>(stream), gpu_index, (double2 *)dest,
      (const int32_t *)src, polynomial_size, total_polynomials);
}

void cuda_convert_lwe_programmable_bootstrap_key_64(
    void *stream, uint32_t gpu_index, void *dest, void const *src,
    uint32_t input_lwe_dim, uint32_t glwe_dim, uint32_t level_count,
    uint32_t polynomial_size) {
  uint32_t total_polynomials =
      input_lwe_dim * (glwe_dim + 1) * (glwe_dim + 1) * level_count;
  cuda_convert_lwe_programmable_bootstrap_key<uint64_t, int64_t>(
      static_cast<cudaStream_t>(stream), gpu_index, (double2 *)dest,
      (const int64_t *)src, polynomial_size, total_polynomials);
}

void cuda_convert_lwe_multi_bit_programmable_bootstrap_key_64(
    void *stream, uint32_t gpu_index, void *dest, void const *src,
    uint32_t input_lwe_dim, uint32_t glwe_dim, uint32_t level_count,
    uint32_t polynomial_size, uint32_t grouping_factor) {
  uint32_t total_polynomials = input_lwe_dim * (glwe_dim + 1) * (glwe_dim + 1) *
                               level_count * (1 << grouping_factor) /
                               grouping_factor;
  size_t buffer_size = total_polynomials * polynomial_size * sizeof(uint64_t);

  cuda_memcpy_async_to_gpu((uint64_t *)dest, (uint64_t *)src, buffer_size,
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

template __device__ const uint64_t *get_multi_bit_ith_lwe_gth_group_kth_block(
    const uint64_t *ptr, int g, int i, int k, int level,
    uint32_t grouping_factor, uint32_t polynomial_size, uint32_t glwe_dimension,
    uint32_t level_count);

template __device__ const double2 *get_multi_bit_ith_lwe_gth_group_kth_block(
    const double2 *ptr, int g, int i, int k, int level,
    uint32_t grouping_factor, uint32_t polynomial_size, uint32_t glwe_dimension,
    uint32_t level_count);

void cuda_fourier_polynomial_mul(void *stream_v, uint32_t gpu_index,
                                 void const *_input1, void const *_input2,
                                 void *_output, uint32_t polynomial_size,
                                 uint32_t total_polynomials) {

  auto stream = static_cast<cudaStream_t>(stream_v);
  cudaSetDevice(gpu_index);
  auto input1 = (double2 *)_input1;
  auto input2 = (double2 *)_input2;
  auto output = (double2 *)_output;

  size_t shared_memory_size = sizeof(double2) * polynomial_size / 2;

  int gridSize = total_polynomials;
  int blockSize = polynomial_size / choose_opt_amortized(polynomial_size);

  double2 *buffer;
  switch (polynomial_size) {
  case 256:
    if (shared_memory_size <= cuda_get_max_shared_memory(0)) {
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
          shared_memory_size * total_polynomials, stream, gpu_index);
      batch_polynomial_mul<FFTDegree<AmortizedDegree<256>, ForwardFFT>, NOSM>
          <<<gridSize, blockSize, 0, stream>>>(input1, input2, output, buffer);
    }
    break;
  case 512:
    if (shared_memory_size <= cuda_get_max_shared_memory(0)) {
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
          shared_memory_size * total_polynomials, stream, gpu_index);
      batch_polynomial_mul<FFTDegree<AmortizedDegree<512>, ForwardFFT>, NOSM>
          <<<gridSize, blockSize, 0, stream>>>(input1, input2, output, buffer);
    }
    break;
  case 1024:
    if (shared_memory_size <= cuda_get_max_shared_memory(0)) {
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
          shared_memory_size * total_polynomials, stream, gpu_index);
      batch_polynomial_mul<FFTDegree<AmortizedDegree<1024>, ForwardFFT>, NOSM>
          <<<gridSize, blockSize, 0, stream>>>(input1, input2, output, buffer);
    }
    break;
  case 2048:
    if (shared_memory_size <= cuda_get_max_shared_memory(0)) {
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
          shared_memory_size * total_polynomials, stream, gpu_index);
      batch_polynomial_mul<FFTDegree<AmortizedDegree<2048>, ForwardFFT>, NOSM>
          <<<gridSize, blockSize, 0, stream>>>(input1, input2, output, buffer);
    }
    break;
  case 4096:
    if (shared_memory_size <= cuda_get_max_shared_memory(0)) {
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
          shared_memory_size * total_polynomials, stream, gpu_index);
      batch_polynomial_mul<FFTDegree<AmortizedDegree<4096>, ForwardFFT>, NOSM>
          <<<gridSize, blockSize, 0, stream>>>(input1, input2, output, buffer);
    }
    break;
  case 8192:
    if (shared_memory_size <= cuda_get_max_shared_memory(0)) {
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
          shared_memory_size * total_polynomials, stream, gpu_index);
      batch_polynomial_mul<FFTDegree<AmortizedDegree<8192>, ForwardFFT>, NOSM>
          <<<gridSize, blockSize, 0, stream>>>(input1, input2, output, buffer);
    }
    break;
  case 16384:
    if (shared_memory_size <= cuda_get_max_shared_memory(0)) {
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
          shared_memory_size * total_polynomials, stream, gpu_index);
      batch_polynomial_mul<FFTDegree<AmortizedDegree<16384>, ForwardFFT>, NOSM>
          <<<gridSize, blockSize, 0, stream>>>(input1, input2, output, buffer);
    }
    break;
  default:
    break;
  }
  cuda_drop_async(buffer, stream, gpu_index);
}
