#include "bootstrapping_key.cuh"
#include "checked_arithmetic.h"
#include "programmable_bootstrap_classic.cuh"

void cuda_convert_lwe_programmable_bootstrap_key_32_async(
    void *stream, uint32_t gpu_index, void *dest, void const *src,
    uint32_t input_lwe_dim, uint32_t glwe_dim, uint32_t level_count,
    uint32_t polynomial_size) {
  size_t total_polynomials =
      safe_mul((size_t)input_lwe_dim, (size_t)(glwe_dim + 1),
               (size_t)(glwe_dim + 1), (size_t)level_count);
  // We don't have a specialized version for 32 bit
  bool use_specialized = false;
  cuda_convert_lwe_programmable_bootstrap_key<uint32_t, int32_t>(
      static_cast<cudaStream_t>(stream), gpu_index, (double2 *)dest,
      (const int32_t *)src, polynomial_size, total_polynomials, use_specialized,
      /*use_throughput_oriented=*/false);
}

void cuda_convert_lwe_programmable_bootstrap_key_64_async(
    void *stream, uint32_t gpu_index, void *dest, void const *src,
    uint32_t input_lwe_dim, uint32_t glwe_dim, uint32_t level_count,
    uint32_t polynomial_size) {
  size_t total_polynomials =
      safe_mul((size_t)input_lwe_dim, (size_t)(glwe_dim + 1),
               (size_t)(glwe_dim + 1), (size_t)level_count);
  auto max_shared_memory = cuda_get_max_shared_memory(gpu_index);
  bool use_specialized = supports_specialized_2_2_params<uint64_t>(
      polynomial_size, glwe_dim, level_count, max_shared_memory);
  bool use_throughput_oriented =
      use_specialized && specialized_2_2_use_throughput_oriented<uint64_t>(
                             polynomial_size, glwe_dim, level_count,
                             input_lwe_dim, max_shared_memory);
  cuda_convert_lwe_programmable_bootstrap_key<uint64_t, int64_t>(
      static_cast<cudaStream_t>(stream), gpu_index, (double2 *)dest,
      (const int64_t *)src, polynomial_size, total_polynomials, use_specialized,
      use_throughput_oriented);
}

// Only used for testing to keep the vanilla layout of the bsk.
void cuda_convert_lwe_programmable_bootstrap_key_standard_64_async(
    void *stream, uint32_t gpu_index, void *dest, void const *src,
    uint32_t input_lwe_dim, uint32_t glwe_dim, uint32_t level_count,
    uint32_t polynomial_size) {
  size_t total_polynomials =
      safe_mul((size_t)input_lwe_dim, (size_t)(glwe_dim + 1),
               (size_t)(glwe_dim + 1), (size_t)level_count);
  // Force vanilla FFT layout.
  constexpr bool use_specialized_fft_2_2 = false;
  cuda_convert_lwe_programmable_bootstrap_key<uint64_t, int64_t>(
      static_cast<cudaStream_t>(stream), gpu_index, (double2 *)dest,
      (const int64_t *)src, polynomial_size, total_polynomials,
      use_specialized_fft_2_2, /*use_throughput_oriented=*/false);
}

// Only used during testing to convert the classical bsk in the specialized
// 2_2_params layout that works better for the global loads when using
// registers.
void cuda_convert_lwe_programmable_bootstrap_key_specialized_2_2_64_async(
    void *stream, uint32_t gpu_index, void *dest, void const *src,
    uint32_t input_lwe_dim, uint32_t glwe_dim, uint32_t level_count,
    uint32_t polynomial_size) {
  size_t total_polynomials =
      safe_mul((size_t)input_lwe_dim, (size_t)(glwe_dim + 1),
               (size_t)(glwe_dim + 1), (size_t)level_count);
  // We will force the conversion that's why we set the boolean to true.
  constexpr bool use_specialized_fft_2_2 = true;
  auto max_shared_memory = cuda_get_max_shared_memory(gpu_index);
  bool use_throughput_oriented =
      specialized_2_2_use_throughput_oriented<uint64_t>(
          polynomial_size, glwe_dim, level_count, input_lwe_dim,
          max_shared_memory);
  cuda_convert_lwe_programmable_bootstrap_key<uint64_t, int64_t>(
      static_cast<cudaStream_t>(stream), gpu_index, (double2 *)dest,
      (const int64_t *)src, polynomial_size, total_polynomials,
      use_specialized_fft_2_2, use_throughput_oriented);
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

// Test-only entry point: negacyclic polynomial multiplication driven by the
// throughput-oriented FFT16x4x16 cores (the FFT used by the specialized
// 2_2_params PBS). Hardcoded to polynomial_size == 2048 and requires sm_90
// (H100); callers must gate accordingly. See batch_polynomial_mul_fft16x4x16.
void cuda_fourier_polynomial_mul_fft16x4x16_async(
    void *stream_v, uint32_t gpu_index, void const *_input1,
    void const *_input2, void *_output, uint32_t polynomial_size,
    uint32_t total_polynomials) {

  if (polynomial_size != 2048)
    PANIC("cuda_fourier_polynomial_mul_fft16x4x16_async only supports "
          "polynomial_size == 2048");

  auto stream = static_cast<cudaStream_t>(stream_v);
  cuda_set_device(gpu_index);
  auto input1 = (const double2 *)_input1;
  auto input2 = (const double2 *)_input2;
  auto output = (double2 *)_output;

  using params = AccumulatorDegree<2048>;
  size_t shared_memory_size = FFT16x4x16_DUAL_SMEM_BYTES;

  int gridSize = total_polynomials;
  int blockSize = polynomial_size / params::opt; // 64

  check_cuda_error(cudaFuncSetAttribute(
      batch_polynomial_mul_fft16x4x16<params>,
      cudaFuncAttributeMaxDynamicSharedMemorySize, shared_memory_size));
  check_cuda_error(
      cudaFuncSetAttribute(batch_polynomial_mul_fft16x4x16<params>,
                           cudaFuncAttributePreferredSharedMemoryCarveout,
                           cudaSharedmemCarveoutMaxShared));
  check_cuda_error(cudaFuncSetCacheConfig(
      batch_polynomial_mul_fft16x4x16<params>, cudaFuncCachePreferShared));

  batch_polynomial_mul_fft16x4x16<params>
      <<<gridSize, blockSize, shared_memory_size, stream>>>(input1, input2,
                                                            output);
  check_cuda_error(cudaGetLastError());
}

// Test-only entry point: forward-only negacyclic FFT using the classic
// NSMFFT_direct core (the "previous" FFT). Hardcoded to polynomial_size == 2048
// so it can be compared against the FFT16x4x16 forward transform. The output is
// left in NSMFFT_direct's native (bit-reversed) frequency order.
void cuda_forward_fft_classic_async(void *stream_v, uint32_t gpu_index,
                                    void const *_input, void *_output,
                                    uint32_t polynomial_size,
                                    uint32_t total_polynomials) {

  if (polynomial_size != 2048)
    PANIC("cuda_forward_fft_classic_async only supports polynomial_size == "
          "2048");

  auto stream = static_cast<cudaStream_t>(stream_v);
  cuda_set_device(gpu_index);
  auto input = (double2 *)_input;
  auto output = (double2 *)_output;

  using kernel_params = FFTDegree<AmortizedDegree<2048>, ForwardFFT>;
  size_t shared_memory_size = safe_mul_sizeof<double2>(polynomial_size / 2);

  int gridSize = total_polynomials;
  int blockSize = polynomial_size / choose_opt_amortized(polynomial_size);

  // NSMFFT_direct returns the spectrum in shared memory; batch_NSMFFT copies it
  // straight to d_output. The device buffer is only used on the NOSM path.
  double2 *buffer = (double2 *)cuda_malloc_async(0, stream, gpu_index);
  check_cuda_error(cudaFuncSetAttribute(
      batch_NSMFFT<kernel_params, FULLSM>,
      cudaFuncAttributeMaxDynamicSharedMemorySize, shared_memory_size));
  check_cuda_error(cudaFuncSetCacheConfig(batch_NSMFFT<kernel_params, FULLSM>,
                                          cudaFuncCachePreferShared));
  batch_NSMFFT<kernel_params, FULLSM>
      <<<gridSize, blockSize, shared_memory_size, stream>>>(input, output,
                                                            buffer);
  check_cuda_error(cudaGetLastError());
  cuda_drop_async(buffer, stream, gpu_index);
}

// Test-only entry point: forward-only negacyclic FFT driven by the
// throughput-oriented FFT16x4x16 core (the FFT used by the specialized
// 2_2_params PBS). Hardcoded to polynomial_size == 2048 and requires sm_90
// (H100); callers must gate accordingly. The spectrum is written in NATURAL
// frequency order — see batch_forward_fft16x4x16.
void cuda_forward_fft16x4x16_async(void *stream_v, uint32_t gpu_index,
                                   void const *_input, void *_output,
                                   uint32_t polynomial_size,
                                   uint32_t total_polynomials) {

  if (polynomial_size != 2048)
    PANIC("cuda_forward_fft16x4x16_async only supports polynomial_size == "
          "2048");

  auto stream = static_cast<cudaStream_t>(stream_v);
  cuda_set_device(gpu_index);
  auto input = (const double2 *)_input;
  auto output = (double2 *)_output;

  using params = AccumulatorDegree<2048>;
  size_t shared_memory_size = FFT16x4x16_DUAL_SMEM_BYTES;

  int gridSize = total_polynomials;
  int blockSize = polynomial_size / params::opt; // 64

  check_cuda_error(cudaFuncSetAttribute(
      batch_forward_fft16x4x16<params>,
      cudaFuncAttributeMaxDynamicSharedMemorySize, shared_memory_size));
  check_cuda_error(
      cudaFuncSetAttribute(batch_forward_fft16x4x16<params>,
                           cudaFuncAttributePreferredSharedMemoryCarveout,
                           cudaSharedmemCarveoutMaxShared));
  check_cuda_error(cudaFuncSetCacheConfig(batch_forward_fft16x4x16<params>,
                                          cudaFuncCachePreferShared));

  batch_forward_fft16x4x16<params>
      <<<gridSize, blockSize, shared_memory_size, stream>>>(input, output);
  check_cuda_error(cudaGetLastError());
}

bool cuda_fft16x4x16_is_supported_async(uint32_t gpu_index) {
  cudaDeviceProp prop;
  cudaError_t err = cudaGetDeviceProperties(&prop, gpu_index);
  // sm_90 (Hopper) or newer: the FFT16x4x16 core needs the named-barrier /
  // mbarrier primitives introduced with compute capability 9.x.
  return err == cudaSuccess && prop.major >= 9;
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
