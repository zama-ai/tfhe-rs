#include "bootstrapping_key.cuh"
#include "checked_arithmetic.h"
#include "polynomial/dispatch.cuh"
#include "programmable_bootstrap_classic.cuh"

void cuda_convert_lwe_programmable_bootstrap_key_64_async(
    void *stream, uint32_t gpu_index, void *dest, void const *src,
    uint32_t input_lwe_dim, uint32_t glwe_dim, uint32_t polynomial_size,
    uint32_t base_log, uint32_t level_count) {
  size_t total_polynomials =
      safe_mul((size_t)input_lwe_dim, (size_t)(glwe_dim + 1),
               (size_t)(glwe_dim + 1), (size_t)level_count);
  // The gate reads the compute capability of the current device. It is the
  // same gate the PBS scratch and launch decide through, so the key layout and
  // the kernel reading it always agree.
  cuda_set_device(gpu_index);
  auto max_shared_memory = cuda_get_max_shared_memory(gpu_index);
  bool use_2_2_specialized_layout = supports_2_2_specialized_pbs<uint64_t>(
      polynomial_size, glwe_dim, level_count, input_lwe_dim, base_log,
      max_shared_memory);
  cuda_convert_lwe_programmable_bootstrap_key<uint64_t, int64_t>(
      static_cast<cudaStream_t>(stream), gpu_index, (double2 *)dest,
      (const int64_t *)src, polynomial_size, total_polynomials,
      use_2_2_specialized_layout);
}

// Only used for testing to keep the default layout of the bsk, so the DEFAULT
// flavor can be tested on parameters the automatic gate would route to the
// 2_2 specialized layout.
void cuda_convert_lwe_programmable_bootstrap_key_default_64_async(
    void *stream, uint32_t gpu_index, void *dest, void const *src,
    uint32_t input_lwe_dim, uint32_t glwe_dim, uint32_t polynomial_size,
    uint32_t level_count) {
  size_t total_polynomials =
      safe_mul((size_t)input_lwe_dim, (size_t)(glwe_dim + 1),
               (size_t)(glwe_dim + 1), (size_t)level_count);
  // Force the default FFT layout.
  cuda_convert_lwe_programmable_bootstrap_key<uint64_t, int64_t>(
      static_cast<cudaStream_t>(stream), gpu_index, (double2 *)dest,
      (const int64_t *)src, polynomial_size, total_polynomials,
      /*use_2_2_specialized_layout=*/false);
}

// Only used during testing to force the FFT16x16x4 2_2 specialized layout of
// the bsk, bypassing the compute capability policy of the automatic gate.
void cuda_convert_lwe_programmable_bootstrap_key_2_2_specialized_64_async(
    void *stream, uint32_t gpu_index, void *dest, void const *src,
    uint32_t input_lwe_dim, uint32_t glwe_dim, uint32_t polynomial_size,
    uint32_t level_count) {
  size_t total_polynomials =
      safe_mul((size_t)input_lwe_dim, (size_t)(glwe_dim + 1),
               (size_t)(glwe_dim + 1), (size_t)level_count);
  cuda_convert_lwe_programmable_bootstrap_key<uint64_t, int64_t>(
      static_cast<cudaStream_t>(stream), gpu_index, (double2 *)dest,
      (const int64_t *)src, polynomial_size, total_polynomials,
      /*use_2_2_specialized_layout=*/true);
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
template __device__ const double2 *
get_ith_mask_kth_block(const double2 *ptr, int i, int k, int level,
                       uint32_t polynomial_size, int glwe_dimension,
                       uint32_t level_count);
template __device__ uint64_t *get_ith_mask_kth_block(uint64_t *ptr, int i,
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

void cuda_fourier_polynomial_mul_async(void *stream, uint32_t gpu_index,
                                       void const *input1, void const *input2,
                                       void *output, uint32_t polynomial_size,
                                       uint32_t total_polynomials) {

  auto s = static_cast<cudaStream_t>(stream);
  cuda_set_device(gpu_index);
  auto *in1 = (double2 *)input1;
  auto *in2 = (double2 *)input2;
  auto *out = (double2 *)output;

  size_t shared_memory_size = safe_mul_sizeof<double2>(polynomial_size / 2);

  int gridSize = total_polynomials;
  int blockSize = polynomial_size / choose_opt_amortized(polynomial_size);

  auto max_shared_memory = cuda_get_max_shared_memory(gpu_index);

  double2 *buf;
  DISPATCH_POLY_SIZE(
      polynomial_size, AmortizedDegreePolicy,
      if (shared_memory_size <= max_shared_memory) {
        buf = (double2 *)cuda_malloc_async(0, s, gpu_index);
        check_cuda_error(cudaFuncSetAttribute(
            batch_polynomial_mul<FFTDegree<Params, ForwardFFT>, FULLSM>,
            cudaFuncAttributeMaxDynamicSharedMemorySize, shared_memory_size));
        check_cuda_error(cudaFuncSetCacheConfig(
            batch_polynomial_mul<FFTDegree<Params, ForwardFFT>, FULLSM>,
            cudaFuncCachePreferShared));
        batch_polynomial_mul<FFTDegree<Params, ForwardFFT>, FULLSM>
            <<<gridSize, blockSize, shared_memory_size, s>>>(in1, in2, out,
                                                             buf);
      } else {
        buf = (double2 *)cuda_malloc_async(
            safe_mul(shared_memory_size, (size_t)total_polynomials), s,
            gpu_index);
        batch_polynomial_mul<FFTDegree<Params, ForwardFFT>, NOSM>
            <<<gridSize, blockSize, 0, s>>>(in1, in2, out, buf);
      });
  check_cuda_error(cudaGetLastError());

  cuda_drop_async(buf, s, gpu_index);
}

// Shared launch path of the three FFT16x16x4 test entry points below: same
// parameter checks, same (total_polynomials / 2) x (64, 2, 1) launch shape and
// the same shared memory opt-in, so the transforms run exactly as the
// 2_2 specialized PBS runs them. Only the kernel and its tensor
// arguments differ. `entry_point_name` identifies the caller in the PANIC
// messages, since they all fire from this function's lines.
template <typename Kernel, typename... Args>
static void launch_fft16x16x4_pair_kernel(cudaStream_t stream,
                                          uint32_t gpu_index,
                                          const char *entry_point_name,
                                          uint32_t polynomial_size,
                                          uint32_t total_polynomials,
                                          Kernel *kernel, Args... args) {
  PANIC_IF_FALSE(polynomial_size == 2048,
                 "%s only supports polynomial_size == 2048", entry_point_name);
  PANIC_IF_FALSE(total_polynomials % 2 == 0,
                 "%s needs an even number of polynomials (two per block)",
                 entry_point_name);

  cuda_set_device(gpu_index);

  using params = AccumulatorDegree<2048>;
  size_t shared_memory_size = FFT16x16x4_DUAL_SMEM_BYTES;

  dim3 grid(total_polynomials / 2);
  dim3 block(polynomial_size / params::opt, 2, 1); // (64, 2, 1)

  check_cuda_error(cudaFuncSetAttribute(
      kernel, cudaFuncAttributeMaxDynamicSharedMemorySize, shared_memory_size));
  check_cuda_error(cudaFuncSetAttribute(
      kernel, cudaFuncAttributePreferredSharedMemoryCarveout,
      cudaSharedmemCarveoutMaxShared));
  check_cuda_error(cudaFuncSetCacheConfig(kernel, cudaFuncCachePreferShared));

  kernel<<<grid, block, shared_memory_size, stream>>>(args...);
  check_cuda_error(cudaGetLastError());
}

// Test-only entry point: negacyclic polynomial multiplication driven by the
// paired FFT16x16x4 transforms (the FFTs of the 2_2 specialized PBS).
// Hardcoded to polynomial_size == 2048 and two polynomials per block, so
// total_polynomials must be even. See batch_polynomial_mul_fft16x16x4.
void cuda_fourier_polynomial_mul_fft16x16x4_async(
    void *stream, uint32_t gpu_index, void const *input1, void const *input2,
    void *output, uint32_t polynomial_size, uint32_t total_polynomials) {
  launch_fft16x16x4_pair_kernel(
      static_cast<cudaStream_t>(stream), gpu_index,
      "cuda_fourier_polynomial_mul_fft16x16x4_async", polynomial_size,
      total_polynomials,
      batch_polynomial_mul_fft16x16x4<AccumulatorDegree<2048>>,
      static_cast<const double2 *>(input1),
      static_cast<const double2 *>(input2), static_cast<double2 *>(output));
}

// Test-only entry point: forward-only negacyclic FFT using the classic
// NSMFFT_direct core (the "previous" FFT). Hardcoded to polynomial_size == 2048
// so it can be compared against the FFT16x16x4 forward transform. The output is
// left in NSMFFT_direct's native (bit-reversed) frequency order.
void cuda_forward_fft_classic_async(void *stream, uint32_t gpu_index,
                                    void const *input, void *output,
                                    uint32_t polynomial_size,
                                    uint32_t total_polynomials) {

  if (polynomial_size != 2048)
    PANIC("cuda_forward_fft_classic_async only supports polynomial_size == "
          "2048");

  auto s = static_cast<cudaStream_t>(stream);
  cuda_set_device(gpu_index);
  auto *in = (double2 *)input;
  auto *out = (double2 *)output;

  using kernel_params = FFTDegree<AmortizedDegree<2048>, ForwardFFT>;
  size_t shared_memory_size = safe_mul_sizeof<double2>(polynomial_size / 2);

  int gridSize = total_polynomials;
  int blockSize = polynomial_size / choose_opt_amortized(polynomial_size);

  // NSMFFT_direct returns the spectrum in shared memory; batch_NSMFFT copies it
  // straight to d_output. The device buffer is only used on the NOSM path.
  auto *buf = (double2 *)cuda_malloc_async(0, s, gpu_index);
  check_cuda_error(cudaFuncSetAttribute(
      batch_NSMFFT<kernel_params, FULLSM>,
      cudaFuncAttributeMaxDynamicSharedMemorySize, shared_memory_size));
  check_cuda_error(cudaFuncSetCacheConfig(batch_NSMFFT<kernel_params, FULLSM>,
                                          cudaFuncCachePreferShared));
  batch_NSMFFT<kernel_params, FULLSM>
      <<<gridSize, blockSize, shared_memory_size, s>>>(in, out, buf);
  check_cuda_error(cudaGetLastError());
  cuda_drop_async(buf, s, gpu_index);
}

// Test-only entry point: forward-only negacyclic FFT driven by the paired
// FFT16x16x4 transform (the forward FFT of the 2_2 specialized PBS).
// Hardcoded to polynomial_size == 2048 and two polynomials per block, so
// total_polynomials must be even. The spectra are written in NATURAL frequency
// order; see batch_forward_fft16x16x4.
void cuda_forward_fft16x16x4_async(void *stream, uint32_t gpu_index,
                                   void const *input, void *output,
                                   uint32_t polynomial_size,
                                   uint32_t total_polynomials) {
  launch_fft16x16x4_pair_kernel(
      static_cast<cudaStream_t>(stream), gpu_index,
      "cuda_forward_fft16x16x4_async", polynomial_size, total_polynomials,
      batch_forward_fft16x16x4<AccumulatorDegree<2048>>,
      static_cast<const double2 *>(input), static_cast<double2 *>(output));
}

// Test-only entry point: inverse-only negacyclic FFT driven by the paired
// FFT16x16x4 transform (the inverse FFT of the 2_2 specialized PBS).
// The clean inverse of cuda_forward_fft16x16x4_async: natural-order spectra
// in, natural time order out, no 1/N (the PBS folds it into the key). Same
// restrictions as the forward entry point; see batch_backward_fft16x16x4.
void cuda_backward_fft16x16x4_async(void *stream, uint32_t gpu_index,
                                    void const *input, void *output,
                                    uint32_t polynomial_size,
                                    uint32_t total_polynomials) {
  launch_fft16x16x4_pair_kernel(
      static_cast<cudaStream_t>(stream), gpu_index,
      "cuda_backward_fft16x16x4_async", polynomial_size, total_polynomials,
      batch_backward_fft16x16x4<AccumulatorDegree<2048>>,
      static_cast<const double2 *>(input), static_cast<double2 *>(output));
}

bool cuda_pbs128_golden_is_supported_async(uint32_t gpu_index) {
  cudaDeviceProp prop{};
  cudaError_t err = cudaGetDeviceProperties(&prop, gpu_index);
  // sm_90 (Hopper) or newer: the only architecture the 128-bit PBS golden
  // data is validated on.
  return err == cudaSuccess && prop.major >= 9;
}

bool cuda_pbs_golden_is_supported_async(uint32_t gpu_index) {
  cudaDeviceProp prop{};
  cudaError_t err = cudaGetDeviceProperties(&prop, gpu_index);
  // sm_80 (Ampere) or newer: the committed golden data is reproduced bit for
  // bit on A100, L40 and H100 (rounding-pinned intrinsics throughout).
  return err == cudaSuccess && prop.major >= 8;
}

bool cuda_fft16x16x4_is_supported_async(uint32_t gpu_index) {
  cudaDeviceProp prop{};
  cudaError_t err = cudaGetDeviceProperties(&prop, gpu_index);
  // sm_80 (Ampere) or newer: the transforms run there and reproduce the H100
  // golden data bit for bit (checked on A100, L40 and an RTX 4060 Laptop).
  // Kept separate from the PBS golden probe above so tightening one policy
  // does not silently drop the other's test coverage.
  return err == cudaSuccess && prop.major >= 8;
}

void cuda_convert_lwe_programmable_bootstrap_key_u128_async(
    cudaStream_t stream, uint32_t gpu_index, double *dest,
    __uint128_t const *src, uint32_t polynomial_size,
    uint32_t total_polynomials) {

  // Here the buffer size is the size of double times the number of polynomials
  // time 4 each polynomial is represented with 4 double array with size
  // polynomial_size / 2 into the complex domain to perform the FFT
  size_t buffer_size = safe_mul_sizeof<double>(
      (size_t)total_polynomials, (size_t)(polynomial_size / 2), (size_t)4);

  auto *d_standard =
      (__uint128_t *)cuda_malloc_async(buffer_size, stream, gpu_index);

  cuda_memcpy_async_to_gpu(d_standard, src, buffer_size, stream, gpu_index);

  DISPATCH_POLY_SIZE(
      polynomial_size, AmortizedDegreePolicy128,
      convert_u128_to_f128_and_forward_fft_128<Params>(
          stream, gpu_index, dest, d_standard, total_polynomials));

  cuda_drop_async(d_standard, stream, gpu_index);
}

// Same (polynomial_size, level_count) argument order as the 64-bit classical
// conversion family, so the calls cannot be swapped silently.
void cuda_convert_lwe_programmable_bootstrap_key_128_async(
    void *stream, uint32_t gpu_index, void *dest, void const *src,
    uint32_t input_lwe_dim, uint32_t glwe_dim, uint32_t polynomial_size,
    uint32_t level_count) {

  size_t total_polynomials =
      safe_mul((size_t)input_lwe_dim, (size_t)(glwe_dim + 1),
               (size_t)(glwe_dim + 1), (size_t)level_count);
  cuda_convert_lwe_programmable_bootstrap_key_u128_async(
      static_cast<cudaStream_t>(stream), gpu_index, (double *)dest,
      (const __uint128_t *)src, polynomial_size, total_polynomials);
}
