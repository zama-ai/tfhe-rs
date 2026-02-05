// Test-only GPU helper functions for Fp operations
// These functions launch single-thread kernels for testing purposes only
// They are not part of the production API

#include "device.h"
#include "fp.h"
#include "fp_helpers.h" // Include test-only kernel declarations
#include <cuda_runtime.h>

// ============================================================================
// Host wrapper functions for testing individual operations on GPU
// These functions launch single-operation kernels to verify arithmetic works on
// device
// ============================================================================

void fp_add_gpu(cudaStream_t stream, uint32_t gpu_index, Fp *result,
                const Fp *a, const Fp *b) {
  cuda_set_device(gpu_index);

  uint64_t size_tracker = 0;

  auto *d_result = static_cast<Fp *>(cuda_malloc_with_size_tracking_async(
      sizeof(Fp), stream, gpu_index, size_tracker, true));
  auto *d_a = static_cast<Fp *>(cuda_malloc_with_size_tracking_async(
      sizeof(Fp), stream, gpu_index, size_tracker, true));
  auto *d_b = static_cast<Fp *>(cuda_malloc_with_size_tracking_async(
      sizeof(Fp), stream, gpu_index, size_tracker, true));

  cuda_memcpy_with_size_tracking_async_to_gpu(d_a, a, sizeof(Fp), stream,
                                              gpu_index, true);
  cuda_memcpy_with_size_tracking_async_to_gpu(d_b, b, sizeof(Fp), stream,
                                              gpu_index, true);

  kernel_fp_add<<<1, 1, 0, stream>>>(d_result, d_a, d_b);
  check_cuda_error(cudaGetLastError());

  cuda_synchronize_stream(stream, gpu_index);

  cuda_memcpy_async_to_cpu(result, d_result, sizeof(Fp), stream, gpu_index);
  cuda_synchronize_stream(stream, gpu_index);

  if (d_result != nullptr)
    cuda_drop_with_size_tracking_async(d_result, stream, gpu_index, true);
  if (d_a != nullptr)
    cuda_drop_with_size_tracking_async(d_a, stream, gpu_index, true);
  if (d_b != nullptr)
    cuda_drop_with_size_tracking_async(d_b, stream, gpu_index, true);
}

void fp_sub_gpu(cudaStream_t stream, uint32_t gpu_index, Fp *result,
                const Fp *a, const Fp *b) {
  cuda_set_device(gpu_index);

  uint64_t size_tracker = 0;

  auto *d_result = static_cast<Fp *>(cuda_malloc_with_size_tracking_async(
      sizeof(Fp), stream, gpu_index, size_tracker, true));
  auto *d_a = static_cast<Fp *>(cuda_malloc_with_size_tracking_async(
      sizeof(Fp), stream, gpu_index, size_tracker, true));
  auto *d_b = static_cast<Fp *>(cuda_malloc_with_size_tracking_async(
      sizeof(Fp), stream, gpu_index, size_tracker, true));

  cuda_memcpy_with_size_tracking_async_to_gpu(d_a, a, sizeof(Fp), stream,
                                              gpu_index, true);
  cuda_memcpy_with_size_tracking_async_to_gpu(d_b, b, sizeof(Fp), stream,
                                              gpu_index, true);

  kernel_fp_sub<<<1, 1, 0, stream>>>(d_result, d_a, d_b);
  check_cuda_error(cudaGetLastError());

  cuda_synchronize_stream(stream, gpu_index);

  cuda_memcpy_async_to_cpu(result, d_result, sizeof(Fp), stream, gpu_index);
  cuda_synchronize_stream(stream, gpu_index);

  if (d_result != nullptr)
    cuda_drop_with_size_tracking_async(d_result, stream, gpu_index, true);
  if (d_a != nullptr)
    cuda_drop_with_size_tracking_async(d_a, stream, gpu_index, true);
  if (d_b != nullptr)
    cuda_drop_with_size_tracking_async(d_b, stream, gpu_index, true);
}

void fp_mul_gpu(cudaStream_t stream, uint32_t gpu_index, Fp *result,
                const Fp *a, const Fp *b) {
  cuda_set_device(gpu_index);

  uint64_t size_tracker = 0;

  auto *d_result = static_cast<Fp *>(cuda_malloc_with_size_tracking_async(
      sizeof(Fp), stream, gpu_index, size_tracker, true));
  auto *d_a = static_cast<Fp *>(cuda_malloc_with_size_tracking_async(
      sizeof(Fp), stream, gpu_index, size_tracker, true));
  auto *d_b = static_cast<Fp *>(cuda_malloc_with_size_tracking_async(
      sizeof(Fp), stream, gpu_index, size_tracker, true));

  cuda_memcpy_with_size_tracking_async_to_gpu(d_a, a, sizeof(Fp), stream,
                                              gpu_index, true);
  cuda_memcpy_with_size_tracking_async_to_gpu(d_b, b, sizeof(Fp), stream,
                                              gpu_index, true);

  kernel_fp_mul<<<1, 1, 0, stream>>>(d_result, d_a, d_b);
  check_cuda_error(cudaGetLastError());

  cuda_synchronize_stream(stream, gpu_index);

  cuda_memcpy_async_to_cpu(result, d_result, sizeof(Fp), stream, gpu_index);
  cuda_synchronize_stream(stream, gpu_index);

  if (d_result != nullptr)
    cuda_drop_with_size_tracking_async(d_result, stream, gpu_index, true);
  if (d_a != nullptr)
    cuda_drop_with_size_tracking_async(d_a, stream, gpu_index, true);
  if (d_b != nullptr)
    cuda_drop_with_size_tracking_async(d_b, stream, gpu_index, true);
}

void fp_neg_gpu(cudaStream_t stream, uint32_t gpu_index, Fp *result,
                const Fp *a) {
  cuda_set_device(gpu_index);

  uint64_t size_tracker = 0;

  auto *d_result = static_cast<Fp *>(cuda_malloc_with_size_tracking_async(
      sizeof(Fp), stream, gpu_index, size_tracker, true));
  auto *d_a = static_cast<Fp *>(cuda_malloc_with_size_tracking_async(
      sizeof(Fp), stream, gpu_index, size_tracker, true));

  cuda_memcpy_with_size_tracking_async_to_gpu(d_a, a, sizeof(Fp), stream,
                                              gpu_index, true);

  kernel_fp_neg<<<1, 1, 0, stream>>>(d_result, d_a);
  check_cuda_error(cudaGetLastError());

  cuda_synchronize_stream(stream, gpu_index);

  cuda_memcpy_async_to_cpu(result, d_result, sizeof(Fp), stream, gpu_index);
  cuda_synchronize_stream(stream, gpu_index);

  if (d_result != nullptr)
    cuda_drop_with_size_tracking_async(d_result, stream, gpu_index, true);
  if (d_a != nullptr)
    cuda_drop_with_size_tracking_async(d_a, stream, gpu_index, true);
}

void fp_inv_gpu(cudaStream_t stream, uint32_t gpu_index, Fp *result,
                const Fp *a) {
  cuda_set_device(gpu_index);

  uint64_t size_tracker = 0;

  auto *d_result = static_cast<Fp *>(cuda_malloc_with_size_tracking_async(
      sizeof(Fp), stream, gpu_index, size_tracker, true));
  auto *d_a = static_cast<Fp *>(cuda_malloc_with_size_tracking_async(
      sizeof(Fp), stream, gpu_index, size_tracker, true));

  cuda_memcpy_with_size_tracking_async_to_gpu(d_a, a, sizeof(Fp), stream,
                                              gpu_index, true);

  kernel_fp_inv<<<1, 1, 0, stream>>>(d_result, d_a);
  check_cuda_error(cudaGetLastError());

  cuda_synchronize_stream(stream, gpu_index);

  cuda_memcpy_async_to_cpu(result, d_result, sizeof(Fp), stream, gpu_index);
  cuda_synchronize_stream(stream, gpu_index);

  if (d_result != nullptr)
    cuda_drop_with_size_tracking_async(d_result, stream, gpu_index, true);
  if (d_a != nullptr)
    cuda_drop_with_size_tracking_async(d_a, stream, gpu_index, true);
}

void fp_div_gpu(cudaStream_t stream, uint32_t gpu_index, Fp *result,
                const Fp *a, const Fp *b) {
  cuda_set_device(gpu_index);

  uint64_t size_tracker = 0;

  auto *d_result = static_cast<Fp *>(cuda_malloc_with_size_tracking_async(
      sizeof(Fp), stream, gpu_index, size_tracker, true));
  auto *d_a = static_cast<Fp *>(cuda_malloc_with_size_tracking_async(
      sizeof(Fp), stream, gpu_index, size_tracker, true));
  auto *d_b = static_cast<Fp *>(cuda_malloc_with_size_tracking_async(
      sizeof(Fp), stream, gpu_index, size_tracker, true));

  cuda_memcpy_with_size_tracking_async_to_gpu(d_a, a, sizeof(Fp), stream,
                                              gpu_index, true);
  cuda_memcpy_with_size_tracking_async_to_gpu(d_b, b, sizeof(Fp), stream,
                                              gpu_index, true);

  kernel_fp_div<<<1, 1, 0, stream>>>(d_result, d_a, d_b);
  check_cuda_error(cudaGetLastError());

  cuda_synchronize_stream(stream, gpu_index);

  cuda_memcpy_async_to_cpu(result, d_result, sizeof(Fp), stream, gpu_index);
  cuda_synchronize_stream(stream, gpu_index);

  if (d_result != nullptr)
    cuda_drop_with_size_tracking_async(d_result, stream, gpu_index, true);
  if (d_a != nullptr)
    cuda_drop_with_size_tracking_async(d_a, stream, gpu_index, true);
  if (d_b != nullptr)
    cuda_drop_with_size_tracking_async(d_b, stream, gpu_index, true);
}

ComparisonType fp_cmp_gpu(cudaStream_t stream, uint32_t gpu_index, const Fp *a,
                          const Fp *b) {
  cuda_set_device(gpu_index);

  uint64_t size_tracker = 0;

  auto *h_result = new int;
  auto *d_result = static_cast<int *>(cuda_malloc_with_size_tracking_async(
      sizeof(int), stream, gpu_index, size_tracker, true));
  auto *d_a = static_cast<Fp *>(cuda_malloc_with_size_tracking_async(
      sizeof(Fp), stream, gpu_index, size_tracker, true));
  auto *d_b = static_cast<Fp *>(cuda_malloc_with_size_tracking_async(
      sizeof(Fp), stream, gpu_index, size_tracker, true));
  ComparisonType result = ComparisonType::Equal;

  cuda_memcpy_with_size_tracking_async_to_gpu(d_a, a, sizeof(Fp), stream,
                                              gpu_index, true);
  cuda_memcpy_with_size_tracking_async_to_gpu(d_b, b, sizeof(Fp), stream,
                                              gpu_index, true);

  kernel_fp_cmp<<<1, 1, 0, stream>>>(d_result, d_a, d_b);
  check_cuda_error(cudaGetLastError());

  cuda_synchronize_stream(stream, gpu_index);

  cuda_memcpy_async_to_cpu(h_result, d_result, sizeof(int), stream, gpu_index);
  cuda_synchronize_stream(stream, gpu_index);
  result = static_cast<ComparisonType>(*h_result);

  if (d_result != nullptr)
    cuda_drop_with_size_tracking_async(d_result, stream, gpu_index, true);
  if (d_a != nullptr)
    cuda_drop_with_size_tracking_async(d_a, stream, gpu_index, true);
  if (d_b != nullptr)
    cuda_drop_with_size_tracking_async(d_b, stream, gpu_index, true);
  if (h_result != nullptr)
    delete h_result;
  return result;
}

bool fp_is_zero_gpu(cudaStream_t stream, uint32_t gpu_index, const Fp *a) {
  cuda_set_device(gpu_index);

  uint64_t size_tracker = 0;

  auto *h_result = new bool;
  auto *d_result = static_cast<bool *>(cuda_malloc_with_size_tracking_async(
      sizeof(bool), stream, gpu_index, size_tracker, true));
  auto *d_a = static_cast<Fp *>(cuda_malloc_with_size_tracking_async(
      sizeof(Fp), stream, gpu_index, size_tracker, true));
  bool result = false;

  cuda_memcpy_with_size_tracking_async_to_gpu(d_a, a, sizeof(Fp), stream,
                                              gpu_index, true);

  kernel_fp_is_zero<<<1, 1, 0, stream>>>(d_result, d_a);
  check_cuda_error(cudaGetLastError());

  cuda_synchronize_stream(stream, gpu_index);

  cuda_memcpy_async_to_cpu(h_result, d_result, sizeof(bool), stream, gpu_index);
  cuda_synchronize_stream(stream, gpu_index);
  result = *h_result;

  if (d_result != nullptr)
    cuda_drop_with_size_tracking_async(d_result, stream, gpu_index, true);
  if (d_a != nullptr)
    cuda_drop_with_size_tracking_async(d_a, stream, gpu_index, true);
  if (h_result != nullptr)
    delete h_result;
  return result;
}

bool fp_is_one_gpu(cudaStream_t stream, uint32_t gpu_index, const Fp *a) {
  cuda_set_device(gpu_index);

  uint64_t size_tracker = 0;

  auto *h_result = new bool;
  auto *d_result = static_cast<bool *>(cuda_malloc_with_size_tracking_async(
      sizeof(bool), stream, gpu_index, size_tracker, true));
  auto *d_a = static_cast<Fp *>(cuda_malloc_with_size_tracking_async(
      sizeof(Fp), stream, gpu_index, size_tracker, true));
  bool result = false;

  cuda_memcpy_with_size_tracking_async_to_gpu(d_a, a, sizeof(Fp), stream,
                                              gpu_index, true);

  kernel_fp_is_one<<<1, 1, 0, stream>>>(d_result, d_a);
  check_cuda_error(cudaGetLastError());

  cuda_synchronize_stream(stream, gpu_index);

  cuda_memcpy_async_to_cpu(h_result, d_result, sizeof(bool), stream, gpu_index);
  cuda_synchronize_stream(stream, gpu_index);
  result = *h_result;

  if (d_result != nullptr)
    cuda_drop_with_size_tracking_async(d_result, stream, gpu_index, true);
  if (d_a != nullptr)
    cuda_drop_with_size_tracking_async(d_a, stream, gpu_index, true);
  if (h_result != nullptr)
    delete h_result;
  return result;
}

void fp_to_montgomery_gpu(cudaStream_t stream, uint32_t gpu_index, Fp *result,
                          const Fp *a) {
  cuda_set_device(gpu_index);

  uint64_t size_tracker = 0;

  auto *d_result = static_cast<Fp *>(cuda_malloc_with_size_tracking_async(
      sizeof(Fp), stream, gpu_index, size_tracker, true));
  auto *d_a = static_cast<Fp *>(cuda_malloc_with_size_tracking_async(
      sizeof(Fp), stream, gpu_index, size_tracker, true));

  cuda_memcpy_with_size_tracking_async_to_gpu(d_a, a, sizeof(Fp), stream,
                                              gpu_index, true);

  kernel_fp_to_montgomery<<<1, 1, 0, stream>>>(d_result, d_a);
  check_cuda_error(cudaGetLastError());

  cuda_synchronize_stream(stream, gpu_index);

  cuda_memcpy_async_to_cpu(result, d_result, sizeof(Fp), stream, gpu_index);
  cuda_synchronize_stream(stream, gpu_index);

  if (d_result != nullptr)
    cuda_drop_with_size_tracking_async(d_result, stream, gpu_index, true);
  if (d_a != nullptr)
    cuda_drop_with_size_tracking_async(d_a, stream, gpu_index, true);
}

void fp_from_montgomery_gpu(cudaStream_t stream, uint32_t gpu_index, Fp *result,
                            const Fp *a) {
  cuda_set_device(gpu_index);

  uint64_t size_tracker = 0;

  auto *d_result = static_cast<Fp *>(cuda_malloc_with_size_tracking_async(
      sizeof(Fp), stream, gpu_index, size_tracker, true));
  auto *d_a = static_cast<Fp *>(cuda_malloc_with_size_tracking_async(
      sizeof(Fp), stream, gpu_index, size_tracker, true));

  cuda_memcpy_with_size_tracking_async_to_gpu(d_a, a, sizeof(Fp), stream,
                                              gpu_index, true);

  kernel_fp_from_montgomery<<<1, 1, 0, stream>>>(d_result, d_a);
  check_cuda_error(cudaGetLastError());

  cuda_synchronize_stream(stream, gpu_index);

  cuda_memcpy_async_to_cpu(result, d_result, sizeof(Fp), stream, gpu_index);
  cuda_synchronize_stream(stream, gpu_index);

  if (d_result != nullptr)
    cuda_drop_with_size_tracking_async(d_result, stream, gpu_index, true);
  if (d_a != nullptr)
    cuda_drop_with_size_tracking_async(d_a, stream, gpu_index, true);
}

void fp_mont_mul_gpu(cudaStream_t stream, uint32_t gpu_index, Fp *result,
                     const Fp *a, const Fp *b) {
  cuda_set_device(gpu_index);

  uint64_t size_tracker = 0;

  auto *d_result = static_cast<Fp *>(cuda_malloc_with_size_tracking_async(
      sizeof(Fp), stream, gpu_index, size_tracker, true));
  auto *d_a = static_cast<Fp *>(cuda_malloc_with_size_tracking_async(
      sizeof(Fp), stream, gpu_index, size_tracker, true));
  auto *d_b = static_cast<Fp *>(cuda_malloc_with_size_tracking_async(
      sizeof(Fp), stream, gpu_index, size_tracker, true));

  cuda_memcpy_with_size_tracking_async_to_gpu(d_a, a, sizeof(Fp), stream,
                                              gpu_index, true);
  cuda_memcpy_with_size_tracking_async_to_gpu(d_b, b, sizeof(Fp), stream,
                                              gpu_index, true);

  kernel_fp_mont_mul<<<1, 1, 0, stream>>>(d_result, d_a, d_b);
  check_cuda_error(cudaGetLastError());

  cuda_synchronize_stream(stream, gpu_index);

  cuda_memcpy_async_to_cpu(result, d_result, sizeof(Fp), stream, gpu_index);
  cuda_synchronize_stream(stream, gpu_index);

  if (d_result != nullptr)
    cuda_drop_with_size_tracking_async(d_result, stream, gpu_index, true);
  if (d_a != nullptr)
    cuda_drop_with_size_tracking_async(d_a, stream, gpu_index, true);
  if (d_b != nullptr)
    cuda_drop_with_size_tracking_async(d_b, stream, gpu_index, true);
}

void fp_copy_gpu(cudaStream_t stream, uint32_t gpu_index, Fp *result,
                 const Fp *a) {
  cuda_set_device(gpu_index);

  uint64_t size_tracker = 0;

  auto *d_result = static_cast<Fp *>(cuda_malloc_with_size_tracking_async(
      sizeof(Fp), stream, gpu_index, size_tracker, true));
  auto *d_a = static_cast<Fp *>(cuda_malloc_with_size_tracking_async(
      sizeof(Fp), stream, gpu_index, size_tracker, true));

  cuda_memcpy_with_size_tracking_async_to_gpu(d_a, a, sizeof(Fp), stream,
                                              gpu_index, true);

  kernel_fp_copy<<<1, 1, 0, stream>>>(d_result, d_a);
  check_cuda_error(cudaGetLastError());

  cuda_synchronize_stream(stream, gpu_index);

  cuda_memcpy_async_to_cpu(result, d_result, sizeof(Fp), stream, gpu_index);
  cuda_synchronize_stream(stream, gpu_index);

  if (d_result != nullptr)
    cuda_drop_with_size_tracking_async(d_result, stream, gpu_index, true);
  if (d_a != nullptr)
    cuda_drop_with_size_tracking_async(d_a, stream, gpu_index, true);
}

void fp_cmov_gpu(cudaStream_t stream, uint32_t gpu_index, Fp *result,
                 const Fp *src, uint64_t condition) {
  cuda_set_device(gpu_index);

  uint64_t size_tracker = 0;

  auto *d_result = static_cast<Fp *>(cuda_malloc_with_size_tracking_async(
      sizeof(Fp), stream, gpu_index, size_tracker, true));
  auto *d_src = static_cast<Fp *>(cuda_malloc_with_size_tracking_async(
      sizeof(Fp), stream, gpu_index, size_tracker, true));
  auto *d_condition =
      static_cast<uint64_t *>(cuda_malloc_with_size_tracking_async(
          sizeof(uint64_t), stream, gpu_index, size_tracker, true));

  cuda_memcpy_with_size_tracking_async_to_gpu(d_result, result, sizeof(Fp),
                                              stream, gpu_index, true);
  cuda_memcpy_with_size_tracking_async_to_gpu(d_src, src, sizeof(Fp), stream,
                                              gpu_index, true);
  cuda_memcpy_with_size_tracking_async_to_gpu(
      d_condition, &condition, sizeof(uint64_t), stream, gpu_index, true);

  kernel_fp_cmov<<<1, 1, 0, stream>>>(d_result, d_src, condition);
  check_cuda_error(cudaGetLastError());

  cuda_synchronize_stream(stream, gpu_index);

  cuda_memcpy_async_to_cpu(result, d_result, sizeof(Fp), stream, gpu_index);
  cuda_synchronize_stream(stream, gpu_index);

  if (d_result != nullptr)
    cuda_drop_with_size_tracking_async(d_result, stream, gpu_index, true);
  if (d_src != nullptr)
    cuda_drop_with_size_tracking_async(d_src, stream, gpu_index, true);
  if (d_condition != nullptr)
    cuda_drop_with_size_tracking_async(d_condition, stream, gpu_index, true);
}

bool fp_sqrt_gpu(cudaStream_t stream, uint32_t gpu_index, Fp *result,
                 const Fp *a) {
  cuda_set_device(gpu_index);

  uint64_t size_tracker = 0;

  auto *h_has_sqrt = new bool;
  auto *d_has_sqrt = static_cast<bool *>(cuda_malloc_with_size_tracking_async(
      sizeof(bool), stream, gpu_index, size_tracker, true));
  auto *d_result = static_cast<Fp *>(cuda_malloc_with_size_tracking_async(
      sizeof(Fp), stream, gpu_index, size_tracker, true));
  auto *d_a = static_cast<Fp *>(cuda_malloc_with_size_tracking_async(
      sizeof(Fp), stream, gpu_index, size_tracker, true));
  bool has_sqrt = false;

  cuda_memcpy_with_size_tracking_async_to_gpu(d_a, a, sizeof(Fp), stream,
                                              gpu_index, true);

  kernel_fp_sqrt<<<1, 1, 0, stream>>>(d_has_sqrt, d_result, d_a);
  check_cuda_error(cudaGetLastError());

  cuda_synchronize_stream(stream, gpu_index);

  cuda_memcpy_async_to_cpu(h_has_sqrt, d_has_sqrt, sizeof(bool), stream,
                           gpu_index);
  cuda_memcpy_async_to_cpu(result, d_result, sizeof(Fp), stream, gpu_index);
  cuda_synchronize_stream(stream, gpu_index);
  has_sqrt = *h_has_sqrt;

  if (d_has_sqrt != nullptr)
    cuda_drop_with_size_tracking_async(d_has_sqrt, stream, gpu_index, true);
  if (d_result != nullptr)
    cuda_drop_with_size_tracking_async(d_result, stream, gpu_index, true);
  if (d_a != nullptr)
    cuda_drop_with_size_tracking_async(d_a, stream, gpu_index, true);
  if (h_has_sqrt != nullptr)
    delete h_has_sqrt;
  return has_sqrt;
}

bool fp_is_quadratic_residue_gpu(cudaStream_t stream, uint32_t gpu_index,
                                 const Fp *a) {
  cuda_set_device(gpu_index);

  uint64_t size_tracker = 0;

  auto *h_result = new bool;
  auto *d_result = static_cast<bool *>(cuda_malloc_with_size_tracking_async(
      sizeof(bool), stream, gpu_index, size_tracker, true));
  auto *d_a = static_cast<Fp *>(cuda_malloc_with_size_tracking_async(
      sizeof(Fp), stream, gpu_index, size_tracker, true));
  bool result = false;

  cuda_memcpy_with_size_tracking_async_to_gpu(d_a, a, sizeof(Fp), stream,
                                              gpu_index, true);

  kernel_fp_is_quadratic_residue<<<1, 1, 0, stream>>>(d_result, d_a);
  check_cuda_error(cudaGetLastError());

  cuda_synchronize_stream(stream, gpu_index);

  cuda_memcpy_async_to_cpu(h_result, d_result, sizeof(bool), stream, gpu_index);
  cuda_synchronize_stream(stream, gpu_index);
  result = *h_result;

  if (d_result != nullptr)
    cuda_drop_with_size_tracking_async(d_result, stream, gpu_index, true);
  if (d_a != nullptr)
    cuda_drop_with_size_tracking_async(d_a, stream, gpu_index, true);
  if (h_result != nullptr)
    delete h_result;
  return result;
}

void fp_pow_u64_gpu(cudaStream_t stream, uint32_t gpu_index, Fp *result,
                    const Fp *base, uint64_t exp) {
  cuda_set_device(gpu_index);

  uint64_t size_tracker = 0;

  Fp *d_result = nullptr, *d_base = nullptr;

  d_result = static_cast<Fp *>(cuda_malloc_with_size_tracking_async(
      sizeof(Fp), stream, gpu_index, size_tracker, true));
  d_base = static_cast<Fp *>(cuda_malloc_with_size_tracking_async(
      sizeof(Fp), stream, gpu_index, size_tracker, true));

  cuda_memcpy_with_size_tracking_async_to_gpu(d_base, base, sizeof(Fp), stream,
                                              gpu_index, true);

  kernel_fp_pow_u64<<<1, 1, 0, stream>>>(d_result, d_base, exp);
  check_cuda_error(cudaGetLastError());

  cuda_synchronize_stream(stream, gpu_index);

  cuda_memcpy_async_to_cpu(result, d_result, sizeof(Fp), stream, gpu_index);
  cuda_synchronize_stream(stream, gpu_index);

  if (d_result != nullptr)
    cuda_drop_with_size_tracking_async(d_result, stream, gpu_index, true);
  if (d_base != nullptr)
    cuda_drop_with_size_tracking_async(d_base, stream, gpu_index, true);
}
