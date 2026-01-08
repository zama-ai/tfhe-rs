// Test-only GPU helper functions for Fp2 operations
// These functions launch single-thread kernels for testing purposes only
// They are not part of the production API

#include "device.h"
#include "fp2.h"
#include "fp2_helpers.h" // Include test-only kernel declarations
#include <cuda_runtime.h>

// ============================================================================
// Host wrapper functions for testing individual operations on GPU
// These functions launch single-operation kernels to verify arithmetic works on
// device
// ============================================================================

void fp2_add_gpu(Fp2 *result, const Fp2 *a, const Fp2 *b) {
  uint32_t gpu_index = cuda_get_device();
  auto *d_result = static_cast<Fp2 *>(cuda_malloc(sizeof(Fp2), gpu_index));
  auto *d_a = static_cast<Fp2 *>(cuda_malloc(sizeof(Fp2), gpu_index));
  auto *d_b = static_cast<Fp2 *>(cuda_malloc(sizeof(Fp2), gpu_index));

  check_cuda_error(cudaMemcpy(d_a, a, sizeof(Fp2), cudaMemcpyHostToDevice));
  check_cuda_error(cudaMemcpy(d_b, b, sizeof(Fp2), cudaMemcpyHostToDevice));

  kernel_fp2_add<<<1, 1>>>(d_result, d_a, d_b);
  check_cuda_error(cudaGetLastError());

  cuda_synchronize_device(gpu_index);

  check_cuda_error(
      cudaMemcpy(result, d_result, sizeof(Fp2), cudaMemcpyDeviceToHost));

  if (d_result != nullptr)
    cuda_drop(d_result, gpu_index);
  if (d_a != nullptr)
    cuda_drop(d_a, gpu_index);
  if (d_b != nullptr)
    cuda_drop(d_b, gpu_index);
}

void fp2_sub_gpu(Fp2 *result, const Fp2 *a, const Fp2 *b) {
  uint32_t gpu_index = cuda_get_device();
  auto *d_result = static_cast<Fp2 *>(cuda_malloc(sizeof(Fp2), gpu_index));
  auto *d_a = static_cast<Fp2 *>(cuda_malloc(sizeof(Fp2), gpu_index));
  auto *d_b = static_cast<Fp2 *>(cuda_malloc(sizeof(Fp2), gpu_index));

  check_cuda_error(cudaMemcpy(d_a, a, sizeof(Fp2), cudaMemcpyHostToDevice));
  check_cuda_error(cudaMemcpy(d_b, b, sizeof(Fp2), cudaMemcpyHostToDevice));

  kernel_fp2_sub<<<1, 1>>>(d_result, d_a, d_b);
  check_cuda_error(cudaGetLastError());

  cuda_synchronize_device(gpu_index);

  check_cuda_error(
      cudaMemcpy(result, d_result, sizeof(Fp2), cudaMemcpyDeviceToHost));

  if (d_result != nullptr)
    cuda_drop(d_result, gpu_index);
  if (d_a != nullptr)
    cuda_drop(d_a, gpu_index);
  if (d_b != nullptr)
    cuda_drop(d_b, gpu_index);
}

void fp2_mul_gpu(Fp2 *result, const Fp2 *a, const Fp2 *b) {
  uint32_t gpu_index = cuda_get_device();
  auto *d_result = static_cast<Fp2 *>(cuda_malloc(sizeof(Fp2), gpu_index));
  auto *d_a = static_cast<Fp2 *>(cuda_malloc(sizeof(Fp2), gpu_index));
  auto *d_b = static_cast<Fp2 *>(cuda_malloc(sizeof(Fp2), gpu_index));

  // Zero-initialize result to ensure mont flags are properly set
  Fp2 zero_result;
  fp2_zero(zero_result);
  check_cuda_error(
      cudaMemcpy(d_result, &zero_result, sizeof(Fp2), cudaMemcpyHostToDevice));

  check_cuda_error(cudaMemcpy(d_a, a, sizeof(Fp2), cudaMemcpyHostToDevice));
  check_cuda_error(cudaMemcpy(d_b, b, sizeof(Fp2), cudaMemcpyHostToDevice));

  kernel_fp2_mul<<<1, 1>>>(d_result, d_a, d_b);
  check_cuda_error(cudaGetLastError());

  cuda_synchronize_device(gpu_index);

  check_cuda_error(
      cudaMemcpy(result, d_result, sizeof(Fp2), cudaMemcpyDeviceToHost));

  if (d_result != nullptr)
    cuda_drop(d_result, gpu_index);
  if (d_a != nullptr)
    cuda_drop(d_a, gpu_index);
  if (d_b != nullptr)
    cuda_drop(d_b, gpu_index);
}

void fp2_neg_gpu(Fp2 *result, const Fp2 *a) {
  uint32_t gpu_index = cuda_get_device();
  Fp2 *d_result = nullptr, *d_a = nullptr;

  d_result = static_cast<Fp2 *>(cuda_malloc(sizeof(Fp2), gpu_index));
  d_a = static_cast<Fp2 *>(cuda_malloc(sizeof(Fp2), gpu_index));

  check_cuda_error(cudaMemcpy(d_a, a, sizeof(Fp2), cudaMemcpyHostToDevice));

  kernel_fp2_neg<<<1, 1>>>(d_result, d_a);
  check_cuda_error(cudaGetLastError());

  cuda_synchronize_device(gpu_index);

  check_cuda_error(
      cudaMemcpy(result, d_result, sizeof(Fp2), cudaMemcpyDeviceToHost));

  if (d_result != nullptr)
    cuda_drop(d_result, gpu_index);
  if (d_a != nullptr)
    cuda_drop(d_a, gpu_index);
}

void fp2_conjugate_gpu(Fp2 *result, const Fp2 *a) {
  uint32_t gpu_index = cuda_get_device();
  Fp2 *d_result = nullptr, *d_a = nullptr;

  d_result = static_cast<Fp2 *>(cuda_malloc(sizeof(Fp2), gpu_index));
  d_a = static_cast<Fp2 *>(cuda_malloc(sizeof(Fp2), gpu_index));

  check_cuda_error(cudaMemcpy(d_a, a, sizeof(Fp2), cudaMemcpyHostToDevice));

  kernel_fp2_conjugate<<<1, 1>>>(d_result, d_a);
  check_cuda_error(cudaGetLastError());

  cuda_synchronize_device(gpu_index);

  check_cuda_error(
      cudaMemcpy(result, d_result, sizeof(Fp2), cudaMemcpyDeviceToHost));

  if (d_result != nullptr)
    cuda_drop(d_result, gpu_index);
  if (d_a != nullptr)
    cuda_drop(d_a, gpu_index);
}

void fp2_square_gpu(Fp2 *result, const Fp2 *a) {
  uint32_t gpu_index = cuda_get_device();
  Fp2 *d_result = nullptr, *d_a = nullptr;

  d_result = static_cast<Fp2 *>(cuda_malloc(sizeof(Fp2), gpu_index));
  d_a = static_cast<Fp2 *>(cuda_malloc(sizeof(Fp2), gpu_index));

  check_cuda_error(cudaMemcpy(d_a, a, sizeof(Fp2), cudaMemcpyHostToDevice));

  kernel_fp2_square<<<1, 1>>>(d_result, d_a);
  check_cuda_error(cudaGetLastError());

  cuda_synchronize_device(gpu_index);

  check_cuda_error(
      cudaMemcpy(result, d_result, sizeof(Fp2), cudaMemcpyDeviceToHost));

  if (d_result != nullptr)
    cuda_drop(d_result, gpu_index);
  if (d_a != nullptr)
    cuda_drop(d_a, gpu_index);
}

void fp2_inv_gpu(Fp2 *result, const Fp2 *a) {
  uint32_t gpu_index = cuda_get_device();
  Fp2 *d_result = nullptr, *d_a = nullptr;

  d_result = static_cast<Fp2 *>(cuda_malloc(sizeof(Fp2), gpu_index));
  d_a = static_cast<Fp2 *>(cuda_malloc(sizeof(Fp2), gpu_index));

  // Zero-initialize result to ensure mont flags are properly set
  Fp2 zero_result;
  fp2_zero(zero_result);
  check_cuda_error(
      cudaMemcpy(d_result, &zero_result, sizeof(Fp2), cudaMemcpyHostToDevice));

  check_cuda_error(cudaMemcpy(d_a, a, sizeof(Fp2), cudaMemcpyHostToDevice));

  kernel_fp2_inv<<<1, 1>>>(d_result, d_a);
  check_cuda_error(cudaGetLastError());

  cuda_synchronize_device(gpu_index);

  check_cuda_error(
      cudaMemcpy(result, d_result, sizeof(Fp2), cudaMemcpyDeviceToHost));

  if (d_result != nullptr)
    cuda_drop(d_result, gpu_index);
  if (d_a != nullptr)
    cuda_drop(d_a, gpu_index);
}

void fp2_div_gpu(Fp2 *result, const Fp2 *a, const Fp2 *b) {
  uint32_t gpu_index = cuda_get_device();
  auto *d_result = static_cast<Fp2 *>(cuda_malloc(sizeof(Fp2), gpu_index));
  auto *d_a = static_cast<Fp2 *>(cuda_malloc(sizeof(Fp2), gpu_index));
  auto *d_b = static_cast<Fp2 *>(cuda_malloc(sizeof(Fp2), gpu_index));

  check_cuda_error(cudaMemcpy(d_a, a, sizeof(Fp2), cudaMemcpyHostToDevice));
  check_cuda_error(cudaMemcpy(d_b, b, sizeof(Fp2), cudaMemcpyHostToDevice));

  kernel_fp2_div<<<1, 1>>>(d_result, d_a, d_b);
  check_cuda_error(cudaGetLastError());

  cuda_synchronize_device(gpu_index);

  check_cuda_error(
      cudaMemcpy(result, d_result, sizeof(Fp2), cudaMemcpyDeviceToHost));

  if (d_result != nullptr)
    cuda_drop(d_result, gpu_index);
  if (d_a != nullptr)
    cuda_drop(d_a, gpu_index);
  if (d_b != nullptr)
    cuda_drop(d_b, gpu_index);
}

void fp2_mul_by_i_gpu(Fp2 *result, const Fp2 *a) {
  uint32_t gpu_index = cuda_get_device();
  Fp2 *d_result = nullptr, *d_a = nullptr;

  d_result = static_cast<Fp2 *>(cuda_malloc(sizeof(Fp2), gpu_index));
  d_a = static_cast<Fp2 *>(cuda_malloc(sizeof(Fp2), gpu_index));

  check_cuda_error(cudaMemcpy(d_a, a, sizeof(Fp2), cudaMemcpyHostToDevice));

  kernel_fp2_mul_by_i<<<1, 1>>>(d_result, d_a);
  check_cuda_error(cudaGetLastError());

  cuda_synchronize_device(gpu_index);

  check_cuda_error(
      cudaMemcpy(result, d_result, sizeof(Fp2), cudaMemcpyDeviceToHost));

  if (d_result != nullptr)
    cuda_drop(d_result, gpu_index);
  if (d_a != nullptr)
    cuda_drop(d_a, gpu_index);
}

void fp2_frobenius_gpu(Fp2 *result, const Fp2 *a) {
  uint32_t gpu_index = cuda_get_device();
  Fp2 *d_result = nullptr, *d_a = nullptr;

  d_result = static_cast<Fp2 *>(cuda_malloc(sizeof(Fp2), gpu_index));
  d_a = static_cast<Fp2 *>(cuda_malloc(sizeof(Fp2), gpu_index));

  check_cuda_error(cudaMemcpy(d_a, a, sizeof(Fp2), cudaMemcpyHostToDevice));

  kernel_fp2_frobenius<<<1, 1>>>(d_result, d_a);
  check_cuda_error(cudaGetLastError());

  cuda_synchronize_device(gpu_index);

  check_cuda_error(
      cudaMemcpy(result, d_result, sizeof(Fp2), cudaMemcpyDeviceToHost));

  if (d_result != nullptr)
    cuda_drop(d_result, gpu_index);
  if (d_a != nullptr)
    cuda_drop(d_a, gpu_index);
}

ComparisonType fp2_cmp_gpu(const Fp2 *a, const Fp2 *b) {
  uint32_t gpu_index = cuda_get_device();
  int *d_result = nullptr, *h_result = nullptr;
  Fp2 *d_a = nullptr, *d_b = nullptr;
  ComparisonType result = ComparisonType::Equal;

  h_result = new int;
  d_result = static_cast<int *>(cuda_malloc(sizeof(int), gpu_index));
  d_a = static_cast<Fp2 *>(cuda_malloc(sizeof(Fp2), gpu_index));
  d_b = static_cast<Fp2 *>(cuda_malloc(sizeof(Fp2), gpu_index));

  check_cuda_error(cudaMemcpy(d_a, a, sizeof(Fp2), cudaMemcpyHostToDevice));
  check_cuda_error(cudaMemcpy(d_b, b, sizeof(Fp2), cudaMemcpyHostToDevice));

  kernel_fp2_cmp<<<1, 1>>>(d_result, d_a, d_b);
  check_cuda_error(cudaGetLastError());

  cuda_synchronize_device(gpu_index);

  check_cuda_error(
      cudaMemcpy(h_result, d_result, sizeof(int), cudaMemcpyDeviceToHost));
  result = static_cast<ComparisonType>(*h_result);

  if (d_result != nullptr)
    cuda_drop(d_result, gpu_index);
  if (d_a != nullptr)
    cuda_drop(d_a, gpu_index);
  if (d_b != nullptr)
    cuda_drop(d_b, gpu_index);
  if (h_result != nullptr)
    delete h_result;
  return result;
}

bool fp2_is_zero_gpu(const Fp2 *a) {
  uint32_t gpu_index = cuda_get_device();
  auto *h_result = new bool;
  auto *d_result = static_cast<bool *>(cuda_malloc(sizeof(bool), gpu_index));
  auto *d_a = static_cast<Fp2 *>(cuda_malloc(sizeof(Fp2), gpu_index));
  bool result = false;

  check_cuda_error(cudaMemcpy(d_a, a, sizeof(Fp2), cudaMemcpyHostToDevice));

  kernel_fp2_is_zero<<<1, 1>>>(d_result, d_a);
  check_cuda_error(cudaGetLastError());

  cuda_synchronize_device(gpu_index);

  check_cuda_error(
      cudaMemcpy(h_result, d_result, sizeof(bool), cudaMemcpyDeviceToHost));
  result = *h_result;

  if (d_result != nullptr)
    cuda_drop(d_result, gpu_index);
  if (d_a != nullptr)
    cuda_drop(d_a, gpu_index);
  if (h_result != nullptr)
    delete h_result;
  return result;
}

bool fp2_is_one_gpu(const Fp2 *a) {
  uint32_t gpu_index = cuda_get_device();
  auto *h_result = new bool;
  auto *d_result = static_cast<bool *>(cuda_malloc(sizeof(bool), gpu_index));
  auto *d_a = static_cast<Fp2 *>(cuda_malloc(sizeof(Fp2), gpu_index));
  bool result = false;

  check_cuda_error(cudaMemcpy(d_a, a, sizeof(Fp2), cudaMemcpyHostToDevice));

  kernel_fp2_is_one<<<1, 1>>>(d_result, d_a);
  check_cuda_error(cudaGetLastError());

  cuda_synchronize_device(gpu_index);

  check_cuda_error(
      cudaMemcpy(h_result, d_result, sizeof(bool), cudaMemcpyDeviceToHost));
  result = *h_result;

  if (d_result != nullptr)
    cuda_drop(d_result, gpu_index);
  if (d_a != nullptr)
    cuda_drop(d_a, gpu_index);
  if (h_result != nullptr)
    delete h_result;
  return result;
}

void fp2_copy_gpu(Fp2 *result, const Fp2 *a) {
  uint32_t gpu_index = cuda_get_device();
  Fp2 *d_result = nullptr, *d_a = nullptr;

  d_result = static_cast<Fp2 *>(cuda_malloc(sizeof(Fp2), gpu_index));
  d_a = static_cast<Fp2 *>(cuda_malloc(sizeof(Fp2), gpu_index));

  check_cuda_error(cudaMemcpy(d_a, a, sizeof(Fp2), cudaMemcpyHostToDevice));

  kernel_fp2_copy<<<1, 1>>>(d_result, d_a);
  check_cuda_error(cudaGetLastError());

  cuda_synchronize_device(gpu_index);

  check_cuda_error(
      cudaMemcpy(result, d_result, sizeof(Fp2), cudaMemcpyDeviceToHost));

  if (d_result != nullptr)
    cuda_drop(d_result, gpu_index);
  if (d_a != nullptr)
    cuda_drop(d_a, gpu_index);
}

void fp2_cmov_gpu(Fp2 *result, const Fp2 *src, uint64_t condition) {
  uint32_t gpu_index = cuda_get_device();
  auto *d_result = static_cast<Fp2 *>(cuda_malloc(sizeof(Fp2), gpu_index));
  auto *d_src = static_cast<Fp2 *>(cuda_malloc(sizeof(Fp2), gpu_index));
  auto *d_condition =
      static_cast<uint64_t *>(cuda_malloc(sizeof(uint64_t), gpu_index));

  check_cuda_error(
      cudaMemcpy(d_result, result, sizeof(Fp2), cudaMemcpyHostToDevice));
  check_cuda_error(cudaMemcpy(d_src, src, sizeof(Fp2), cudaMemcpyHostToDevice));
  check_cuda_error(cudaMemcpy(d_condition, &condition, sizeof(uint64_t),
                              cudaMemcpyHostToDevice));

  kernel_fp2_cmov<<<1, 1>>>(d_result, d_src, condition);
  check_cuda_error(cudaGetLastError());

  cuda_synchronize_device(gpu_index);

  check_cuda_error(
      cudaMemcpy(result, d_result, sizeof(Fp2), cudaMemcpyDeviceToHost));

  if (d_result != nullptr)
    cuda_drop(d_result, gpu_index);
  if (d_src != nullptr)
    cuda_drop(d_src, gpu_index);
  if (d_condition != nullptr)
    cuda_drop(d_condition, gpu_index);
}
