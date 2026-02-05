#include "device.h"
#include "fp.h"
#include <cuda_runtime.h>
#include <gtest/gtest.h>

// Kernel that calls fp_one_montgomery INSIDE the device kernel
__global__ void kernel_fp_one_montgomery_device(Fp *result) {
  fp_one_montgomery(*result);
}

// Kernel that calls fp_to_montgomery INSIDE the device kernel
__global__ void kernel_fp_to_montgomery_device(Fp *result) {
  Fp one;
  one.limb[0] = 1;
  for (int i = 1; i < FP_LIMBS; i++) {
    one.limb[i] = 0;
  }
  fp_to_montgomery(*result, one);
}

// Kernel that manually sets hardcoded Z value
__global__ void kernel_hardcoded_z(Fp *result) {
  result->limb[0] = 0x3b8fff65553d5554ULL;
  result->limb[1] = 0xa446eb5cea3128cfULL;
  result->limb[2] = 0xf6c648f07714c846ULL;
  result->limb[3] = 0xc22966d114e3a7f5ULL;
  result->limb[4] = 0xfda96d21d7f40737ULL;
  result->limb[5] = 0x7fc0f2da6954a6ffULL;
  result->limb[6] = 0x0c847c135ce86b2bULL;
}

TEST(FpDeviceCall, FpOneMontgomeryInKernel) {
  uint64_t size_tracker = 0;
  if (!cuda_is_available()) {
    GTEST_SKIP() << "CUDA not available";
  }

  uint32_t gpu_index = 0;
  auto stream = cuda_create_stream(gpu_index);

  auto *d_result = static_cast<Fp *>(cuda_malloc_with_size_tracking_async(
      sizeof(Fp), stream, gpu_index, size_tracker, true));

  // Call fp_one_montgomery INSIDE device kernel
  kernel_fp_one_montgomery_device<<<1, 1, 0, stream>>>(d_result);
  check_cuda_error(cudaGetLastError());

  cuda_synchronize_stream(stream, gpu_index);

  Fp h_result;
  cuda_memcpy_async_to_cpu(&h_result, d_result, sizeof(Fp), stream, gpu_index);
  cuda_synchronize_stream(stream, gpu_index);

  // Check if result is zero
  bool is_zero = fp_is_zero(h_result);

  std::cout << "fp_one_montgomery (called IN device kernel) result:"
            << std::endl;
  for (int i = 0; i < 7; i++) {
    std::cout << "  limb[" << i << "] = 0x" << std::hex << h_result.limb[i]
              << std::dec << std::endl;
  }
  std::cout << "Is zero: " << (is_zero ? "YES - BUG!" : "no") << std::endl;

  EXPECT_FALSE(is_zero)
      << "fp_one_montgomery should NOT return zero when called from device!";

  cuda_drop_with_size_tracking_async(d_result, stream, gpu_index, true);
  cuda_destroy_stream(stream, gpu_index);
}

TEST(FpDeviceCall, FpToMontgomeryInKernel) {
  uint64_t size_tracker = 0;
  if (!cuda_is_available()) {
    GTEST_SKIP() << "CUDA not available";
  }

  uint32_t gpu_index = 0;
  auto stream = cuda_create_stream(gpu_index);

  auto *d_result = static_cast<Fp *>(cuda_malloc_with_size_tracking_async(
      sizeof(Fp), stream, gpu_index, size_tracker, true));

  // Call fp_to_montgomery INSIDE device kernel
  kernel_fp_to_montgomery_device<<<1, 1, 0, stream>>>(d_result);
  check_cuda_error(cudaGetLastError());

  cuda_synchronize_stream(stream, gpu_index);

  Fp h_result;
  cuda_memcpy_async_to_cpu(&h_result, d_result, sizeof(Fp), stream, gpu_index);
  cuda_synchronize_stream(stream, gpu_index);

  // Check if result is zero
  bool is_zero = fp_is_zero(h_result);

  std::cout << "fp_to_montgomery(1) (called IN device kernel) result:"
            << std::endl;
  for (int i = 0; i < 7; i++) {
    std::cout << "  limb[" << i << "] = 0x" << std::hex << h_result.limb[i]
              << std::dec << std::endl;
  }
  std::cout << "Is zero: " << (is_zero ? "YES - BUG!" : "no") << std::endl;

  EXPECT_FALSE(is_zero)
      << "fp_to_montgomery(1) should NOT return zero when called from device!";

  cuda_drop_with_size_tracking_async(d_result, stream, gpu_index, true);
  cuda_destroy_stream(stream, gpu_index);
}

TEST(FpDeviceCall, HardcodedZValue) {
  uint64_t size_tracker = 0;
  if (!cuda_is_available()) {
    GTEST_SKIP() << "CUDA not available";
  }

  uint32_t gpu_index = 0;
  auto stream = cuda_create_stream(gpu_index);

  auto *d_result = static_cast<Fp *>(cuda_malloc_with_size_tracking_async(
      sizeof(Fp), stream, gpu_index, size_tracker, true));

  // Set hardcoded Z value INSIDE device kernel
  kernel_hardcoded_z<<<1, 1, 0, stream>>>(d_result);
  check_cuda_error(cudaGetLastError());

  cuda_synchronize_stream(stream, gpu_index);

  Fp h_result;
  cuda_memcpy_async_to_cpu(&h_result, d_result, sizeof(Fp), stream, gpu_index);
  cuda_synchronize_stream(stream, gpu_index);

  // Check if result is zero
  bool is_zero = fp_is_zero(h_result);

  std::cout << "Hardcoded Z (set IN device kernel) result:" << std::endl;
  for (int i = 0; i < 7; i++) {
    std::cout << "  limb[" << i << "] = 0x" << std::hex << h_result.limb[i]
              << std::dec << std::endl;
  }
  std::cout << "Is zero: " << (is_zero ? "YES - BUG!" : "no") << std::endl;

  EXPECT_FALSE(is_zero) << "Hardcoded Z value should NOT be zero!";

  cuda_drop_with_size_tracking_async(d_result, stream, gpu_index, true);
  cuda_destroy_stream(stream, gpu_index);
}
