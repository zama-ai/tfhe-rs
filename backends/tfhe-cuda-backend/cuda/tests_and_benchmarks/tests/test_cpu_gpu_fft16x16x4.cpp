#include "checked_arithmetic.h"
#include "device.h"
#include "fft16x16x4_cpu_reference.h"
#include "pbs/programmable_bootstrap.h"
#include "gtest/gtest.h"
#include <cstdint>
#include <cuda_runtime.h>
#include <iostream>
#include <random>
#include <vector>

// Bit-exact CPU-vs-GPU cross-check of the paired FFT16x16x4 forward transform
// (the forward FFT of the specialized 2_2_params PBS). Every run draws fresh
// random inputs, transforms them with cuda_forward_fft16x16x4_async and with
// the serial host port of fft16x16x4_cpu_reference.h, and requires identical
// bits: the kernel uses round-to-nearest intrinsics only, so a faithful port
// reproduces it exactly. Runs on compute capability 8.x and newer, where the
// kernel was checked bit for bit against the H100.

// FFT16x16x4 is specialized for N = 2048; two polynomials per block.
constexpr size_t FFT16_POLYNOMIAL_SIZE = 2048;
constexpr int FFT16_SAMPLES = 100;

TEST(CpuGpuFFT16x16x4, forward_matches_cpu_bitwise) {
  using namespace fft16x16x4_cpu;
  const uint32_t gpu_index = 0;

  cudaDeviceProp prop;
  cudaError_t err = cudaGetDeviceProperties(&prop, gpu_index);
  if (err != cudaSuccess || prop.major < 8) {
    GTEST_SKIP() << "FFT16x16x4 CPU/GPU bit-exact test requires compute "
                 << "capability 8.x or above; detected "
                 << (err == cudaSuccess ? prop.major : -1) << "."
                 << (err == cudaSuccess ? prop.minor : -1);
  }

  static Tables tables;
  load_tables_from_device(tables);

  const size_t half = FFT16_POLYNOMIAL_SIZE / 2;
  const size_t total = half * (size_t)FFT16_SAMPLES;

  // Fresh random complex input on every run.
  std::random_device rd;
  std::mt19937_64 gen(rd());
  std::uniform_real_distribution<double> unif(-1.0, 1.0);
  std::vector<double2> h_input(total);
  for (size_t i = 0; i < total; i++)
    h_input[i] = double2{unif(gen), unif(gen)};

  cudaStream_t stream = cuda_create_stream(gpu_index);
  double2 *d_input = (double2 *)cuda_malloc_async(
      safe_mul_sizeof<double2>(total), stream, gpu_index);
  double2 *d_output = (double2 *)cuda_malloc_async(
      safe_mul_sizeof<double2>(total), stream, gpu_index);
  cuda_memcpy_async_to_gpu(d_input, h_input.data(),
                           safe_mul_sizeof<double2>(total), stream, gpu_index);

  cuda_forward_fft16x16x4_async(stream, gpu_index, d_input, d_output,
                                FFT16_POLYNOMIAL_SIZE, FFT16_SAMPLES);

  std::vector<double2> h_gpu(total);
  cuda_memcpy_async_to_cpu(h_gpu.data(), d_output,
                           safe_mul_sizeof<double2>(total), stream, gpu_index);
  cuda_synchronize_stream(stream, gpu_index);

  std::vector<double2> h_cpu(total);
  for (int p = 0; p < FFT16_SAMPLES; p += 2)
    forward_pair(tables, &h_input[p * half], &h_input[(p + 1) * half],
                 &h_cpu[p * half], &h_cpu[(p + 1) * half]);

  size_t mismatches = 0;
  for (size_t i = 0; i < total; i++) {
    const bool same = f64_to_bits(h_gpu[i].x) == f64_to_bits(h_cpu[i].x) &&
                      f64_to_bits(h_gpu[i].y) == f64_to_bits(h_cpu[i].y);
    if (!same && mismatches++ < 8) {
      ADD_FAILURE() << "sample " << i / half << " frequency " << i % half
                    << ": gpu (" << h_gpu[i].x << ", " << h_gpu[i].y
                    << ") cpu (" << h_cpu[i].x << ", " << h_cpu[i].y << ")";
    }
  }
  EXPECT_EQ(mismatches, 0u) << "coefficients differing from the CPU reference";

  // AVX-512 host path, lane-wise over the thread index, must be bit-identical
  // too. Reported as skipped where the CPU lacks AVX-512; the scalar check
  // above stands on its own.
#ifdef FFT16_HAVE_AVX512
  if (__builtin_cpu_supports("avx512f") && __builtin_cpu_supports("avx512dq")) {
    static avx512::Tw tw_avx;
    avx512::build_tw(tables, tw_avx);
    std::vector<double2> h_avx(total);
    for (int p = 0; p < FFT16_SAMPLES; p += 2)
      avx512::forward_pair(tw_avx, &h_input[p * half], &h_input[(p + 1) * half],
                           &h_avx[p * half], &h_avx[(p + 1) * half]);
    size_t avx_mismatches = 0;
    for (size_t i = 0; i < total; i++) {
      const bool same = f64_to_bits(h_gpu[i].x) == f64_to_bits(h_avx[i].x) &&
                        f64_to_bits(h_gpu[i].y) == f64_to_bits(h_avx[i].y);
      if (!same && avx_mismatches++ < 8) {
        ADD_FAILURE() << "avx512 sample " << i / half << " index " << i % half
                      << ": gpu (" << h_gpu[i].x << ", " << h_gpu[i].y
                      << ") avx (" << h_avx[i].x << ", " << h_avx[i].y << ")";
      }
    }
    EXPECT_EQ(avx_mismatches, 0u)
        << "coefficients differing from the AVX-512 reference";
    std::cout
        << "[ INFO     ] AVX-512 forward path compared bit-for-bit vs GPU ("
        << FFT16_SAMPLES << " polynomials)" << std::endl;
  } else {
    std::cout << "[ INFO     ] AVX-512 unavailable at runtime; AVX comparison "
                 "skipped (scalar vs GPU still checked)"
              << std::endl;
  }
#else
  std::cout << "[ INFO     ] AVX-512 not compiled on this architecture; AVX "
               "comparison skipped (scalar vs GPU still checked)"
            << std::endl;
#endif

  cuda_drop_async(d_input, stream, gpu_index);
  cuda_drop_async(d_output, stream, gpu_index);
  cuda_synchronize_stream(stream, gpu_index);
  cuda_destroy_stream(stream, gpu_index);
}
