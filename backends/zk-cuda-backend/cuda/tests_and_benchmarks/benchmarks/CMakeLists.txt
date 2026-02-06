project(benchmark_zk_cuda_backend LANGUAGES CXX CUDA)

# Fetch Google Benchmark
include(FetchContent)
FetchContent_Declare(
  googlebenchmark
  GIT_REPOSITORY https://github.com/google/benchmark.git
  GIT_TAG v1.8.3)
# Disable testing of benchmark library itself
set(BENCHMARK_ENABLE_TESTING
    OFF
    CACHE BOOL "" FORCE)
set(BENCHMARK_ENABLE_GTEST_TESTS
    OFF
    CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googlebenchmark)

# Path to tfhe-cuda-backend for device utilities
set(TFHE_CUDA_BACKEND_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../../../../tfhe-cuda-backend/cuda)

# Path to main source (needed for CUDA device linking)
set(ZK_SRC_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../../src)
set(ZK_PRIMITIVES_DIR ${ZK_SRC_DIR}/primitives)

# Build device library from tfhe-cuda-backend
add_library(tfhe_device_bench STATIC ${TFHE_CUDA_BACKEND_DIR}/src/device.cu)
set_target_properties(
  tfhe_device_bench
  PROPERTIES CUDA_SEPARABLE_COMPILATION ON
             POSITION_INDEPENDENT_CODE ON
             CUDA_RESOLVE_DEVICE_SYMBOLS ON)
target_include_directories(tfhe_device_bench PUBLIC ${TFHE_CUDA_BACKEND_DIR}/include)
target_link_libraries(tfhe_device_bench PUBLIC cudart)

# Benchmark executable for Fp Include fp.cu, fp2.cu and curve.cu directly to enable proper CUDA device linking with
# benchmark kernels (curve.cu depends on both fp and fp2)
add_executable(benchmark_fp benchmark_fp.cu ../tests/primitives/fp_helpers.cu ${ZK_PRIMITIVES_DIR}/fp.cu
                            ${ZK_PRIMITIVES_DIR}/fp2.cu ${ZK_SRC_DIR}/curve.cu)
target_link_libraries(benchmark_fp tfhe_device_bench benchmark::benchmark benchmark::benchmark_main)
target_include_directories(benchmark_fp PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../../include)
set_target_properties(
  benchmark_fp
  PROPERTIES CUDA_ARCHITECTURES ${CMAKE_CUDA_ARCHITECTURES}
             CUDA_SEPARABLE_COMPILATION ON
             CUDA_RESOLVE_DEVICE_SYMBOLS ON)

# Benchmark executable for Fp2 Include fp.cu, fp2.cu and curve.cu directly to enable proper CUDA device linking with
# benchmark kernels
add_executable(benchmark_fp2 benchmark_fp2.cu ../tests/primitives/fp2_helpers.cu ${ZK_PRIMITIVES_DIR}/fp.cu
                             ${ZK_PRIMITIVES_DIR}/fp2.cu ${ZK_SRC_DIR}/curve.cu)
target_link_libraries(benchmark_fp2 tfhe_device_bench benchmark::benchmark benchmark::benchmark_main)
target_include_directories(benchmark_fp2 PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../../include)
set_target_properties(
  benchmark_fp2
  PROPERTIES CUDA_ARCHITECTURES ${CMAKE_CUDA_ARCHITECTURES}
             CUDA_SEPARABLE_COMPILATION ON
             CUDA_RESOLVE_DEVICE_SYMBOLS ON)

# Benchmark executable for MSM
add_executable(benchmark_msm benchmark_msm.cu)
target_link_libraries(benchmark_msm zk_cuda_backend tfhe_device_bench benchmark::benchmark benchmark::benchmark_main)
set_target_properties(
  benchmark_msm
  PROPERTIES CUDA_ARCHITECTURES ${CMAKE_CUDA_ARCHITECTURES}
             CUDA_SEPARABLE_COMPILATION ON
             CUDA_RESOLVE_DEVICE_SYMBOLS ON)
