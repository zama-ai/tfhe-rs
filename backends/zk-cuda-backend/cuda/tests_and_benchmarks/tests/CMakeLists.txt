project(test_zk_cuda_backend LANGUAGES CXX CUDA)

# Fetch Google Test
include(FetchContent)
FetchContent_Declare(
  googletest
  GIT_REPOSITORY https://github.com/google/googletest.git
  GIT_TAG v1.14.0)
# For Windows: Prevent overriding the parent project's compiler/linker settings
set(gtest_force_shared_crt
    ON
    CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

# Path to tfhe-cuda-backend for device utilities
set(TFHE_CUDA_BACKEND_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../../../../tfhe-cuda-backend/cuda)

# Path to main source (needed for CUDA device linking)
set(ZK_SRC_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../../src)
set(ZK_PRIMITIVES_DIR ${ZK_SRC_DIR}/primitives)

# Build device library from tfhe-cuda-backend
add_library(tfhe_device STATIC ${TFHE_CUDA_BACKEND_DIR}/src/device.cu)
set_target_properties(
  tfhe_device
  PROPERTIES CUDA_SEPARABLE_COMPILATION ON
             POSITION_INDEPENDENT_CODE ON
             CUDA_RESOLVE_DEVICE_SYMBOLS ON)
target_include_directories(tfhe_device PUBLIC ${TFHE_CUDA_BACKEND_DIR}/include)
target_link_libraries(tfhe_device PUBLIC cudart)

# Test executable for Fp Include fp.cu, fp2.cu and curve.cu directly to enable proper CUDA device linking with test
# kernels (curve.cu depends on both fp and fp2)
add_executable(test_fp primitives/test_fp.cu primitives/test_fp_gpu_helpers.cu primitives/fp_helpers.cu
                       ${ZK_PRIMITIVES_DIR}/fp.cu ${ZK_PRIMITIVES_DIR}/fp2.cu ${ZK_SRC_DIR}/curve.cu)
target_link_libraries(test_fp tfhe_device GTest::gtest_main)
target_include_directories(test_fp PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../../include)
set_target_properties(
  test_fp
  PROPERTIES CUDA_ARCHITECTURES ${CMAKE_CUDA_ARCHITECTURES}
             CUDA_SEPARABLE_COMPILATION ON
             CUDA_RESOLVE_DEVICE_SYMBOLS ON)

# Test executable for Fp2 Include fp.cu, fp2.cu and curve.cu directly to enable proper CUDA device linking with test
# kernels
add_executable(test_fp2 primitives/test_fp2.cu primitives/test_fp2_gpu_helpers.cu primitives/fp2_helpers.cu
                        ${ZK_PRIMITIVES_DIR}/fp.cu ${ZK_PRIMITIVES_DIR}/fp2.cu ${ZK_SRC_DIR}/curve.cu)
target_link_libraries(test_fp2 tfhe_device GTest::gtest_main)
target_include_directories(test_fp2 PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../../include)
set_target_properties(
  test_fp2
  PROPERTIES CUDA_ARCHITECTURES ${CMAKE_CUDA_ARCHITECTURES}
             CUDA_SEPARABLE_COMPILATION ON
             CUDA_RESOLVE_DEVICE_SYMBOLS ON)

# Test executable for MSM
add_executable(test_msm test_msm.cu)
target_link_libraries(test_msm zk_cuda_backend tfhe_device GTest::gtest_main)
set_target_properties(
  test_msm
  PROPERTIES CUDA_ARCHITECTURES ${CMAKE_CUDA_ARCHITECTURES}
             CUDA_SEPARABLE_COMPILATION ON
             CUDA_RESOLVE_DEVICE_SYMBOLS ON)

# Test executable for point operations
add_executable(test_point_ops test_point_ops.cu)
target_link_libraries(test_point_ops zk_cuda_backend tfhe_device GTest::gtest_main)
set_target_properties(
  test_point_ops
  PROPERTIES CUDA_ARCHITECTURES ${CMAKE_CUDA_ARCHITECTURES}
             CUDA_SEPARABLE_COMPILATION ON
             CUDA_RESOLVE_DEVICE_SYMBOLS ON)

# Register tests with CTest
include(GoogleTest)
gtest_discover_tests(test_fp)
gtest_discover_tests(test_fp2)
gtest_discover_tests(test_msm)
gtest_discover_tests(test_point_ops)

# Basic usage examples (standalone programs, not registered with CTest)
add_subdirectory(basic)
