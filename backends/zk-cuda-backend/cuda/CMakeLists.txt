cmake_minimum_required(VERSION 3.18)
project(
  FpArithmetic
  VERSION 1.0.0
  LANGUAGES CXX CUDA)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CUDA_STANDARD 17)
set(CMAKE_CUDA_STANDARD_REQUIRED ON)

# CUDA architecture - adjust based on your GPU Common values: sm_60 (Pascal), sm_70 (Volta), sm_75 (Turing), sm_80/86
# (Ampere), sm_89 (Ada), sm_90 (Hopper)
set(CMAKE_CUDA_ARCHITECTURES
    "89"
    CACHE STRING "CUDA architectures to build for")

# Enable CUDA separable compilation for better optimization
set(CMAKE_CUDA_SEPARABLE_COMPILATION ON)

# Build type - set default if not specified
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE
      Release
      CACHE STRING "Build type" FORCE)
endif()

# Compiler flags - CMake will automatically use these based on CMAKE_BUILD_TYPE These must be set before targets are
# created to be effective
set(CMAKE_CXX_FLAGS_RELEASE "-O3 -DNDEBUG")
set(CMAKE_CUDA_FLAGS_RELEASE "-O3 -DNDEBUG")
set(CMAKE_CXX_FLAGS_DEBUG "-g -O0")
set(CMAKE_CUDA_FLAGS_DEBUG "-g -O0 -G")

# Additional CUDA flags
set(CMAKE_CUDA_FLAGS "${CMAKE_CUDA_FLAGS} -Xcompiler -Wall -Xcompiler -Wextra")

# USE_NAIVE_MSM flag to select MSM algorithm
option(USE_NAIVE_MSM "Use naive MSM algorithm instead of Pippenger" OFF)

# =============================================================================
# Path to tfhe-cuda-backend for device utilities
# =============================================================================
set(TFHE_CUDA_BACKEND_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../../tfhe-cuda-backend/cuda)

# Core source files (without device utilities) Device utilities come from tfhe-cuda-backend.
set(FP_CORE_SOURCES
    src/primitives/fp.cu
    src/primitives/fp2.cu
    src/curve.cu
    src/msm/common.cuh
    src/msm/naive/msm_naive.cu
    src/msm/pippenger/msm_pippenger.cu
    src/msm/msm.cu)

# C wrapper source for FFI bindings (CUDA for CUDA headers)
set(C_WRAPPER_SOURCES ../src/c_wrapper.cu)

# Headers (device.h comes from tfhe-cuda-backend)
set(FP_HEADERS include/fp.h include/fp_kernels.h include/fp2.h include/fp2_kernels.h include/curve.h)

# Find CUDA toolkit
find_package(CUDAToolkit REQUIRED)

# =============================================================================
# fp_arithmetic: For Rust/Cargo builds (WITHOUT device.cu) Device utilities are provided by tfhe-cuda-backend when
# linking with tfhe.
# =============================================================================
add_library(fp_arithmetic STATIC ${FP_CORE_SOURCES} ${FP_HEADERS} ${C_WRAPPER_SOURCES})

set_target_properties(
  fp_arithmetic
  PROPERTIES CUDA_SEPARABLE_COMPILATION ON
             POSITION_INDEPENDENT_CODE ON
             CUDA_RESOLVE_DEVICE_SYMBOLS ON)

if(CMAKE_BUILD_TYPE STREQUAL "Release")
  set_target_properties(fp_arithmetic PROPERTIES CUDA_OPTIMIZE_DEPENDENCIES ON)
elseif(CMAKE_BUILD_TYPE STREQUAL "Debug")
  # Explicitly set Debug flags for CUDA to ensure -g and -G are included
  target_compile_options(fp_arithmetic PRIVATE $<$<COMPILE_LANGUAGE:CUDA>:-g -O0 -G>)
  message(STATUS "Debug build: CUDA flags -g -O0 -G will be used")
endif()

target_link_libraries(fp_arithmetic PUBLIC CUDA::cudart)

if(USE_NAIVE_MSM)
  target_compile_definitions(fp_arithmetic PRIVATE USE_NAIVE_MSM=1)
  message(STATUS "USE_NAIVE_MSM enabled: using naive MSM algorithm")
else()
  message(STATUS "USE_NAIVE_MSM disabled: using Pippenger algorithm (default)")
endif()

# Include both local headers and tfhe-cuda-backend headers (for device.h)
target_include_directories(fp_arithmetic PUBLIC include ../src/include ${TFHE_CUDA_BACKEND_DIR}/include)

# =============================================================================
# Tests and Benchmarks (optional, controlled by ZK_CUDA_BACKEND_BUILD_TESTS/BENCHMARKS)
# =============================================================================
enable_testing()
add_subdirectory(tests_and_benchmarks)

# =============================================================================
# Installation (optional)
# =============================================================================
install(
  TARGETS fp_arithmetic
  ARCHIVE DESTINATION lib
  LIBRARY DESTINATION lib)

install(FILES ${FP_HEADERS} DESTINATION include)

# Print configuration
message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")
message(STATUS "CUDA architectures: ${CMAKE_CUDA_ARCHITECTURES}")
message(STATUS "C++ standard: ${CMAKE_CXX_STANDARD}")
message(STATUS "CUDA standard: ${CMAKE_CUDA_STANDARD}")
message(STATUS "USE_NAIVE_MSM flag: ${USE_NAIVE_MSM}")
message(STATUS "tfhe-cuda-backend path: ${TFHE_CUDA_BACKEND_DIR}")
