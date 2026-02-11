cmake_minimum_required(VERSION 3.18)
project(
  FpArithmetic
  VERSION 1.0.0
  LANGUAGES CXX)

# Find and enable CUDA using the same pattern as tfhe-cuda-backend. This approach is more robust than declaring CUDA in
# project() because it uses a more forgiving code path that properly finds nvcc from PATH.
set(MINIMUM_SUPPORTED_CUDA_VERSION 10.0)
include(CheckLanguage)
check_language(CUDA)
if(CMAKE_CUDA_COMPILER)
  enable_language(CUDA)
else()
  message(FATAL_ERROR "CUDA compiler not found.")
endif()

if(CMAKE_CUDA_COMPILER_VERSION VERSION_LESS ${MINIMUM_SUPPORTED_CUDA_VERSION})
  message(FATAL_ERROR "CUDA ${MINIMUM_SUPPORTED_CUDA_VERSION} or greater is required for compilation.")
endif()

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CUDA_STANDARD 17)
set(CMAKE_CUDA_STANDARD_REQUIRED ON)

# Auto-detect CUDA compute capability using the same mechanism as tfhe-cuda-backend
set(OUTPUTFILE ${CMAKE_CURRENT_SOURCE_DIR}/cuda_script)
set(CUDAFILE ${CMAKE_CURRENT_SOURCE_DIR}/check_cuda.cu)
execute_process(COMMAND nvcc -lcuda ${CUDAFILE} -o ${OUTPUTFILE})
execute_process(
  COMMAND ${OUTPUTFILE}
  RESULT_VARIABLE CUDA_RETURN_CODE
  OUTPUT_VARIABLE ARCH)
file(REMOVE ${OUTPUTFILE})

if(${CUDA_RETURN_CODE} EQUAL 0)
  set(CUDA_SUCCESS "TRUE")
  message(STATUS "Detected CUDA architecture: ${ARCH}")
else()
  set(CUDA_SUCCESS "FALSE")
  message(WARNING "Could not detect CUDA architecture: ${ARCH}")
endif()

# CUDA architecture - auto-detect or fallback to 70 (Volta) Common values: 60 (Pascal), 70 (Volta), 75 (Turing), 80/86
# (Ampere), 89 (Ada), 90 (Hopper)
if(${CUDA_SUCCESS})
  set(CMAKE_CUDA_ARCHITECTURES native)
else()
  set(CMAKE_CUDA_ARCHITECTURES 70)
endif()

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

# Additional CUDA flags (aligned with tfhe-cuda-backend)
set(CMAKE_CUDA_FLAGS "${CMAKE_CUDA_FLAGS} -Xcompiler -Wall -Xcompiler -Wextra --use_fast_math --expt-relaxed-constexpr")

# =============================================================================
# Path to tfhe-cuda-backend for device utilities
# =============================================================================
set(TFHE_CUDA_BACKEND_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../../tfhe-cuda-backend/cuda)

# Core source files (without device utilities) Device utilities come from tfhe-cuda-backend.
set(FP_CORE_SOURCES src/primitives/fp.cu src/primitives/fp2.cu src/curve.cu src/msm/pippenger/msm_pippenger.cu
                    src/msm/msm.cu)

# Headers (common.cuh is a header, not a compiled source)
set(FP_MSM_HEADERS src/msm/common.cuh)

# C wrapper source for FFI bindings (CUDA for CUDA headers)
set(C_WRAPPER_SOURCES ../src/c_wrapper.cu)

# Headers (device.h comes from tfhe-cuda-backend)
set(FP_HEADERS include/fp.h include/fp_kernels.h include/fp2.h include/fp2_kernels.h include/curve.h)

# =============================================================================
# zk_cuda_backend: For Rust/Cargo builds (WITHOUT device.cu) Device utilities are provided by tfhe-cuda-backend when
# linking with tfhe.
# =============================================================================
add_library(zk_cuda_backend STATIC ${FP_CORE_SOURCES} ${FP_HEADERS} ${C_WRAPPER_SOURCES})

set_target_properties(
  zk_cuda_backend
  PROPERTIES CUDA_SEPARABLE_COMPILATION ON
             POSITION_INDEPENDENT_CODE ON
             CUDA_RESOLVE_DEVICE_SYMBOLS ON)

if(CMAKE_BUILD_TYPE STREQUAL "Release")
  set_target_properties(zk_cuda_backend PROPERTIES CUDA_OPTIMIZE_DEPENDENCIES ON)
elseif(CMAKE_BUILD_TYPE STREQUAL "Debug")
  # Explicitly set Debug flags for CUDA to ensure -g and -G are included
  target_compile_options(zk_cuda_backend PRIVATE $<$<COMPILE_LANGUAGE:CUDA>:-g -O0 -G>)
  message(STATUS "Debug build: CUDA flags -g -O0 -G will be used")
endif()

target_link_libraries(zk_cuda_backend PUBLIC cudart)

# Include both local headers and tfhe-cuda-backend headers (for device.h)
target_include_directories(zk_cuda_backend PUBLIC include ../src/include ${TFHE_CUDA_BACKEND_DIR}/include)

# =============================================================================
# Tests and Benchmarks (optional, controlled by ZK_CUDA_BACKEND_BUILD_TESTS/BENCHMARKS)
# =============================================================================
enable_testing()
add_subdirectory(tests_and_benchmarks)

# =============================================================================
# Installation (optional)
# =============================================================================
install(
  TARGETS zk_cuda_backend
  ARCHIVE DESTINATION lib
  LIBRARY DESTINATION lib)

install(FILES ${FP_HEADERS} DESTINATION include)

# Print configuration
message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")
message(STATUS "CUDA architectures: ${CMAKE_CUDA_ARCHITECTURES}")
message(STATUS "C++ standard: ${CMAKE_CXX_STANDARD}")
message(STATUS "CUDA standard: ${CMAKE_CUDA_STANDARD}")
message(STATUS "tfhe-cuda-backend path: ${TFHE_CUDA_BACKEND_DIR}")
