cmake_minimum_required(VERSION 3.18)
project(
  CommonCudaBackend
  VERSION 1.0.0
  LANGUAGES CXX)

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

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CUDA_STANDARD 17)
set(CMAKE_CUDA_STANDARD_REQUIRED ON)

# Auto-detect CUDA compute capability
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
else()
  set(CUDA_SUCCESS "FALSE")
endif()

if(${CUDA_SUCCESS})
  set(CMAKE_CUDA_ARCHITECTURES native)
else()
  set(CMAKE_CUDA_ARCHITECTURES 70)
endif()

set(CMAKE_CUDA_SEPARABLE_COMPILATION ON)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE
      Release
      CACHE STRING "Build type" FORCE)
endif()

set(CMAKE_CXX_FLAGS_RELEASE "-O3 -DNDEBUG")
set(CMAKE_CUDA_FLAGS_RELEASE "-O3 -DNDEBUG")
set(CMAKE_CXX_FLAGS_DEBUG "-g -O0")
set(CMAKE_CUDA_FLAGS_DEBUG "-g -O0 -G")

if(${USE_NVTOOLS})
  add_definitions(-DUSE_NVTOOLS)
endif()

set(CMAKE_CUDA_FLAGS "${CMAKE_CUDA_FLAGS} -Xcompiler -Wall -Xcompiler -Wextra --use_fast_math --expt-relaxed-constexpr")

set(COMMON_SOURCES src/device.cu src/helper_profile.cu)

add_library(tfhe_cuda_common STATIC ${COMMON_SOURCES})

set_target_properties(
  tfhe_cuda_common
  PROPERTIES CUDA_SEPARABLE_COMPILATION ON
             POSITION_INDEPENDENT_CODE ON
             CUDA_RESOLVE_DEVICE_SYMBOLS ON)

if(CMAKE_BUILD_TYPE STREQUAL "Release")
  set_target_properties(tfhe_cuda_common PROPERTIES CUDA_OPTIMIZE_DEPENDENCIES ON)
elseif(CMAKE_BUILD_TYPE STREQUAL "Debug")
  target_compile_options(tfhe_cuda_common PRIVATE $<$<COMPILE_LANGUAGE:CUDA>:-g -O0 -G>)
endif()

target_include_directories(tfhe_cuda_common PUBLIC include)
target_link_libraries(tfhe_cuda_common PUBLIC cudart)

install(
  TARGETS tfhe_cuda_common
  ARCHIVE DESTINATION lib
  LIBRARY DESTINATION lib)
