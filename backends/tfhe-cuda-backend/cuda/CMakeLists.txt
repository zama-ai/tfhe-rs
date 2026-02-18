cmake_minimum_required(VERSION 3.24 FATAL_ERROR)
project(tfhe_cuda_backend LANGUAGES CXX)

# See if the minimum CUDA version is available. If not, only enable documentation building.
set(MINIMUM_SUPPORTED_CUDA_VERSION 10.0)
include(CheckLanguage)
# See if CUDA is available
check_language(CUDA)
# If so, enable CUDA to check the version.
if(CMAKE_CUDA_COMPILER)
  enable_language(CUDA)
endif()
# If CUDA is not available, or the minimum version is too low do not build
if(NOT CMAKE_CUDA_COMPILER)
  message(FATAL_ERROR "Cuda compiler not found.")
endif()

if(CMAKE_CUDA_COMPILER_VERSION VERSION_LESS ${MINIMUM_SUPPORTED_CUDA_VERSION})
  message(FATAL_ERROR "CUDA ${MINIMUM_SUPPORTED_CUDA_VERSION} or greater is required for compilation.")
endif()
# Get CUDA compute capability
set(OUTPUTFILE ${CMAKE_CURRENT_SOURCE_DIR}/cuda_script) # No suffix required
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

if(${MULTI_ARCH})
  message(STATUS "Multi-architecture GPU build enabled, 75, 80, 86, 89")
  message(STATUS "CUDA Version: ${CUDA_VERSION_STRING}")
  message(STATUS "CUDA Path: ${CUDA_TOOLKIT_ROOT_DIR}")
  message(STATUS "CUDA Libraries: ${CUDA_LIBRARIES}")
  message(STATUS "CUDA Performance Primitives: ${CUDA_npp_LIBRARY}")
elseif(${CUDA_SUCCESS})
  message(STATUS "CUDA Architecture: ${ARCH}")
  message(STATUS "CUDA Version: ${CUDA_VERSION_STRING}")
  message(STATUS "CUDA Path: ${CUDA_TOOLKIT_ROOT_DIR}")
  message(STATUS "CUDA Libraries: ${CUDA_LIBRARIES}")
  message(STATUS "CUDA Performance Primitives: ${CUDA_npp_LIBRARY}")
else()
  message(WARNING ${ARCH})
endif()

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
else()
  message("Building CUDA backend in ${CMAKE_BUILD_TYPE}")
endif()

# Add OpenMP support
find_package(OpenMP REQUIRED)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -Wpedantic")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS}  -g")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${OpenMP_CXX_FLAGS}")
set(CMAKE_CUDA_FLAGS "${CMAKE_CUDA_FLAGS} -Xcompiler ${OpenMP_CXX_FLAGS}")
if(${MULTI_ARCH})
  set(CUDA_ARCH "750")
  set(CMAKE_CUDA_ARCHITECTURES 75 80 86 89)
elseif(${CUDA_SUCCESS})
  set(CMAKE_CUDA_ARCHITECTURES native)
  string(REPLACE "-arch=sm_" "" CUDA_ARCH "${ARCH}")
  set(CUDA_ARCH "${CUDA_ARCH}0")
else()
  set(CMAKE_CUDA_ARCHITECTURES 70)
  set(CUDA_ARCH "700")
endif()

add_compile_definitions(CUDA_ARCH=${CUDA_ARCH})

string(TOLOWER "${CMAKE_BUILD_TYPE}" CMAKE_BUILD_TYPE_LOWERCASE)

# Check if the DEBUG flag is defined
if(CMAKE_BUILD_TYPE_LOWERCASE STREQUAL "debug")
  # Debug mode
  message("Compiling in Debug mode")
  add_definitions(-DDEBUG)
  set(OPTIMIZATION_FLAGS "${OPTIMIZATION_FLAGS} -O0 -G -g")
  set(USE_NVTOOLS 1)
elseif(CMAKE_BUILD_TYPE_LOWERCASE STREQUAL "debugonlycpu")
  message("Compiling GPU kernels in Release and CPU code in Debug")
  set(OPTIMIZATION_FLAGS "${OPTIMIZATION_FLAGS} -O0 -g")
else()
  # Release mode
  message("Compiling in Release mode")
  set(OPTIMIZATION_FLAGS "${OPTIMIZATION_FLAGS} -O3")
endif()

# Check if the USE_NVTOOLS environment variable is set
if(${USE_NVTOOLS})
  message(STATUS "USE_NVTOOLS is enabled")
  add_definitions(-DUSE_NVTOOLS)
endif()

if(${FAKE_MULTI_GPU})
  message(STATUS "Fake multi-gpu debugging is enabled")
  add_definitions(-DDEBUG_FAKE_MULTI_GPU)
endif()

# in production, should use -arch=sm_70 --ptxas-options=-v to see register spills -lineinfo for better debugging to use
# nvtx when profiling -lnvToolsExt
set(CMAKE_CUDA_FLAGS
    "${CMAKE_CUDA_FLAGS} -ccbin ${CMAKE_CXX_COMPILER} ${OPTIMIZATION_FLAGS}\
  -std=c++17 --no-exceptions  --expt-relaxed-constexpr -rdc=true \
  --use_fast_math -Xcompiler -fPIC ")

set(INCLUDE_DIR include)

add_subdirectory(src)
enable_testing()
add_subdirectory(tests_and_benchmarks)
target_include_directories(tfhe_cuda_backend PRIVATE ${INCLUDE_DIR})

# This is required for rust cargo build
install(TARGETS tfhe_cuda_backend DESTINATION .)

install(TARGETS tfhe_cuda_backend DESTINATION lib)

# Define a function to add a lint target.
find_file(CPPLINT NAMES cpplint cpplint.exe)
if(CPPLINT)
  # Add a custom target to lint all child projects. Dependencies are specified in child projects.
  add_custom_target(all_lint)
  # Don't trigger this target on ALL_BUILD or Visual Studio 'Rebuild Solution'
  set_target_properties(all_lint PROPERTIES EXCLUDE_FROM_ALL TRUE)
  # set_target_properties(all_lint PROPERTIES EXCLUDE_FROM_DEFAULT_BUILD TRUE)
endif()
