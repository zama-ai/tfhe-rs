project(benchmark_tfhe_cuda_backend LANGUAGES CXX)

# See if the minimum CUDA version is available. If not, only enable documentation building.
set(MINIMUM_SUPPORTED_CUDA_VERSION 10.0)
include(CheckLanguage)
# See if CUDA is available
check_language(CUDA)
# If so, enable CUDA to check the version.
if(CMAKE_CUDA_COMPILER)
  enable_language(CUDA)
  find_package(CUDAToolkit)
endif()
# If CUDA is not available, or the minimum version is too low do not build
if(NOT CMAKE_CUDA_COMPILER)
  message(FATAL_ERROR "Cuda compiler not found.")
endif()

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

# Disable the Google Benchmark requirement on Google Test
set(BENCHMARK_ENABLE_GTEST_TESTS OFF)
set(BENCHMARK_ENABLE_TESTING OFF)

include(FetchContent)
FetchContent_Declare(
  googlebenchmark
  GIT_REPOSITORY https://github.com/google/benchmark.git
  GIT_TAG v1.7.1)
FetchContent_MakeAvailable(googlebenchmark)

# Enable ExternalProject CMake module
include(ExternalProject)

set(CONCRETE_CUDA_SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../")

# Enable ExternalProject CMake module
include(ExternalProject)
set(TFHE_RS_SOURCE_DIR "${CMAKE_BINARY_DIR}/../../../../")
set(TFHE_RS_BINARY_DIR "${TFHE_RS_SOURCE_DIR}/target/release")

if(NOT TARGET tfhe-rs)
  ExternalProject_Add(
    tfhe-rs
    SOURCE_DIR ${TFHE_RS_SOURCE_DIR}
    BINARY_DIR ${TFHE_RS_SOURCE_DIR}
    BUILD_ALWAYS 1
    CONFIGURE_COMMAND ""
    BUILD_COMMAND ${CMAKE_COMMAND} -E env CARGO_PROFILE=release make build_c_api
    INSTALL_COMMAND ""
    LOG_BUILD ON)
endif()

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../include)
include_directories(${CONCRETE_CUDA_SOURCE_DIR}/include)
include_directories(${CONCRETE_CUDA_SOURCE_DIR}/src)
include_directories(${TFHE_RS_BINARY_DIR})
include_directories(${TFHE_RS_BINARY_DIR}/deps)
include_directories("${CMAKE_CURRENT_SOURCE_DIR}")

find_package(OpenMP REQUIRED)
# Add the OpenMP flag to the compiler flags
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${OpenMP_CXX_FLAGS}")

add_library(tfhe_rs_lib STATIC IMPORTED)
add_dependencies(tfhe_rs_lib tfhe-rs)
set_target_properties(tfhe_rs_lib PROPERTIES IMPORTED_LOCATION ${TFHE_RS_BINARY_DIR}/libtfhe.a)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wl,--no-as-needed -ldl")

set(BINARY benchmark_tfhe_cuda_backend)

file(
  GLOB_RECURSE BENCH_SOURCES
  LIST_DIRECTORIES false
  benchmark*.cpp main.cpp)

add_executable(${BINARY} ${BENCH_SOURCES} ../utils.cpp ../setup_and_teardown.cpp)

set_target_properties(benchmark_tfhe_cuda_backend PROPERTIES CUDA_SEPARABLE_COMPILATION ON CUDA_RESOLVE_DEVICE_SYMBOLS
                                                                                           ON)
target_link_libraries(
  benchmark_tfhe_cuda_backend
  PUBLIC benchmark::benchmark tfhe_rs_lib tfhe_cuda_backend OpenMP::OpenMP_CXX
  PRIVATE CUDA::cudart)
