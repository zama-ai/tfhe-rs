option(TFHE_CUDA_BACKEND_BUILD_TESTS "Build the test tool" OFF)
option(TFHE_CUDA_BACKEND_BUILD_BENCHMARKS "Build the benchmark tool" OFF)

if(TFHE_CUDA_BACKEND_BUILD_TESTS)
  message(STATUS "Building the test tool")
  add_subdirectory(tests)
endif()

if(TFHE_CUDA_BACKEND_BUILD_BENCHMARKS)
  message(STATUS "Building the benchmark tool")
  add_subdirectory(benchmarks)
endif()
