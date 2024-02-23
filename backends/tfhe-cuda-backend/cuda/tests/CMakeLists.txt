option(TFHE_CUDA_BACKEND_BUILD_TESTS "Build the test tool" OFF)

if(TFHE_CUDA_BACKEND_BUILD_TESTS)
  message(STATUS "Building the test tool")
  add_subdirectory(src)
endif()
