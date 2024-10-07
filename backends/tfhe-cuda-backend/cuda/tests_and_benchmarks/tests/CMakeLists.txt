project(test_tfhe_cuda_backend LANGUAGES CXX)

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

include(FetchContent)
FetchContent_Declare(googletest
                     URL https://github.com/google/googletest/archive/03597a01ee50ed33e9dfd640b249b4be3799d395.zip)

# For Windows: Prevent overriding the parent project's compiler/linker settings
set(gtest_force_shared_crt
    ON
    CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

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
include_directories(${TFHE_RS_BINARY_DIR})
include_directories(${TFHE_RS_BINARY_DIR}/deps)
include_directories("${CMAKE_CURRENT_SOURCE_DIR}")
include_directories("${CMAKE_CUDA_TOOLKIT_INCLUDE_DIRECTORIES}")

add_library(tfhe_rs_lib STATIC IMPORTED)
add_dependencies(tfhe_rs_lib tfhe-rs)
set_target_properties(tfhe_rs_lib PROPERTIES IMPORTED_LOCATION ${TFHE_RS_BINARY_DIR}/libtfhe.a)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wl,--no-as-needed -ldl")

set(BINARY test_tfhe_cuda_backend)

file(
  GLOB_RECURSE TEST_SOURCES
  LIST_DIRECTORIES false
  test_*.cpp)

add_executable(${BINARY} ${TEST_SOURCES} ../utils.cpp ../setup_and_teardown.cpp)

add_test(NAME ${BINARY} COMMAND ${BINARY})

set_target_properties(${BINARY} PROPERTIES CUDA_SEPARABLE_COMPILATION ON CUDA_RESOLVE_DEVICE_SYMBOLS ON)
target_link_libraries(${BINARY} PUBLIC GTest::gtest_main tfhe_rs_lib tfhe_cuda_backend cudart)

include(GoogleTest)
gtest_discover_tests(${BINARY})
