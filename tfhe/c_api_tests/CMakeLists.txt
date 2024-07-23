project(tfhe-c-api-tests)

cmake_minimum_required(VERSION 3.16)

if(NOT CARGO_PROFILE)
    set(CARGO_PROFILE release)
endif()
set(TFHE_C_API_RELEASE "${CMAKE_CURRENT_SOURCE_DIR}/../../target/${CARGO_PROFILE}")

option(WITH_FEATURE_GPU "Enable if tfhe-rs C API was compiled with the 'gpu' feature activated" OFF)

include_directories(${TFHE_C_API_RELEASE})
# This one is to fetch the dynamic buffer header
include_directories(${TFHE_C_API_RELEASE}/deps)
add_library(Tfhe STATIC IMPORTED)
set_target_properties(Tfhe PROPERTIES IMPORTED_LOCATION ${TFHE_C_API_RELEASE}/libtfhe.a)

if(APPLE)
    find_library(SECURITY_FRAMEWORK Security)
    if (NOT SECURITY_FRAMEWORK)
        message(FATAL_ERROR "Security framework not found")
    endif()
endif()

if (WITH_FEATURE_GPU)
    find_package(CUDAToolkit 10.0 REQUIRED)
    find_package(OpenMP REQUIRED)
endif()

file(GLOB TEST_CASES test_*.c)
foreach (testsourcefile ${TEST_CASES})
    get_filename_component(testname ${testsourcefile} NAME_WLE)
    get_filename_component(groupname ${testsourcefile} DIRECTORY)
    add_executable(${testname} ${testsourcefile})
    add_test(
            NAME ${testname}
            COMMAND ${testname}
            WORKING_DIRECTORY ${CMAKE_BINARY_DIR}/Testing
    )
    target_include_directories(${testname} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
    target_link_libraries(${testname} LINK_PUBLIC Tfhe m pthread dl)

    if (WITH_FEATURE_GPU)
        target_link_libraries(${testname} LINK_PUBLIC CUDA::cudart -lstdc++ OpenMP::OpenMP_CXX)
        target_compile_definitions(${testname} PUBLIC -DWITH_FEATURE_GPU)
    endif()

    if(APPLE)
        target_link_libraries(${testname} LINK_PUBLIC ${SECURITY_FRAMEWORK})
    endif()
    target_compile_options(${testname} PRIVATE -Werror)
    # Enabled asserts even in release mode
    add_definitions(-UNDEBUG)
endforeach (testsourcefile ${TEST_CASES})
