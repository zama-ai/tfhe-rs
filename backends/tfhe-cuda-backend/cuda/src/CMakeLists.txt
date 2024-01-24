set(SOURCES
    ${CMAKE_SOURCE_DIR}/${INCLUDE_DIR}/bit_extraction.h
    ${CMAKE_SOURCE_DIR}/${INCLUDE_DIR}/bitwise_ops.h
    ${CMAKE_SOURCE_DIR}/${INCLUDE_DIR}/bootstrap.h
    ${CMAKE_SOURCE_DIR}/${INCLUDE_DIR}/bootstrap_multibit.h
    ${CMAKE_SOURCE_DIR}/${INCLUDE_DIR}/ciphertext.h
    ${CMAKE_SOURCE_DIR}/${INCLUDE_DIR}/circuit_bootstrap.h
    ${CMAKE_SOURCE_DIR}/${INCLUDE_DIR}/device.h
    ${CMAKE_SOURCE_DIR}/${INCLUDE_DIR}/integer.h
    ${CMAKE_SOURCE_DIR}/${INCLUDE_DIR}/keyswitch.h
    ${CMAKE_SOURCE_DIR}/${INCLUDE_DIR}/linear_algebra.h
    ${CMAKE_SOURCE_DIR}/${INCLUDE_DIR}/shifts.h
    ${CMAKE_SOURCE_DIR}/${INCLUDE_DIR}/vertical_packing.h)
file(GLOB_RECURSE SOURCES "*.cu")
add_library(tfhe_cuda_backend STATIC ${SOURCES})
set_target_properties(tfhe_cuda_backend PROPERTIES CUDA_SEPARABLE_COMPILATION ON CUDA_RESOLVE_DEVICE_SYMBOLS ON)
target_link_libraries(tfhe_cuda_backend PUBLIC cudart OpenMP::OpenMP_CXX)
target_include_directories(tfhe_cuda_backend PRIVATE .)
