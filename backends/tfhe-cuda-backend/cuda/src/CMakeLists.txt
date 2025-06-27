file(GLOB_RECURSE SOURCES "*.cu")
add_library(tfhe_cuda_backend STATIC ${SOURCES} pbs/programmable_bootstrap_multibit_128.cuh
                                     pbs/programmable_bootstrap_multibit_128.cu)
set_target_properties(tfhe_cuda_backend PROPERTIES CUDA_SEPARABLE_COMPILATION ON CUDA_RESOLVE_DEVICE_SYMBOLS ON)
target_link_libraries(tfhe_cuda_backend PUBLIC cudart OpenMP::OpenMP_CXX)
target_include_directories(tfhe_cuda_backend PRIVATE .)
