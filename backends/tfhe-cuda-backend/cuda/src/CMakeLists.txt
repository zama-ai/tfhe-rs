file(GLOB_RECURSE SOURCES "*.cu")
file(GLOB_RECURSE HEADERS "*.cuh" "../include/*.h" "../include/*.cuh")

add_library(
  tfhe_cuda_backend STATIC
  ${SOURCES} ${HEADERS} pbs/programmable_bootstrap_multibit_128.cuh pbs/programmable_bootstrap_multibit_128.cu
  ../include/integer/kv_store/kv_store.h ../include/integer/kv_store/kv_store_utilities.h)
set_target_properties(tfhe_cuda_backend PROPERTIES CUDA_SEPARABLE_COMPILATION ON CUDA_RESOLVE_DEVICE_SYMBOLS ON)
target_link_libraries(tfhe_cuda_backend PUBLIC cudart OpenMP::OpenMP_CXX tfhe_cuda_common)
target_include_directories(tfhe_cuda_backend PRIVATE .)
