file(GLOB_RECURSE SOURCES "*.cu")
file(GLOB_RECURSE HEADERS "*.cuh" "../include/*.h" "../include/*.cuh")

if(TFHE_CUDA_EXT_PBS)
  file(GLOB_RECURSE EXT_PBS_SOURCES "../src_ext/pbs/*.cu")
  file(GLOB_RECURSE EXT_PBS_HEADERS "../src_ext/pbs/*.cuh" "../src_ext/include/pbs/*.h")
  list(APPEND SOURCES ${EXT_PBS_SOURCES})
  list(APPEND HEADERS ${EXT_PBS_HEADERS})
endif()

add_library(tfhe_cuda_backend STATIC ${SOURCES} ${HEADERS} ../include/integer/kv_store/kv_store.h
                                     ../include/integer/kv_store/kv_store_utilities.h)
set_target_properties(tfhe_cuda_backend PROPERTIES CUDA_SEPARABLE_COMPILATION ON CUDA_RESOLVE_DEVICE_SYMBOLS ON)
target_link_libraries(tfhe_cuda_backend PUBLIC cudart OpenMP::OpenMP_CXX tfhe_cuda_common)
target_include_directories(tfhe_cuda_backend PRIVATE .)
if(TFHE_CUDA_EXT_PBS)
  target_include_directories(tfhe_cuda_backend PRIVATE pbs ../src_ext ../src_ext/pbs ../src_ext/include)
endif()
