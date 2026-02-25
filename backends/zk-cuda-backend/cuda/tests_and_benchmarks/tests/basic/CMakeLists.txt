# Basic usage examples for zk-cuda-backend. These are standalone programs for learning purposes, not part of the CTest
# suite. Run them directly after building to verify the API works end-to-end.

set(ZK_INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../../../include)

# basic_fp_ops: host-side Fp field arithmetic
add_executable(basic_fp_ops basic_fp_ops.cu)
target_link_libraries(basic_fp_ops zk_cuda_backend tfhe_device)
target_include_directories(basic_fp_ops PRIVATE ${ZK_INCLUDE_DIR})
set_target_properties(
  basic_fp_ops
  PROPERTIES CUDA_ARCHITECTURES ${CMAKE_CUDA_ARCHITECTURES}
             CUDA_SEPARABLE_COMPILATION ON
             CUDA_RESOLVE_DEVICE_SYMBOLS ON)

# basic_curve_ops: host-side G1 elliptic curve operations
add_executable(basic_curve_ops basic_curve_ops.cu)
target_link_libraries(basic_curve_ops zk_cuda_backend tfhe_device)
target_include_directories(basic_curve_ops PRIVATE ${ZK_INCLUDE_DIR})
set_target_properties(
  basic_curve_ops
  PROPERTIES CUDA_ARCHITECTURES ${CMAKE_CUDA_ARCHITECTURES}
             CUDA_SEPARABLE_COMPILATION ON
             CUDA_RESOLVE_DEVICE_SYMBOLS ON)

# basic_msm: GPU-accelerated multi-scalar multiplication
add_executable(basic_msm basic_msm.cu)
target_link_libraries(basic_msm zk_cuda_backend tfhe_device)
target_include_directories(basic_msm PRIVATE ${ZK_INCLUDE_DIR})
set_target_properties(
  basic_msm
  PROPERTIES CUDA_ARCHITECTURES ${CMAKE_CUDA_ARCHITECTURES}
             CUDA_SEPARABLE_COMPILATION ON
             CUDA_RESOLVE_DEVICE_SYMBOLS ON)
