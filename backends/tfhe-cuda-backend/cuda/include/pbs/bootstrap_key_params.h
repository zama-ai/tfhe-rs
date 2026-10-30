#ifndef CUDA_BOOTSTRAP_KEY_PARAMS_H
#define CUDA_BOOTSTRAP_KEY_PARAMS_H

#include <stdint.h>

typedef struct {
  uint32_t noise_reduction_type; // PBS_MS_REDUCTION_T
} CudaClassicalPbsParamsFFI;

typedef struct {
  uint32_t grouping_factor;
} CudaMultiBitPbsParamsFFI;

typedef union {
  CudaClassicalPbsParamsFFI classical;
  CudaMultiBitPbsParamsFFI multi_bit;
} CudaPbsTypeParamsFFI;

// FFI-boundary parameter struct for a LWE bootstrap key.
// Every leaf field is a plain uint32_t for safe Rust/C++ interop.
// Use pbs_type_params_from_ffi() (integer_utilities.h) to obtain the
// strongly-typed C++ PBS parameters.
typedef struct {
  uint32_t input_lwe_dimension;
  uint32_t glwe_dimension;
  uint32_t polynomial_size;
  uint32_t base_log;
  uint32_t level_count;
  uint32_t big_lwe_dimension;
  uint32_t pbs_type; // PBS_TYPE, selects the active member of pbs_params
  CudaPbsTypeParamsFFI pbs_params;
} CudaLweBootstrapKeyParamsFFI;

#endif // CUDA_BOOTSTRAP_KEY_PARAMS_H
