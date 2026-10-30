#pragma once

#include <stdint.h>

struct CudaClassicalPbsParamsFFI {
  uint32_t noise_reduction_type; // PBS_MS_REDUCTION_T
};

struct CudaMultiBitPbsParamsFFI {
  uint32_t grouping_factor;
};

union CudaPbsTypeParamsFFI {
  CudaClassicalPbsParamsFFI classical;
  CudaMultiBitPbsParamsFFI multi_bit;
};

// FFI-boundary parameter struct for a LWE bootstrap key.
// Every leaf field is a plain uint32_t for safe Rust/C++ interop.
// Use pbs_type_params_from_ffi() (integer_utilities.h) to obtain the
// strongly-typed C++ PBS parameters.
struct CudaLweBootstrapKeyParamsFFI {
  uint32_t input_lwe_dimension;
  uint32_t glwe_dimension;
  uint32_t polynomial_size;
  uint32_t base_log;
  uint32_t level_count;
  uint32_t big_lwe_dimension;
  uint32_t pbs_type; // PBS_TYPE, selects the active member of pbs_params
  CudaPbsTypeParamsFFI pbs_params;
};
