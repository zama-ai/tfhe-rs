#ifndef CUDA_PBS_ENUMS_H
#define CUDA_PBS_ENUMS_H
#include <stdint.h>
// HALFHALF is the HP+HR generalized key: per-section, per-row (mask/body)
// decompositions, described by CudaHalfhalfPbsParamsFFI instead of a single
// base_log/level_count pair. Only the 128-bit dispatchers accept it; the 32-
// and 64-bit ones reject it.
enum PBS_TYPE { MULTI_BIT = 0, CLASSICAL = 1, HALFHALF = 2 };
enum PBS_VARIANT { DEFAULT = 0, CG = 1, TBC = 2, TBC_HOST_DRIVEN = 3 };
enum PBS_MS_REDUCTION_T { NO_REDUCTION = 0, CENTERED = 1 };

#endif // CUDA_PBS_ENUMS_H
