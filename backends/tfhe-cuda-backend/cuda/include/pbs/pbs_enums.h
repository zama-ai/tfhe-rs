#ifndef CUDA_PBS_ENUMS_H
#define CUDA_PBS_ENUMS_H
#include <stdint.h>
enum PBS_TYPE { MULTI_BIT = 0, CLASSICAL = 1 };
enum PBS_VARIANT { DEFAULT = 0, CG = 1, TBC = 2 };
enum PBS_MS_REDUCTION_T { NO_REDUCTION = 0, CENTERED = 1 };

#endif // CUDA_PBS_ENUMS_H
