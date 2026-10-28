#ifndef CUDA_PBS_ENUMS_H
#define CUDA_PBS_ENUMS_H
#include <stdint.h>
enum PBS_TYPE { MULTI_BIT = 0, CLASSICAL = 1 };
// DEFAULT and SPECIALIZED_2_2 are the two 64-bit classical PBS flavors:
// DEFAULT is the generic split step-one/step-two implementation that works
// for any parameter set, SPECIALIZED_2_2 the throughput-oriented kernel tuned
// for the 2_2 parameters (N=2048, k=1, l=1). CG, TBC and TBC_HOST_DRIVEN remain
// for the multi-bit and 128-bit classical PBS only.
enum PBS_VARIANT {
  DEFAULT = 0,
  CG = 1,
  TBC = 2,
  TBC_HOST_DRIVEN = 3,
  SPECIALIZED_2_2 = 4
};
enum PBS_MS_REDUCTION_T { NO_REDUCTION = 0, CENTERED = 1 };

#endif // CUDA_PBS_ENUMS_H
