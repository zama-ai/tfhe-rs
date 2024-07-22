#ifndef HELPER_PROFILE
#define HELPER_PROFILE
#include <nvToolsExt.h>

void cuda_nvtx_label_with_color(const char *name);

#define PUSH_RANGE(name)                                                       \
  { cuda_nvtx_label_with_color(name); }
#define POP_RANGE() nvtxRangePop();

#endif
