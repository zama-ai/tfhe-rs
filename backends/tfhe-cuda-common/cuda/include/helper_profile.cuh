#ifndef HELPER_PROFILE
#define HELPER_PROFILE

#ifdef USE_NVTOOLS
#include <nvtx3/nvToolsExt.h>
#endif

void cuda_nvtx_label_with_color(const char *name);
void cuda_nvtx_pop();

#define PUSH_RANGE(name)                                                       \
  { cuda_nvtx_label_with_color(name); }
#define POP_RANGE()                                                            \
  { cuda_nvtx_pop(); }

#endif
