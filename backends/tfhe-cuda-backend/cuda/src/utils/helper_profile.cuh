#ifndef HELPER_PROFILE
#define HELPER_PROFILE
#include <nvToolsExt.h>

void cuda_nvtx_label_with_color(const char *name);
void cuda_nvtx_pop();

#define PUSH_RANGE(name)                                                       \
  { cuda_nvtx_label_with_color(name); }
#define POP_RANGE()                                                            \
  { cuda_nvtx_pop(); }

#endif
