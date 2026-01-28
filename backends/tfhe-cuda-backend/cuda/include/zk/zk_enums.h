#ifndef CUDA_ZK_ENUMS_H
#define CUDA_ZK_ENUMS_H
#include <stdint.h>
// Additional to the two kinds of expand (no_casting and casting), we have a
// third that is used only in the noise tests
enum EXPAND_KIND { NO_CASTING = 0, CASTING = 1, SANITY_CHECK = 2 };
#endif // CUDA_ZK_ENUMS_H
