#ifndef HELPER_H
#define HELPER_H

extern "C" {
int cuda_setup_multi_gpu();
}

void multi_gpu_checks(uint32_t gpu_count);

#endif
