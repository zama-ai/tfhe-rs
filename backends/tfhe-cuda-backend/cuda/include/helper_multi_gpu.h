#ifndef HELPER_MULTI_GPU_H
#define HELPER_MULTI_GPU_H
#include <mutex>

extern std::mutex m;
extern bool p2p_enabled;

extern "C" {
int cuda_setup_multi_gpu();
}

int get_active_gpu_count(int num_inputs, int gpu_count);

int get_num_inputs_on_gpu(int total_num_inputs, int gpu_index, int gpu_count);

int get_gpu_offset(int total_num_inputs, int gpu_index, int gpu_count);

#endif
