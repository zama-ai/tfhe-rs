#ifndef HELPER_H
#define HELPER_H

extern "C" {
int cuda_setup_multi_gpu();
void cuda_cleanup_multi_gpu();
}

int get_num_inputs_on_gpu(int total_num_inputs, int gpu_index, int gpu_count);

#endif
