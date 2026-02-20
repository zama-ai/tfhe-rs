#include "device.h"
#include "helper.cuh"
#include "helper_multi_gpu.cuh"
#include <mutex>
#include <omp.h>

std::mutex m;
bool p2p_enabled = false;
const int THRESHOLD_MULTI_GPU_WITH_MULTI_BIT_PARAMS = 12;
const int THRESHOLD_MULTI_GPU_WITH_CLASSICAL_PARAMS_U128 = 12;

// Returns the threshold for multi-GPU with classical params.
// Computed once based on GPU 0's compute capability and SM count.
// We are assuming that 2_2 params are going to be used.
int get_threshold_multi_gpu_classical() {
  static int threshold = -1;
  static std::once_flag init_flag;

  std::call_once(init_flag, []() {
    cudaDeviceProp deviceProp;
    check_cuda_error(cudaGetDeviceProperties(&deviceProp, 0));
    int num_sms = deviceProp.multiProcessorCount;
    int major = deviceProp.major;
    int minor = deviceProp.minor;

    // For cc70 and cc80 we can scale up to the number of SMs
    // because the default specialized pbs is triggered
    // for other compute capabilities each lwe use 2 SMs, so we can only scale
    // up to half the number of SMs the +2 is added so the multi-gpu is enabled
    // only when we have more than the number of SMs.
    if ((major == 7 && minor == 0) || (major == 8 && minor == 0)) {
      threshold = num_sms + 2;
    } else {
      threshold = num_sms / 2 + 2;
    }
  });

  return threshold;
}

uint32_t get_active_gpu_count(uint32_t num_inputs, uint32_t gpu_count,
                              PBS_TYPE pbs_type) {
  int threshold = (pbs_type == MULTI_BIT)
                      ? THRESHOLD_MULTI_GPU_WITH_MULTI_BIT_PARAMS
                      : get_threshold_multi_gpu_classical();
  uint32_t ceil_div_inputs =
      std::max((uint32_t)1, CEIL_DIV(num_inputs, (uint32_t)threshold));
  uint32_t active_gpu_count = std::min(ceil_div_inputs, gpu_count);
  return active_gpu_count;
}

// For pbs 128 we need to use the smaller threshold in both multi bit and
// classical
uint32_t get_active_gpu_count_u128(uint32_t num_inputs, uint32_t gpu_count,
                                   PBS_TYPE pbs_type) {
  int threshold = (pbs_type == MULTI_BIT)
                      ? THRESHOLD_MULTI_GPU_WITH_MULTI_BIT_PARAMS
                      : THRESHOLD_MULTI_GPU_WITH_CLASSICAL_PARAMS_U128;

  uint32_t ceil_div_inputs =
      std::max((uint32_t)1, CEIL_DIV(num_inputs, (uint32_t)threshold));
  uint32_t active_gpu_count = std::min(ceil_div_inputs, gpu_count);
  return active_gpu_count;
}

int get_gpu_offset(int total_num_inputs, int gpu_index, int gpu_count) {
  int gpu_offset = 0;
  for (uint i = 0; i < gpu_index; i++)
    gpu_offset += get_num_inputs_on_gpu(total_num_inputs, i, gpu_count);
  return gpu_offset;
}

int get_num_inputs_on_gpu(int total_num_inputs, int gpu_index, int gpu_count) {

  int num_inputs = 0;
  // If there are fewer inputs than GPUs, not all GPUs are active and GPU 0
  // handles everything
  if (gpu_count > total_num_inputs) {
    if (gpu_index < total_num_inputs) {
      num_inputs = 1;
    }
  } else {
    // If there are more inputs than GPUs, all GPUs are active and compute over
    // a chunk of the total inputs. The chunk size is smaller on the last GPUs.
    int small_input_num, large_input_num, cutoff;
    if (total_num_inputs % gpu_count == 0) {
      small_input_num = total_num_inputs / gpu_count;
      large_input_num = small_input_num;
      cutoff = 0;
    } else {
      int y = ceil((double)total_num_inputs / (double)gpu_count) * gpu_count -
              total_num_inputs;
      cutoff = gpu_count - y;
      small_input_num = total_num_inputs / gpu_count;
      large_input_num = (int)ceil((double)total_num_inputs / (double)gpu_count);
    }
    if (gpu_index < cutoff)
      num_inputs = large_input_num;
    else
      num_inputs = small_input_num;
  }
  return num_inputs;
}
