#include "device.h"
#include "helper_multi_gpu.cuh"
#include <mutex>
#include <omp.h>

std::mutex m;
bool p2p_enabled = false;

// Enable bidirectional p2p access between all available GPUs and device_0_id
int32_t cuda_setup_multi_gpu(int device_0_id) {
  int num_gpus = cuda_get_number_of_gpus();
  if (num_gpus == 0)
    PANIC("GPU error: the number of GPUs should be > 0.")
  if (num_gpus > 1) {
    m.lock();
    if (!p2p_enabled) {
      p2p_enabled = true;
      omp_set_nested(1);
      int has_peer_access_to_device_0;
      for (int i = 0; i < num_gpus; i++) {
        if (i != device_0_id) {
          check_cuda_error(cudaDeviceCanAccessPeer(&has_peer_access_to_device_0,
                                                   i, device_0_id));
          if (has_peer_access_to_device_0) {
            cuda_set_device(i);
            check_cuda_error(cudaDeviceEnablePeerAccess(device_0_id, 0));
            cuda_set_device(device_0_id);
            check_cuda_error(cudaDeviceEnablePeerAccess(i, 0));
          }
        }
      }
    }
    m.unlock();
  }
  return num_gpus;
}

int get_active_gpu_count(int num_inputs, int gpu_count) {
  int active_gpu_count = gpu_count;
  if (gpu_count > num_inputs) {
    active_gpu_count = num_inputs;
  }
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
