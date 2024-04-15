#include "device.h"
#include "helper.h"

int cuda_setup_multi_gpu() {

  int num_gpus = cuda_get_number_of_gpus();
  if (num_gpus == 0)
    PANIC("GPU error: the number of GPUs should be > 0.")

  if (num_gpus > 1) {
    int can_access_peer;
    for (int i = 0; i < num_gpus; i++) {
      cudaSetDevice(i);
      for (int j = 0; i < num_gpus; i++) {
        if (i == j)
          break;
        check_cuda_error(cudaDeviceCanAccessPeer(&can_access_peer, i, j));
        cudaDeviceEnablePeerAccess(j, 0);

        if (!can_access_peer)
          PANIC("Multi GPU error: all GPUs should have peer access to GPU each "
                "other.")
      }
    }
  }
  return num_gpus;
}

void multi_gpu_checks(uint32_t gpu_count) {

  if (gpu_count == 0)
    PANIC("GPU error: the number of GPUs should be > 0.")

  if (gpu_count > cuda_get_number_of_gpus())
    PANIC("Multi GPU error: the number of cuda streams should be lower than "
          "the number of GPUs on the machine.")

  if (gpu_count > 1) {
    int can_access_peer;
    for (int i = 1; i < gpu_count; i++) {
      cudaSetDevice(i);
      for (int j = 0; i < gpu_count; i++) {
        if (i == j)
          break;
        check_cuda_error(cudaDeviceCanAccessPeer(&can_access_peer, i, j));
        if (!can_access_peer)
          PANIC("Multi GPU error: all GPUs should have peer access to GPU each "
                "other.")
      }
    }
  }
}
