#include "device.h"
#include "helper.h"
#include <mutex>

int cuda_setup_multi_gpu() {
  int num_gpus = cuda_get_number_of_gpus();
  if (num_gpus == 0)
    PANIC("GPU error: the number of GPUs should be > 0.")
  int num_used_gpus = 1;
  if (num_gpus > 1) {
    int has_peer_access_to_device_0;
    for (int i = 1; i < num_gpus; i++) {
      check_cuda_error(
          cudaDeviceCanAccessPeer(&has_peer_access_to_device_0, i, 0));
      if (has_peer_access_to_device_0) {
        cudaMemPool_t mempool;
        cudaMemAccessDesc desc = {};
        // Enable P2P Access and mempool access
        check_cuda_error(cudaSetDevice(i));
        check_cuda_error_ignore_specific(cudaDeviceEnablePeerAccess(0, 0),
                                         cudaErrorPeerAccessAlreadyEnabled);

        check_cuda_error(cudaDeviceGetDefaultMemPool(&mempool, 0));
        desc.location.type = cudaMemLocationTypeDevice;
        desc.location.id = i;
        desc.flags = cudaMemAccessFlagsProtReadWrite;
        check_cuda_error(
            cudaMemPoolSetAccess(mempool, &desc, 1 /* numDescs */));

        num_used_gpus += 1;
      } else {
        printf("Number of GPUs with p2p access used: %d\n", num_used_gpus);
        break;
      }
    }
  }
  return num_used_gpus;
}

void cuda_cleanup_multi_gpu() {
  int num_gpus = cuda_get_number_of_gpus();
  if (num_gpus == 0)
    PANIC("GPU error: the number of GPUs should be > 0.")
  if (num_gpus > 1) {
    int has_peer_access_to_device_0;
    for (int i = 1; i < num_gpus; i++) {
      check_cuda_error(
          cudaDeviceCanAccessPeer(&has_peer_access_to_device_0, i, 0));
      if (has_peer_access_to_device_0) {
        //// Disable access to memory pool
        cudaMemPool_t mempool;
        cudaMemAccessDesc desc = {};
        cudaDeviceGetDefaultMemPool(&mempool, 0);
        desc.location.type = cudaMemLocationTypeDevice;
        desc.location.id = i;
        desc.flags = cudaMemAccessFlagsProtNone;
        cudaMemPoolSetAccess(mempool, &desc, 1 /* numDescs */);
        //  Disable P2P Access
        cudaSetDevice(i);
        cudaDeviceDisablePeerAccess(0);
      } else {
        break;
      }
    }
  }
}

int get_num_inputs_on_gpu(int total_num_inputs, int gpu_index, int gpu_count) {

  int num_inputs = 0;
  // If there are fewer inputs than GPUs, not all GPUs are active and each
  // active GPU handles 1 input
  if (gpu_count > total_num_inputs) {
    if (gpu_index <= total_num_inputs - 1)
      num_inputs = 1;
  } else {
    // If there are more inputs than GPUs, all GPUs are active and compute over
    // a chunk of the total inputs. The chunk size is smaller on the last GPU.
    num_inputs =
        total_num_inputs / gpu_count + (total_num_inputs % gpu_count != 0);
    if (gpu_index == gpu_count - 1)
      num_inputs = total_num_inputs - (gpu_count - 1) * num_inputs;
  }
  return num_inputs;
}
