#include "device.h"
#include "twiddles.cuh"
#include <mutex>
#include <vector>

__device__ double2 neg_twiddles_aos[2 * NEG_TWIDDLES_COUNT];

static __global__ void device_build_neg_twiddles_aos() {
  const uint32_t i = blockIdx.x * blockDim.x + threadIdx.x;
  neg_twiddles_aos[2 * i] =
      make_double2(neg_twiddles_re_hi[i], neg_twiddles_re_lo[i]);
  neg_twiddles_aos[2 * i + 1] =
      make_double2(neg_twiddles_im_hi[i], neg_twiddles_im_lo[i]);
}

/*
 * Fills neg_twiddles_aos on `gpu_index` by interleaving the four plane arrays
 * (layout in twiddles.cuh). The first call for a GPU launches the build kernel
 * and waits for it to finish. Later calls for the same GPU return immediately.
 *
 * The table is built on the device instead of being a second compile-time
 * initialized array. This avoids duplicating the 4 * NEG_TWIDDLES_COUNT
 * constants already in twiddles.cu, and the two copies cannot get out of sync.
 *
 * The mutex protects `built`. Scratch functions for the same GPU or for
 * different GPUs can run at the same time on different host threads, and
 * resize() modifies the whole vector. Because of this lock, call this function
 * from scratch functions, not from the launchers that run on every PBS
 * iteration (see scratch_programmable_bootstrap_128).
 */
void host_build_neg_twiddles_aos(cudaStream_t stream, uint32_t gpu_index) {
  static std::mutex build_mutex;
  static std::vector<bool> built;

  const std::lock_guard<std::mutex> guard(build_mutex);
  if (gpu_index >= built.size())
    built.resize(gpu_index + 1, false);
  if (built[gpu_index])
    return;

  constexpr uint32_t threads_per_block = 256;
  static_assert(NEG_TWIDDLES_COUNT % threads_per_block == 0,
                "the twiddle count must tile the build kernel exactly");

  cuda_set_device(gpu_index);
  device_build_neg_twiddles_aos<<<NEG_TWIDDLES_COUNT / threads_per_block,
                                  threads_per_block, 0, stream>>>();
  check_cuda_error(cudaGetLastError());
  cuda_synchronize_stream(stream, gpu_index);

  built[gpu_index] = true;
}
