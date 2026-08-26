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
 * Each GPU holds its own instance of the __device__ symbols, so the work is
 * tracked per GPU index.
 * The stream is synchronized before returning: the table is read by kernels
 * that may be launched on a different stream of the same GPU.
 *
 * The only kernels that read the table are the classical 128-bit PBS step
 * kernels, and they are reachable only through a buffer built by
 * scratch_programmable_bootstrap_128, which calls this once per GPU before the
 * first launch. Keeping the call out of the per-iteration launchers matters:
 * they run about 2 * lwe_dimension times per bootstrap, and a process-wide
 * mutex there would serialize the host threads driving different GPUs.
 *
 * The mutex is still needed because concurrent scratch calls on the same GPU
 * come from different host threads.
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
