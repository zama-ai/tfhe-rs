#include "device.h"
#include "twiddles.cuh"
#include <mutex>
#include <vector>

__device__ double2 neg_twiddles_aos[2 * NEG_TWIDDLES_COUNT];

static __global__ void kernel_build_neg_twiddles_aos() {
  const uint32_t i = blockIdx.x * blockDim.x + threadIdx.x;
  neg_twiddles_aos[2 * i] =
      make_double2(neg_twiddles_re_hi[i], neg_twiddles_re_lo[i]);
  neg_twiddles_aos[2 * i + 1] =
      make_double2(neg_twiddles_im_hi[i], neg_twiddles_im_lo[i]);
}

/*
 * Fills the interleaved twiddle table from the plane arrays. Each GPU holds its
 * own instance of the __device__ symbols, so the work is tracked per GPU index.
 * The stream is synchronized before returning: the table is read by kernels
 * that may be launched on a different stream of the same GPU.
 *
 * This is called by every launcher of a kernel that reads the table, not only
 * at scratch time, so that no such kernel can ever run against an unfilled
 * table. After the first call per GPU the cost is one uncontended mutex
 * acquisition and one flag read, which is small next to a kernel launch.
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
  kernel_build_neg_twiddles_aos<<<NEG_TWIDDLES_COUNT / threads_per_block,
                                  threads_per_block, 0, stream>>>();
  check_cuda_error(cudaGetLastError());
  cuda_synchronize_stream(stream, gpu_index);

  built[gpu_index] = true;
}
