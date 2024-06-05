#ifndef CNCRT_KS_CUH
#define CNCRT_KS_CUH

#include "device.h"
#include "gadget.cuh"
#include "helper.h"
#include "polynomial/functions.cuh"
#include "polynomial/polynomial_math.cuh"
#include "torus.cuh"
#include "utils/kernel_dimensions.cuh"
#include <thread>
#include <vector>

template <typename Torus>
__device__ Torus *get_ith_block(Torus *ksk, int i, int level,
                                uint32_t lwe_dimension_out,
                                uint32_t level_count) {
  int pos = i * level_count * (lwe_dimension_out + 1) +
            level * (lwe_dimension_out + 1);
  Torus *ptr = &ksk[pos];
  return ptr;
}

/*
 * keyswitch kernel
 * Each thread handles a piece of the following equation:
 * $$GLWE_s2(\Delta.m+e) = (0,0,..,0,b) - \sum_{i=0,k-1} <Dec(a_i),
 * (GLWE_s2(s1_i q/beta),..,GLWE(s1_i q/beta^l)>$$ where k is the dimension of
 * the GLWE ciphertext. If the polynomial dimension in GLWE is > 1, this
 * equation is solved for each polynomial coefficient. where Dec denotes the
 * decomposition with base beta and l levels and the inner product is done
 * between the decomposition of a_i and l GLWE encryptions of s1_i q/\beta^j,
 * with j in [1,l] We obtain a GLWE encryption of Delta.m (with Delta the
 * scaling factor) under key s2 instead of s1, with an increased noise
 *
 */
// Each thread in x are used to calculate one output.
// threads in y are used to paralelize the lwe_dimension_in loop.
// shared memory is used to store intermediate results of the reduction.
template <typename Torus>
__global__ void keyswitch(Torus *lwe_array_out, Torus *lwe_output_indexes,
                          Torus *lwe_array_in, Torus *lwe_input_indexes,
                          Torus *ksk, uint32_t lwe_dimension_in,
                          uint32_t lwe_dimension_out, uint32_t base_log,
                          uint32_t level_count, int gpu_offset) {
  const int tid = threadIdx.x + blockIdx.x * blockDim.x;
  const int shmem_index = threadIdx.x + threadIdx.y * blockDim.x;

  extern __shared__ int8_t sharedmem[];
  Torus *lwe_acc_out = (Torus *)sharedmem;
  auto block_lwe_array_out =
      get_chunk(lwe_array_out, lwe_output_indexes[blockIdx.y + gpu_offset],
                lwe_dimension_out + 1);

  if (tid <= lwe_dimension_out) {

    Torus local_lwe_out = 0;
    auto block_lwe_array_in =
        get_chunk(lwe_array_in, lwe_input_indexes[blockIdx.y + gpu_offset],
                  lwe_dimension_in + 1);

    if (tid == lwe_dimension_out && threadIdx.y == 0) {
      local_lwe_out = block_lwe_array_in[lwe_dimension_in];
    }
    const Torus mask_mod_b = (1ll << base_log) - 1ll;

    const int pack_size = (lwe_dimension_in + blockDim.y - 1) / blockDim.y;
    const int start_i = pack_size * threadIdx.y;
    const int end_i = SEL(lwe_dimension_in, pack_size * (threadIdx.y + 1),
                          pack_size * (threadIdx.y + 1) <= lwe_dimension_in);

    // This loop distribution seems to benefit the global mem reads
    for (int i = start_i; i < end_i; i++) {
      Torus a_i = round_to_closest_multiple(block_lwe_array_in[i], base_log,
                                            level_count);
      Torus state = a_i >> (sizeof(Torus) * 8 - base_log * level_count);

      for (int j = 0; j < level_count; j++) {
        auto ksk_block =
            get_ith_block(ksk, i, j, lwe_dimension_out, level_count);
        Torus decomposed = decompose_one<Torus>(state, mask_mod_b, base_log);
        local_lwe_out -= (Torus)ksk_block[tid] * decomposed;
      }
    }

    lwe_acc_out[shmem_index] = local_lwe_out;
  }

  if (tid <= lwe_dimension_out) {
    for (int offset = blockDim.y / 2; offset > 0 && threadIdx.y < offset;
         offset /= 2) {
      __syncthreads();
      lwe_acc_out[shmem_index] +=
          lwe_acc_out[shmem_index + offset * blockDim.x];
    }
    if (threadIdx.y == 0)
      block_lwe_array_out[tid] = lwe_acc_out[shmem_index];
  }
}

template <typename Torus>
__host__ void cuda_keyswitch_lwe_ciphertext_vector(
    cudaStream_t stream, uint32_t gpu_index, Torus *lwe_array_out,
    Torus *lwe_output_indexes, Torus *lwe_array_in, Torus *lwe_input_indexes,
    Torus *ksk, uint32_t lwe_dimension_in, uint32_t lwe_dimension_out,
    uint32_t base_log, uint32_t level_count, uint32_t num_samples,
    uint32_t gpu_offset = 0) {

  cudaSetDevice(gpu_index);

  constexpr int num_threads_y = 32;
  int num_blocks, num_threads_x;

  getNumBlocksAndThreads2D(lwe_dimension_out + 1, 512, num_threads_y,
                           num_blocks, num_threads_x);

  int shared_mem = sizeof(Torus) * num_threads_y * num_threads_x;
  dim3 grid(num_blocks, num_samples, 1);
  dim3 threads(num_threads_x, num_threads_y, 1);

  keyswitch<Torus><<<grid, threads, shared_mem, stream>>>(
      lwe_array_out, lwe_output_indexes, lwe_array_in, lwe_input_indexes, ksk,
      lwe_dimension_in, lwe_dimension_out, base_log, level_count, gpu_offset);
  check_cuda_error(cudaGetLastError());
}

template <typename Torus>
void execute_keyswitch(cudaStream_t *streams, uint32_t *gpu_indexes,
                       uint32_t gpu_count, Torus *lwe_array_out,
                       Torus *lwe_output_indexes, Torus *lwe_array_in,
                       Torus *lwe_input_indexes, Torus **ksks,
                       uint32_t lwe_dimension_in, uint32_t lwe_dimension_out,
                       uint32_t base_log, uint32_t level_count,
                       uint32_t num_samples, bool sync_streams = true) {

  /// If the number of radix blocks is lower than the number of GPUs, not all
  /// GPUs will be active and there will be 1 input per GPU
  auto active_gpu_count = get_active_gpu_count(num_samples, gpu_count);
  int num_samples_on_gpu_0 = get_num_inputs_on_gpu(num_samples, 0, gpu_count);
  if (sync_streams)
    cuda_synchronize_stream(streams[0], gpu_indexes[0]);
#pragma omp parallel for num_threads(active_gpu_count)
  for (uint i = 0; i < active_gpu_count; i++) {
    int num_samples_on_gpu = get_num_inputs_on_gpu(num_samples, i, gpu_count);
    int gpu_offset = get_gpu_offset(num_samples, i, gpu_count);

    // Compute Keyswitch
    cuda_keyswitch_lwe_ciphertext_vector<Torus>(
        streams[i], gpu_indexes[i], lwe_array_out, lwe_output_indexes,
        lwe_array_in, lwe_input_indexes, ksks[i], lwe_dimension_in,
        lwe_dimension_out, base_log, level_count, num_samples_on_gpu,
        gpu_offset);
  }

  if (sync_streams)
    for (uint i = 0; i < active_gpu_count; i++) {
      cuda_synchronize_stream(streams[i], gpu_indexes[i]);
    }
}

#endif
