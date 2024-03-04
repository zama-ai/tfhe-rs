#ifndef CNCRT_KS_CUH
#define CNCRT_KS_CUH

#include "device.h"
#include "gadget.cuh"
#include "polynomial/polynomial_math.cuh"
#include "torus.cuh"
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
template <typename Torus>
__global__ void
keyswitch(Torus *lwe_array_out, Torus *lwe_output_indexes, Torus *lwe_array_in,
          Torus *lwe_input_indexes, Torus *ksk, uint32_t lwe_dimension_in,
          uint32_t lwe_dimension_out, uint32_t base_log, uint32_t level_count,
          int lwe_lower, int lwe_upper, int cutoff) {
  int tid = threadIdx.x;

  extern __shared__ int8_t sharedmem[];

  Torus *local_lwe_array_out = (Torus *)sharedmem;

  auto block_lwe_array_in = get_chunk(
      lwe_array_in, lwe_input_indexes[blockIdx.x], lwe_dimension_in + 1);
  auto block_lwe_array_out = get_chunk(
      lwe_array_out, lwe_output_indexes[blockIdx.x], lwe_dimension_out + 1);

  auto gadget = GadgetMatrixSingle<Torus>(base_log, level_count);

  int lwe_part_per_thd;
  if (tid < cutoff) {
    lwe_part_per_thd = lwe_upper;
  } else {
    lwe_part_per_thd = lwe_lower;
  }
  __syncthreads();

  for (int k = 0; k < lwe_part_per_thd; k++) {
    int idx = tid + k * blockDim.x;
    local_lwe_array_out[idx] = 0;
  }
  __syncthreads();

  if (tid == 0) {
    local_lwe_array_out[lwe_dimension_out] =
        block_lwe_array_in[lwe_dimension_in];
  }

  for (int i = 0; i < lwe_dimension_in; i++) {

    __syncthreads();

    Torus a_i =
        round_to_closest_multiple(block_lwe_array_in[i], base_log, level_count);

    Torus state = a_i >> (sizeof(Torus) * 8 - base_log * level_count);
    Torus mask_mod_b = (1ll << base_log) - 1ll;

    for (int j = 0; j < level_count; j++) {
      auto ksk_block = get_ith_block(ksk, i, j, lwe_dimension_out, level_count);
      Torus decomposed = decompose_one<Torus>(state, mask_mod_b, base_log);
      for (int k = 0; k < lwe_part_per_thd; k++) {
        int idx = tid + k * blockDim.x;
        local_lwe_array_out[idx] -= (Torus)ksk_block[idx] * decomposed;
      }
    }
  }

  for (int k = 0; k < lwe_part_per_thd; k++) {
    int idx = tid + k * blockDim.x;
    block_lwe_array_out[idx] = local_lwe_array_out[idx];
  }
}

/// assume lwe_array_in in the gpu
template <typename Torus>
__host__ void cuda_keyswitch_lwe_ciphertext_vector(
    cuda_stream_t *stream, Torus *lwe_array_out, Torus *lwe_output_indexes,
    Torus *lwe_array_in, Torus *lwe_input_indexes, Torus *ksk,
    uint32_t lwe_dimension_in, uint32_t lwe_dimension_out, uint32_t base_log,
    uint32_t level_count, uint32_t num_samples) {

  cudaSetDevice(stream->gpu_index);
  constexpr int ideal_threads = 128;

  int lwe_size = lwe_dimension_out + 1;
  int lwe_lower, lwe_upper, cutoff;
  if (lwe_size % ideal_threads == 0) {
    lwe_lower = lwe_size / ideal_threads;
    lwe_upper = lwe_size / ideal_threads;
    cutoff = 0;
  } else {
    int y = ceil((double)lwe_size / (double)ideal_threads) * ideal_threads -
            lwe_size;
    cutoff = ideal_threads - y;
    lwe_lower = lwe_size / ideal_threads;
    lwe_upper = (int)ceil((double)lwe_size / (double)ideal_threads);
  }

  int lwe_size_after = lwe_size * num_samples;

  int shared_mem = sizeof(Torus) * lwe_size;

  cuda_memset_async(lwe_array_out, 0, sizeof(Torus) * lwe_size_after, stream);
  check_cuda_error(cudaGetLastError());

  dim3 grid(num_samples, 1, 1);
  dim3 threads(ideal_threads, 1, 1);

  keyswitch<Torus><<<grid, threads, shared_mem, stream->stream>>>(
      lwe_array_out, lwe_output_indexes, lwe_array_in, lwe_input_indexes, ksk,
      lwe_dimension_in, lwe_dimension_out, base_log, level_count, lwe_lower,
      lwe_upper, cutoff);
  check_cuda_error(cudaGetLastError());
}

#endif
