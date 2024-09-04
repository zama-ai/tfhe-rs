#ifndef CNCRT_KS_CUH
#define CNCRT_KS_CUH

#include "device.h"
#include "gadget.cuh"
#include "helper_multi_gpu.h"
#include "polynomial/functions.cuh"
#include "polynomial/polynomial_math.cuh"
#include "torus.cuh"
#include "utils/helper.cuh"
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
__global__ void
keyswitch(Torus *lwe_array_out, const Torus *__restrict__ lwe_output_indexes,
          const Torus *__restrict__ lwe_array_in,
          const Torus *__restrict__ lwe_input_indexes,
          const Torus *__restrict__ ksk, uint32_t lwe_dimension_in,
          uint32_t lwe_dimension_out, uint32_t base_log, uint32_t level_count) {
  const int tid = threadIdx.x + blockIdx.x * blockDim.x;
  const int shmem_index = threadIdx.x + threadIdx.y * blockDim.x;

  extern __shared__ int8_t sharedmem[];
  Torus *lwe_acc_out = (Torus *)sharedmem;
  auto block_lwe_array_out = get_chunk(
      lwe_array_out, lwe_output_indexes[blockIdx.y], lwe_dimension_out + 1);

  if (tid <= lwe_dimension_out) {

    Torus local_lwe_out = 0;
    auto block_lwe_array_in = get_chunk(
        lwe_array_in, lwe_input_indexes[blockIdx.y], lwe_dimension_in + 1);

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

      for (int j = level_count - 1; j >= 0; j--) {
        // Levels are stored in reverse order
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
__host__ void host_keyswitch_lwe_ciphertext_vector(
    cudaStream_t stream, uint32_t gpu_index, Torus *lwe_array_out,
    Torus const *lwe_output_indexes, Torus const *lwe_array_in,
    Torus const *lwe_input_indexes, Torus const *ksk, uint32_t lwe_dimension_in,
    uint32_t lwe_dimension_out, uint32_t base_log, uint32_t level_count,
    uint32_t num_samples) {

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
      lwe_dimension_in, lwe_dimension_out, base_log, level_count);
  check_cuda_error(cudaGetLastError());
}

template <typename Torus>
void execute_keyswitch_async(cudaStream_t const *streams,
                             uint32_t const *gpu_indexes, uint32_t gpu_count,
                             const LweArrayVariant<Torus> &lwe_array_out,
                             const LweArrayVariant<Torus> &lwe_output_indexes,
                             const LweArrayVariant<Torus> &lwe_array_in,
                             const LweArrayVariant<Torus> &lwe_input_indexes,
                             Torus *const *ksks, uint32_t lwe_dimension_in,
                             uint32_t lwe_dimension_out, uint32_t base_log,
                             uint32_t level_count, uint32_t num_samples) {

  /// If the number of radix blocks is lower than the number of GPUs, not all
  /// GPUs will be active and there will be 1 input per GPU
  for (uint i = 0; i < gpu_count; i++) {
    int num_samples_on_gpu = get_num_inputs_on_gpu(num_samples, i, gpu_count);

    Torus *current_lwe_array_out = GET_VARIANT_ELEMENT(lwe_array_out, i);
    Torus *current_lwe_output_indexes =
        GET_VARIANT_ELEMENT(lwe_output_indexes, i);
    Torus *current_lwe_array_in = GET_VARIANT_ELEMENT(lwe_array_in, i);
    Torus *current_lwe_input_indexes =
        GET_VARIANT_ELEMENT(lwe_input_indexes, i);

    // Compute Keyswitch
    host_keyswitch_lwe_ciphertext_vector<Torus>(
        streams[i], gpu_indexes[i], current_lwe_array_out,
        current_lwe_output_indexes, current_lwe_array_in,
        current_lwe_input_indexes, ksks[i], lwe_dimension_in, lwe_dimension_out,
        base_log, level_count, num_samples_on_gpu);
  }
}

template <typename Torus>
__host__ void scratch_packing_keyswitch_lwe_list_to_glwe(
    cudaStream_t stream, uint32_t gpu_index, int8_t **fp_ks_buffer,
    uint32_t glwe_dimension, uint32_t polynomial_size, uint32_t num_lwes,
    bool allocate_gpu_memory) {
  cudaSetDevice(gpu_index);

  int glwe_accumulator_size = (glwe_dimension + 1) * polynomial_size;

  if (allocate_gpu_memory)
    *fp_ks_buffer = (int8_t *)cuda_malloc_async(
        2 * num_lwes * glwe_accumulator_size * sizeof(Torus), stream,
        gpu_index);
}

// public functional packing keyswitch for a single LWE ciphertext
//
// Assumes there are (glwe_dimension+1) * polynomial_size threads split through
// different thread blocks at the x-axis to work on that input.
template <typename Torus>
__device__ void packing_keyswitch_lwe_ciphertext_into_glwe_ciphertext(
    Torus *glwe_out, Torus const *lwe_in, Torus const *fp_ksk,
    uint32_t lwe_dimension_in, uint32_t glwe_dimension,
    uint32_t polynomial_size, uint32_t base_log, uint32_t level_count) {

  const int tid = threadIdx.x + blockIdx.x * blockDim.x;
  size_t glwe_size = (glwe_dimension + 1);

  if (tid < glwe_size * polynomial_size) {
    const int local_index = threadIdx.x;
    // the output_glwe is split in polynomials and each x-block takes one of
    // them
    size_t poly_id = blockIdx.x;
    size_t coef_per_block = blockDim.x;

    // number of coefficients inside fp-ksk block for each lwe_input coefficient
    size_t ksk_block_size = glwe_size * polynomial_size * level_count;

    // initialize accumulator to 0
    glwe_out[tid] = SEL(0, lwe_in[lwe_dimension_in],
                        tid == glwe_dimension * polynomial_size);

    // Iterate through all lwe elements
    for (int i = 0; i < lwe_dimension_in; i++) {
      // Round and prepare decomposition
      Torus a_i = round_to_closest_multiple(lwe_in[i], base_log, level_count);

      Torus state = a_i >> (sizeof(Torus) * 8 - base_log * level_count);
      Torus mod_b_mask = (1ll << base_log) - 1ll;

      // block of key for current lwe coefficient (cur_input_lwe[i])
      auto ksk_block = &fp_ksk[i * ksk_block_size];
      for (int j = level_count - 1; j >= 0; j--) {
        // Levels are stored in reverse order
        auto ksk_glwe = &ksk_block[j * glwe_size * polynomial_size];
        // Iterate through each level and multiply by the ksk piece
        auto ksk_glwe_chunk = &ksk_glwe[poly_id * coef_per_block];
        Torus decomposed = decompose_one<Torus>(state, mod_b_mask, base_log);
        glwe_out[tid] -= decomposed * ksk_glwe_chunk[local_index];
      }
    }
  }
}

// public functional packing keyswitch for a batch of LWE ciphertexts
//
// Selects the input each thread is working on using the y-block index.
//
// Assumes there are (glwe_dimension+1) * polynomial_size threads split through
// different thread blocks at the x-axis to work on that input.
template <typename Torus>
__global__ void packing_keyswitch_lwe_list_to_glwe(
    Torus *glwe_array_out, Torus const *lwe_array_in, Torus const *fp_ksk,
    uint32_t lwe_dimension_in, uint32_t glwe_dimension,
    uint32_t polynomial_size, uint32_t base_log, uint32_t level_count,
    Torus *d_mem) {
  const int tid = threadIdx.x + blockIdx.x * blockDim.x;

  const int glwe_accumulator_size = (glwe_dimension + 1) * polynomial_size;
  const int lwe_size = (lwe_dimension_in + 1);

  const int input_id = blockIdx.y;
  const int degree = input_id;

  // Select an input
  auto lwe_in = lwe_array_in + input_id * lwe_size;
  auto ks_glwe_out = d_mem + input_id * glwe_accumulator_size;
  auto glwe_out = glwe_array_out + input_id * glwe_accumulator_size;
  // KS LWE to GLWE
  packing_keyswitch_lwe_ciphertext_into_glwe_ciphertext<Torus>(
      ks_glwe_out, lwe_in, fp_ksk, lwe_dimension_in, glwe_dimension,
      polynomial_size, base_log, level_count);

  // P * x ^degree
  auto in_poly = ks_glwe_out + (tid / polynomial_size) * polynomial_size;
  auto out_result = glwe_out + (tid / polynomial_size) * polynomial_size;
  polynomial_accumulate_monic_monomial_mul<Torus>(out_result, in_poly, degree,
                                                  tid % polynomial_size,
                                                  polynomial_size, 1, true);
}

/// To-do: Rewrite this kernel for efficiency
template <typename Torus>
__global__ void accumulate_glwes(Torus *glwe_out, Torus *glwe_array_in,
                                 uint32_t glwe_dimension,
                                 uint32_t polynomial_size, uint32_t num_lwes) {
  const int tid = threadIdx.x + blockIdx.x * blockDim.x;
  if (tid < (glwe_dimension + 1) * polynomial_size) {
    glwe_out[tid] = glwe_array_in[tid];

    // Accumulate
    for (int i = 1; i < num_lwes; i++) {
      auto glwe_in = glwe_array_in + i * (glwe_dimension + 1) * polynomial_size;
      glwe_out[tid] += glwe_in[tid];
    }
  }
}

template <typename Torus>
__host__ void host_packing_keyswitch_lwe_list_to_glwe(
    cudaStream_t stream, uint32_t gpu_index, Torus *glwe_out,
    Torus const *lwe_array_in, Torus const *fp_ksk_array, int8_t *fp_ks_buffer,
    uint32_t lwe_dimension_in, uint32_t glwe_dimension,
    uint32_t polynomial_size, uint32_t base_log, uint32_t level_count,
    uint32_t num_lwes) {

  if (num_lwes > polynomial_size)
    PANIC("Cuda error: too many LWEs to pack. The number of LWEs should be "
          "smaller than "
          "polynomial_size.")

  cudaSetDevice(gpu_index);
  int glwe_accumulator_size = (glwe_dimension + 1) * polynomial_size;

  int num_blocks = 0, num_threads = 0;
  getNumBlocksAndThreads(glwe_accumulator_size, 128, num_blocks, num_threads);

  dim3 grid(num_blocks, num_lwes);
  dim3 threads(num_threads);

  auto d_mem = (Torus *)fp_ks_buffer;
  auto d_tmp_glwe_array_out = d_mem + num_lwes * glwe_accumulator_size;

  // individually keyswitch each lwe
  packing_keyswitch_lwe_list_to_glwe<Torus><<<grid, threads, 0, stream>>>(
      d_tmp_glwe_array_out, lwe_array_in, fp_ksk_array, lwe_dimension_in,
      glwe_dimension, polynomial_size, base_log, level_count, d_mem);
  check_cuda_error(cudaGetLastError());

  // accumulate to a single glwe
  accumulate_glwes<Torus><<<num_blocks, threads, 0, stream>>>(
      glwe_out, d_tmp_glwe_array_out, glwe_dimension, polynomial_size,
      num_lwes);
  check_cuda_error(cudaGetLastError());
}

#endif
