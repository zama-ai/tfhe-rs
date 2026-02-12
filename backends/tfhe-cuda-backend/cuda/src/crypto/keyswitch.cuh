#ifndef CNCRT_KS_CUH
#define CNCRT_KS_CUH

#include <algorithm>

#include "checked_arithmetic.h"
#include "device.h"
#include "gadget.cuh"
#include "helper_multi_gpu.h"
#include "polynomial/functions.cuh"
#include "polynomial/polynomial_math.cuh"
#include "torus.cuh"
#include "utils/helper.cuh"
#include <thread>
#include <vector>

const int BLOCK_SIZE_DECOMP = 8;
const int BLOCK_SIZE_GEMM_KS = 36;
const int THREADS_GEMM_KS = 6;

inline uint64_t get_threshold_ks_gemm() { return 128; }

template <typename Torus> struct ks_mem {
  Torus *d_buffer;
  uint64_t num_lwes;
  uint32_t lwe_dimension;
};

template <typename Torus>
uint64_t scratch_cuda_keyswitch_size(uint32_t lwe_dimension_in,
                                     uint32_t lwe_dimension_out,
                                     uint32_t num_lwes) {
  GPU_ASSERT(lwe_dimension_in >= lwe_dimension_out,
             "Trying to allocate KS temp buffer for invalid LWE dimensions");
  return safe_mul_sizeof<Torus>((size_t)num_lwes, (size_t)lwe_dimension_in,
                                (size_t)2);
}

template <typename Torus>
__device__ Torus *get_ith_block(Torus *ksk, int i, int level,
                                uint32_t lwe_dimension_out,
                                uint32_t level_count) {
  int pos = i * level_count * (lwe_dimension_out + 1) +
            level * (lwe_dimension_out + 1);
  Torus *ptr = &ksk[pos];
  return ptr;
}

template <typename T>
__device__ T closest_repr(T input, uint32_t base_log, uint32_t level_count) {
  T minus_2 = static_cast<T>(-2);
  const T rep_bit_count = level_count * base_log;            // 32
  const T non_rep_bit_count = sizeof(T) * 8 - rep_bit_count; // 32
  auto shift = (non_rep_bit_count - 1);                      // 31
  T res = input >> shift;
  res++;
  res &= minus_2;
  res <<= shift;
  return res;
}

template <typename T>
__global__ void closest_representable(const T *input, T *output,
                                      uint32_t base_log, uint32_t level_count) {
  output[0] = closest_repr(input[0], base_log, level_count);
}

template <typename T>
__host__ void
host_cuda_closest_representable(cudaStream_t stream, uint32_t gpu_index,
                                const T *input, T *output, uint32_t base_log,
                                uint32_t level_count) {
  dim3 grid(1, 1, 1);
  dim3 threads(1, 1, 1);

  cuda_set_device(gpu_index);
  closest_representable<<<grid, threads, 0, stream>>>(input, output, base_log,
                                                      level_count);
}

// Initialize decomposition by performing rounding
// and decomposing one level of an array of Torus LWEs. Only
// decomposes the mask elements of the incoming LWEs.
template <typename Torus, typename KSTorus>
__global__ void decompose_vectorize_init(Torus const *lwe_in, Torus *lwe_out,
                                         uint32_t lwe_dimension,
                                         uint32_t num_lwe, uint32_t base_log,
                                         uint32_t level_count) {

  // index of this LWE ct in the buffer
  auto lwe_idx = blockIdx.x * blockDim.x + threadIdx.x;
  // index of the LWE sample in the LWE ct
  auto lwe_sample_idx = blockIdx.y * blockDim.y + threadIdx.y;

  if (lwe_idx >= num_lwe || lwe_sample_idx >= lwe_dimension)
    return;

  // Input LWE array is [mask_0, .., mask_lwe_dim, message] and
  // we only decompose the mask. Thus the stride for reading
  // is lwe_dimension + 1, while for writing it is lwe_dimension
  auto read_val_idx = lwe_idx * (lwe_dimension + 1) + lwe_sample_idx;
  auto write_val_idx = lwe_idx * lwe_dimension + lwe_sample_idx;
  auto write_state_idx =
      num_lwe * lwe_dimension + lwe_idx * lwe_dimension + lwe_sample_idx;

  Torus a_i = lwe_in[read_val_idx];

  Torus state = init_decomposer_state(a_i, base_log, level_count);

  Torus mod_b_mask = (1ll << base_log) - 1ll;
  KSTorus *kst_ptr_lwe_out = (KSTorus *)lwe_out;
  kst_ptr_lwe_out[write_val_idx] =
      decompose_one<Torus>(state, mod_b_mask, base_log);
  __syncthreads();
  lwe_out[write_state_idx] = state;
}

// Decompose an array of LWEs with indirection through lwe_input_indices
// The LWE array can contain total_lwe LWEs where total_lwe can be different
// from num_lwe. The maximum index should be <= total_lwe. num_lwe is the number
// of LWEs to decompose The output buffer should have space for num_lwe LWEs.
// These will be sorted according to the input indices.
template <typename Torus, typename KSTorus>
__global__ void decompose_vectorize_init_with_indices(
    Torus const *lwe_in, const Torus *__restrict__ lwe_input_indices,
    Torus *lwe_out, uint32_t lwe_dimension, uint32_t num_lwe, uint32_t base_log,
    uint32_t level_count) {

  // index of this LWE ct in the buffer
  auto lwe_idx = blockIdx.x * blockDim.x + threadIdx.x;
  // index of the LWE sample in the LWE ct
  auto lwe_sample_idx = blockIdx.y * blockDim.y + threadIdx.y;

  if (lwe_idx >= num_lwe || lwe_sample_idx >= lwe_dimension)
    return;

  // Input LWE array is [mask_0, .., mask_lwe_dim, message] and
  // we only decompose the mask. Thus the stride for reading
  // is lwe_dimension + 1, while for writing it is lwe_dimension
  auto read_val_idx =
      lwe_input_indices[lwe_idx] * (lwe_dimension + 1) + lwe_sample_idx;
  auto write_val_idx = lwe_idx * lwe_dimension + lwe_sample_idx;
  auto write_state_idx =
      num_lwe * lwe_dimension + lwe_idx * lwe_dimension + lwe_sample_idx;

  Torus a_i = lwe_in[read_val_idx];

  Torus state = init_decomposer_state(a_i, base_log, level_count);

  Torus mod_b_mask = (1ll << base_log) - 1ll;
  KSTorus *kst_ptr_lwe_out = (KSTorus *)lwe_out;
  kst_ptr_lwe_out[write_val_idx] =
      decompose_one<Torus>(state, mod_b_mask, base_log);
  __syncthreads();
  lwe_out[write_state_idx] = state;
}

// Continue decomposition of an array of Torus elements in place. Supposes
// that the array contains already decomposed elements and
// computes the new decomposed level in place.
template <typename Torus, typename KSTorus>
__global__ void
decompose_vectorize_step_inplace(Torus *buffer_in, uint32_t lwe_dimension,
                                 uint32_t num_lwe, uint32_t base_log,
                                 uint32_t level_count) {

  // index of this LWE ct in the buffer
  auto lwe_idx = blockIdx.x * blockDim.x + threadIdx.x;
  // index of the LWE sample in the LWE ct
  auto lwe_sample_idx = blockIdx.y * blockDim.y + threadIdx.y;

  if (lwe_idx >= num_lwe || lwe_sample_idx >= lwe_dimension)
    return;

  auto val_idx = lwe_idx * lwe_dimension + lwe_sample_idx;
  auto state_idx = num_lwe * lwe_dimension + val_idx;

  Torus state = buffer_in[state_idx];
  __syncthreads();

  Torus mod_b_mask = (1ll << base_log) - 1ll;

  KSTorus *kst_ptr_lwe_out = (KSTorus *)buffer_in;
  kst_ptr_lwe_out[val_idx] = decompose_one<Torus>(state, mod_b_mask, base_log);
  __syncthreads();
  buffer_in[state_idx] = state;
}

/* LWEs inputs to the keyswitch function are stored as a_0,...,a_{lwe_dim},b,
 * where a_i are mask elements and b is the message. We initialize
 * the output keyswitched LWEs to 0, ..., 0, -b. The GEMM keyswitch is computed
 * as:
 * -(-b + sum(a_i A_KSK))
 */
template <typename Torus, typename KSTorus>
__global__ void keyswitch_gemm_copy_negated_message_with_indices(
    const Torus *__restrict__ lwe_in,
    const Torus *__restrict__ lwe_input_indices, KSTorus *__restrict__ lwe_out,
    const Torus *__restrict__ lwe_output_indices,

    uint32_t lwe_dimension_in, uint32_t num_lwes, uint32_t lwe_dimension_out) {

  uint32_t lwe_id = blockIdx.x * blockDim.x + threadIdx.x;

  if (lwe_id >= num_lwes)
    return;

  uint32_t lwe_in_idx = lwe_input_indices[lwe_id];
  uint32_t lwe_out_idx = lwe_output_indices[lwe_id];

  Torus body_in =
      lwe_in[lwe_in_idx * (lwe_dimension_in + 1) + lwe_dimension_in];
  Torus body_out;
  if constexpr (std::is_same_v<KSTorus, Torus>) {
    body_out = -body_in;
  } else {
    body_out = closest_repr(
        lwe_in[lwe_in_idx * (lwe_dimension_in + 1) + lwe_dimension_in],
        sizeof(KSTorus) * 8, 1);

    // Power of two are encoded in the MSBs of the types so we need to scale
    // the type to the other one without having to worry about the moduli
    static_assert(sizeof(Torus) >= sizeof(KSTorus),
                  "Cannot compile keyswitch with given input/output dtypes");
    Torus input_to_output_scaling_factor =
        (sizeof(Torus) - sizeof(KSTorus)) * 8;

    auto rounded_downscaled_body =
        (KSTorus)(body_out >> input_to_output_scaling_factor);

    body_out = -rounded_downscaled_body;
  }
  lwe_out[lwe_out_idx * (lwe_dimension_out + 1) + lwe_dimension_out] =
      (KSTorus)body_out;
}

// The GEMM keyswitch is computed as: -(-b + sum(a_i A_KSK)).
// This function finishes the KS computation by negating all elements in the
// array using output indices. The array contains -b + SUM(a_i x LWE_i) and this
// final step computes b - SUM(a_i x LWE_i).
template <typename Torus, typename KSTorus>
__global__ void keyswitch_negate_with_output_indices(
    KSTorus *buffer_in, const Torus *__restrict__ lwe_output_indices,
    uint32_t lwe_size, uint32_t num_lwe) {

  // index of this LWE ct in the buffer
  auto lwe_sample_idx = blockIdx.x * blockDim.x + threadIdx.x;
  // index of the LWE sample in the LWE ct
  auto lwe_idx = blockIdx.y * blockDim.y + threadIdx.y;

  if (lwe_idx >= num_lwe || lwe_sample_idx >= lwe_size)
    return;

  auto val_idx = lwe_output_indices[lwe_idx] * lwe_size + lwe_sample_idx;

  Torus val = buffer_in[val_idx];
  buffer_in[val_idx] = -val;
}

template <typename Torus, typename KSTorus>
__global__ void keyswitch_zero_output_with_output_indices(
    KSTorus *buffer_in, const Torus *__restrict__ lwe_output_indices,
    uint32_t lwe_size, uint32_t num_lwe) {

  // index of this LWE ct in the buffer
  auto lwe_sample_idx = blockIdx.x * blockDim.x + threadIdx.x;
  // index of the LWE sample in the LWE ct
  auto lwe_idx = blockIdx.y * blockDim.y + threadIdx.y;

  if (lwe_idx >= num_lwe || lwe_sample_idx >= lwe_size)
    return;

  auto val_idx = lwe_output_indices[lwe_idx] * lwe_size + lwe_sample_idx;

  buffer_in[val_idx] = 0;
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
// threads in y are used to parallelize the lwe_dimension_in loop.
// shared memory is used to store intermediate results of the reduction.
// Note: To reduce register pressure we have slightly changed the algorithm,
// the idea consists in calculating the negate value of the output. So, instead
// of accumulating subtractions using -=, we accumulate additions using += in
// the local_lwe_out. This seems to work better cause profits madd ops and save
// some regs. For this to work, we need to negate the input
// lwe_array_in[lwe_dimension_in], and negate back the output at the end to get
// the correct results. Additionally, we split the calculation of the ksk offset
// in two parts, a constant part is calculated before the loop, and a variable
// part is calculated inside the loop. This seems to help with the register
// pressure as well.
template <typename Torus, typename KSTorus>
__global__ void
keyswitch(KSTorus *lwe_array_out, const Torus *__restrict__ lwe_output_indexes,
          const Torus *__restrict__ lwe_array_in,
          const Torus *__restrict__ lwe_input_indexes,
          const KSTorus *__restrict__ ksk, uint32_t lwe_dimension_in,
          uint32_t lwe_dimension_out, uint32_t base_log, uint32_t level_count) {
  const int tid = threadIdx.x + blockIdx.y * blockDim.x;
  const int shmem_index = threadIdx.x + threadIdx.y * blockDim.x;

  extern __shared__ int8_t sharedmem[];
  Torus *lwe_acc_out = (Torus *)sharedmem;
  auto block_lwe_array_out = get_chunk(
      lwe_array_out, lwe_output_indexes[blockIdx.x], lwe_dimension_out + 1);

  if (tid <= lwe_dimension_out) {

    KSTorus local_lwe_out = 0;
    auto block_lwe_array_in = get_chunk(
        lwe_array_in, lwe_input_indexes[blockIdx.x], lwe_dimension_in + 1);

    if (tid == lwe_dimension_out && threadIdx.y == 0) {
      if constexpr (std::is_same_v<KSTorus, Torus>) {
        local_lwe_out = -block_lwe_array_in[lwe_dimension_in];
      } else {
        auto new_body = closest_repr(block_lwe_array_in[lwe_dimension_in],
                                     sizeof(KSTorus) * 8, 1);

        // Power of two are encoded in the MSBs of the types so we need to scale
        // the type to the other one without having to worry about the moduli
        Torus input_to_output_scaling_factor =
            (sizeof(Torus) - sizeof(KSTorus)) * 8;

        auto rounded_downscaled_body =
            (KSTorus)(new_body >> input_to_output_scaling_factor);

        local_lwe_out = -rounded_downscaled_body;
      }
    }
    const Torus mask_mod_b = (1ll << base_log) - 1ll;

    const int pack_size = (lwe_dimension_in + blockDim.y - 1) / blockDim.y;
    const int start_i = pack_size * threadIdx.y;
    const int end_i = SEL(lwe_dimension_in, pack_size * (threadIdx.y + 1),
                          pack_size * (threadIdx.y + 1) <= lwe_dimension_in);

    // This loop distribution seems to benefit the global mem reads
    for (int i = start_i; i < end_i; i++) {
      Torus state =
          init_decomposer_state(block_lwe_array_in[i], base_log, level_count);
      uint32_t offset = i * level_count * (lwe_dimension_out + 1);
#pragma unroll 1
      for (int j = 0; j < level_count; j++) {

        KSTorus decomposed = decompose_one<Torus>(state, mask_mod_b, base_log);
        local_lwe_out +=
            (KSTorus)ksk[tid + j * (lwe_dimension_out + 1) + offset] *
            decomposed;
      }
    }

    lwe_acc_out[shmem_index] = local_lwe_out;
  }

  for (int offset = blockDim.y / 2; offset > 0; offset /= 2) {
    __syncthreads();
    if (tid <= lwe_dimension_out && threadIdx.y < offset) {
      lwe_acc_out[shmem_index] +=
          lwe_acc_out[shmem_index + offset * blockDim.x];
    }
  }
  if (tid <= lwe_dimension_out && threadIdx.y == 0)
    block_lwe_array_out[tid] = -lwe_acc_out[shmem_index];
}

template <typename Torus, typename KSTorus>
__host__ void host_keyswitch_lwe_ciphertext_vector(
    cudaStream_t stream, uint32_t gpu_index, KSTorus *lwe_array_out,
    Torus const *lwe_output_indexes, Torus const *lwe_array_in,
    Torus const *lwe_input_indexes, KSTorus const *ksk,
    uint32_t lwe_dimension_in, uint32_t lwe_dimension_out, uint32_t base_log,
    uint32_t level_count, uint32_t num_samples) {

  cuda_set_device(gpu_index);

  constexpr int num_threads_y = 32;
  int num_blocks_per_sample, num_threads_x;

  getNumBlocksAndThreads2D(lwe_dimension_out + 1, 512, num_threads_y,
                           num_blocks_per_sample, num_threads_x);

  int shared_mem =
      safe_mul_sizeof<Torus>((size_t)num_threads_y, (size_t)num_threads_x);
  PANIC_IF_FALSE(
      num_blocks_per_sample <= 65536,
      "Cuda error (Keyswitch): number of blocks per sample (%d) is too large",
      num_blocks_per_sample);

  // In multiplication of large integers (512, 1024, 2048), the number of
  // samples can be larger than 65536, so we need to set it in the first
  // dimension of the grid
  dim3 grid(num_samples, num_blocks_per_sample, 1);
  dim3 threads(num_threads_x, num_threads_y, 1);

  keyswitch<Torus, KSTorus><<<grid, threads, shared_mem, stream>>>(
      lwe_array_out, lwe_output_indexes, lwe_array_in, lwe_input_indexes, ksk,
      lwe_dimension_in, lwe_dimension_out, base_log, level_count);
  check_cuda_error(cudaGetLastError());
}

// The GEMM keyswitch is computed as: -(-b + sum(a_i A_KSK))
template <typename Torus, typename KSTorus>
__host__ void host_gemm_keyswitch_lwe_ciphertext_vector(
    cudaStream_t stream, uint32_t gpu_index, KSTorus *lwe_array_out,
    Torus const *lwe_output_indices, Torus const *lwe_array_in,
    Torus const *lwe_input_indices, KSTorus const *ksk,
    uint32_t lwe_dimension_in, uint32_t lwe_dimension_out, uint32_t base_log,
    uint32_t level_count, uint32_t num_samples, Torus *fp_tmp_buffer,
    bool uses_trivial_indices) {
  cuda_set_device(gpu_index);
  check_cuda_error(cudaGetLastError());

  // fp_tmp_buffer contains 2x the space to store the input LWE masks without
  // the body the first half can be interpreted with a smaller dtype when
  // performing 64->32 KS the second half, storing decomposition state, must be
  // interpreted as Torus* (usually 64b)
  KSTorus *d_mem_0 =
      (KSTorus *)fp_tmp_buffer; // keeps decomposed value (in KSTorus type)

  // Set the scratch buffer to 0 as it is used to accumulate
  // decomposition temporary results
  if (uses_trivial_indices) {
    cuda_memset_async(lwe_array_out, 0,
                      safe_mul_sizeof<KSTorus>((size_t)num_samples,
                                               (size_t)(lwe_dimension_out + 1)),
                      stream, gpu_index);
  } else {
    // gemm to ks the individual LWEs to GLWEs
    dim3 grid_zero(CEIL_DIV(lwe_dimension_out + 1, BLOCK_SIZE_DECOMP),
                   CEIL_DIV(num_samples, BLOCK_SIZE_DECOMP));
    dim3 threads_zero(BLOCK_SIZE_DECOMP, BLOCK_SIZE_DECOMP);

    keyswitch_zero_output_with_output_indices<Torus, KSTorus>
        <<<grid_zero, threads_zero, 0, stream>>>(
            lwe_array_out, lwe_output_indices, lwe_dimension_out + 1,
            num_samples);
  }
  check_cuda_error(cudaGetLastError());

  dim3 grid_copy(CEIL_DIV(num_samples, BLOCK_SIZE_DECOMP));
  dim3 threads_copy(BLOCK_SIZE_DECOMP);

  // lwe_array_out is num_samples x (lwe_dimension_out + 1). copy the bodies
  // lwe_array_in[:,lwe_dimension_in] to lwe_array_out[:,lwe_dimension_out]
  // and negates them
  keyswitch_gemm_copy_negated_message_with_indices<Torus, KSTorus>
      <<<grid_copy, threads_copy, 0, stream>>>(
          lwe_array_in, lwe_input_indices, lwe_array_out, lwe_output_indices,
          lwe_dimension_in, num_samples, lwe_dimension_out);
  check_cuda_error(cudaGetLastError());

  // decompose LWEs
  // don't decompose LWE body - the LWE has lwe_size + 1 elements. The last
  // element, the body is ignored by rounding down the number of blocks assuming
  // here that the LWE dimension is a multiple of the block size
  dim3 grid_decomp(CEIL_DIV(num_samples, BLOCK_SIZE_DECOMP),
                   CEIL_DIV(lwe_dimension_in, BLOCK_SIZE_DECOMP));
  dim3 threads_decomp(BLOCK_SIZE_DECOMP, BLOCK_SIZE_DECOMP);

  uint32_t shared_mem_size = get_shared_mem_size_tgemm<Torus>();
  // Shared memory requirement is 4096, 8192, and 16384 bytes respectively for
  // 32, 64, and 128-bit Torus elements
  // Sanity check: the shared memory size is a constant defined by the algorithm
  GPU_ASSERT(shared_mem_size <= 1024 * sizeof(Torus),
             "GEMM kernel error: shared memory required might be too large");

  auto stride_KSK_buffer = (lwe_dimension_out + 1) * level_count;

  // gemm to ks the individual LWEs to GLWEs
  dim3 grid_gemm(CEIL_DIV(lwe_dimension_out + 1, BLOCK_SIZE_GEMM_KS),
                 CEIL_DIV(num_samples, BLOCK_SIZE_GEMM_KS));
  dim3 threads_gemm(BLOCK_SIZE_GEMM_KS * THREADS_GEMM_KS);

  // decompose first level (skips the body in the input buffer)
  decompose_vectorize_init_with_indices<Torus, KSTorus>
      <<<grid_decomp, threads_decomp, 0, stream>>>(
          lwe_array_in, lwe_input_indices, fp_tmp_buffer, lwe_dimension_in,
          num_samples, base_log, level_count);
  check_cuda_error(cudaGetLastError());

  if (uses_trivial_indices) {
    tgemm<KSTorus, BLOCK_SIZE_GEMM_KS, THREADS_GEMM_KS>
        <<<grid_gemm, threads_gemm, shared_mem_size, stream>>>(
            num_samples, (lwe_dimension_out + 1), lwe_dimension_in, d_mem_0,
            ksk, stride_KSK_buffer, lwe_array_out, lwe_dimension_out + 1);
    check_cuda_error(cudaGetLastError());

  } else {
    tgemm_with_indices<KSTorus, Torus, BLOCK_SIZE_GEMM_KS, THREADS_GEMM_KS>
        <<<grid_gemm, threads_gemm, shared_mem_size, stream>>>(
            num_samples, (lwe_dimension_out + 1), lwe_dimension_in, d_mem_0,
            ksk, stride_KSK_buffer, lwe_array_out, lwe_dimension_out + 1,
            lwe_output_indices);
    check_cuda_error(cudaGetLastError());
  }

  auto ksk_block_size = (lwe_dimension_out + 1);

  for (int li = 1; li < level_count; ++li) {
    decompose_vectorize_step_inplace<Torus, KSTorus>
        <<<grid_decomp, threads_decomp, 0, stream>>>(
            fp_tmp_buffer, lwe_dimension_in, num_samples, base_log,
            level_count);
    check_cuda_error(cudaGetLastError());

    if (uses_trivial_indices) {
      tgemm<KSTorus, BLOCK_SIZE_GEMM_KS, THREADS_GEMM_KS>
          <<<grid_gemm, threads_gemm, shared_mem_size, stream>>>(
              num_samples, (lwe_dimension_out + 1), lwe_dimension_in, d_mem_0,
              ksk + li * ksk_block_size, stride_KSK_buffer, lwe_array_out,
              lwe_dimension_out + 1);
      check_cuda_error(cudaGetLastError());

    } else {
      tgemm_with_indices<KSTorus, Torus, BLOCK_SIZE_GEMM_KS, THREADS_GEMM_KS>
          <<<grid_gemm, threads_gemm, shared_mem_size, stream>>>(
              num_samples, (lwe_dimension_out + 1), lwe_dimension_in, d_mem_0,
              ksk + li * ksk_block_size, stride_KSK_buffer, lwe_array_out,
              lwe_dimension_out + 1, lwe_output_indices);
      check_cuda_error(cudaGetLastError());
    }
  }

  // gemm to ks the individual LWEs to GLWEs
  dim3 grid_negate(CEIL_DIV(lwe_dimension_out + 1, BLOCK_SIZE_DECOMP),
                   CEIL_DIV(num_samples, BLOCK_SIZE_DECOMP));
  dim3 threads_negate(BLOCK_SIZE_DECOMP, BLOCK_SIZE_DECOMP);

  // Negate all outputs in the output LWEs. This is the final step in the GEMM
  // keyswitch computed as: -(-b + sum(a_i A_KSK))
  keyswitch_negate_with_output_indices<Torus, KSTorus>
      <<<grid_negate, threads_negate, 0, stream>>>(
          lwe_array_out, lwe_output_indices, lwe_dimension_out + 1,
          num_samples);
  check_cuda_error(cudaGetLastError());
}

template <typename Torus, typename KSTorus>
void execute_keyswitch_async(
    CudaStreams streams, const LweArrayVariant<Torus> &lwe_array_out,
    const LweArrayVariant<Torus> &lwe_output_indexes,
    const LweArrayVariant<Torus> &lwe_array_in,
    const LweArrayVariant<Torus> &lwe_input_indexes, KSTorus *const *ksks,
    uint32_t lwe_dimension_in, uint32_t lwe_dimension_out, uint32_t base_log,
    uint32_t level_count, uint32_t num_samples, bool uses_trivial_indices,
    const std::vector<ks_mem<Torus> *> &fp_tmp_buffer) {

  /// If the number of radix blocks is lower than the number of GPUs, not all
  /// GPUs will be active and there will be 1 input per GPU
  for (uint i = 0; i < streams.count(); i++) {
    int num_samples_on_gpu =
        get_num_inputs_on_gpu(num_samples, i, streams.count());

    Torus *current_lwe_array_out = get_variant_element(lwe_array_out, i);
    Torus *current_lwe_output_indexes =
        get_variant_element(lwe_output_indexes, i);
    Torus *current_lwe_array_in = get_variant_element(lwe_array_in, i);
    Torus *current_lwe_input_indexes =
        get_variant_element(lwe_input_indexes, i);

    if (!fp_tmp_buffer.empty() &&
        num_samples_on_gpu >= get_threshold_ks_gemm()) {
      GPU_ASSERT(fp_tmp_buffer.size() >= streams.count(),
                 "GEMM KS Buffers %ld were not initialized for this amount of "
                 "streams, %d",
                 fp_tmp_buffer.size(), streams.count());

      GPU_ASSERT(fp_tmp_buffer[i]->num_lwes >= num_samples_on_gpu,
                 "KS temp buffer not big enough");

      GPU_ASSERT(fp_tmp_buffer[i]->lwe_dimension ==
                     std::max(lwe_dimension_in, lwe_dimension_out),
                 "KS temp buffer was created for a different input LWE size: "
                 "%d vs (in:%d, out:%d)",
                 fp_tmp_buffer[i]->lwe_dimension, lwe_dimension_in,
                 lwe_dimension_out);

      // Compute Keyswitch
      host_gemm_keyswitch_lwe_ciphertext_vector<Torus>(
          streams.stream(i), streams.gpu_index(i), current_lwe_array_out,
          current_lwe_output_indexes, current_lwe_array_in,
          current_lwe_input_indexes, ksks[i], lwe_dimension_in,
          lwe_dimension_out, base_log, level_count, num_samples_on_gpu,
          fp_tmp_buffer[i]->d_buffer, uses_trivial_indices);

    } else {
      // Compute Keyswitch
      host_keyswitch_lwe_ciphertext_vector<Torus>(
          streams.stream(i), streams.gpu_index(i), current_lwe_array_out,
          current_lwe_output_indexes, current_lwe_array_in,
          current_lwe_input_indexes, ksks[i], lwe_dimension_in,
          lwe_dimension_out, base_log, level_count, num_samples_on_gpu);
    }
  }
}

template <typename Torus>
__host__ uint64_t scratch_packing_keyswitch_lwe_list_to_glwe(
    cudaStream_t stream, uint32_t gpu_index, int8_t **fp_ks_buffer,
    uint32_t lwe_dimension, uint32_t glwe_dimension, uint32_t polynomial_size,
    uint32_t num_lwes, bool allocate_gpu_memory) {
  cuda_set_device(gpu_index);

  int glwe_accumulator_size = (glwe_dimension + 1) * polynomial_size;

  // allocate at least LWE-mask times two: to keep both decomposition state and
  // decomposed intermediate value
  uint64_t memory_unit = glwe_accumulator_size > lwe_dimension * 2
                             ? glwe_accumulator_size
                             : lwe_dimension * 2;

  uint64_t size_tracker = 0;
  uint64_t buffer_size =
      safe_mul_sizeof<Torus>((size_t)2, (size_t)num_lwes, memory_unit);
  *fp_ks_buffer = (int8_t *)cuda_malloc_with_size_tracking_async(
      buffer_size, stream, gpu_index, size_tracker, allocate_gpu_memory);
  return size_tracker;
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
      Torus state = init_decomposer_state(lwe_in[i], base_log, level_count);

      Torus mod_b_mask = (1ll << base_log) - 1ll;

      // block of key for current lwe coefficient (cur_input_lwe[i])
      auto ksk_block = &fp_ksk[i * ksk_block_size];
      for (int j = 0; j < level_count; j++) {
        auto ksk_glwe = &ksk_block[j * glwe_size * polynomial_size];
        // Iterate through each level and multiply by the ksk piece
        auto ksk_glwe_chunk = &ksk_glwe[poly_id * coef_per_block];
        Torus decomposed = decompose_one<Torus>(state, mod_b_mask, base_log);
        glwe_out[tid] -= decomposed * ksk_glwe_chunk[local_index];
      }
    }
  }
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
uint64_t scratch_cuda_keyswitch(cudaStream_t stream, uint32_t gpu_index,
                                ks_mem<Torus> **ks_tmp_memory,
                                uint32_t lwe_dimension_in,
                                uint32_t lwe_dimension_out, uint32_t num_lwes,
                                bool allocate_gpu_memory) {
  uint64_t sub_size_tracker = 0;
  uint64_t buffer_size = scratch_cuda_keyswitch_size<Torus>(
      lwe_dimension_in, lwe_dimension_out, num_lwes);

  *ks_tmp_memory = new ks_mem<Torus>;
  (*ks_tmp_memory)->d_buffer = (uint64_t *)cuda_malloc_with_size_tracking_async(
      buffer_size, stream, gpu_index, sub_size_tracker, allocate_gpu_memory);
  (*ks_tmp_memory)->lwe_dimension =
      std::max(lwe_dimension_in, lwe_dimension_out);
  (*ks_tmp_memory)->num_lwes = num_lwes;
  return sub_size_tracker;
}

template <typename Torus>
void cleanup_cuda_keyswitch(cudaStream_t stream, uint32_t gpu_index,
                            ks_mem<Torus> *ks_tmp_memory,
                            bool allocate_gpu_memory) {
  cuda_drop_with_size_tracking_async(ks_tmp_memory->d_buffer, stream, gpu_index,
                                     allocate_gpu_memory);
  delete ks_tmp_memory;
}

#endif
