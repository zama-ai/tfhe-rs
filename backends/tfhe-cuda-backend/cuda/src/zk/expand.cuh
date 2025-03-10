#ifndef EXPAND_CUH
#define EXPAND_CUH

#include "device.h"
#include "polynomial/functions.cuh"
#include "polynomial/polynomial_math.cuh"
#include "zk/zk.h"
#include <cstdint>

#include "utils/helper.cuh"

// Expand a LweCompactCiphertextList into a LweCiphertextList
// - Each x-block computes one output ciphertext
template <typename Torus, class params>
__global__ void lwe_expand(Torus const *lwe_compact_array_in,
                           Torus *lwe_array_out,
                           const uint32_t *compact_list_length_per_thread,
                           const uint32_t *lwe_compact_input_indexes) {
  const auto lwe_output_id = blockIdx.x;
  const auto lwe_dimension = params::degree;

  const auto compact_list_length =
      compact_list_length_per_thread[lwe_output_id];
  const auto body_id = lwe_output_id % compact_list_length;

  const auto input_mask =
      &lwe_compact_array_in[lwe_compact_input_indexes[blockIdx.x]];
  const auto input_body = &input_mask[lwe_dimension + body_id];

  auto output_mask = &lwe_array_out[(lwe_dimension + 1) * lwe_output_id];
  auto output_body = &output_mask[lwe_dimension];

  // We rotate the input mask by i to calculate the mask related to the i-th
  // output
  const auto monomial_degree = body_id;
  polynomial_accumulate_monic_monomial_mul<Torus>(
      output_mask, input_mask, monomial_degree, threadIdx.x, lwe_dimension,
      params::opt, true);

  // The output body is just copied
  if (threadIdx.x == 0)
    *output_body = *input_body;
}

template <typename Torus> bool is_power_of_2(Torus value) {
  return (value != 0) && ((value & (value - 1)) == 0);
}

template <typename Torus, class params>
void host_lwe_expand(cudaStream_t stream, int gpu_index, Torus *lwe_array_out,
                     const Torus *lwe_compact_array_in, uint32_t num_lwes,
                     const uint32_t *compact_list_length_per_thread,
                     const uint32_t *lwe_compact_input_indexes) {
  // Set the GPU device
  cudaSetDevice(gpu_index);

  uint32_t threads_per_block = params::degree / params::opt;
  uint32_t num_blocks = num_lwes;
  auto lwe_dimension = params::degree;

  // Check if lwe_dimension is a power of 2
  // For now, and probably forever, we only support lwe_dimension being a power
  // of 2
  if (!is_power_of_2(lwe_dimension))
    PANIC("Error: lwe_dimension must be a power of 2");

  // Launch the `lwe_expand` kernel
  lwe_expand<Torus, params><<<num_blocks, threads_per_block, 0, stream>>>(
      lwe_compact_array_in, lwe_array_out, compact_list_length_per_thread,
      lwe_compact_input_indexes);
  check_cuda_error(cudaGetLastError());
}
#endif // EXPAND_CUH
