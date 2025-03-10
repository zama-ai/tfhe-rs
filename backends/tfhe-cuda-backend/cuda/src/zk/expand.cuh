#ifndef EXPAND_CUH
#define EXPAND_CUH

#include "zk/zk.h"
#include "device.h"
#include "polynomial/functions.cuh"
#include "polynomial/polynomial_math.cuh"
#include <cstdint>

// Expand a LweCompactCiphertextList into a LweCiphertextList
// - Each x-block computes one output ciphertext
template <typename Torus, class params>
__global__ void lwe_expand(Torus const *lwe_compact_array_in,
                           Torus *lwe_array_out,
                           uint32_t max_ciphertext_per_bin, uint32_t num_lwe) {
  auto output_id = blockIdx.x;
  auto input_mask_id = output_id / max_ciphertext_per_bin;
  auto body_id = output_id;
  auto lwe_dimension = params::degree;

  auto input_mask = &lwe_compact_array_in[lwe_dimension * input_mask_id];
  auto input_body = &lwe_compact_array_in[lwe_dimension * num_lwe + body_id];

  auto output_mask = &lwe_array_out[lwe_dimension * output_id];
  auto output_body = &lwe_array_out[lwe_dimension * (output_id + 1) - 1];

  auto monomial_degree = output_id % max_ciphertext_per_bin;
  // We rotate the input mask by i to calculate the mask related to the i-th
  // output
  polynomial_product_accumulate_by_monomial_nosync<Torus, params>(
      output_mask, input_mask, monomial_degree);
  // The output body is just copied
  *output_body = *input_body;
}

bool is_power_of_2(uint32_t value) {
  return (value != 0) && ((value & (value - 1)) == 0);
}

template <typename Torus, class params>
void host_lwe_expand(cudaStream_t stream, int gpu_index, Torus *lwe_array_out,
                     const Torus *lwe_compact_array_in, uint32_t num_lwe,
                     uint32_t max_ciphertext_per_bin) {
  printf("CUDA Expand\n"); 
  // Set the GPU device
  cudaSetDevice(gpu_index);

  uint32_t threads_per_block = params::degree / params::opt;
  uint32_t num_blocks = num_lwe;
  auto lwe_dimension = params::degree;

  // Check if lwe_dimension is a power of 2
  // For now, and probably forever, we only support lwe_dimension being a power
  // of 2
  if (!is_power_of_2(lwe_dimension))
    PANIC("Error: lwe_dimension must be a power of 2");

  // Launch the `lwe_expand` kernel
  lwe_expand<Torus, params><<<num_blocks, threads_per_block, 0, stream>>>(
      lwe_compact_array_in, lwe_array_out, max_ciphertext_per_bin, num_lwe);
  check_cuda_error(cudaGetLastError());
}
#endif // EXPAND_CUH
