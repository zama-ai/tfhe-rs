#ifndef EXPAND_CUH
#define EXPAND_CUH

#include "device.h"
#include "polynomial/functions.cuh"
#include "polynomial/polynomial_math.cuh"
#include "zk/zk.h"
#include "zk/zk_utilities.h"
#include <cstdint>

// Expand a LweCompactCiphertextList into a LweCiphertextList
// - Each x-block computes one output ciphertext
template <typename Torus, class params>
__global__ void lwe_expand(const expand_job<Torus> *jobs,
                           Torus *lwe_array_out) {
  const auto lwe_output_id = blockIdx.x;
  const auto lwe_dimension = params::degree;

  const auto job = jobs[lwe_output_id];

  const lwe_mask<Torus> input_mask = job.mask_to_use;
  const compact_lwe_body<Torus> input_body = job.body_to_use;

  auto output_mask = &lwe_array_out[(lwe_dimension + 1) * lwe_output_id];
  auto output_body = &output_mask[lwe_dimension];

  // We rotate the input mask by i to calculate the mask related to the i-th
  // output
  const auto monomial_degree = input_body.monomial_degree;
  polynomial_accumulate_monic_monomial_mul<Torus>(
      output_mask, input_mask.mask, monomial_degree, threadIdx.x, lwe_dimension,
      params::opt, true);

  // The output body is just copied
  if (threadIdx.x == 0)
    *output_body = *input_body.body;
}

template <typename Torus> bool is_power_of_2(Torus value) {
  return (value != 0) && ((value & (value - 1)) == 0);
}

template <typename Torus, class params>
void host_lwe_expand(cudaStream_t stream, int gpu_index, Torus *lwe_array_out,
                     const expand_job<Torus> *d_jobs, uint32_t num_lwes) {
  // Set the GPU device
  check_cuda_error(cudaSetDevice(gpu_index));

  uint32_t threads_per_block = params::degree / params::opt;
  uint32_t num_blocks = num_lwes;
  auto lwe_dimension = params::degree;

  // Check if lwe_dimension is a power of 2
  // For now, and probably forever, we only support lwe_dimension being a power
  // of 2
  if (!is_power_of_2(lwe_dimension))
    PANIC("Error: lwe_dimension must be a power of 2");

  // Launch the `lwe_expand` kernel
  lwe_expand<Torus, params>
      <<<num_blocks, threads_per_block, 0, stream>>>(d_jobs, lwe_array_out);
  check_cuda_error(cudaGetLastError());
}
#endif // EXPAND_CUH
