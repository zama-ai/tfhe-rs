#ifndef CUDA_CIPHERTEXT_CUH
#define CUDA_CIPHERTEXT_CUH

#include "checked_arithmetic.h"
#include "ciphertext.h"
#include "device.h"
#include "polynomial/functions.cuh"
#include <cstdint>

template <typename T>
void cuda_convert_lwe_ciphertext_vector_to_gpu(cudaStream_t stream,
                                               uint32_t gpu_index, T *dest,
                                               T *src, uint32_t number_of_cts,
                                               uint32_t lwe_dimension) {
  cuda_set_device(gpu_index);
  uint64_t size =
      safe_mul_sizeof<T>((size_t)number_of_cts, (size_t)(lwe_dimension + 1));
  cuda_memcpy_async_to_gpu(dest, src, size, stream, gpu_index);
}

template <typename T>
void cuda_convert_lwe_ciphertext_vector_to_cpu(cudaStream_t stream,
                                               uint32_t gpu_index, T *dest,
                                               T *src, uint32_t number_of_cts,
                                               uint32_t lwe_dimension) {
  cuda_set_device(gpu_index);
  uint64_t size =
      safe_mul_sizeof<T>((size_t)number_of_cts, (size_t)(lwe_dimension + 1));
  cuda_memcpy_async_to_cpu(dest, src, size, stream, gpu_index);
}

template <typename Torus, class params>
__global__ void sample_extract(Torus *lwe_array_out, Torus const *glwe_array_in,
                               uint32_t const *nth_array, uint32_t lwe_per_glwe,
                               uint32_t glwe_dimension) {

  const int input_id = blockIdx.x;

  const int glwe_input_size = (glwe_dimension + 1) * params::degree;
  const int lwe_output_size = glwe_dimension * params::degree + 1;

  auto lwe_out = lwe_array_out + input_id * lwe_output_size;

  // We assume each GLWE will store the first polynomial_size inputs
  auto glwe_in = glwe_array_in + (input_id / lwe_per_glwe) * glwe_input_size;

  // nth is ensured to be in [0, params::degree)
  auto nth = nth_array[input_id] % params::degree;

  sample_extract_mask<Torus, params>(lwe_out, glwe_in, glwe_dimension, nth);
  sample_extract_body<Torus, params>(lwe_out, glwe_in, glwe_dimension, nth);
}

// lwe_per_glwe LWEs will be extracted per GLWE ciphertext, thus we need to have
// enough indexes
template <typename Torus, class params>
__host__ void
host_sample_extract(cudaStream_t stream, uint32_t gpu_index,
                    Torus *lwe_array_out, Torus const *glwe_array_in,
                    uint32_t const *nth_array, uint32_t num_nths,
                    uint32_t lwe_per_glwe, uint32_t glwe_dimension) {
  cuda_set_device(gpu_index);
  dim3 grid(num_nths);
  dim3 thds(params::degree / params::opt);
  sample_extract<Torus, params><<<grid, thds, 0, stream>>>(
      lwe_array_out, glwe_array_in, nth_array, lwe_per_glwe, glwe_dimension);
  check_cuda_error(cudaGetLastError());
}

#endif
