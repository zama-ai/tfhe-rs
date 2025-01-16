#ifndef CUDA_INTEGER_RADIX_CIPHERTEXT_CUH
#define CUDA_INTEGER_RADIX_CIPHERTEXT_CUH

#include "device.h"
#include "integer/integer.h"

template <typename Torus>
void create_trivial_radix_ciphertext_async(cudaStream_t const stream,
                                           uint32_t const gpu_index,
                                           CudaRadixCiphertextFFI *output_radix,
                                           const uint32_t num_radix_blocks,
                                           const uint32_t lwe_dimension) {
  output_radix->lwe_dimension = lwe_dimension;
  output_radix->num_radix_blocks = num_radix_blocks;
  uint32_t lwe_size_bytes = (lwe_dimension + 1) * sizeof(Torus);
  output_radix->ptr = (void *)cuda_malloc_async(
      num_radix_blocks * lwe_size_bytes, stream, gpu_index);
  output_radix->degrees = (Torus *)(malloc(num_radix_blocks * sizeof(Torus)));
  output_radix->noise_levels =
      (Torus *)(malloc(num_radix_blocks * sizeof(Torus)));
  for (uint i = 0; i < output_radix->num_radix_blocks; i++) {
    output_radix->degrees[i] = 0;
    output_radix->noise_levels[i] = 0;
  }
}

// end_lwe_index is inclusive
template <typename Torus>
void as_radix_ciphertext_slice(CudaRadixCiphertextFFI *output_radix,
                               const CudaRadixCiphertextFFI *input_radix,
                               const uint32_t start_lwe_index,
                               const uint32_t end_lwe_index) {
  if (input_radix->num_radix_blocks < end_lwe_index - start_lwe_index + 1)
    PANIC("Cuda error: input radix should have more blocks than the specified "
          "range")
  if (start_lwe_index >= end_lwe_index)
    PANIC("Cuda error: slice range should be strictly positive")

  auto lwe_size = input_radix->lwe_dimension + 1;
  output_radix->num_radix_blocks = end_lwe_index - start_lwe_index + 1;
  output_radix->lwe_dimension = input_radix->lwe_dimension;
  Torus *in_ptr = (Torus *)input_radix->ptr;
  output_radix->ptr = (void *)(&in_ptr[start_lwe_index * lwe_size]);
  output_radix->degrees = &input_radix->degrees[start_lwe_index * lwe_size];
  output_radix->noise_levels =
      &input_radix->noise_levels[start_lwe_index * lwe_size];
}

template <typename Torus>
void copy_radix_ciphertext_to_larger_output_slice_async(
    cudaStream_t const stream, uint32_t const gpu_index,
    CudaRadixCiphertextFFI *output_radix,
    const CudaRadixCiphertextFFI *input_radix,
    const uint32_t output_start_lwe_index) {
  if (output_radix->lwe_dimension != input_radix->lwe_dimension)
    PANIC("Cuda error: input lwe dimension should be equal to output lwe "
          "dimension")
  if (output_radix->num_radix_blocks - output_start_lwe_index <
      input_radix->num_radix_blocks)
    PANIC("Cuda error: output range should have more blocks than there are"
          "input radix blocks")
  if (output_start_lwe_index >= output_radix->num_radix_blocks)
    PANIC("Cuda error: output index should be strictly smaller than the number "
          "of blocks")

  auto lwe_size = input_radix->lwe_dimension + 1;
  Torus *out_ptr = (Torus *)output_radix->ptr;
  out_ptr = &out_ptr[output_start_lwe_index * lwe_size];

  cuda_memcpy_async_gpu_to_gpu(out_ptr, input_radix->ptr,
                               input_radix->num_radix_blocks *
                                   (input_radix->lwe_dimension + 1) *
                                   sizeof(Torus),
                               stream, gpu_index);
  for (uint i = 0; i < input_radix->num_radix_blocks; i++) {
    output_radix->degrees[i + output_start_lwe_index] = input_radix->degrees[i];
    output_radix->noise_levels[i + output_start_lwe_index] =
        input_radix->noise_levels[i];
  }
}

#endif
