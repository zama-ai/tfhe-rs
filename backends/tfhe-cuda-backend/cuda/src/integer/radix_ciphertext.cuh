#ifndef CUDA_INTEGER_RADIX_CIPHERTEXT_CUH
#define CUDA_INTEGER_RADIX_CIPHERTEXT_CUH

#include "device.h"
#include "integer/integer.h"

template <typename Torus>
void create_zero_radix_ciphertext_async(cudaStream_t const stream,
                                        uint32_t const gpu_index,
                                        CudaRadixCiphertextFFI *radix,
                                        const uint32_t num_radix_blocks,
                                        const uint32_t lwe_dimension) {
  radix->lwe_dimension = lwe_dimension;
  radix->num_radix_blocks = num_radix_blocks;
  uint32_t size = (lwe_dimension + 1) * num_radix_blocks * sizeof(Torus);
  radix->ptr = (void *)cuda_malloc_async(size, stream, gpu_index);
  cuda_memset_async(radix->ptr, 0, size, stream, gpu_index);

  radix->degrees = (uint64_t *)(calloc(num_radix_blocks, sizeof(uint64_t)));
  radix->noise_levels =
      (uint64_t *)(calloc(num_radix_blocks, sizeof(uint64_t)));
  if (radix->degrees == NULL || radix->noise_levels == NULL) {
    PANIC("Cuda error: degrees / noise levels not allocated correctly")
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
  if (start_lwe_index > end_lwe_index)
    PANIC("Cuda error: slice range should be non negative")

  auto lwe_size = input_radix->lwe_dimension + 1;
  output_radix->num_radix_blocks = end_lwe_index - start_lwe_index + 1;
  output_radix->lwe_dimension = input_radix->lwe_dimension;
  Torus *in_ptr = (Torus *)input_radix->ptr;
  output_radix->ptr = (void *)(in_ptr + start_lwe_index * lwe_size);
  output_radix->degrees = input_radix->degrees + start_lwe_index;
  output_radix->noise_levels = input_radix->noise_levels + start_lwe_index;
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
                               input_radix->num_radix_blocks * lwe_size *
                                   sizeof(Torus),
                               stream, gpu_index);
  for (uint i = 0; i < input_radix->num_radix_blocks; i++) {
    output_radix->degrees[i + output_start_lwe_index] = input_radix->degrees[i];
    output_radix->noise_levels[i + output_start_lwe_index] =
        input_radix->noise_levels[i];
  }
}

template <typename Torus>
void copy_radix_ciphertext_async(cudaStream_t const stream,
                                 uint32_t const gpu_index,
                                 CudaRadixCiphertextFFI *output_radix,
                                 const CudaRadixCiphertextFFI *input_radix) {
  copy_radix_ciphertext_to_larger_output_slice_async<Torus>(
      stream, gpu_index, output_radix, input_radix, 0);
}

// end_lwe_index is inclusive
template <typename Torus>
void set_zero_radix_ciphertext_async(cudaStream_t const stream,
                                     uint32_t const gpu_index,
                                     CudaRadixCiphertextFFI *radix,
                                     const uint32_t start_lwe_index,
                                     const uint32_t end_lwe_index) {
  if (radix->num_radix_blocks < end_lwe_index - start_lwe_index + 1)
    PANIC("Cuda error: input radix should have more blocks than the specified "
          "range")
  if (start_lwe_index > end_lwe_index)
    PANIC("Cuda error: slice range should be non negative")

  auto lwe_size = radix->lwe_dimension + 1;
  auto num_blocks_to_set = end_lwe_index - start_lwe_index + 1;
  auto lwe_array_out_block = (Torus *)radix->ptr + start_lwe_index * lwe_size;
  cuda_memset_async(lwe_array_out_block, 0,
                    num_blocks_to_set * lwe_size * sizeof(Torus), stream,
                    gpu_index);
  memset(&radix->degrees[start_lwe_index], 0,
         num_blocks_to_set * sizeof(uint64_t));
  memset(&radix->noise_levels[start_lwe_index], 0,
         num_blocks_to_set * sizeof(uint64_t));
}

#endif
