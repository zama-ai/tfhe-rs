#ifndef CUDA_INTEGER_RADIX_CIPHERTEXT_CUH
#define CUDA_INTEGER_RADIX_CIPHERTEXT_CUH

#include "device.h"
#include "integer/integer.h"
#include "utils/kernel_dimensions.cuh"

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

template <typename Torus>
__global__ void
device_create_trivial_radix(Torus *lwe_array, Torus const *scalar_input,
                            int32_t num_blocks, uint32_t lwe_dimension,
                            uint64_t delta) {
  int tid = blockIdx.x * blockDim.x + threadIdx.x;
  if (tid < num_blocks) {
    Torus scalar = scalar_input[tid];
    Torus *body = lwe_array + tid * (lwe_dimension + 1) + lwe_dimension;

    *body = scalar * delta;
  }
}

// end_input_lwe_index is exclusive
template <typename Torus>
void as_radix_ciphertext_slice(CudaRadixCiphertextFFI *output_radix,
                               const CudaRadixCiphertextFFI *input_radix,
                               const uint32_t start_input_lwe_index,
                               const uint32_t end_input_lwe_index) {
  if (input_radix->num_radix_blocks <
      end_input_lwe_index - start_input_lwe_index)
    PANIC("Cuda error: input radix should have more blocks than the specified "
          "range")
  if (start_input_lwe_index >= end_input_lwe_index)
    PANIC("Cuda error: slice range should be non negative")

  auto lwe_size = input_radix->lwe_dimension + 1;
  output_radix->num_radix_blocks = end_input_lwe_index - start_input_lwe_index;
  output_radix->lwe_dimension = input_radix->lwe_dimension;
  Torus *in_ptr = (Torus *)input_radix->ptr;
  output_radix->ptr = (void *)(in_ptr + start_input_lwe_index * lwe_size);
  output_radix->degrees = input_radix->degrees + start_input_lwe_index;
  output_radix->noise_levels =
      input_radix->noise_levels + start_input_lwe_index;
}

// end_lwe_index are exclusive
template <typename Torus>
void copy_radix_ciphertext_slice_async(
    cudaStream_t const stream, uint32_t const gpu_index,
    CudaRadixCiphertextFFI *output_radix, const uint32_t output_start_lwe_index,
    const uint32_t output_end_lwe_index,
    const CudaRadixCiphertextFFI *input_radix,
    const uint32_t input_start_lwe_index, const uint32_t input_end_lwe_index) {
  if (output_radix->lwe_dimension != input_radix->lwe_dimension)
    PANIC("Cuda error: input lwe dimension should be equal to output lwe "
          "dimension")
  if (output_end_lwe_index - output_start_lwe_index !=
      input_end_lwe_index - input_start_lwe_index)
    PANIC("Cuda error: output and input ranges should have the same size")
  if (output_end_lwe_index - output_start_lwe_index >
      output_radix->num_radix_blocks)
    PANIC("Cuda error: output range should be lower or equal to output num "
          "blocks")
  if (input_end_lwe_index - input_start_lwe_index >
      input_radix->num_radix_blocks)
    PANIC(
        "Cuda error: input range should be lower or equal to input num blocks")
  if (output_end_lwe_index - output_start_lwe_index <= 0)
    PANIC("Cuda error: output range should be greater than zero")
  if (input_end_lwe_index - input_start_lwe_index <= 0)
    PANIC("Cuda error: input range should be greater than zero")
  if (output_end_lwe_index <= output_start_lwe_index)
    PANIC("Cuda error: output end index should be greater or equal to output "
          "start index")
  if (input_end_lwe_index <= input_start_lwe_index)
    PANIC("Cuda error: input end index should be greater or equal to input "
          "start index")
  if (output_start_lwe_index > output_radix->num_radix_blocks)
    PANIC("Cuda error: output start index should be smaller than the number "
          "of blocks")
  if (input_start_lwe_index > input_radix->num_radix_blocks)
    PANIC("Cuda error: input start index should be smaller than the number "
          "of blocks")

  auto lwe_size = input_radix->lwe_dimension + 1;
  Torus *out_ptr = (Torus *)output_radix->ptr;
  out_ptr = &out_ptr[output_start_lwe_index * lwe_size];
  Torus *in_ptr = (Torus *)input_radix->ptr;
  in_ptr = &in_ptr[input_start_lwe_index * lwe_size];
  auto num_blocks = input_end_lwe_index - input_start_lwe_index;

  cuda_memcpy_async_gpu_to_gpu(out_ptr, in_ptr,
                               num_blocks * lwe_size * sizeof(Torus), stream,
                               gpu_index);
  for (uint i = 0; i < num_blocks; i++) {
    output_radix->degrees[i + output_start_lwe_index] =
        input_radix->degrees[i + input_start_lwe_index];
    output_radix->noise_levels[i + output_start_lwe_index] =
        input_radix->noise_levels[i + input_start_lwe_index];
  }
}

template <typename Torus>
void copy_radix_ciphertext_async(cudaStream_t const stream,
                                 uint32_t const gpu_index,
                                 CudaRadixCiphertextFFI *output_radix,
                                 const CudaRadixCiphertextFFI *input_radix) {
  copy_radix_ciphertext_slice_async<Torus>(
      stream, gpu_index, output_radix, 0, output_radix->num_radix_blocks,
      input_radix, 0, input_radix->num_radix_blocks);
}

// end_lwe_index is exclusive
template <typename Torus>
void set_zero_radix_ciphertext_slice_async(cudaStream_t const stream,
                                           uint32_t const gpu_index,
                                           CudaRadixCiphertextFFI *radix,
                                           const uint32_t start_lwe_index,
                                           const uint32_t end_lwe_index) {
  if (radix->num_radix_blocks < end_lwe_index - start_lwe_index)
    PANIC("Cuda error: input radix should have more blocks than the specified "
          "range")
  if (start_lwe_index > end_lwe_index)
    PANIC("Cuda error: slice range should be positive")

  auto lwe_size = radix->lwe_dimension + 1;
  auto num_blocks_to_set = end_lwe_index - start_lwe_index;
  auto lwe_array_out_block = (Torus *)radix->ptr + start_lwe_index * lwe_size;
  cuda_memset_async(lwe_array_out_block, 0,
                    num_blocks_to_set * lwe_size * sizeof(Torus), stream,
                    gpu_index);
  memset(&radix->degrees[start_lwe_index], 0,
         num_blocks_to_set * sizeof(uint64_t));
  memset(&radix->noise_levels[start_lwe_index], 0,
         num_blocks_to_set * sizeof(uint64_t));
}

template <typename Torus>
__host__ void set_trivial_radix_ciphertext_async(
    cudaStream_t stream, uint32_t gpu_index,
    CudaRadixCiphertextFFI *lwe_array_out, Torus const *scalar_array,
    uint32_t num_scalar_blocks, Torus message_modulus, Torus carry_modulus) {

  if (num_scalar_blocks > lwe_array_out->num_radix_blocks)
    PANIC("Cuda error: num scalar blocks should be lower or equal to the "
          "number of input radix blocks")
  set_zero_radix_ciphertext_slice_async<Torus>(
      stream, gpu_index, lwe_array_out, 0, lwe_array_out->num_radix_blocks);
  if (num_scalar_blocks == 0)
    return;

  // Create a 1-dimensional grid of threads
  int num_blocks = 0, num_threads = 0;
  int num_entries = num_scalar_blocks;
  getNumBlocksAndThreads(num_entries, 512, num_blocks, num_threads);
  dim3 grid(num_blocks, 1, 1);
  dim3 thds(num_threads, 1, 1);

  // Value of the shift we multiply our messages by
  // If message_modulus and carry_modulus are always powers of 2 we can simplify
  // this
  auto nbits = sizeof(Torus) * 8;
  Torus delta = (static_cast<Torus>(1) << (nbits - 1)) /
                (message_modulus * carry_modulus);

  device_create_trivial_radix<Torus><<<grid, thds, 0, stream>>>(
      (Torus *)lwe_array_out->ptr, scalar_array, num_scalar_blocks,
      lwe_array_out->lwe_dimension, delta);
  check_cuda_error(cudaGetLastError());
  Torus scalar_array_cpu[num_scalar_blocks];
  cuda_memcpy_async_to_cpu(&scalar_array_cpu, scalar_array,
                           num_scalar_blocks * sizeof(Torus), stream,
                           gpu_index);
  cuda_synchronize_stream(stream, gpu_index);
  for (uint i = 0; i < num_scalar_blocks; i++) {
    lwe_array_out->degrees[i] = scalar_array_cpu[i];
  }
}

#endif
