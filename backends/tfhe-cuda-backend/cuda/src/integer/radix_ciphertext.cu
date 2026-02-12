#include "radix_ciphertext.cuh"

void release_radix_ciphertext_async(cudaStream_t const stream,
                                    uint32_t const gpu_index,
                                    CudaRadixCiphertextFFI *data,
                                    const bool gpu_memory_allocated) {
  cuda_drop_with_size_tracking_async(data->ptr, stream, gpu_index,
                                     gpu_memory_allocated);
  free(data->degrees);
  free(data->noise_levels);
}

void release_cpu_radix_ciphertext_async(CudaRadixCiphertextFFI *data) {
  free(data->degrees);
  free(data->noise_levels);
}
void reset_radix_ciphertext_blocks(CudaRadixCiphertextFFI *data,
                                   uint32_t new_num_blocks) {
  if (new_num_blocks > data->max_num_radix_blocks)
    PANIC("Cuda error: new num blocks should be lower or equal than the "
          "radix' maximum number of blocks")
  data->num_radix_blocks = new_num_blocks;
}

void into_radix_ciphertext(CudaRadixCiphertextFFI *radix, void *lwe_array,
                           const uint32_t num_radix_blocks,
                           const uint32_t lwe_dimension) {
  radix->lwe_dimension = lwe_dimension;
  radix->num_radix_blocks = num_radix_blocks;
  radix->max_num_radix_blocks = num_radix_blocks;
  radix->ptr = lwe_array;

  radix->degrees =
      (uint64_t *)(calloc(1, safe_mul_sizeof<uint64_t>(num_radix_blocks)));
  radix->noise_levels =
      (uint64_t *)(calloc(1, safe_mul_sizeof<uint64_t>(num_radix_blocks)));
  if (radix->degrees == NULL || radix->noise_levels == NULL) {
    PANIC("Cuda error: degrees / noise levels not allocated correctly")
  }
}
