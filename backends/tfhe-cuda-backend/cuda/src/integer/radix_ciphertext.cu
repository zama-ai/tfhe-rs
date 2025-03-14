#include "radix_ciphertext.cuh"

void release_radix_ciphertext(cudaStream_t const stream,
                              uint32_t const gpu_index,
                              CudaRadixCiphertextFFI *data) {
  cuda_drop_async(data->ptr, stream, gpu_index);
  free(data->degrees);
  free(data->noise_levels);
  cuda_synchronize_stream(stream, gpu_index);
}

void reset_radix_ciphertext_blocks(CudaRadixCiphertextFFI *data,
                                   uint32_t new_num_blocks) {
  if (new_num_blocks > data->max_num_radix_blocks)
    PANIC("Cuda error: new num blocks should be lower or equal than the "
          "radix' maximum number of blocks")
  data->num_radix_blocks = new_num_blocks;
}
