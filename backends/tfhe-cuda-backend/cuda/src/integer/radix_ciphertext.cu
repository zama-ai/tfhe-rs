#include "radix_ciphertext.cuh"

void release_radix_ciphertext(cudaStream_t const stream,
                              uint32_t const gpu_index,
                              CudaRadixCiphertextFFI *data) {
  cuda_drop_async(data->ptr, stream, gpu_index);
  free(data->degrees);
  free(data->noise_levels);
  cuda_synchronize_stream(stream, gpu_index);
}
