#include "radix_ciphertext.cuh"

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
