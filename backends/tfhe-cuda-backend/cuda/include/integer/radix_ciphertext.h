#ifndef CUDA_RADIX_CIPHERTEXT_H
#define CUDA_RADIX_CIPHERTEXT_H

void release_radix_ciphertext_async(cudaStream_t const stream,
                                    uint32_t const gpu_index,
                                    CudaRadixCiphertextFFI *data,
                                    const bool gpu_memory_allocated);

void reset_radix_ciphertext_blocks(CudaRadixCiphertextFFI *data,
                                   uint32_t new_num_blocks);

void into_radix_ciphertext(CudaRadixCiphertextFFI *radix, void *lwe_array,
                           const uint32_t num_radix_blocks,
                           const uint32_t lwe_dimension);
#endif
