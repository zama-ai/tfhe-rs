#ifndef CUDA_RADIX_CIPHERTEXT_H
#define CUDA_RADIX_CIPHERTEXT_H

#include "cuda_radix_ciphertext.h"

void release_radix_ciphertext_async(cudaStream_t const stream,
                                    uint32_t const gpu_index,
                                    CudaRadixCiphertext *data,
                                    const bool gpu_memory_allocated);

void release_cpu_radix_ciphertext_async(CudaRadixCiphertext *data);

void reset_radix_ciphertext_blocks(CudaRadixCiphertextFFI *data,
                                   uint32_t new_num_blocks);

void into_radix_ciphertext(CudaRadixCiphertext *radix, void *lwe_array,
                           const uint32_t num_radix_blocks,
                           const uint32_t lwe_dimension);
#endif
