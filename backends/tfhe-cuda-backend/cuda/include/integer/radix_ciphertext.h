#ifndef CUDA_RADIX_CIPHERTEXT_H
#define CUDA_RADIX_CIPHERTEXT_H

void release_radix_ciphertext(cudaStream_t const stream,
                              uint32_t const gpu_index,
                              CudaRadixCiphertextFFI *data);

void reset_radix_ciphertext_blocks(CudaRadixCiphertextFFI *data,
                                   uint32_t new_num_blocks);

#endif
