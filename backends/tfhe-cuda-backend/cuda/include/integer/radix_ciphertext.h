#ifndef CUDA_RADIX_CIPHERTEXT_H
#define CUDA_RADIX_CIPHERTEXT_H

void release_radix_ciphertext(cudaStream_t const stream,
                              uint32_t const gpu_index,
                              CudaRadixCiphertextFFI *data);

#endif
