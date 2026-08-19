#ifndef CUDA_RADIX_CIPHERTEXT_H
#define CUDA_RADIX_CIPHERTEXT_H

/// @brief Releases GPU memory and host arrays owned by a radix ciphertext.
///
/// @param data Radix ciphertext whose buffers are freed.
/// @param gpu_memory_allocated When true, the device pointer is freed.
void release_radix_ciphertext_async(cudaStream_t stream,
                                    uint32_t const gpu_index,
                                    CudaRadixCiphertextFFI *data,
                                    const bool gpu_memory_allocated);

void release_cpu_radix_ciphertext_async(CudaRadixCiphertextFFI *data);

void reset_radix_ciphertext_blocks(CudaRadixCiphertextFFI *data,
                                   uint32_t new_num_blocks);

void into_radix_ciphertext(CudaRadixCiphertextFFI *radix, void *lwe_array,
                           const uint32_t num_radix_blocks,
                           const uint32_t lwe_dimension);
#endif
