#ifndef CUDA_INTEGER_CUDA_RADIX_CIPHERTEXT_H
#define CUDA_INTEGER_CUDA_RADIX_CIPHERTEXT_H

#include "integer.h"

struct CudaRadixCiphertext {
  void *ptr;
  uint64_t *degrees;
  uint64_t *noise_levels;
  uint32_t num_radix_blocks;
  uint32_t max_num_radix_blocks;
  uint32_t lwe_dimension;

  bool _owns_gpu_memory;
  bool _owns_degrees_and_noise_levels;

  CudaRadixCiphertext()
      : ptr(nullptr), degrees(nullptr), noise_levels(nullptr),
        num_radix_blocks(0), max_num_radix_blocks(0), lwe_dimension(0),
        _owns_gpu_memory(false), _owns_degrees_and_noise_levels(false) {}

  explicit CudaRadixCiphertext(const CudaRadixCiphertextFFI &ffi)
      : ptr(ffi.ptr), degrees(ffi.degrees), noise_levels(ffi.noise_levels),
        num_radix_blocks(ffi.num_radix_blocks),
        max_num_radix_blocks(ffi.max_num_radix_blocks),
        lwe_dimension(ffi.lwe_dimension), _owns_gpu_memory(false),
        _owns_degrees_and_noise_levels(false) {}

  CudaRadixCiphertext(const CudaRadixCiphertext &src)
      : ptr(src.ptr), degrees(src.degrees), noise_levels(src.noise_levels),
        num_radix_blocks(src.num_radix_blocks),
        max_num_radix_blocks(src.max_num_radix_blocks),
        lwe_dimension(src.lwe_dimension), _owns_gpu_memory(false),
        _owns_degrees_and_noise_levels(false) {}

  CudaRadixCiphertext &operator=(const CudaRadixCiphertext &src) {
    ptr = src.ptr;
    degrees = src.degrees;
    noise_levels = src.noise_levels;
    num_radix_blocks = src.num_radix_blocks;
    max_num_radix_blocks = src.max_num_radix_blocks;
    lwe_dimension = src.lwe_dimension;
    _owns_gpu_memory = false;
    _owns_degrees_and_noise_levels = false;
    return *this;
  }

  ~CudaRadixCiphertext();
};

#endif
