#ifndef CUDA_INTEGER_CUDA_RADIX_CIPHERTEXT_H
#define CUDA_INTEGER_CUDA_RADIX_CIPHERTEXT_H

#include "device.h"
#include "integer/integer.h"

struct CudaRadixCiphertext : public CudaRadixCiphertextFFI {
  bool _owns_gpu_memory;
  bool _owns_degrees_and_noise_levels;

  CudaRadixCiphertext()
      : CudaRadixCiphertextFFI{nullptr, nullptr, nullptr, 0, 0, 0},
        _owns_gpu_memory(false), _owns_degrees_and_noise_levels(false) {}

  explicit CudaRadixCiphertext(const CudaRadixCiphertextFFI &ffi)
      : CudaRadixCiphertextFFI(ffi), _owns_gpu_memory(false),
        _owns_degrees_and_noise_levels(false) {}

  CudaRadixCiphertext(const CudaRadixCiphertext &src)
      : CudaRadixCiphertextFFI(src), _owns_gpu_memory(false),
        _owns_degrees_and_noise_levels(false) {}

  CudaRadixCiphertext &operator=(const CudaRadixCiphertext &src) {
    static_cast<CudaRadixCiphertextFFI &>(*this) = src;
    _owns_gpu_memory = false;
    _owns_degrees_and_noise_levels = false;
    return *this;
  }

  ~CudaRadixCiphertext() {
    PANIC_IF_FALSE(!_owns_gpu_memory || ptr == nullptr,
                   "release_radix_ciphertext_async was not called on an owning "
                   "CudaRadixCiphertext (this=%p, ptr=%p)",
                   this, ptr);
    PANIC_IF_FALSE(!_owns_degrees_and_noise_levels ||
                       (degrees == nullptr && noise_levels == nullptr),
                   "release_(cpu_)radix_ciphertext_async was not called on an "
                   "owning CudaRadixCiphertext (this=%p, degrees=%p, "
                   "noise_levels=%p)",
                   this, degrees, noise_levels);
  }
};

#endif
