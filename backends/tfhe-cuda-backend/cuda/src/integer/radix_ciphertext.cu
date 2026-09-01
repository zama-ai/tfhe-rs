#include "radix_ciphertext.cuh"

CudaRadixCiphertext::~CudaRadixCiphertext() {
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

void release_radix_ciphertext_async(
    cudaStream_t const
        stream, // nosemgrep: cuda-radix-ciphertext-non-const-param
    uint32_t const gpu_index, CudaRadixCiphertext *data,
    const bool gpu_memory_allocated) {
  PANIC_IF_FALSE(
      data->_owns_gpu_memory,
      "release_radix_ciphertext_async called on a CudaRadixCiphertext "
      "that does not own its GPU memory");
  PANIC_IF_FALSE(
      data->_owns_degrees_and_noise_levels,
      "release_radix_ciphertext_async called on a CudaRadixCiphertext "
      "that does not own its degrees / noise_levels arrays");
  cuda_drop_with_size_tracking_async(data->ptr, stream, gpu_index,
                                     gpu_memory_allocated);
  free(data->degrees);
  free(data->noise_levels);
  data->ptr = nullptr;
  data->degrees = nullptr;
  data->noise_levels = nullptr;
}

void release_cpu_radix_ciphertext_async(
    CudaRadixCiphertext
        *data) { // nosemgrep: cuda-radix-ciphertext-non-const-param
  PANIC_IF_FALSE(data->_owns_degrees_and_noise_levels,
                 "release_cpu_radix_ciphertext_async called on a "
                 "CudaRadixCiphertext that does not own its degrees / "
                 "noise_levels arrays");
  free(data->degrees);
  free(data->noise_levels);
  data->degrees = nullptr;
  data->noise_levels = nullptr;
}
void into_radix_ciphertext(
    CudaRadixCiphertext *radix,
    void *lwe_array, // nosemgrep: cuda-radix-ciphertext-non-const-param
    const uint32_t num_radix_blocks, const uint32_t lwe_dimension) {
  PANIC_IF_FALSE(!radix->_owns_gpu_memory &&
                     !radix->_owns_degrees_and_noise_levels,
                 "into_radix_ciphertext called on a CudaRadixCiphertext that "
                 "already owns memory");
  radix->lwe_dimension = lwe_dimension;
  radix->num_radix_blocks = num_radix_blocks;
  radix->max_num_radix_blocks = num_radix_blocks;
  radix->ptr = lwe_array;

  radix->degrees =
      (uint64_t *)(calloc(1, safe_mul_sizeof<uint64_t>(num_radix_blocks)));
  radix->noise_levels =
      (uint64_t *)(calloc(1, safe_mul_sizeof<uint64_t>(num_radix_blocks)));
  if (radix->degrees == NULL || radix->noise_levels == NULL) {
    PANIC("Cuda error: degrees / noise levels not allocated correctly")
  }
  radix->_owns_degrees_and_noise_levels = true;
}
