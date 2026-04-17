#include "linearalgebra/multiplication.cuh"
#include "polynomial/dot_product.cuh"

void scratch_cuda_wrapping_polynomial_mul_one_to_many_64_async(
    void *stream, uint32_t gpu_index, uint32_t polynomial_size,
    int8_t **circulant_buf) {
  scratch_wrapping_polynomial_mul_one_to_many<uint64_t>(
      stream, gpu_index, polynomial_size, circulant_buf);
}

void cleanup_cuda_wrapping_polynomial_mul_one_to_many_64(
    void *stream, uint32_t gpu_index, int8_t *circulant_buf) {
  cleanup_wrapping_polynomial_mul_one_to_many<uint64_t>(stream, gpu_index,
                                                        circulant_buf);
  cuda_synchronize_stream(static_cast<cudaStream_t>(stream), gpu_index);
}

void cuda_wrapping_polynomial_mul_one_to_many_64_async(
    void *stream, uint32_t gpu_index, void *result, void const *poly_lhs,
    int8_t *circulant, void const *poly_rhs, uint32_t polynomial_size,
    uint32_t n_rhs) {
  PANIC_IF_FALSE(result != poly_lhs,
                 "Output and left input pointers must be different for "
                 "out-of-place operations");
  PANIC_IF_FALSE(result != poly_rhs,
                 "Output and right input pointers must be different for "
                 "out-of-place operations");

  host_wrapping_polynomial_mul_one_to_many<uint64_t, ulonglong4>(
      static_cast<cudaStream_t>(stream), gpu_index,
      static_cast<uint64_t *>(result), static_cast<uint64_t const *>(poly_lhs),
      circulant, static_cast<uint64_t const *>(poly_rhs), polynomial_size, 0,
      n_rhs);
}

void cuda_glwe_wrapping_polynomial_mul_one_to_many_64_async(
    void *stream, uint32_t gpu_index, void *result, void const *glwe_lhs,
    int8_t *circulant, void const *poly_rhs, uint32_t polynomial_size,
    uint32_t glwe_dimension, uint32_t n_rhs) {
  PANIC_IF_FALSE(result != glwe_lhs,
                 "Output and left input pointers must be different for "
                 "out-of-place operations");
  PANIC_IF_FALSE(result != poly_rhs,
                 "Output and right input pointers must be different for "
                 "out-of-place operations");

  host_glwe_wrapping_polynomial_mul_one_to_many<uint64_t, ulonglong4>(
      static_cast<cudaStream_t>(stream), gpu_index,
      static_cast<uint64_t *>(result), static_cast<uint64_t const *>(glwe_lhs),
      circulant, static_cast<uint64_t const *>(poly_rhs), polynomial_size,
      glwe_dimension, n_rhs);
}
