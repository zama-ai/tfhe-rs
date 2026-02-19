#include "ciphertext.cuh"
#include "polynomial/parameters.cuh"

void cuda_convert_lwe_ciphertext_vector_to_gpu_64_async(
    void *stream, uint32_t gpu_index, void *dest, void *src,
    uint32_t number_of_cts, uint32_t lwe_dimension) {
  cuda_convert_lwe_ciphertext_vector_to_gpu<uint64_t>(
      static_cast<cudaStream_t>(stream), gpu_index, (uint64_t *)dest,
      (uint64_t *)src, number_of_cts, lwe_dimension);
}

void cuda_convert_lwe_ciphertext_vector_to_cpu_64_async(
    void *stream, uint32_t gpu_index, void *dest, void *src,
    uint32_t number_of_cts, uint32_t lwe_dimension) {
  cuda_convert_lwe_ciphertext_vector_to_cpu<uint64_t>(
      static_cast<cudaStream_t>(stream), gpu_index, (uint64_t *)dest,
      (uint64_t *)src, number_of_cts, lwe_dimension);
}

void cuda_glwe_sample_extract_64_async(
    void *stream, uint32_t gpu_index, void *lwe_array_out,
    void const *glwe_array_in, uint32_t const *nth_array, uint32_t num_nths,
    uint32_t num_lwes_to_extract_per_glwe, uint32_t num_lwes_stored_per_glwe,
    uint32_t glwe_dimension, uint32_t polynomial_size) {

  switch (polynomial_size) {
  case 256:
    host_sample_extract<uint64_t, AmortizedDegree<256>>(
        static_cast<cudaStream_t>(stream), gpu_index, (uint64_t *)lwe_array_out,
        (uint64_t const *)glwe_array_in, (uint32_t const *)nth_array, num_nths,
        num_lwes_to_extract_per_glwe, num_lwes_stored_per_glwe, glwe_dimension);
    break;
  case 512:
    host_sample_extract<uint64_t, AmortizedDegree<512>>(
        static_cast<cudaStream_t>(stream), gpu_index, (uint64_t *)lwe_array_out,
        (uint64_t const *)glwe_array_in, (uint32_t const *)nth_array, num_nths,
        num_lwes_to_extract_per_glwe, num_lwes_stored_per_glwe, glwe_dimension);
    break;
  case 1024:
    host_sample_extract<uint64_t, AmortizedDegree<1024>>(
        static_cast<cudaStream_t>(stream), gpu_index, (uint64_t *)lwe_array_out,
        (uint64_t const *)glwe_array_in, (uint32_t const *)nth_array, num_nths,
        num_lwes_to_extract_per_glwe, num_lwes_stored_per_glwe, glwe_dimension);
    break;
  case 2048:
    host_sample_extract<uint64_t, AmortizedDegree<2048>>(
        static_cast<cudaStream_t>(stream), gpu_index, (uint64_t *)lwe_array_out,
        (uint64_t const *)glwe_array_in, (uint32_t const *)nth_array, num_nths,
        num_lwes_to_extract_per_glwe, num_lwes_stored_per_glwe, glwe_dimension);
    break;
  case 4096:
    host_sample_extract<uint64_t, AmortizedDegree<4096>>(
        static_cast<cudaStream_t>(stream), gpu_index, (uint64_t *)lwe_array_out,
        (uint64_t const *)glwe_array_in, (uint32_t const *)nth_array, num_nths,
        num_lwes_to_extract_per_glwe, num_lwes_stored_per_glwe, glwe_dimension);
    break;
  case 8192:
    host_sample_extract<uint64_t, AmortizedDegree<8192>>(
        static_cast<cudaStream_t>(stream), gpu_index, (uint64_t *)lwe_array_out,
        (uint64_t const *)glwe_array_in, (uint32_t const *)nth_array, num_nths,
        num_lwes_to_extract_per_glwe, num_lwes_stored_per_glwe, glwe_dimension);
    break;
  case 16384:
    host_sample_extract<uint64_t, AmortizedDegree<16384>>(
        static_cast<cudaStream_t>(stream), gpu_index, (uint64_t *)lwe_array_out,
        (uint64_t const *)glwe_array_in, (uint32_t const *)nth_array, num_nths,
        num_lwes_to_extract_per_glwe, num_lwes_stored_per_glwe, glwe_dimension);
    break;
  default:
    PANIC("Cuda error: unsupported polynomial size. Supported "
          "N's are powers of two in the interval [256..16384].")
  }
}

void cuda_modulus_switch_inplace_64_async(void *stream, uint32_t gpu_index,
                                          void *lwe_array_out, uint32_t size,
                                          uint32_t log_modulus) {
  host_modulus_switch_inplace<uint64_t>(
      static_cast<cudaStream_t>(stream), gpu_index,
      static_cast<uint64_t *>(lwe_array_out), size, log_modulus);
}

void cuda_modulus_switch_64_async(void *stream, uint32_t gpu_index,
                                  void *lwe_out, const void *lwe_in,
                                  uint32_t size, uint32_t log_modulus) {
  host_modulus_switch<uint64_t>(static_cast<cudaStream_t>(stream), gpu_index,
                                static_cast<uint64_t *>(lwe_out),
                                static_cast<const uint64_t *>(lwe_in), size,
                                log_modulus);
}

void cuda_centered_modulus_switch_64_async(void *stream, uint32_t gpu_index,
                                           void *lwe_out, const void *lwe_in,
                                           uint32_t lwe_dimension,
                                           uint32_t log_modulus) {
  host_centered_modulus_switch_inplace<uint64_t>(
      static_cast<cudaStream_t>(stream), gpu_index,
      static_cast<uint64_t *>(lwe_out), static_cast<const uint64_t *>(lwe_in),
      lwe_dimension, log_modulus);
}

void cuda_glwe_sample_extract_128_async(
    void *stream, uint32_t gpu_index, void *lwe_array_out,
    void const *glwe_array_in, uint32_t const *nth_array, uint32_t num_nths,
    uint32_t num_lwes_to_extract_per_glwe, uint32_t num_lwes_stored_per_glwe,
    uint32_t glwe_dimension, uint32_t polynomial_size) {

  switch (polynomial_size) {
  case 256:
    host_sample_extract<__uint128_t, AmortizedDegree<256>>(
        static_cast<cudaStream_t>(stream), gpu_index,
        (__uint128_t *)lwe_array_out, (__uint128_t const *)glwe_array_in,
        (uint32_t const *)nth_array, num_nths, num_lwes_to_extract_per_glwe,
        num_lwes_stored_per_glwe, glwe_dimension);
    break;
  case 512:
    host_sample_extract<__uint128_t, AmortizedDegree<512>>(
        static_cast<cudaStream_t>(stream), gpu_index,
        (__uint128_t *)lwe_array_out, (__uint128_t const *)glwe_array_in,
        (uint32_t const *)nth_array, num_nths, num_lwes_to_extract_per_glwe,
        num_lwes_stored_per_glwe, glwe_dimension);
    break;
  case 1024:
    host_sample_extract<__uint128_t, AmortizedDegree<1024>>(
        static_cast<cudaStream_t>(stream), gpu_index,
        (__uint128_t *)lwe_array_out, (__uint128_t const *)glwe_array_in,
        (uint32_t const *)nth_array, num_nths, num_lwes_to_extract_per_glwe,
        num_lwes_stored_per_glwe, glwe_dimension);
    break;
  case 2048:
    host_sample_extract<__uint128_t, AmortizedDegree<2048>>(
        static_cast<cudaStream_t>(stream), gpu_index,
        (__uint128_t *)lwe_array_out, (__uint128_t const *)glwe_array_in,
        (uint32_t const *)nth_array, num_nths, num_lwes_to_extract_per_glwe,
        num_lwes_stored_per_glwe, glwe_dimension);
    break;
  case 4096:
    host_sample_extract<__uint128_t, AmortizedDegree<4096>>(
        static_cast<cudaStream_t>(stream), gpu_index,
        (__uint128_t *)lwe_array_out, (__uint128_t const *)glwe_array_in,
        (uint32_t const *)nth_array, num_nths, num_lwes_to_extract_per_glwe,
        num_lwes_stored_per_glwe, glwe_dimension);
    break;
  default:
    PANIC("Cuda error: unsupported polynomial size. Supported "
          "N's are powers of two in the interval [256..4096].")
  }
}
