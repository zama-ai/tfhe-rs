#include "integer/scalar_mul.cuh"

void scratch_cuda_integer_scalar_mul_kb_64(
    cuda_stream_t *stream, int8_t **mem_ptr, uint32_t glwe_dimension,
    uint32_t polynomial_size, uint32_t lwe_dimension, uint32_t ks_level,
    uint32_t ks_base_log, uint32_t pbs_level, uint32_t pbs_base_log,
    uint32_t grouping_factor, uint32_t num_blocks, uint32_t message_modulus,
    uint32_t carry_modulus, PBS_TYPE pbs_type, bool allocate_gpu_memory) {

  int_radix_params params(pbs_type, glwe_dimension, polynomial_size,
                          glwe_dimension * polynomial_size, lwe_dimension,
                          ks_level, ks_base_log, pbs_level, pbs_base_log,
                          grouping_factor, message_modulus, carry_modulus);

  scratch_cuda_integer_radix_scalar_mul_kb<uint64_t>(
      stream, (int_scalar_mul_buffer<uint64_t> **)mem_ptr, num_blocks, params,
      allocate_gpu_memory);
}

void cuda_scalar_multiplication_integer_radix_ciphertext_64_inplace(
    cuda_stream_t *stream, void *lwe_array, uint64_t *decomposed_scalar,
    uint64_t *has_at_least_one_set, int8_t *mem, void *bsk, void *ksk,
    uint32_t lwe_dimension, uint32_t polynomial_size, uint32_t message_modulus,
    uint32_t num_blocks, uint32_t num_scalars) {

  switch (polynomial_size) {
  case 512:
    host_integer_scalar_mul_radix<uint64_t, AmortizedDegree<512>>(
        stream, static_cast<uint64_t *>(lwe_array), decomposed_scalar,
        has_at_least_one_set,
        reinterpret_cast<int_scalar_mul_buffer<uint64_t> *>(mem), bsk,
        static_cast<uint64_t *>(ksk), lwe_dimension, message_modulus,
        num_blocks, num_scalars);
    break;
  case 1024:
    host_integer_scalar_mul_radix<uint64_t, AmortizedDegree<1024>>(
        stream, static_cast<uint64_t *>(lwe_array), decomposed_scalar,
        has_at_least_one_set,
        reinterpret_cast<int_scalar_mul_buffer<uint64_t> *>(mem), bsk,
        static_cast<uint64_t *>(ksk), lwe_dimension, message_modulus,
        num_blocks, num_scalars);
    break;
  case 2048:
    host_integer_scalar_mul_radix<uint64_t, AmortizedDegree<2048>>(
        stream, static_cast<uint64_t *>(lwe_array), decomposed_scalar,
        has_at_least_one_set,
        reinterpret_cast<int_scalar_mul_buffer<uint64_t> *>(mem), bsk,
        static_cast<uint64_t *>(ksk), lwe_dimension, message_modulus,
        num_blocks, num_scalars);
    break;
  case 4096:
    host_integer_scalar_mul_radix<uint64_t, AmortizedDegree<4096>>(
        stream, static_cast<uint64_t *>(lwe_array), decomposed_scalar,
        has_at_least_one_set,
        reinterpret_cast<int_scalar_mul_buffer<uint64_t> *>(mem), bsk,
        static_cast<uint64_t *>(ksk), lwe_dimension, message_modulus,
        num_blocks, num_scalars);
    break;
  case 8192:
    host_integer_scalar_mul_radix<uint64_t, AmortizedDegree<8192>>(
        stream, static_cast<uint64_t *>(lwe_array), decomposed_scalar,
        has_at_least_one_set,
        reinterpret_cast<int_scalar_mul_buffer<uint64_t> *>(mem), bsk,
        static_cast<uint64_t *>(ksk), lwe_dimension, message_modulus,
        num_blocks, num_scalars);
    break;
  case 16384:
    host_integer_scalar_mul_radix<uint64_t, AmortizedDegree<16384>>(
        stream, static_cast<uint64_t *>(lwe_array), decomposed_scalar,
        has_at_least_one_set,
        reinterpret_cast<int_scalar_mul_buffer<uint64_t> *>(mem), bsk,
        static_cast<uint64_t *>(ksk), lwe_dimension, message_modulus,
        num_blocks, num_scalars);
    break;
  default:
    PANIC("Cuda error (scalar multiplication): unsupported polynomial size. "
          "Only N = 512, 1024, 2048, 4096, 8192, 16384 are supported.")
  }
}

void cleanup_cuda_integer_radix_scalar_mul(cuda_stream_t *stream,
                                           int8_t **mem_ptr_void) {

  cudaSetDevice(stream->gpu_index);
  int_scalar_mul_buffer<uint64_t> *mem_ptr =
      (int_scalar_mul_buffer<uint64_t> *)(*mem_ptr_void);

  mem_ptr->release(stream);
}
