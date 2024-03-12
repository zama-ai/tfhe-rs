#include "integer/multiplication.cuh"

/*
 * This scratch function allocates the necessary amount of data on the GPU for
 * the integer radix multiplication in keyswitch->bootstrap order.
 */
void scratch_cuda_integer_mult_radix_ciphertext_kb_64(
    cuda_stream_t *stream, int8_t **mem_ptr, uint32_t message_modulus,
    uint32_t carry_modulus, uint32_t glwe_dimension, uint32_t lwe_dimension,
    uint32_t polynomial_size, uint32_t pbs_base_log, uint32_t pbs_level,
    uint32_t ks_base_log, uint32_t ks_level, uint32_t grouping_factor,
    uint32_t num_radix_blocks, PBS_TYPE pbs_type, uint32_t max_shared_memory,
    bool allocate_gpu_memory) {

  int_radix_params params(pbs_type, glwe_dimension, polynomial_size,
                          polynomial_size, lwe_dimension, ks_level, ks_base_log,
                          pbs_level, pbs_base_log, grouping_factor,
                          message_modulus, carry_modulus);

  switch (polynomial_size) {
  case 2048:
    scratch_cuda_integer_mult_radix_ciphertext_kb<uint64_t>(
        stream, (int_mul_memory<uint64_t> **)mem_ptr, num_radix_blocks, params,
        allocate_gpu_memory);
    break;
  default:
    PANIC("Cuda error (integer multiplication): unsupported polynomial size. "
          "Only N = 2048 is supported")
  }
}

/*
 * Computes a multiplication between two 64 bit radix lwe ciphertexts
 * encrypting integer values. keyswitch -> bootstrap pattern is used, function
 * works for single pair of radix ciphertexts, 'v_stream' can be used for
 * parallelization
 * - 'v_stream' is a void pointer to the Cuda stream to be used in the kernel
 * launch
 * - 'gpu_index' is the index of the GPU to be used in the kernel launch
 * - 'radix_lwe_out' is 64 bit radix big lwe ciphertext, product of
 * multiplication
 * - 'radix_lwe_left' left radix big lwe ciphertext
 * - 'radix_lwe_right' right radix big lwe ciphertext
 * - 'bsk' bootstrapping key in fourier domain
 * - 'ksk' keyswitching key
 * - 'mem_ptr'
 * - 'message_modulus' message_modulus
 * - 'carry_modulus' carry_modulus
 * - 'glwe_dimension' glwe_dimension
 * - 'lwe_dimension' is the dimension of small lwe ciphertext
 * - 'polynomial_size' polynomial size
 * - 'pbs_base_log' base log used in the pbs
 * - 'pbs_level' decomposition level count used in the pbs
 * - 'ks_level' decomposition level count used in the keyswitch
 * - 'num_blocks' is the number of big lwe ciphertext blocks inside radix
 * ciphertext
 * - 'pbs_type' selects which PBS implementation should be used
 * - 'max_shared_memory' maximum shared memory per cuda block
 */
void cuda_integer_mult_radix_ciphertext_kb_64(
    cuda_stream_t *stream, void *radix_lwe_out, void *radix_lwe_left,
    void *radix_lwe_right, void *bsk, void *ksk, int8_t *mem_ptr,
    uint32_t message_modulus, uint32_t carry_modulus, uint32_t glwe_dimension,
    uint32_t lwe_dimension, uint32_t polynomial_size, uint32_t pbs_base_log,
    uint32_t pbs_level, uint32_t ks_base_log, uint32_t ks_level,
    uint32_t grouping_factor, uint32_t num_blocks, PBS_TYPE pbs_type,
    uint32_t max_shared_memory) {

  switch (polynomial_size) {
  case 2048:
    host_integer_mult_radix_kb<uint64_t, int64_t, Degree<2048>>(
        stream, static_cast<uint64_t *>(radix_lwe_out),
        static_cast<uint64_t *>(radix_lwe_left),
        static_cast<uint64_t *>(radix_lwe_right), bsk,
        static_cast<uint64_t *>(ksk), (int_mul_memory<uint64_t> *)mem_ptr,
        num_blocks);
    break;
  default:
    PANIC("Cuda error (integer multiplication): unsupported polynomial size. "
          "Only N = 2048 is supported")
  }
}

void cleanup_cuda_integer_mult(cuda_stream_t *stream, int8_t **mem_ptr_void) {

  int_mul_memory<uint64_t> *mem_ptr =
      (int_mul_memory<uint64_t> *)(*mem_ptr_void);

  mem_ptr->release(stream);
}

void cuda_small_scalar_multiplication_integer_radix_ciphertext_64_inplace(
    cuda_stream_t *stream, void *lwe_array, uint64_t scalar,
    uint32_t lwe_dimension, uint32_t lwe_ciphertext_count) {

  cuda_small_scalar_multiplication_integer_radix_ciphertext_64(
      stream, lwe_array, lwe_array, scalar, lwe_dimension,
      lwe_ciphertext_count);
}

void cuda_small_scalar_multiplication_integer_radix_ciphertext_64(
    cuda_stream_t *stream, void *output_lwe_array, void *input_lwe_array,
    uint64_t scalar, uint32_t lwe_dimension, uint32_t lwe_ciphertext_count) {

  host_integer_small_scalar_mult_radix(
      stream, static_cast<uint64_t *>(output_lwe_array),
      static_cast<uint64_t *>(input_lwe_array), scalar, lwe_dimension,
      lwe_ciphertext_count);
}

void scratch_cuda_integer_radix_sum_ciphertexts_vec_kb_64(
    cuda_stream_t *stream, int8_t **mem_ptr, uint32_t glwe_dimension,
    uint32_t polynomial_size, uint32_t big_lwe_dimension,
    uint32_t small_lwe_dimension, uint32_t ks_level, uint32_t ks_base_log,
    uint32_t pbs_level, uint32_t pbs_base_log, uint32_t grouping_factor,
    uint32_t num_blocks_in_radix, uint32_t max_num_radix_in_vec,
    uint32_t message_modulus, uint32_t carry_modulus, PBS_TYPE pbs_type,
    bool allocate_gpu_memory) {

  int_radix_params params(pbs_type, glwe_dimension, polynomial_size,
                          big_lwe_dimension, small_lwe_dimension, ks_level,
                          ks_base_log, pbs_level, pbs_base_log, grouping_factor,
                          message_modulus, carry_modulus);
  scratch_cuda_integer_sum_ciphertexts_vec_kb<uint64_t>(
      stream, (int_sum_ciphertexts_vec_memory<uint64_t> **)mem_ptr,
      num_blocks_in_radix, max_num_radix_in_vec, params, allocate_gpu_memory);
}

void cuda_integer_radix_sum_ciphertexts_vec_kb_64(
    cuda_stream_t *stream, void *radix_lwe_out, void *radix_lwe_vec,
    uint32_t num_radix_in_vec, int8_t *mem_ptr, void *bsk, void *ksk,
    uint32_t num_blocks_in_radix) {

  auto mem = (int_sum_ciphertexts_vec_memory<uint64_t> *)mem_ptr;

  int *terms_degree =
      (int *)malloc(num_blocks_in_radix * num_radix_in_vec * sizeof(int));

  for (int i = 0; i < num_radix_in_vec * num_blocks_in_radix; i++) {
    terms_degree[i] = mem->params.message_modulus - 1;
  }

  switch (mem->params.polynomial_size) {
  case 512:
    host_integer_sum_ciphertexts_vec_kb<uint64_t, Degree<512>>(
        stream, static_cast<uint64_t *>(radix_lwe_out),
        static_cast<uint64_t *>(radix_lwe_vec), terms_degree, bsk,
        static_cast<uint64_t *>(ksk), mem, num_blocks_in_radix,
        num_radix_in_vec);
    break;
  case 1024:
    host_integer_sum_ciphertexts_vec_kb<uint64_t, Degree<1024>>(
        stream, static_cast<uint64_t *>(radix_lwe_out),
        static_cast<uint64_t *>(radix_lwe_vec), terms_degree, bsk,
        static_cast<uint64_t *>(ksk), mem, num_blocks_in_radix,
        num_radix_in_vec);
    break;
  case 2048:
    host_integer_sum_ciphertexts_vec_kb<uint64_t, Degree<2048>>(
        stream, static_cast<uint64_t *>(radix_lwe_out),
        static_cast<uint64_t *>(radix_lwe_vec), terms_degree, bsk,
        static_cast<uint64_t *>(ksk), mem, num_blocks_in_radix,
        num_radix_in_vec);
    break;
  case 4096:
    host_integer_sum_ciphertexts_vec_kb<uint64_t, Degree<4096>>(
        stream, static_cast<uint64_t *>(radix_lwe_out),
        static_cast<uint64_t *>(radix_lwe_vec), terms_degree, bsk,
        static_cast<uint64_t *>(ksk), mem, num_blocks_in_radix,
        num_radix_in_vec);
    break;
  case 8192:
    host_integer_sum_ciphertexts_vec_kb<uint64_t, Degree<8192>>(
        stream, static_cast<uint64_t *>(radix_lwe_out),
        static_cast<uint64_t *>(radix_lwe_vec), terms_degree, bsk,
        static_cast<uint64_t *>(ksk), mem, num_blocks_in_radix,
        num_radix_in_vec);
    break;
//  case 16384:
//    host_integer_sum_ciphertexts_vec_kb<uint64_t, Degree<16384>>(
//        stream, static_cast<uint64_t *>(radix_lwe_out),
//        static_cast<uint64_t *>(radix_lwe_vec), terms_degree, bsk,
//        static_cast<uint64_t *>(ksk), mem, num_blocks_in_radix,
//        num_radix_in_vec);
//    break;
  default:
    PANIC("Cuda error (integer multiplication): unsupported polynomial size. "
          "Only N = 512, 1024, 2048, 4096, 8192 is supported")
  }

  free(terms_degree);
}

void cleanup_cuda_integer_radix_sum_ciphertexts_vec(cuda_stream_t *stream,
                                                    int8_t **mem_ptr_void) {
  int_sum_ciphertexts_vec_memory<uint64_t> *mem_ptr =
      (int_sum_ciphertexts_vec_memory<uint64_t> *)(*mem_ptr_void);

  mem_ptr->release(stream);
}
