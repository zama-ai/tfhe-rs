#include "integer/multiplication.cuh"

/*
 * when adding chunk_size times terms together, there might be some blocks
 * where addition have not happened or degree is zero, in that case we don't
 * need to apply lookup table, so we find the indexes of the blocks where
 * addition happened and store them inside h_lwe_idx_in, from same block
 * might be extracted message and carry(if it is not the last block), so
 * one block id might have two output id and we store them in h_lwe_idx_out
 * blocks that do not require applying lookup table might be copied on both
 * message and carry side or be replaced with zero ciphertexts, indexes of such
 * blocks are stored inside h_smart_copy_in as input ids and h_smart_copy_out
 * as output ids, -1 value as an input id means that zero ciphertext will be
 * copied on output index.
 */
void generate_ids_update_degrees(int *terms_degree, size_t *h_lwe_idx_in,
                                 size_t *h_lwe_idx_out,
                                 int32_t *h_smart_copy_in,
                                 int32_t *h_smart_copy_out, size_t ch_amount,
                                 uint32_t num_radix, uint32_t num_blocks,
                                 size_t chunk_size, size_t message_max,
                                 size_t &total_count, size_t &message_count,
                                 size_t &carry_count, size_t &sm_copy_count) {
  for (size_t c_id = 0; c_id < ch_amount; c_id++) {
    auto cur_chunk = &terms_degree[c_id * chunk_size * num_blocks];
    for (size_t r_id = 0; r_id < num_blocks; r_id++) {
      size_t new_degree = 0;
      for (size_t chunk_id = 0; chunk_id < chunk_size; chunk_id++) {
        new_degree += cur_chunk[chunk_id * num_blocks + r_id];
      }

      if (new_degree > message_max) {
        h_lwe_idx_in[message_count] = c_id * num_blocks + r_id;
        h_lwe_idx_out[message_count] = c_id * num_blocks + r_id;
        message_count++;
      } else {
        h_smart_copy_in[sm_copy_count] = c_id * num_blocks + r_id;
        h_smart_copy_out[sm_copy_count] = c_id * num_blocks + r_id;
        sm_copy_count++;
      }
    }
  }
  for (size_t i = 0; i < sm_copy_count; i++) {
    h_smart_copy_in[i] = -1;
    h_smart_copy_out[i] = h_smart_copy_out[i] + ch_amount * num_blocks + 1;
  }

  for (size_t i = 0; i < message_count; i++) {
    if (h_lwe_idx_in[i] % num_blocks != num_blocks - 1) {
      h_lwe_idx_in[message_count + carry_count] = h_lwe_idx_in[i];
      h_lwe_idx_out[message_count + carry_count] =
          ch_amount * num_blocks + h_lwe_idx_in[i] + 1;
      carry_count++;
    } else {
      h_smart_copy_in[sm_copy_count] = -1;
      h_smart_copy_out[sm_copy_count] =
          h_lwe_idx_in[i] - (num_blocks - 1) + ch_amount * num_blocks;
      sm_copy_count++;
    }
  }

  total_count = message_count + carry_count;
}
/*
 * This scratch function allocates the necessary amount of data on the GPU for
 * the integer radix multiplication in keyswitch->bootstrap order.
 */
void scratch_cuda_integer_mult_radix_ciphertext_kb_64(
    void *const *streams, uint32_t const *gpu_indexes, uint32_t gpu_count,
    int8_t **mem_ptr, bool const is_boolean_left, bool const is_boolean_right,
    uint32_t message_modulus, uint32_t carry_modulus, uint32_t glwe_dimension,
    uint32_t lwe_dimension, uint32_t polynomial_size, uint32_t pbs_base_log,
    uint32_t pbs_level, uint32_t ks_base_log, uint32_t ks_level,
    uint32_t grouping_factor, uint32_t num_radix_blocks, PBS_TYPE pbs_type,
    bool allocate_gpu_memory) {

  int_radix_params params(pbs_type, glwe_dimension, polynomial_size,
                          polynomial_size * glwe_dimension, lwe_dimension,
                          ks_level, ks_base_log, pbs_level, pbs_base_log,
                          grouping_factor, message_modulus, carry_modulus);

  switch (polynomial_size) {
  case 256:
  case 512:
  case 1024:
  case 2048:
  case 4096:
  case 8192:
  case 16384:
    scratch_cuda_integer_mult_radix_ciphertext_kb<uint64_t>(
        (cudaStream_t const *)(streams), gpu_indexes, gpu_count,
        (int_mul_memory<uint64_t> **)mem_ptr, is_boolean_left, is_boolean_right,
        num_radix_blocks, params, allocate_gpu_memory);
    break;
  default:
    PANIC("Cuda error (integer multiplication): unsupported polynomial size. "
          "Supported N's are powers of two in the interval [256..16384].")
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
 */
void cuda_integer_mult_radix_ciphertext_kb_64(
    void *const *streams, uint32_t const *gpu_indexes, uint32_t gpu_count,
    void *radix_lwe_out, void const *radix_lwe_left, bool const is_bool_left,
    void const *radix_lwe_right, bool const is_bool_right, void *const *bsks,
    void *const *ksks, int8_t *mem_ptr, uint32_t polynomial_size,
    uint32_t num_blocks) {

  switch (polynomial_size) {
  case 256:
    host_integer_mult_radix_kb<uint64_t, AmortizedDegree<256>>(
        (cudaStream_t *)(streams), gpu_indexes, gpu_count,
        static_cast<uint64_t *>(radix_lwe_out),
        static_cast<const uint64_t *>(radix_lwe_left), is_bool_left,
        static_cast<const uint64_t *>(radix_lwe_right), is_bool_right, bsks,
        (uint64_t **)(ksks), (int_mul_memory<uint64_t> *)mem_ptr, num_blocks);
    break;
  case 512:
    host_integer_mult_radix_kb<uint64_t, AmortizedDegree<512>>(
        (cudaStream_t *)(streams), gpu_indexes, gpu_count,
        static_cast<uint64_t *>(radix_lwe_out),
        static_cast<const uint64_t *>(radix_lwe_left), is_bool_left,
        static_cast<const uint64_t *>(radix_lwe_right), is_bool_right, bsks,
        (uint64_t **)(ksks), (int_mul_memory<uint64_t> *)mem_ptr, num_blocks);
    break;
  case 1024:
    host_integer_mult_radix_kb<uint64_t, AmortizedDegree<1024>>(
        (cudaStream_t *)(streams), gpu_indexes, gpu_count,
        static_cast<uint64_t *>(radix_lwe_out),
        static_cast<const uint64_t *>(radix_lwe_left), is_bool_left,
        static_cast<const uint64_t *>(radix_lwe_right), is_bool_right, bsks,
        (uint64_t **)(ksks), (int_mul_memory<uint64_t> *)mem_ptr, num_blocks);
    break;
  case 2048:
    host_integer_mult_radix_kb<uint64_t, AmortizedDegree<2048>>(
        (cudaStream_t *)(streams), gpu_indexes, gpu_count,
        static_cast<uint64_t *>(radix_lwe_out),
        static_cast<const uint64_t *>(radix_lwe_left), is_bool_left,
        static_cast<const uint64_t *>(radix_lwe_right), is_bool_right, bsks,
        (uint64_t **)(ksks), (int_mul_memory<uint64_t> *)mem_ptr, num_blocks);
    break;
  case 4096:
    host_integer_mult_radix_kb<uint64_t, AmortizedDegree<4096>>(
        (cudaStream_t *)(streams), gpu_indexes, gpu_count,
        static_cast<uint64_t *>(radix_lwe_out),
        static_cast<const uint64_t *>(radix_lwe_left), is_bool_left,
        static_cast<const uint64_t *>(radix_lwe_right), is_bool_right, bsks,
        (uint64_t **)(ksks), (int_mul_memory<uint64_t> *)mem_ptr, num_blocks);
    break;
  case 8192:
    host_integer_mult_radix_kb<uint64_t, AmortizedDegree<8192>>(
        (cudaStream_t *)(streams), gpu_indexes, gpu_count,
        static_cast<uint64_t *>(radix_lwe_out),
        static_cast<const uint64_t *>(radix_lwe_left), is_bool_left,
        static_cast<const uint64_t *>(radix_lwe_right), is_bool_right, bsks,
        (uint64_t **)(ksks), (int_mul_memory<uint64_t> *)mem_ptr, num_blocks);
    break;
  case 16384:
    host_integer_mult_radix_kb<uint64_t, AmortizedDegree<16384>>(
        (cudaStream_t *)(streams), gpu_indexes, gpu_count,
        static_cast<uint64_t *>(radix_lwe_out),
        static_cast<const uint64_t *>(radix_lwe_left), is_bool_left,
        static_cast<const uint64_t *>(radix_lwe_right), is_bool_right, bsks,
        (uint64_t **)(ksks), (int_mul_memory<uint64_t> *)mem_ptr, num_blocks);
    break;
  default:
    PANIC("Cuda error (integer multiplication): unsupported polynomial size. "
          "Supported N's are powers of two in the interval [256..16384].")
  }
}

void cleanup_cuda_integer_mult(void *const *streams,
                               uint32_t const *gpu_indexes, uint32_t gpu_count,
                               int8_t **mem_ptr_void) {

  int_mul_memory<uint64_t> *mem_ptr =
      (int_mul_memory<uint64_t> *)(*mem_ptr_void);

  mem_ptr->release((cudaStream_t *)(streams), gpu_indexes, gpu_count);
}

void scratch_cuda_integer_radix_partial_sum_ciphertexts_vec_kb_64(
    void *const *streams, uint32_t const *gpu_indexes, uint32_t gpu_count,
    int8_t **mem_ptr, uint32_t glwe_dimension, uint32_t polynomial_size,
    uint32_t lwe_dimension, uint32_t ks_level, uint32_t ks_base_log,
    uint32_t pbs_level, uint32_t pbs_base_log, uint32_t grouping_factor,
    uint32_t num_blocks_in_radix, uint32_t max_num_radix_in_vec,
    uint32_t message_modulus, uint32_t carry_modulus, PBS_TYPE pbs_type,
    bool allocate_gpu_memory) {

  int_radix_params params(pbs_type, glwe_dimension, polynomial_size,
                          glwe_dimension * polynomial_size, lwe_dimension,
                          ks_level, ks_base_log, pbs_level, pbs_base_log,
                          grouping_factor, message_modulus, carry_modulus);
  scratch_cuda_integer_partial_sum_ciphertexts_vec_kb<uint64_t>(
      (cudaStream_t *)(streams), gpu_indexes, gpu_count,
      (int_sum_ciphertexts_vec_memory<uint64_t> **)mem_ptr, num_blocks_in_radix,
      max_num_radix_in_vec, params, allocate_gpu_memory);
}

void cuda_integer_radix_partial_sum_ciphertexts_vec_kb_64(
    void *const *streams, uint32_t const *gpu_indexes, uint32_t gpu_count,
    void *radix_lwe_out, void *radix_lwe_vec, uint32_t num_radix_in_vec,
    int8_t *mem_ptr, void *const *bsks, void *const *ksks,
    uint32_t num_blocks_in_radix) {

  auto mem = (int_sum_ciphertexts_vec_memory<uint64_t> *)mem_ptr;

  int *terms_degree =
      (int *)malloc(num_blocks_in_radix * num_radix_in_vec * sizeof(int));

  for (int i = 0; i < num_radix_in_vec * num_blocks_in_radix; i++) {
    terms_degree[i] = mem->params.message_modulus - 1;
  }

  switch (mem->params.polynomial_size) {
  case 512:
    host_integer_partial_sum_ciphertexts_vec_kb<uint64_t, AmortizedDegree<512>>(
        (cudaStream_t *)(streams), gpu_indexes, gpu_count,
        static_cast<uint64_t *>(radix_lwe_out),
        static_cast<uint64_t *>(radix_lwe_vec), terms_degree, bsks,
        (uint64_t **)(ksks), mem, num_blocks_in_radix, num_radix_in_vec,
        nullptr);
    break;
  case 1024:
    host_integer_partial_sum_ciphertexts_vec_kb<uint64_t,
                                                AmortizedDegree<1024>>(
        (cudaStream_t *)(streams), gpu_indexes, gpu_count,
        static_cast<uint64_t *>(radix_lwe_out),
        static_cast<uint64_t *>(radix_lwe_vec), terms_degree, bsks,
        (uint64_t **)(ksks), mem, num_blocks_in_radix, num_radix_in_vec,
        nullptr);
    break;
  case 2048:
    host_integer_partial_sum_ciphertexts_vec_kb<uint64_t,
                                                AmortizedDegree<2048>>(
        (cudaStream_t *)(streams), gpu_indexes, gpu_count,
        static_cast<uint64_t *>(radix_lwe_out),
        static_cast<uint64_t *>(radix_lwe_vec), terms_degree, bsks,
        (uint64_t **)(ksks), mem, num_blocks_in_radix, num_radix_in_vec,
        nullptr);
    break;
  case 4096:
    host_integer_partial_sum_ciphertexts_vec_kb<uint64_t,
                                                AmortizedDegree<4096>>(
        (cudaStream_t *)(streams), gpu_indexes, gpu_count,
        static_cast<uint64_t *>(radix_lwe_out),
        static_cast<uint64_t *>(radix_lwe_vec), terms_degree, bsks,
        (uint64_t **)(ksks), mem, num_blocks_in_radix, num_radix_in_vec,
        nullptr);
    break;
  case 8192:
    host_integer_partial_sum_ciphertexts_vec_kb<uint64_t,
                                                AmortizedDegree<8192>>(
        (cudaStream_t *)(streams), gpu_indexes, gpu_count,
        static_cast<uint64_t *>(radix_lwe_out),
        static_cast<uint64_t *>(radix_lwe_vec), terms_degree, bsks,
        (uint64_t **)(ksks), mem, num_blocks_in_radix, num_radix_in_vec,
        nullptr);
    break;
  case 16384:
    host_integer_partial_sum_ciphertexts_vec_kb<uint64_t,
                                                AmortizedDegree<16384>>(
        (cudaStream_t *)(streams), gpu_indexes, gpu_count,
        static_cast<uint64_t *>(radix_lwe_out),
        static_cast<uint64_t *>(radix_lwe_vec), terms_degree, bsks,
        (uint64_t **)(ksks), mem, num_blocks_in_radix, num_radix_in_vec,
        nullptr);
    break;
  default:
    PANIC("Cuda error (integer multiplication): unsupported polynomial size. "
          "Supported N's are powers of two in the interval [256..16384].")
  }

  free(terms_degree);
}

void cleanup_cuda_integer_radix_partial_sum_ciphertexts_vec(
    void *const *streams, uint32_t const *gpu_indexes, uint32_t gpu_count,
    int8_t **mem_ptr_void) {
  int_sum_ciphertexts_vec_memory<uint64_t> *mem_ptr =
      (int_sum_ciphertexts_vec_memory<uint64_t> *)(*mem_ptr_void);

  mem_ptr->release((cudaStream_t *)(streams), gpu_indexes, gpu_count);
}
