#include "integer/comparison.cuh"

uint64_t scratch_cuda_integer_radix_comparison_kb_64(
    void *const *streams, uint32_t const *gpu_indexes, uint32_t gpu_count,
    int8_t **mem_ptr, uint32_t glwe_dimension, uint32_t polynomial_size,
    uint32_t big_lwe_dimension, uint32_t small_lwe_dimension, uint32_t ks_level,
    uint32_t ks_base_log, uint32_t pbs_level, uint32_t pbs_base_log,
    uint32_t grouping_factor, uint32_t num_radix_blocks,
    uint32_t message_modulus, uint32_t carry_modulus, PBS_TYPE pbs_type,
    COMPARISON_TYPE op_type, bool is_signed, bool allocate_gpu_memory,
    bool allocate_ms_array) {
  PUSH_RANGE("scratch comparison")
  int_radix_params params(pbs_type, glwe_dimension, polynomial_size,
                          big_lwe_dimension, small_lwe_dimension, ks_level,
                          ks_base_log, pbs_level, pbs_base_log, grouping_factor,
                          message_modulus, carry_modulus, allocate_ms_array);

  uint64_t size_tracker = 0;
  switch (op_type) {
  case EQ:
  case NE:
    size_tracker += scratch_cuda_integer_radix_comparison_check_kb<uint64_t>(
        (cudaStream_t *)(streams), gpu_indexes, gpu_count,
        (int_comparison_buffer<uint64_t> **)mem_ptr, num_radix_blocks, params,
        op_type, false, allocate_gpu_memory);
    break;
  case GT:
  case GE:
  case LT:
  case LE:
  case MAX:
  case MIN:
    size_tracker += scratch_cuda_integer_radix_comparison_check_kb<uint64_t>(
        (cudaStream_t *)(streams), gpu_indexes, gpu_count,
        (int_comparison_buffer<uint64_t> **)mem_ptr, num_radix_blocks, params,
        op_type, is_signed, allocate_gpu_memory);
    break;
  }
  POP_RANGE()
  return size_tracker;
}

void cuda_comparison_integer_radix_ciphertext_kb_64(
    void *const *streams, uint32_t const *gpu_indexes, uint32_t gpu_count,
    CudaRadixCiphertextFFI *lwe_array_out,
    CudaRadixCiphertextFFI const *lwe_array_1,
    CudaRadixCiphertextFFI const *lwe_array_2, int8_t *mem_ptr,
    void *const *bsks, void *const *ksks,
    CudaModulusSwitchNoiseReductionKeyFFI const *ms_noise_reduction_key) {
  PUSH_RANGE("comparison")
  if (lwe_array_1->num_radix_blocks != lwe_array_2->num_radix_blocks)
    PANIC("Cuda error: input num radix blocks must be the same")
  // The output ciphertext might be a boolean block or a radix ciphertext
  // depending on the case (eq/gt vs max/min) so the amount of blocks to
  // consider for calculation is the one of the input
  auto num_radix_blocks = lwe_array_1->num_radix_blocks;
  int_comparison_buffer<uint64_t> *buffer =
      (int_comparison_buffer<uint64_t> *)mem_ptr;
  switch (buffer->op) {
  case EQ:
  case NE:
    host_integer_radix_equality_check_kb<uint64_t>(
        (cudaStream_t *)(streams), gpu_indexes, gpu_count, lwe_array_out,
        lwe_array_1, lwe_array_2, buffer, bsks, (uint64_t **)(ksks),
        ms_noise_reduction_key, num_radix_blocks);
    break;
  case GT:
  case GE:
  case LT:
  case LE:
    if (num_radix_blocks % 2 != 0)
      PANIC("Cuda error (comparisons): the number of radix blocks has to be "
            "even.")
    host_integer_radix_difference_check_kb<uint64_t>(
        (cudaStream_t *)(streams), gpu_indexes, gpu_count, lwe_array_out,
        lwe_array_1, lwe_array_2, buffer, buffer->diff_buffer->operator_f, bsks,
        (uint64_t **)(ksks), ms_noise_reduction_key, num_radix_blocks);
    break;
  case MAX:
  case MIN:
    if (num_radix_blocks % 2 != 0)
      PANIC("Cuda error (max/min): the number of radix blocks has to be even.")
    host_integer_radix_maxmin_kb<uint64_t>(
        (cudaStream_t *)(streams), gpu_indexes, gpu_count, lwe_array_out,
        lwe_array_1, lwe_array_2, buffer, bsks, (uint64_t **)(ksks),
        ms_noise_reduction_key, num_radix_blocks);
    break;
  default:
    PANIC("Cuda error: integer operation not supported")
  }
  POP_RANGE()
}

void cleanup_cuda_integer_comparison(void *const *streams,
                                     uint32_t const *gpu_indexes,
                                     uint32_t gpu_count,
                                     int8_t **mem_ptr_void) {
  PUSH_RANGE("cleanup comparison")
  int_comparison_buffer<uint64_t> *mem_ptr =
      (int_comparison_buffer<uint64_t> *)(*mem_ptr_void);
  mem_ptr->release((cudaStream_t *)(streams), gpu_indexes, gpu_count);
  POP_RANGE()
}

uint64_t scratch_cuda_integer_are_all_comparisons_block_true_kb_64(
    void *const *streams, uint32_t const *gpu_indexes, uint32_t gpu_count,
    int8_t **mem_ptr, uint32_t glwe_dimension, uint32_t polynomial_size,
    uint32_t big_lwe_dimension, uint32_t small_lwe_dimension, uint32_t ks_level,
    uint32_t ks_base_log, uint32_t pbs_level, uint32_t pbs_base_log,
    uint32_t grouping_factor, uint32_t num_radix_blocks,
    uint32_t message_modulus, uint32_t carry_modulus, PBS_TYPE pbs_type,
    bool allocate_gpu_memory, bool allocate_ms_array) {

  int_radix_params params(pbs_type, glwe_dimension, polynomial_size,
                          big_lwe_dimension, small_lwe_dimension, ks_level,
                          ks_base_log, pbs_level, pbs_base_log, grouping_factor,
                          message_modulus, carry_modulus, allocate_ms_array);

  return scratch_cuda_integer_radix_comparison_check_kb<uint64_t>(
      (cudaStream_t *)(streams), gpu_indexes, gpu_count,
      (int_comparison_buffer<uint64_t> **)mem_ptr, num_radix_blocks, params, EQ,
      false, allocate_gpu_memory);
}

void cuda_integer_are_all_comparisons_block_true_kb_64(
    void *const *streams, uint32_t const *gpu_indexes, uint32_t gpu_count,
    CudaRadixCiphertextFFI *lwe_array_out,
    CudaRadixCiphertextFFI const *lwe_array_in, int8_t *mem_ptr,
    void *const *bsks, void *const *ksks,
    CudaModulusSwitchNoiseReductionKeyFFI const *ms_noise_reduction_key,
    uint32_t num_radix_blocks) {

  int_comparison_buffer<uint64_t> *buffer =
      (int_comparison_buffer<uint64_t> *)mem_ptr;

  host_integer_are_all_comparisons_block_true_kb<uint64_t>(
      (cudaStream_t *)(streams), gpu_indexes, gpu_count, lwe_array_out,
      lwe_array_in, buffer, bsks, (uint64_t **)(ksks), ms_noise_reduction_key,
      num_radix_blocks);
}

void cleanup_cuda_integer_are_all_comparisons_block_true(
    void *const *streams, uint32_t const *gpu_indexes, uint32_t gpu_count,
    int8_t **mem_ptr_void) {

  int_comparison_buffer<uint64_t> *mem_ptr =
      (int_comparison_buffer<uint64_t> *)(*mem_ptr_void);
  mem_ptr->release((cudaStream_t *)(streams), gpu_indexes, gpu_count);
}

uint64_t scratch_cuda_integer_is_at_least_one_comparisons_block_true_kb_64(
    void *const *streams, uint32_t const *gpu_indexes, uint32_t gpu_count,
    int8_t **mem_ptr, uint32_t glwe_dimension, uint32_t polynomial_size,
    uint32_t big_lwe_dimension, uint32_t small_lwe_dimension, uint32_t ks_level,
    uint32_t ks_base_log, uint32_t pbs_level, uint32_t pbs_base_log,
    uint32_t grouping_factor, uint32_t num_radix_blocks,
    uint32_t message_modulus, uint32_t carry_modulus, PBS_TYPE pbs_type,
    bool allocate_gpu_memory, bool allocate_ms_array) {

  int_radix_params params(pbs_type, glwe_dimension, polynomial_size,
                          big_lwe_dimension, small_lwe_dimension, ks_level,
                          ks_base_log, pbs_level, pbs_base_log, grouping_factor,
                          message_modulus, carry_modulus, allocate_ms_array);

  return scratch_cuda_integer_radix_comparison_check_kb<uint64_t>(
      (cudaStream_t *)(streams), gpu_indexes, gpu_count,
      (int_comparison_buffer<uint64_t> **)mem_ptr, num_radix_blocks, params, EQ,
      false, allocate_gpu_memory);
}

void cuda_integer_is_at_least_one_comparisons_block_true_kb_64(
    void *const *streams, uint32_t const *gpu_indexes, uint32_t gpu_count,
    CudaRadixCiphertextFFI *lwe_array_out,
    CudaRadixCiphertextFFI const *lwe_array_in, int8_t *mem_ptr,
    void *const *bsks, void *const *ksks,
    CudaModulusSwitchNoiseReductionKeyFFI const *ms_noise_reduction_key,
    uint32_t num_radix_blocks) {

  int_comparison_buffer<uint64_t> *buffer =
      (int_comparison_buffer<uint64_t> *)mem_ptr;

  host_integer_is_at_least_one_comparisons_block_true_kb<uint64_t>(
      (cudaStream_t *)(streams), gpu_indexes, gpu_count, lwe_array_out,
      lwe_array_in, buffer, bsks, (uint64_t **)(ksks), ms_noise_reduction_key,
      num_radix_blocks);
}

void cleanup_cuda_integer_is_at_least_one_comparisons_block_true(
    void *const *streams, uint32_t const *gpu_indexes, uint32_t gpu_count,
    int8_t **mem_ptr_void) {

  int_comparison_buffer<uint64_t> *mem_ptr =
      (int_comparison_buffer<uint64_t> *)(*mem_ptr_void);
  mem_ptr->release((cudaStream_t *)(streams), gpu_indexes, gpu_count);
}
