#include "integer/comparison.cuh"

uint64_t scratch_cuda_integer_comparison_64_async(
    CudaStreamsFFI streams, int8_t **mem_ptr, uint32_t glwe_dimension,
    uint32_t polynomial_size, uint32_t big_lwe_dimension,
    uint32_t small_lwe_dimension, uint32_t ks_level, uint32_t ks_base_log,
    uint32_t pbs_level, uint32_t pbs_base_log, uint32_t grouping_factor,
    uint32_t num_radix_blocks, uint32_t message_modulus, uint32_t carry_modulus,
    PBS_TYPE pbs_type, COMPARISON_TYPE op_type, bool is_signed,
    bool allocate_gpu_memory, PBS_MS_REDUCTION_T noise_reduction_type) {
  PUSH_RANGE("scratch comparison")
  int_radix_params params(pbs_type, glwe_dimension, polynomial_size,
                          big_lwe_dimension, small_lwe_dimension, ks_level,
                          ks_base_log, pbs_level, pbs_base_log, grouping_factor,
                          message_modulus, carry_modulus, noise_reduction_type);

  uint64_t size_tracker = 0;
  switch (op_type) {
  case EQ:
  case NE:
    size_tracker += scratch_cuda_comparison_check<uint64_t>(
        CudaStreams(streams), (int_comparison_buffer<uint64_t> **)mem_ptr,
        num_radix_blocks, params, op_type, false, allocate_gpu_memory);
    break;
  case GT:
  case GE:
  case LT:
  case LE:
  case MAX:
  case MIN:
    size_tracker += scratch_cuda_comparison_check<uint64_t>(
        CudaStreams(streams), (int_comparison_buffer<uint64_t> **)mem_ptr,
        num_radix_blocks, params, op_type, is_signed, allocate_gpu_memory);
    break;
  }
  POP_RANGE()
  return size_tracker;
}

uint64_t scratch_cuda_integer_scalar_comparison_64_async(
    CudaStreamsFFI streams, int8_t **mem_ptr, uint32_t glwe_dimension,
    uint32_t polynomial_size, uint32_t big_lwe_dimension,
    uint32_t small_lwe_dimension, uint32_t ks_level, uint32_t ks_base_log,
    uint32_t pbs_level, uint32_t pbs_base_log, uint32_t grouping_factor,
    uint32_t num_radix_blocks, uint32_t message_modulus, uint32_t carry_modulus,
    PBS_TYPE pbs_type, COMPARISON_TYPE op_type, bool is_signed,
    bool allocate_gpu_memory, PBS_MS_REDUCTION_T noise_reduction_type) {
  PUSH_RANGE("scratch scalar comparison")
  int_radix_params params(pbs_type, glwe_dimension, polynomial_size,
                          big_lwe_dimension, small_lwe_dimension, ks_level,
                          ks_base_log, pbs_level, pbs_base_log, grouping_factor,
                          message_modulus, carry_modulus, noise_reduction_type);

  uint64_t size_tracker = 0;
  switch (op_type) {
  case EQ:
  case NE:
    size_tracker += scratch_cuda_comparison_check<uint64_t>(
        CudaStreams(streams), (int_comparison_buffer<uint64_t> **)mem_ptr,
        num_radix_blocks, params, op_type, false, allocate_gpu_memory);
    break;
  case GT:
  case GE:
  case LT:
  case LE:
  case MAX:
  case MIN:
    size_tracker += scratch_cuda_comparison_check<uint64_t>(
        CudaStreams(streams), (int_comparison_buffer<uint64_t> **)mem_ptr,
        num_radix_blocks, params, op_type, is_signed, allocate_gpu_memory);
    break;
  }
  POP_RANGE()
  return size_tracker;
}

void cuda_integer_comparison_64_async(CudaStreamsFFI streams,
                                      CudaRadixCiphertextFFI *lwe_array_out,
                                      CudaRadixCiphertextFFI const *lwe_array_1,
                                      CudaRadixCiphertextFFI const *lwe_array_2,
                                      int8_t *mem_ptr, void *const *bsks,
                                      void *const *ksks) {
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
    host_equality_check<uint64_t>(CudaStreams(streams), lwe_array_out,
                                  lwe_array_1, lwe_array_2, buffer, bsks,
                                  (uint64_t **)(ksks), num_radix_blocks);
    break;
  case GT:
  case GE:
  case LT:
  case LE:
    if (num_radix_blocks % 2 != 0)
      PANIC("Cuda error (comparisons): the number of radix blocks has to be "
            "even.")
    host_difference_check<uint64_t>(CudaStreams(streams), lwe_array_out,
                                    lwe_array_1, lwe_array_2, buffer,
                                    buffer->diff_buffer->operator_f, bsks,
                                    (uint64_t **)(ksks), num_radix_blocks);
    break;
  case MAX:
  case MIN:
    if (num_radix_blocks % 2 != 0)
      PANIC("Cuda error (max/min): the number of radix blocks has to be even.")
    host_maxmin<uint64_t>(CudaStreams(streams), lwe_array_out, lwe_array_1,
                          lwe_array_2, buffer, bsks, (uint64_t **)(ksks),
                          num_radix_blocks);
    break;
  default:
    PANIC("Cuda error: integer operation not supported")
  }
  POP_RANGE()
}

void cleanup_cuda_integer_comparison_64(CudaStreamsFFI streams,
                                        int8_t **mem_ptr_void) {
  PUSH_RANGE("cleanup comparison")
  int_comparison_buffer<uint64_t> *mem_ptr =
      (int_comparison_buffer<uint64_t> *)(*mem_ptr_void);
  mem_ptr->release(CudaStreams(streams));
  delete mem_ptr;
  *mem_ptr_void = nullptr;
  POP_RANGE()
}

void cleanup_cuda_integer_scalar_comparison_64(CudaStreamsFFI streams,
                                               int8_t **mem_ptr_void) {
  PUSH_RANGE("cleanup scalar comparison")
  int_comparison_buffer<uint64_t> *mem_ptr =
      (int_comparison_buffer<uint64_t> *)(*mem_ptr_void);
  mem_ptr->release(CudaStreams(streams));
  delete mem_ptr;
  *mem_ptr_void = nullptr;
  POP_RANGE()
}

uint64_t scratch_cuda_integer_are_all_comparisons_block_true_64_async(
    CudaStreamsFFI streams, int8_t **mem_ptr, uint32_t glwe_dimension,
    uint32_t polynomial_size, uint32_t big_lwe_dimension,
    uint32_t small_lwe_dimension, uint32_t ks_level, uint32_t ks_base_log,
    uint32_t pbs_level, uint32_t pbs_base_log, uint32_t grouping_factor,
    uint32_t num_radix_blocks, uint32_t message_modulus, uint32_t carry_modulus,
    PBS_TYPE pbs_type, bool allocate_gpu_memory,
    PBS_MS_REDUCTION_T noise_reduction_type) {

  int_radix_params params(pbs_type, glwe_dimension, polynomial_size,
                          big_lwe_dimension, small_lwe_dimension, ks_level,
                          ks_base_log, pbs_level, pbs_base_log, grouping_factor,
                          message_modulus, carry_modulus, noise_reduction_type);

  return scratch_cuda_comparison_check<uint64_t>(
      CudaStreams(streams), (int_comparison_buffer<uint64_t> **)mem_ptr,
      num_radix_blocks, params, EQ, false, allocate_gpu_memory);
}

void cuda_integer_are_all_comparisons_block_true_64_async(
    CudaStreamsFFI streams, CudaRadixCiphertextFFI *lwe_array_out,
    CudaRadixCiphertextFFI const *lwe_array_in, int8_t *mem_ptr,
    void *const *bsks, void *const *ksks, uint32_t num_radix_blocks) {

  int_comparison_buffer<uint64_t> *buffer =
      (int_comparison_buffer<uint64_t> *)mem_ptr;

  host_integer_are_all_comparisons_block_true<uint64_t>(
      CudaStreams(streams), lwe_array_out, lwe_array_in, buffer, bsks,
      (uint64_t **)(ksks), num_radix_blocks);
}

void cleanup_cuda_integer_are_all_comparisons_block_true_64(
    CudaStreamsFFI streams, int8_t **mem_ptr_void) {

  int_comparison_buffer<uint64_t> *mem_ptr =
      (int_comparison_buffer<uint64_t> *)(*mem_ptr_void);
  mem_ptr->release(CudaStreams(streams));
  delete mem_ptr;
  *mem_ptr_void = nullptr;
}

uint64_t scratch_cuda_integer_is_at_least_one_comparisons_block_true_64_async(
    CudaStreamsFFI streams, int8_t **mem_ptr, uint32_t glwe_dimension,
    uint32_t polynomial_size, uint32_t big_lwe_dimension,
    uint32_t small_lwe_dimension, uint32_t ks_level, uint32_t ks_base_log,
    uint32_t pbs_level, uint32_t pbs_base_log, uint32_t grouping_factor,
    uint32_t num_radix_blocks, uint32_t message_modulus, uint32_t carry_modulus,
    PBS_TYPE pbs_type, bool allocate_gpu_memory,
    PBS_MS_REDUCTION_T noise_reduction_type) {

  int_radix_params params(pbs_type, glwe_dimension, polynomial_size,
                          big_lwe_dimension, small_lwe_dimension, ks_level,
                          ks_base_log, pbs_level, pbs_base_log, grouping_factor,
                          message_modulus, carry_modulus, noise_reduction_type);

  return scratch_cuda_comparison_check<uint64_t>(
      CudaStreams(streams), (int_comparison_buffer<uint64_t> **)mem_ptr,
      num_radix_blocks, params, EQ, false, allocate_gpu_memory);
}

void cuda_integer_is_at_least_one_comparisons_block_true_64_async(
    CudaStreamsFFI streams, CudaRadixCiphertextFFI *lwe_array_out,
    CudaRadixCiphertextFFI const *lwe_array_in, int8_t *mem_ptr,
    void *const *bsks, void *const *ksks, uint32_t num_radix_blocks) {

  int_comparison_buffer<uint64_t> *buffer =
      (int_comparison_buffer<uint64_t> *)mem_ptr;

  host_integer_is_at_least_one_comparisons_block_true<uint64_t>(
      CudaStreams(streams), lwe_array_out, lwe_array_in, buffer, bsks,
      (uint64_t **)(ksks), num_radix_blocks);
}

void cleanup_cuda_integer_is_at_least_one_comparisons_block_true_64(
    CudaStreamsFFI streams, int8_t **mem_ptr_void) {

  int_comparison_buffer<uint64_t> *mem_ptr =
      (int_comparison_buffer<uint64_t> *)(*mem_ptr_void);
  mem_ptr->release(CudaStreams(streams));
  delete mem_ptr;
  *mem_ptr_void = nullptr;
}
