#include "scalar_shifts.cuh"

void scratch_cuda_integer_radix_logical_scalar_shift_kb_64(
    void *const *streams, uint32_t const *gpu_indexes, uint32_t gpu_count,
    int8_t **mem_ptr, uint32_t glwe_dimension, uint32_t polynomial_size,
    uint32_t big_lwe_dimension, uint32_t small_lwe_dimension, uint32_t ks_level,
    uint32_t ks_base_log, uint32_t pbs_level, uint32_t pbs_base_log,
    uint32_t grouping_factor, uint32_t num_blocks, uint32_t message_modulus,
    uint32_t carry_modulus, PBS_TYPE pbs_type, SHIFT_OR_ROTATE_TYPE shift_type,
    bool allocate_gpu_memory) {

  int_radix_params params(pbs_type, glwe_dimension, polynomial_size,
                          big_lwe_dimension, small_lwe_dimension, ks_level,
                          ks_base_log, pbs_level, pbs_base_log, grouping_factor,
                          message_modulus, carry_modulus);

  scratch_cuda_integer_radix_logical_scalar_shift_kb<uint64_t>(
      (cudaStream_t *)(streams), gpu_indexes, gpu_count,
      (int_logical_scalar_shift_buffer<uint64_t> **)mem_ptr, num_blocks, params,
      shift_type, allocate_gpu_memory);
}

/// The logical scalar shift is the one used for unsigned integers, and
/// for the left scalar shift. It is constituted of a rotation, followed by
/// the application of a PBS onto the rotated blocks up to num_blocks -
/// rotations - 1 The remaining blocks are padded with zeros
void cuda_integer_radix_logical_scalar_shift_kb_64_inplace(
    void *const *streams, uint32_t const *gpu_indexes, uint32_t gpu_count,
    void *lwe_array, uint32_t shift, int8_t *mem_ptr, void *const *bsks,
    void *const *ksks, uint32_t num_blocks) {

  host_integer_radix_logical_scalar_shift_kb_inplace<uint64_t>(
      (cudaStream_t *)(streams), gpu_indexes, gpu_count,
      static_cast<uint64_t *>(lwe_array), shift,
      (int_logical_scalar_shift_buffer<uint64_t> *)mem_ptr, bsks,
      (uint64_t **)(ksks), num_blocks);
}

void scratch_cuda_integer_radix_arithmetic_scalar_shift_kb_64(
    void *const *streams, uint32_t const *gpu_indexes, uint32_t gpu_count,
    int8_t **mem_ptr, uint32_t glwe_dimension, uint32_t polynomial_size,
    uint32_t big_lwe_dimension, uint32_t small_lwe_dimension, uint32_t ks_level,
    uint32_t ks_base_log, uint32_t pbs_level, uint32_t pbs_base_log,
    uint32_t grouping_factor, uint32_t num_blocks, uint32_t message_modulus,
    uint32_t carry_modulus, PBS_TYPE pbs_type, SHIFT_OR_ROTATE_TYPE shift_type,
    bool allocate_gpu_memory) {

  int_radix_params params(pbs_type, glwe_dimension, polynomial_size,
                          big_lwe_dimension, small_lwe_dimension, ks_level,
                          ks_base_log, pbs_level, pbs_base_log, grouping_factor,
                          message_modulus, carry_modulus);

  scratch_cuda_integer_radix_arithmetic_scalar_shift_kb<uint64_t>(
      (cudaStream_t *)(streams), gpu_indexes, gpu_count,
      (int_arithmetic_scalar_shift_buffer<uint64_t> **)mem_ptr, num_blocks,
      params, shift_type, allocate_gpu_memory);
}

/// The arithmetic scalar shift is the one used for the signed right shift.
/// It is constituted of a rotation, followed by
/// the application of a PBS onto the rotated blocks up to num_blocks -
/// rotations - 2 The last rotated block has another PBS applied, as it is the
/// sign block, and a second PBS is also applied to it to compute the padding
/// block, which is copied onto all remaining blocks instead of padding with
/// zeros as would be done in the logical shift.
void cuda_integer_radix_arithmetic_scalar_shift_kb_64_inplace(
    void *const *streams, uint32_t const *gpu_indexes, uint32_t gpu_count,
    void *lwe_array, uint32_t shift, int8_t *mem_ptr, void *const *bsks,
    void *const *ksks, uint32_t num_blocks) {

  host_integer_radix_arithmetic_scalar_shift_kb_inplace<uint64_t>(
      (cudaStream_t *)(streams), gpu_indexes, gpu_count,
      static_cast<uint64_t *>(lwe_array), shift,
      (int_arithmetic_scalar_shift_buffer<uint64_t> *)mem_ptr, bsks,
      (uint64_t **)(ksks), num_blocks);
}

void cleanup_cuda_integer_radix_logical_scalar_shift(
    void *const *streams, uint32_t const *gpu_indexes, uint32_t gpu_count,
    int8_t **mem_ptr_void) {

  int_logical_scalar_shift_buffer<uint64_t> *mem_ptr =
      (int_logical_scalar_shift_buffer<uint64_t> *)(*mem_ptr_void);

  mem_ptr->release((cudaStream_t *)(streams), gpu_indexes, gpu_count);
}

void cleanup_cuda_integer_radix_arithmetic_scalar_shift(
    void *const *streams, uint32_t const *gpu_indexes, uint32_t gpu_count,
    int8_t **mem_ptr_void) {

  int_arithmetic_scalar_shift_buffer<uint64_t> *mem_ptr =
      (int_arithmetic_scalar_shift_buffer<uint64_t> *)(*mem_ptr_void);

  mem_ptr->release((cudaStream_t *)(streams), gpu_indexes, gpu_count);
}
