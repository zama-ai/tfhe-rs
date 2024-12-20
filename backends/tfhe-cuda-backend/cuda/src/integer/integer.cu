#include "integer/integer.cuh"
#include "integer/negation.cuh"
#include <linear_algebra.h>

void cuda_full_propagation_64_inplace(void *const *streams,
                                      uint32_t const *gpu_indexes,
                                      uint32_t gpu_count, void *input_blocks,
                                      int8_t *mem_ptr, void *const *ksks,
                                      void *const *bsks, uint32_t num_blocks) {

  int_fullprop_buffer<uint64_t> *buffer =
      (int_fullprop_buffer<uint64_t> *)mem_ptr;

  host_full_propagate_inplace<uint64_t>(
      (cudaStream_t *)(streams), gpu_indexes, gpu_count,
      static_cast<uint64_t *>(input_blocks), buffer, (uint64_t **)(ksks), bsks,
      num_blocks);
}

void scratch_cuda_full_propagation_64(
    void *const *streams, uint32_t const *gpu_indexes, uint32_t gpu_count,
    int8_t **mem_ptr, uint32_t lwe_dimension, uint32_t glwe_dimension,
    uint32_t polynomial_size, uint32_t ks_level, uint32_t ks_base_log,
    uint32_t pbs_level, uint32_t pbs_base_log, uint32_t grouping_factor,
    uint32_t message_modulus, uint32_t carry_modulus, PBS_TYPE pbs_type,
    bool allocate_gpu_memory) {
  int_radix_params params(pbs_type, glwe_dimension, polynomial_size,
                          glwe_dimension * polynomial_size, lwe_dimension,
                          ks_level, ks_base_log, pbs_level, pbs_base_log,
                          grouping_factor, message_modulus, carry_modulus);

  scratch_cuda_full_propagation<uint64_t>(
      (cudaStream_t *)streams, gpu_indexes, gpu_count,
      (int_fullprop_buffer<uint64_t> **)mem_ptr, params, allocate_gpu_memory);
}

void cleanup_cuda_full_propagation(void *const *streams,
                                   uint32_t const *gpu_indexes,
                                   uint32_t gpu_count, int8_t **mem_ptr_void) {

  int_fullprop_buffer<uint64_t> *mem_ptr =
      (int_fullprop_buffer<uint64_t> *)(*mem_ptr_void);

  mem_ptr->release((cudaStream_t *)(streams), gpu_indexes, gpu_count);
}

void scratch_cuda_propagate_single_carry_kb_64_inplace(
    void *const *streams, uint32_t const *gpu_indexes, uint32_t gpu_count,
    int8_t **mem_ptr, uint32_t glwe_dimension, uint32_t polynomial_size,
    uint32_t big_lwe_dimension, uint32_t small_lwe_dimension, uint32_t ks_level,
    uint32_t ks_base_log, uint32_t pbs_level, uint32_t pbs_base_log,
    uint32_t grouping_factor, uint32_t num_blocks, uint32_t message_modulus,
    uint32_t carry_modulus, PBS_TYPE pbs_type, uint32_t requested_flag,
    uint32_t uses_carry, bool allocate_gpu_memory) {

  int_radix_params params(pbs_type, glwe_dimension, polynomial_size,
                          big_lwe_dimension, small_lwe_dimension, ks_level,
                          ks_base_log, pbs_level, pbs_base_log, grouping_factor,
                          message_modulus, carry_modulus);

  scratch_cuda_propagate_single_carry_kb_inplace<uint64_t>(
      (cudaStream_t *)(streams), gpu_indexes, gpu_count,
      (int_sc_prop_memory<uint64_t> **)mem_ptr, num_blocks, params,
      requested_flag, uses_carry, allocate_gpu_memory);
}

void scratch_cuda_add_and_propagate_single_carry_kb_64_inplace(
    void *const *streams, uint32_t const *gpu_indexes, uint32_t gpu_count,
    int8_t **mem_ptr, uint32_t glwe_dimension, uint32_t polynomial_size,
    uint32_t big_lwe_dimension, uint32_t small_lwe_dimension, uint32_t ks_level,
    uint32_t ks_base_log, uint32_t pbs_level, uint32_t pbs_base_log,
    uint32_t grouping_factor, uint32_t num_blocks, uint32_t message_modulus,
    uint32_t carry_modulus, PBS_TYPE pbs_type, uint32_t requested_flag,
    uint32_t uses_carry, bool allocate_gpu_memory) {

  int_radix_params params(pbs_type, glwe_dimension, polynomial_size,
                          big_lwe_dimension, small_lwe_dimension, ks_level,
                          ks_base_log, pbs_level, pbs_base_log, grouping_factor,
                          message_modulus, carry_modulus);

  scratch_cuda_propagate_single_carry_kb_inplace<uint64_t>(
      (cudaStream_t *)(streams), gpu_indexes, gpu_count,
      (int_sc_prop_memory<uint64_t> **)mem_ptr, num_blocks, params,
      requested_flag, uses_carry, allocate_gpu_memory);
}

void scratch_cuda_integer_overflowing_sub_kb_64_inplace(
    void *const *streams, uint32_t const *gpu_indexes, uint32_t gpu_count,
    int8_t **mem_ptr, uint32_t glwe_dimension, uint32_t polynomial_size,
    uint32_t big_lwe_dimension, uint32_t small_lwe_dimension, uint32_t ks_level,
    uint32_t ks_base_log, uint32_t pbs_level, uint32_t pbs_base_log,
    uint32_t grouping_factor, uint32_t num_blocks, uint32_t message_modulus,
    uint32_t carry_modulus, PBS_TYPE pbs_type, uint32_t compute_overflow,
    bool allocate_gpu_memory) {

  int_radix_params params(pbs_type, glwe_dimension, polynomial_size,
                          big_lwe_dimension, small_lwe_dimension, ks_level,
                          ks_base_log, pbs_level, pbs_base_log, grouping_factor,
                          message_modulus, carry_modulus);

  scratch_cuda_integer_overflowing_sub<uint64_t>(
      (cudaStream_t *)(streams), gpu_indexes, gpu_count,
      (int_borrow_prop_memory<uint64_t> **)mem_ptr, num_blocks, params,
      compute_overflow, allocate_gpu_memory);
}

void cuda_propagate_single_carry_kb_64_inplace(
    void *const *streams, uint32_t const *gpu_indexes, uint32_t gpu_count,
    void *lwe_array, void *carry_out, const void *carry_in, int8_t *mem_ptr,
    void *const *bsks, void *const *ksks, uint32_t num_blocks,
    uint32_t requested_flag, uint32_t uses_carry) {

  host_propagate_single_carry<uint64_t>(
      (cudaStream_t *)(streams), gpu_indexes, gpu_count,
      static_cast<uint64_t *>(lwe_array), static_cast<uint64_t *>(carry_out),
      static_cast<const uint64_t *>(carry_in),
      (int_sc_prop_memory<uint64_t> *)mem_ptr, bsks, (uint64_t **)(ksks),
      num_blocks, requested_flag, uses_carry);
}

void cuda_add_and_propagate_single_carry_kb_64_inplace(
    void *const *streams, uint32_t const *gpu_indexes, uint32_t gpu_count,
    void *lhs_array, const void *rhs_array, void *carry_out,
    const void *carry_in, int8_t *mem_ptr, void *const *bsks, void *const *ksks,
    uint32_t num_blocks, uint32_t requested_flag, uint32_t uses_carry) {

  host_add_and_propagate_single_carry<uint64_t>(
      (cudaStream_t *)(streams), gpu_indexes, gpu_count,
      static_cast<uint64_t *>(lhs_array),
      static_cast<const uint64_t *>(rhs_array),
      static_cast<uint64_t *>(carry_out),
      static_cast<const uint64_t *>(carry_in),
      (int_sc_prop_memory<uint64_t> *)mem_ptr, bsks, (uint64_t **)(ksks),
      num_blocks, requested_flag, uses_carry);
}

void cuda_integer_overflowing_sub_kb_64_inplace(
    void *const *streams, uint32_t const *gpu_indexes, uint32_t gpu_count,
    void *lhs_array, const void *rhs_array, void *overflow_block,
    const void *input_borrow, int8_t *mem_ptr, void *const *bsks,
    void *const *ksks, uint32_t num_blocks, uint32_t compute_overflow,
    uint32_t uses_input_borrow) {

  host_integer_overflowing_sub<uint64_t>(
      (cudaStream_t const *)streams, gpu_indexes, gpu_count,
      static_cast<uint64_t *>(lhs_array), static_cast<uint64_t *>(lhs_array),
      static_cast<const uint64_t *>(rhs_array),
      static_cast<uint64_t *>(overflow_block),
      static_cast<const uint64_t *>(input_borrow),
      (int_borrow_prop_memory<uint64_t> *)mem_ptr, bsks, (uint64_t **)ksks,
      num_blocks, compute_overflow, uses_input_borrow);
}

void cleanup_cuda_propagate_single_carry(void *const *streams,
                                         uint32_t const *gpu_indexes,
                                         uint32_t gpu_count,
                                         int8_t **mem_ptr_void) {
  int_sc_prop_memory<uint64_t> *mem_ptr =
      (int_sc_prop_memory<uint64_t> *)(*mem_ptr_void);
  mem_ptr->release((cudaStream_t *)(streams), gpu_indexes, gpu_count);
}

void cleanup_cuda_add_and_propagate_single_carry(void *const *streams,
                                                 uint32_t const *gpu_indexes,
                                                 uint32_t gpu_count,
                                                 int8_t **mem_ptr_void) {
  int_sc_prop_memory<uint64_t> *mem_ptr =
      (int_sc_prop_memory<uint64_t> *)(*mem_ptr_void);
  mem_ptr->release((cudaStream_t *)(streams), gpu_indexes, gpu_count);
}
void cleanup_cuda_integer_overflowing_sub(void *const *streams,
                                          uint32_t const *gpu_indexes,
                                          uint32_t gpu_count,
                                          int8_t **mem_ptr_void) {
  int_borrow_prop_memory<uint64_t> *mem_ptr =
      (int_borrow_prop_memory<uint64_t> *)(*mem_ptr_void);
  mem_ptr->release((cudaStream_t *)(streams), gpu_indexes, gpu_count);
}

void scratch_cuda_apply_univariate_lut_kb_64(
    void *const *streams, uint32_t const *gpu_indexes, uint32_t gpu_count,
    int8_t **mem_ptr, void const *input_lut, uint32_t lwe_dimension,
    uint32_t glwe_dimension, uint32_t polynomial_size, uint32_t ks_level,
    uint32_t ks_base_log, uint32_t pbs_level, uint32_t pbs_base_log,
    uint32_t grouping_factor, uint32_t num_radix_blocks,
    uint32_t message_modulus, uint32_t carry_modulus, PBS_TYPE pbs_type,
    bool allocate_gpu_memory) {

  int_radix_params params(pbs_type, glwe_dimension, polynomial_size,
                          glwe_dimension * polynomial_size, lwe_dimension,
                          ks_level, ks_base_log, pbs_level, pbs_base_log,
                          grouping_factor, message_modulus, carry_modulus);

  scratch_cuda_apply_univariate_lut_kb<uint64_t>(
      (cudaStream_t *)(streams), gpu_indexes, gpu_count,
      (int_radix_lut<uint64_t> **)mem_ptr,
      static_cast<const uint64_t *>(input_lut), num_radix_blocks, params,
      allocate_gpu_memory);
}

void scratch_cuda_apply_many_univariate_lut_kb_64(
    void *const *streams, uint32_t const *gpu_indexes, uint32_t gpu_count,
    int8_t **mem_ptr, void const *input_lut, uint32_t lwe_dimension,
    uint32_t glwe_dimension, uint32_t polynomial_size, uint32_t ks_level,
    uint32_t ks_base_log, uint32_t pbs_level, uint32_t pbs_base_log,
    uint32_t grouping_factor, uint32_t num_radix_blocks,
    uint32_t message_modulus, uint32_t carry_modulus, PBS_TYPE pbs_type,
    uint32_t num_many_lut, bool allocate_gpu_memory) {

  int_radix_params params(pbs_type, glwe_dimension, polynomial_size,
                          glwe_dimension * polynomial_size, lwe_dimension,
                          ks_level, ks_base_log, pbs_level, pbs_base_log,
                          grouping_factor, message_modulus, carry_modulus);

  scratch_cuda_apply_many_univariate_lut_kb<uint64_t>(
      (cudaStream_t *)(streams), gpu_indexes, gpu_count,
      (int_radix_lut<uint64_t> **)mem_ptr,
      static_cast<const uint64_t *>(input_lut), num_radix_blocks, params,
      num_many_lut, allocate_gpu_memory);
}

void cuda_apply_univariate_lut_kb_64(void *const *streams,
                                     uint32_t const *gpu_indexes,
                                     uint32_t gpu_count, void *output_radix_lwe,
                                     void const *input_radix_lwe,
                                     int8_t *mem_ptr, void *const *ksks,
                                     void *const *bsks, uint32_t num_blocks) {

  host_apply_univariate_lut_kb<uint64_t>(
      (cudaStream_t *)(streams), gpu_indexes, gpu_count,
      static_cast<uint64_t *>(output_radix_lwe),
      static_cast<const uint64_t *>(input_radix_lwe),
      (int_radix_lut<uint64_t> *)mem_ptr, (uint64_t **)(ksks), bsks,
      num_blocks);
}

void cleanup_cuda_apply_univariate_lut_kb_64(void *const *streams,
                                             uint32_t const *gpu_indexes,
                                             uint32_t gpu_count,
                                             int8_t **mem_ptr_void) {
  int_radix_lut<uint64_t> *mem_ptr = (int_radix_lut<uint64_t> *)(*mem_ptr_void);
  mem_ptr->release((cudaStream_t *)(streams), gpu_indexes, gpu_count);
}

void cuda_apply_many_univariate_lut_kb_64(
    void *const *streams, uint32_t const *gpu_indexes, uint32_t gpu_count,
    void *output_radix_lwe, void const *input_radix_lwe, int8_t *mem_ptr,
    void *const *ksks, void *const *bsks, uint32_t num_blocks,
    uint32_t num_many_lut, uint32_t lut_stride) {

  host_apply_many_univariate_lut_kb<uint64_t>(
      (cudaStream_t *)(streams), gpu_indexes, gpu_count,
      static_cast<uint64_t *>(output_radix_lwe),
      static_cast<const uint64_t *>(input_radix_lwe),
      (int_radix_lut<uint64_t> *)mem_ptr, (uint64_t **)(ksks), bsks, num_blocks,
      num_many_lut, lut_stride);
}

void scratch_cuda_apply_bivariate_lut_kb_64(
    void *const *streams, uint32_t const *gpu_indexes, uint32_t gpu_count,
    int8_t **mem_ptr, void const *input_lut, uint32_t lwe_dimension,
    uint32_t glwe_dimension, uint32_t polynomial_size, uint32_t ks_level,
    uint32_t ks_base_log, uint32_t pbs_level, uint32_t pbs_base_log,
    uint32_t grouping_factor, uint32_t num_radix_blocks,
    uint32_t message_modulus, uint32_t carry_modulus, PBS_TYPE pbs_type,
    bool allocate_gpu_memory) {

  int_radix_params params(pbs_type, glwe_dimension, polynomial_size,
                          glwe_dimension * polynomial_size, lwe_dimension,
                          ks_level, ks_base_log, pbs_level, pbs_base_log,
                          grouping_factor, message_modulus, carry_modulus);

  scratch_cuda_apply_bivariate_lut_kb<uint64_t>(
      (cudaStream_t *)(streams), gpu_indexes, gpu_count,
      (int_radix_lut<uint64_t> **)mem_ptr,
      static_cast<const uint64_t *>(input_lut), num_radix_blocks, params,
      allocate_gpu_memory);
}

void cuda_apply_bivariate_lut_kb_64(
    void *const *streams, uint32_t const *gpu_indexes, uint32_t gpu_count,
    void *output_radix_lwe, void const *input_radix_lwe_1,
    void const *input_radix_lwe_2, int8_t *mem_ptr, void *const *ksks,
    void *const *bsks, uint32_t num_blocks, uint32_t shift) {

  host_apply_bivariate_lut_kb<uint64_t>(
      (cudaStream_t *)(streams), gpu_indexes, gpu_count,
      static_cast<uint64_t *>(output_radix_lwe),
      static_cast<const uint64_t *>(input_radix_lwe_1),
      static_cast<const uint64_t *>(input_radix_lwe_2),
      (int_radix_lut<uint64_t> *)mem_ptr, (uint64_t **)(ksks), bsks, num_blocks,
      shift);
}

void cleanup_cuda_apply_bivariate_lut_kb_64(void *const *streams,
                                            uint32_t const *gpu_indexes,
                                            uint32_t gpu_count,
                                            int8_t **mem_ptr_void) {
  int_radix_lut<uint64_t> *mem_ptr = (int_radix_lut<uint64_t> *)(*mem_ptr_void);
  mem_ptr->release((cudaStream_t *)(streams), gpu_indexes, gpu_count);
}

void scratch_cuda_integer_compute_prefix_sum_hillis_steele_64(
    void *const *streams, uint32_t const *gpu_indexes, uint32_t gpu_count,
    int8_t **mem_ptr, void const *input_lut, uint32_t lwe_dimension,
    uint32_t glwe_dimension, uint32_t polynomial_size, uint32_t ks_level,
    uint32_t ks_base_log, uint32_t pbs_level, uint32_t pbs_base_log,
    uint32_t grouping_factor, uint32_t num_radix_blocks,
    uint32_t message_modulus, uint32_t carry_modulus, PBS_TYPE pbs_type,
    bool allocate_gpu_memory) {

  int_radix_params params(pbs_type, glwe_dimension, polynomial_size,
                          glwe_dimension * polynomial_size, lwe_dimension,
                          ks_level, ks_base_log, pbs_level, pbs_base_log,
                          grouping_factor, message_modulus, carry_modulus);

  scratch_cuda_apply_bivariate_lut_kb<uint64_t>(
      (cudaStream_t *)(streams), gpu_indexes, gpu_count,
      (int_radix_lut<uint64_t> **)mem_ptr,
      static_cast<const uint64_t *>(input_lut), num_radix_blocks, params,
      allocate_gpu_memory);
}

void cuda_integer_compute_prefix_sum_hillis_steele_64(
    void *const *streams, uint32_t const *gpu_indexes, uint32_t gpu_count,
    void *output_radix_lwe, void *generates_or_propagates, int8_t *mem_ptr,
    void *const *ksks, void *const *bsks, uint32_t num_blocks, uint32_t shift) {

  int_radix_params params = ((int_radix_lut<uint64_t> *)mem_ptr)->params;

  host_compute_prefix_sum_hillis_steele<uint64_t>(
      (cudaStream_t *)(streams), gpu_indexes, gpu_count,
      static_cast<uint64_t *>(output_radix_lwe),
      static_cast<uint64_t *>(generates_or_propagates), params,
      (int_radix_lut<uint64_t> *)mem_ptr, bsks, (uint64_t **)(ksks),
      num_blocks);
}

void cleanup_cuda_integer_compute_prefix_sum_hillis_steele_64(
    void *const *streams, uint32_t const *gpu_indexes, uint32_t gpu_count,
    int8_t **mem_ptr_void) {
  int_radix_lut<uint64_t> *mem_ptr = (int_radix_lut<uint64_t> *)(*mem_ptr_void);
  mem_ptr->release((cudaStream_t *)(streams), gpu_indexes, gpu_count);
}

void cuda_integer_reverse_blocks_64_inplace(void *const *streams,
                                            uint32_t const *gpu_indexes,
                                            uint32_t gpu_count, void *lwe_array,
                                            uint32_t num_blocks,
                                            uint32_t lwe_size) {

  host_radix_blocks_reverse_inplace<uint64_t>(
      (cudaStream_t *)(streams), gpu_indexes,
      static_cast<uint64_t *>(lwe_array), num_blocks, lwe_size);
}
