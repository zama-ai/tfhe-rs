#include "integer/integer.cuh"
#include "integer/negation.cuh"
#include <linear_algebra.h>

void cuda_full_propagation_64_inplace(
    void *const *streams, uint32_t const *gpu_indexes, uint32_t gpu_count,
    CudaRadixCiphertextFFI *input_blocks, int8_t *mem_ptr, void *const *ksks,
    CudaModulusSwitchNoiseReductionKeyFFI const *ms_noise_reduction_key,
    void *const *bsks, uint32_t num_blocks) {

  int_fullprop_buffer<uint64_t> *buffer =
      (int_fullprop_buffer<uint64_t> *)mem_ptr;

  host_full_propagate_inplace<uint64_t>(
      (cudaStream_t *)(streams), gpu_indexes, gpu_count, input_blocks, buffer,
      (uint64_t **)(ksks), ms_noise_reduction_key, bsks, num_blocks);
}

uint64_t scratch_cuda_full_propagation_64(
    void *const *streams, uint32_t const *gpu_indexes, uint32_t gpu_count,
    int8_t **mem_ptr, uint32_t lwe_dimension, uint32_t glwe_dimension,
    uint32_t polynomial_size, uint32_t ks_level, uint32_t ks_base_log,
    uint32_t pbs_level, uint32_t pbs_base_log, uint32_t grouping_factor,
    uint32_t message_modulus, uint32_t carry_modulus, PBS_TYPE pbs_type,
    bool allocate_gpu_memory, bool allocate_ms_array) {
  int_radix_params params(pbs_type, glwe_dimension, polynomial_size,
                          glwe_dimension * polynomial_size, lwe_dimension,
                          ks_level, ks_base_log, pbs_level, pbs_base_log,
                          grouping_factor, message_modulus, carry_modulus,
                          allocate_ms_array);

  return scratch_cuda_full_propagation<uint64_t>(
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

uint64_t scratch_cuda_propagate_single_carry_kb_64_inplace(
    void *const *streams, uint32_t const *gpu_indexes, uint32_t gpu_count,
    int8_t **mem_ptr, uint32_t glwe_dimension, uint32_t polynomial_size,
    uint32_t big_lwe_dimension, uint32_t small_lwe_dimension, uint32_t ks_level,
    uint32_t ks_base_log, uint32_t pbs_level, uint32_t pbs_base_log,
    uint32_t grouping_factor, uint32_t num_blocks, uint32_t message_modulus,
    uint32_t carry_modulus, PBS_TYPE pbs_type, uint32_t requested_flag,
    uint32_t uses_carry, bool allocate_gpu_memory, bool allocate_ms_array) {
  PUSH_RANGE("scratch propagate sc")
  int_radix_params params(pbs_type, glwe_dimension, polynomial_size,
                          big_lwe_dimension, small_lwe_dimension, ks_level,
                          ks_base_log, pbs_level, pbs_base_log, grouping_factor,
                          message_modulus, carry_modulus, allocate_ms_array);

  return scratch_cuda_propagate_single_carry_kb_inplace<uint64_t>(
      (cudaStream_t *)(streams), gpu_indexes, gpu_count,
      (int_sc_prop_memory<uint64_t> **)mem_ptr, num_blocks, params,
      requested_flag, uses_carry, allocate_gpu_memory);
  POP_RANGE()
}

uint64_t scratch_cuda_add_and_propagate_single_carry_kb_64_inplace(
    void *const *streams, uint32_t const *gpu_indexes, uint32_t gpu_count,
    int8_t **mem_ptr, uint32_t glwe_dimension, uint32_t polynomial_size,
    uint32_t big_lwe_dimension, uint32_t small_lwe_dimension, uint32_t ks_level,
    uint32_t ks_base_log, uint32_t pbs_level, uint32_t pbs_base_log,
    uint32_t grouping_factor, uint32_t num_blocks, uint32_t message_modulus,
    uint32_t carry_modulus, PBS_TYPE pbs_type, uint32_t requested_flag,
    uint32_t uses_carry, bool allocate_gpu_memory, bool allocate_ms_array) {
  PUSH_RANGE("scratch add & propagate sc")
  int_radix_params params(pbs_type, glwe_dimension, polynomial_size,
                          big_lwe_dimension, small_lwe_dimension, ks_level,
                          ks_base_log, pbs_level, pbs_base_log, grouping_factor,
                          message_modulus, carry_modulus, allocate_ms_array);

  return scratch_cuda_propagate_single_carry_kb_inplace<uint64_t>(
      (cudaStream_t *)(streams), gpu_indexes, gpu_count,
      (int_sc_prop_memory<uint64_t> **)mem_ptr, num_blocks, params,
      requested_flag, uses_carry, allocate_gpu_memory);
  POP_RANGE()
}

uint64_t scratch_cuda_integer_overflowing_sub_kb_64_inplace(
    void *const *streams, uint32_t const *gpu_indexes, uint32_t gpu_count,
    int8_t **mem_ptr, uint32_t glwe_dimension, uint32_t polynomial_size,
    uint32_t big_lwe_dimension, uint32_t small_lwe_dimension, uint32_t ks_level,
    uint32_t ks_base_log, uint32_t pbs_level, uint32_t pbs_base_log,
    uint32_t grouping_factor, uint32_t num_blocks, uint32_t message_modulus,
    uint32_t carry_modulus, PBS_TYPE pbs_type, uint32_t compute_overflow,
    bool allocate_gpu_memory, bool allocate_ms_array) {
  PUSH_RANGE("scratch overflow sub")
  int_radix_params params(pbs_type, glwe_dimension, polynomial_size,
                          big_lwe_dimension, small_lwe_dimension, ks_level,
                          ks_base_log, pbs_level, pbs_base_log, grouping_factor,
                          message_modulus, carry_modulus, allocate_ms_array);

  return scratch_cuda_integer_overflowing_sub<uint64_t>(
      (cudaStream_t *)(streams), gpu_indexes, gpu_count,
      (int_borrow_prop_memory<uint64_t> **)mem_ptr, num_blocks, params,
      compute_overflow, allocate_gpu_memory);
  POP_RANGE()
}

void cuda_propagate_single_carry_kb_64_inplace(
    void *const *streams, uint32_t const *gpu_indexes, uint32_t gpu_count,
    CudaRadixCiphertextFFI *lwe_array, CudaRadixCiphertextFFI *carry_out,
    const CudaRadixCiphertextFFI *carry_in, int8_t *mem_ptr, void *const *bsks,
    void *const *ksks,
    CudaModulusSwitchNoiseReductionKeyFFI const *ms_noise_reduction_key,
    uint32_t requested_flag, uint32_t uses_carry) {

  host_propagate_single_carry<uint64_t>(
      (cudaStream_t *)(streams), gpu_indexes, gpu_count, lwe_array, carry_out,
      carry_in, (int_sc_prop_memory<uint64_t> *)mem_ptr, bsks,
      (uint64_t **)(ksks), ms_noise_reduction_key, requested_flag, uses_carry);
}

void cuda_add_and_propagate_single_carry_kb_64_inplace(
    void *const *streams, uint32_t const *gpu_indexes, uint32_t gpu_count,
    CudaRadixCiphertextFFI *lhs_array, const CudaRadixCiphertextFFI *rhs_array,
    CudaRadixCiphertextFFI *carry_out, const CudaRadixCiphertextFFI *carry_in,
    int8_t *mem_ptr, void *const *bsks, void *const *ksks,
    CudaModulusSwitchNoiseReductionKeyFFI const *ms_noise_reduction_key,
    uint32_t requested_flag, uint32_t uses_carry) {

  host_add_and_propagate_single_carry<uint64_t>(
      (cudaStream_t *)(streams), gpu_indexes, gpu_count, lhs_array, rhs_array,
      carry_out, carry_in, (int_sc_prop_memory<uint64_t> *)mem_ptr, bsks,
      (uint64_t **)(ksks), ms_noise_reduction_key, requested_flag, uses_carry);
}

void cuda_integer_overflowing_sub_kb_64_inplace(
    void *const *streams, uint32_t const *gpu_indexes, uint32_t gpu_count,
    CudaRadixCiphertextFFI *lhs_array, const CudaRadixCiphertextFFI *rhs_array,
    CudaRadixCiphertextFFI *overflow_block,
    const CudaRadixCiphertextFFI *input_borrow, int8_t *mem_ptr,
    void *const *bsks, void *const *ksks,
    CudaModulusSwitchNoiseReductionKeyFFI const *ms_noise_reduction_key,
    uint32_t compute_overflow, uint32_t uses_input_borrow) {
  PUSH_RANGE("overflow sub")
  host_integer_overflowing_sub<uint64_t>(
      (cudaStream_t const *)streams, gpu_indexes, gpu_count, lhs_array,
      lhs_array, rhs_array, overflow_block, input_borrow,
      (int_borrow_prop_memory<uint64_t> *)mem_ptr, bsks, (uint64_t **)ksks,
      ms_noise_reduction_key, compute_overflow, uses_input_borrow);
  POP_RANGE()
}

void cleanup_cuda_propagate_single_carry(void *const *streams,
                                         uint32_t const *gpu_indexes,
                                         uint32_t gpu_count,
                                         int8_t **mem_ptr_void) {
  PUSH_RANGE("cleanup propagate sc")
  int_sc_prop_memory<uint64_t> *mem_ptr =
      (int_sc_prop_memory<uint64_t> *)(*mem_ptr_void);
  mem_ptr->release((cudaStream_t *)(streams), gpu_indexes, gpu_count);
  POP_RANGE()
}

void cleanup_cuda_add_and_propagate_single_carry(void *const *streams,
                                                 uint32_t const *gpu_indexes,
                                                 uint32_t gpu_count,
                                                 int8_t **mem_ptr_void) {
  PUSH_RANGE("cleanup add & propagate sc")
  int_sc_prop_memory<uint64_t> *mem_ptr =
      (int_sc_prop_memory<uint64_t> *)(*mem_ptr_void);
  mem_ptr->release((cudaStream_t *)(streams), gpu_indexes, gpu_count);
  POP_RANGE()
}
void cleanup_cuda_integer_overflowing_sub(void *const *streams,
                                          uint32_t const *gpu_indexes,
                                          uint32_t gpu_count,
                                          int8_t **mem_ptr_void) {
  PUSH_RANGE("cleanup overflow sub")
  int_borrow_prop_memory<uint64_t> *mem_ptr =
      (int_borrow_prop_memory<uint64_t> *)(*mem_ptr_void);
  mem_ptr->release((cudaStream_t *)(streams), gpu_indexes, gpu_count);
  POP_RANGE()
}

uint64_t scratch_cuda_apply_univariate_lut_kb_64(
    void *const *streams, uint32_t const *gpu_indexes, uint32_t gpu_count,
    int8_t **mem_ptr, void const *input_lut, uint32_t lwe_dimension,
    uint32_t glwe_dimension, uint32_t polynomial_size, uint32_t ks_level,
    uint32_t ks_base_log, uint32_t pbs_level, uint32_t pbs_base_log,
    uint32_t grouping_factor, uint32_t num_radix_blocks,
    uint32_t message_modulus, uint32_t carry_modulus, PBS_TYPE pbs_type,
    uint64_t lut_degree, bool allocate_gpu_memory, bool allocate_ms_array) {
  PUSH_RANGE("scratch univar lut")
  int_radix_params params(pbs_type, glwe_dimension, polynomial_size,
                          glwe_dimension * polynomial_size, lwe_dimension,
                          ks_level, ks_base_log, pbs_level, pbs_base_log,
                          grouping_factor, message_modulus, carry_modulus,
                          allocate_ms_array);

  return scratch_cuda_apply_univariate_lut_kb<uint64_t>(
      (cudaStream_t *)(streams), gpu_indexes, gpu_count,
      (int_radix_lut<uint64_t> **)mem_ptr,
      static_cast<const uint64_t *>(input_lut), num_radix_blocks, params,
      lut_degree, allocate_gpu_memory);
  POP_RANGE()
}

uint64_t scratch_cuda_apply_many_univariate_lut_kb_64(
    void *const *streams, uint32_t const *gpu_indexes, uint32_t gpu_count,
    int8_t **mem_ptr, void const *input_lut, uint32_t lwe_dimension,
    uint32_t glwe_dimension, uint32_t polynomial_size, uint32_t ks_level,
    uint32_t ks_base_log, uint32_t pbs_level, uint32_t pbs_base_log,
    uint32_t grouping_factor, uint32_t num_radix_blocks,
    uint32_t message_modulus, uint32_t carry_modulus, PBS_TYPE pbs_type,
    uint32_t num_many_lut, uint64_t lut_degree, bool allocate_gpu_memory,
    bool allocate_ms_array) {
  PUSH_RANGE("scratch many lut")
  int_radix_params params(pbs_type, glwe_dimension, polynomial_size,
                          glwe_dimension * polynomial_size, lwe_dimension,
                          ks_level, ks_base_log, pbs_level, pbs_base_log,
                          grouping_factor, message_modulus, carry_modulus,
                          allocate_ms_array);

  return scratch_cuda_apply_many_univariate_lut_kb<uint64_t>(
      (cudaStream_t *)(streams), gpu_indexes, gpu_count,
      (int_radix_lut<uint64_t> **)mem_ptr,
      static_cast<const uint64_t *>(input_lut), num_radix_blocks, params,
      num_many_lut, lut_degree, allocate_gpu_memory);
  POP_RANGE()
}

void cuda_apply_univariate_lut_kb_64(
    void *const *streams, uint32_t const *gpu_indexes, uint32_t gpu_count,
    CudaRadixCiphertextFFI *output_radix_lwe,
    CudaRadixCiphertextFFI const *input_radix_lwe, int8_t *mem_ptr,
    void *const *ksks,
    CudaModulusSwitchNoiseReductionKeyFFI const *ms_noise_reduction_key,
    void *const *bsks) {

  host_apply_univariate_lut_kb<uint64_t>(
      (cudaStream_t *)(streams), gpu_indexes, gpu_count, output_radix_lwe,
      input_radix_lwe, (int_radix_lut<uint64_t> *)mem_ptr, (uint64_t **)(ksks),
      ms_noise_reduction_key, bsks);
}

void cleanup_cuda_apply_univariate_lut_kb_64(void *const *streams,
                                             uint32_t const *gpu_indexes,
                                             uint32_t gpu_count,
                                             int8_t **mem_ptr_void) {
  PUSH_RANGE("cleanup univar lut")
  int_radix_lut<uint64_t> *mem_ptr = (int_radix_lut<uint64_t> *)(*mem_ptr_void);
  mem_ptr->release((cudaStream_t *)(streams), gpu_indexes, gpu_count);
  POP_RANGE()
}

void cuda_apply_many_univariate_lut_kb_64(
    void *const *streams, uint32_t const *gpu_indexes, uint32_t gpu_count,
    CudaRadixCiphertextFFI *output_radix_lwe,
    CudaRadixCiphertextFFI const *input_radix_lwe, int8_t *mem_ptr,
    void *const *ksks,
    CudaModulusSwitchNoiseReductionKeyFFI const *ms_noise_reduction_key,
    void *const *bsks, uint32_t num_many_lut, uint32_t lut_stride) {

  host_apply_many_univariate_lut_kb<uint64_t>(
      (cudaStream_t *)(streams), gpu_indexes, gpu_count, output_radix_lwe,
      input_radix_lwe, (int_radix_lut<uint64_t> *)mem_ptr, (uint64_t **)(ksks),
      ms_noise_reduction_key, bsks, num_many_lut, lut_stride);
}

uint64_t scratch_cuda_apply_bivariate_lut_kb_64(
    void *const *streams, uint32_t const *gpu_indexes, uint32_t gpu_count,
    int8_t **mem_ptr, void const *input_lut, uint32_t lwe_dimension,
    uint32_t glwe_dimension, uint32_t polynomial_size, uint32_t ks_level,
    uint32_t ks_base_log, uint32_t pbs_level, uint32_t pbs_base_log,
    uint32_t grouping_factor, uint32_t num_radix_blocks,
    uint32_t message_modulus, uint32_t carry_modulus, PBS_TYPE pbs_type,
    uint64_t lut_degree, bool allocate_gpu_memory, bool allocate_ms_array) {
  PUSH_RANGE("scratch bivar lut")
  int_radix_params params(pbs_type, glwe_dimension, polynomial_size,
                          glwe_dimension * polynomial_size, lwe_dimension,
                          ks_level, ks_base_log, pbs_level, pbs_base_log,
                          grouping_factor, message_modulus, carry_modulus,
                          allocate_ms_array);

  return scratch_cuda_apply_bivariate_lut_kb<uint64_t>(
      (cudaStream_t *)(streams), gpu_indexes, gpu_count,
      (int_radix_lut<uint64_t> **)mem_ptr,
      static_cast<const uint64_t *>(input_lut), num_radix_blocks, params,
      lut_degree, allocate_gpu_memory);
  POP_RANGE()
}

void cuda_apply_bivariate_lut_kb_64(
    void *const *streams, uint32_t const *gpu_indexes, uint32_t gpu_count,
    CudaRadixCiphertextFFI *output_radix_lwe,
    CudaRadixCiphertextFFI const *input_radix_lwe_1,
    CudaRadixCiphertextFFI const *input_radix_lwe_2, int8_t *mem_ptr,
    void *const *ksks,
    CudaModulusSwitchNoiseReductionKeyFFI const *ms_noise_reduction_key,
    void *const *bsks, uint32_t num_radix_blocks, uint32_t shift) {

  host_apply_bivariate_lut_kb<uint64_t>(
      (cudaStream_t *)(streams), gpu_indexes, gpu_count, output_radix_lwe,
      input_radix_lwe_1, input_radix_lwe_2, (int_radix_lut<uint64_t> *)mem_ptr,
      (uint64_t **)(ksks), ms_noise_reduction_key, bsks, num_radix_blocks,
      shift);
}

void cleanup_cuda_apply_bivariate_lut_kb_64(void *const *streams,
                                            uint32_t const *gpu_indexes,
                                            uint32_t gpu_count,
                                            int8_t **mem_ptr_void) {
  PUSH_RANGE("cleanup bivar lut")
  int_radix_lut<uint64_t> *mem_ptr = (int_radix_lut<uint64_t> *)(*mem_ptr_void);
  mem_ptr->release((cudaStream_t *)(streams), gpu_indexes, gpu_count);
  POP_RANGE()
}

uint64_t scratch_cuda_integer_compute_prefix_sum_hillis_steele_64(
    void *const *streams, uint32_t const *gpu_indexes, uint32_t gpu_count,
    int8_t **mem_ptr, void const *input_lut, uint32_t lwe_dimension,
    uint32_t glwe_dimension, uint32_t polynomial_size, uint32_t ks_level,
    uint32_t ks_base_log, uint32_t pbs_level, uint32_t pbs_base_log,
    uint32_t grouping_factor, uint32_t num_radix_blocks,
    uint32_t message_modulus, uint32_t carry_modulus, PBS_TYPE pbs_type,
    uint64_t lut_degree, bool allocate_gpu_memory, bool allocate_ms_array) {

  int_radix_params params(pbs_type, glwe_dimension, polynomial_size,
                          glwe_dimension * polynomial_size, lwe_dimension,
                          ks_level, ks_base_log, pbs_level, pbs_base_log,
                          grouping_factor, message_modulus, carry_modulus,
                          allocate_ms_array);

  return scratch_cuda_apply_bivariate_lut_kb<uint64_t>(
      (cudaStream_t *)(streams), gpu_indexes, gpu_count,
      (int_radix_lut<uint64_t> **)mem_ptr,
      static_cast<const uint64_t *>(input_lut), num_radix_blocks, params,
      lut_degree, allocate_gpu_memory);
}

void cuda_integer_compute_prefix_sum_hillis_steele_64(
    void *const *streams, uint32_t const *gpu_indexes, uint32_t gpu_count,
    CudaRadixCiphertextFFI *output_radix_lwe,
    CudaRadixCiphertextFFI *generates_or_propagates, int8_t *mem_ptr,
    void *const *ksks,
    CudaModulusSwitchNoiseReductionKeyFFI const *ms_noise_reduction_key,
    void *const *bsks, uint32_t num_radix_blocks) {

  host_compute_prefix_sum_hillis_steele<uint64_t>(
      (cudaStream_t *)(streams), gpu_indexes, gpu_count, output_radix_lwe,
      generates_or_propagates, (int_radix_lut<uint64_t> *)mem_ptr, bsks,
      (uint64_t **)(ksks), ms_noise_reduction_key, num_radix_blocks);
}

void cleanup_cuda_integer_compute_prefix_sum_hillis_steele_64(
    void *const *streams, uint32_t const *gpu_indexes, uint32_t gpu_count,
    int8_t **mem_ptr_void) {
  int_radix_lut<uint64_t> *mem_ptr = (int_radix_lut<uint64_t> *)(*mem_ptr_void);
  mem_ptr->release((cudaStream_t *)(streams), gpu_indexes, gpu_count);
}

void cuda_integer_reverse_blocks_64_inplace(void *const *streams,
                                            uint32_t const *gpu_indexes,
                                            uint32_t gpu_count,
                                            CudaRadixCiphertextFFI *lwe_array) {

  host_radix_blocks_reverse_inplace<uint64_t>((cudaStream_t *)(streams),
                                              gpu_indexes, lwe_array);
}

void reverseArray(uint64_t arr[], size_t n) {
  size_t start = 0;
  size_t end = n - 1;

  // Swap elements from the start with elements from the end
  while (start < end) {
    // Swap arr[start] and arr[end]
    uint64_t temp = arr[start];
    arr[start] = arr[end];
    arr[end] = temp;

    // Move towards the middle
    start++;
    end--;
  }
}

uint64_t scratch_cuda_apply_noise_squashing_mem(
    void *const *streams, uint32_t const *gpu_indexes, uint32_t gpu_count,
    int_radix_params params, int_noise_squashing_lut<uint64_t> **mem_ptr,
    uint32_t glwe_dimension, uint32_t polynomial_size,
    uint32_t num_radix_blocks, uint32_t original_num_blocks,
    bool allocate_gpu_memory) {

  uint64_t size_tracker = 0;
  *mem_ptr = new int_noise_squashing_lut<uint64_t>(
      (cudaStream_t *)streams, gpu_indexes, gpu_count, params, glwe_dimension,
      polynomial_size, num_radix_blocks, original_num_blocks,
      allocate_gpu_memory, &size_tracker);
  return size_tracker;
}

uint64_t scratch_cuda_apply_noise_squashing_kb(
    void *const *streams, uint32_t const *gpu_indexes, uint32_t gpu_count,
    int8_t **mem_ptr, uint32_t lwe_dimension, uint32_t glwe_dimension,
    uint32_t polynomial_size, uint32_t input_glwe_dimension,
    uint32_t input_polynomial_size, uint32_t ks_level, uint32_t ks_base_log,
    uint32_t pbs_level, uint32_t pbs_base_log, uint32_t grouping_factor,
    uint32_t num_radix_blocks, uint32_t original_num_blocks,
    uint32_t message_modulus, uint32_t carry_modulus, PBS_TYPE pbs_type,
    bool allocate_gpu_memory, bool allocate_ms_array) {
  PUSH_RANGE("scratch noise squashing")
  int_radix_params params(pbs_type, glwe_dimension, polynomial_size,
                          glwe_dimension * polynomial_size, lwe_dimension,
                          ks_level, ks_base_log, pbs_level, pbs_base_log,
                          grouping_factor, message_modulus, carry_modulus,
                          allocate_ms_array);

  return scratch_cuda_apply_noise_squashing_mem(
      streams, gpu_indexes, gpu_count, params,
      (int_noise_squashing_lut<uint64_t> **)mem_ptr, input_glwe_dimension,
      input_polynomial_size, num_radix_blocks, original_num_blocks,
      allocate_gpu_memory);
  POP_RANGE()
}

void cuda_apply_noise_squashing_kb(
    void *const *streams, uint32_t const *gpu_indexes, uint32_t gpu_count,
    CudaRadixCiphertextFFI *output_radix_lwe,
    CudaRadixCiphertextFFI const *input_radix_lwe, int8_t *mem_ptr,
    void *const *ksks,
    CudaModulusSwitchNoiseReductionKeyFFI const *ms_noise_reduction_key,
    void *const *bsks) {

  PUSH_RANGE("apply noise squashing")
  integer_radix_apply_noise_squashing_kb<uint64_t>(
      (cudaStream_t *)(streams), gpu_indexes, gpu_count, output_radix_lwe,
      input_radix_lwe, (int_noise_squashing_lut<uint64_t> *)mem_ptr, bsks,
      (uint64_t **)ksks, ms_noise_reduction_key);
  POP_RANGE()
}

void cleanup_cuda_apply_noise_squashing_kb(void *const *streams,
                                           uint32_t const *gpu_indexes,
                                           uint32_t gpu_count,
                                           int8_t **mem_ptr_void) {
  PUSH_RANGE("cleanup noise squashing")
  int_noise_squashing_lut<uint64_t> *mem_ptr =
      (int_noise_squashing_lut<uint64_t> *)(*mem_ptr_void);
  mem_ptr->release((cudaStream_t *)(streams), gpu_indexes, gpu_count);
  POP_RANGE()
}
