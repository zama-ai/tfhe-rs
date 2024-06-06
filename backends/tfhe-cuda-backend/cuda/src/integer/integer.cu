#include "integer/integer.cuh"
#include <linear_algebra.h>

void cuda_full_propagation_64_inplace(void **streams, uint32_t *gpu_indexes,
                                      uint32_t gpu_count, void *input_blocks,
                                      int8_t *mem_ptr, void **ksks, void **bsks,
                                      uint32_t num_blocks) {

  int_fullprop_buffer<uint64_t> *buffer =
      (int_fullprop_buffer<uint64_t> *)mem_ptr;

  host_full_propagate_inplace<uint64_t>(
      (cudaStream_t *)(streams), gpu_indexes, gpu_count,
      static_cast<uint64_t *>(input_blocks), buffer, (uint64_t **)(ksks), bsks,
      num_blocks);
}

void scratch_cuda_full_propagation_64(
    void **streams, uint32_t *gpu_indexes, uint32_t gpu_count, int8_t **mem_ptr,
    uint32_t lwe_dimension, uint32_t glwe_dimension, uint32_t polynomial_size,
    uint32_t ks_level, uint32_t ks_base_log, uint32_t pbs_level,
    uint32_t pbs_base_log, uint32_t grouping_factor, uint32_t num_radix_blocks,
    uint32_t message_modulus, uint32_t carry_modulus, PBS_TYPE pbs_type,
    bool allocate_gpu_memory) {
  int_radix_params params(pbs_type, glwe_dimension, polynomial_size,
                          glwe_dimension * polynomial_size, lwe_dimension,
                          ks_level, ks_base_log, pbs_level, pbs_base_log,
                          grouping_factor, message_modulus, carry_modulus);

  scratch_cuda_full_propagation<uint64_t>(
      (cudaStream_t *)streams, gpu_indexes, gpu_count,
      (int_fullprop_buffer<uint64_t> **)mem_ptr, params, num_radix_blocks,
      allocate_gpu_memory);
}

void cleanup_cuda_full_propagation(void **streams, uint32_t *gpu_indexes,
                                   uint32_t gpu_count, int8_t **mem_ptr_void) {

  int_fullprop_buffer<uint64_t> *mem_ptr =
      (int_fullprop_buffer<uint64_t> *)(*mem_ptr_void);

  mem_ptr->release((cudaStream_t *)(streams), gpu_indexes, gpu_count);
}

void scratch_cuda_propagate_single_carry_kb_64_inplace(
    void **streams, uint32_t *gpu_indexes, uint32_t gpu_count, int8_t **mem_ptr,
    uint32_t glwe_dimension, uint32_t polynomial_size,
    uint32_t big_lwe_dimension, uint32_t small_lwe_dimension, uint32_t ks_level,
    uint32_t ks_base_log, uint32_t pbs_level, uint32_t pbs_base_log,
    uint32_t grouping_factor, uint32_t num_blocks, uint32_t message_modulus,
    uint32_t carry_modulus, PBS_TYPE pbs_type, bool allocate_gpu_memory) {

  int_radix_params params(pbs_type, glwe_dimension, polynomial_size,
                          big_lwe_dimension, small_lwe_dimension, ks_level,
                          ks_base_log, pbs_level, pbs_base_log, grouping_factor,
                          message_modulus, carry_modulus);

  scratch_cuda_propagate_single_carry_kb_inplace(
      (cudaStream_t *)(streams), gpu_indexes, gpu_count,
      (int_sc_prop_memory<uint64_t> **)mem_ptr, num_blocks, params,
      allocate_gpu_memory);
}

void cuda_propagate_single_carry_kb_64_inplace(
    void **streams, uint32_t *gpu_indexes, uint32_t gpu_count, void *lwe_array,
    void *carry_out, int8_t *mem_ptr, void **bsks, void **ksks,
    uint32_t num_blocks) {
  host_propagate_single_carry<uint64_t>(
      (cudaStream_t *)(streams), gpu_indexes, gpu_count,
      static_cast<uint64_t *>(lwe_array), static_cast<uint64_t *>(carry_out),
      (int_sc_prop_memory<uint64_t> *)mem_ptr, bsks, (uint64_t **)(ksks),
      num_blocks);
}

void cleanup_cuda_propagate_single_carry(void **streams, uint32_t *gpu_indexes,
                                         uint32_t gpu_count,
                                         int8_t **mem_ptr_void) {
  int_sc_prop_memory<uint64_t> *mem_ptr =
      (int_sc_prop_memory<uint64_t> *)(*mem_ptr_void);
  mem_ptr->release((cudaStream_t *)(streams), gpu_indexes, gpu_count);
}

void scratch_cuda_apply_univariate_lut_kb_64(
    void **streams, uint32_t *gpu_indexes, uint32_t gpu_count, int8_t **mem_ptr,
    void *input_lut, uint32_t lwe_dimension, uint32_t glwe_dimension,
    uint32_t polynomial_size, uint32_t ks_level, uint32_t ks_base_log,
    uint32_t pbs_level, uint32_t pbs_base_log, uint32_t grouping_factor,
    uint32_t num_radix_blocks, uint32_t message_modulus, uint32_t carry_modulus,
    PBS_TYPE pbs_type, bool allocate_gpu_memory) {

  int_radix_params params(pbs_type, glwe_dimension, polynomial_size,
                          glwe_dimension * polynomial_size, lwe_dimension,
                          ks_level, ks_base_log, pbs_level, pbs_base_log,
                          grouping_factor, message_modulus, carry_modulus);

  scratch_cuda_apply_univariate_lut_kb<uint64_t>(
      (cudaStream_t *)(streams), gpu_indexes, gpu_count,
      (int_radix_lut<uint64_t> **)mem_ptr, static_cast<uint64_t *>(input_lut),
      num_radix_blocks, params, allocate_gpu_memory);
}

void cuda_apply_univariate_lut_kb_64(void **streams, uint32_t *gpu_indexes,
                                     uint32_t gpu_count, void *output_radix_lwe,
                                     void *input_radix_lwe, int8_t *mem_ptr,
                                     void **ksks, void **bsks,
                                     uint32_t num_blocks) {

  host_apply_univariate_lut_kb<uint64_t>(
      (cudaStream_t *)(streams), gpu_indexes, gpu_count,
      static_cast<uint64_t *>(output_radix_lwe),
      static_cast<uint64_t *>(input_radix_lwe),
      (int_radix_lut<uint64_t> *)mem_ptr, (uint64_t **)(ksks), bsks,
      num_blocks);
}

void cleanup_cuda_apply_univariate_lut_kb_64(void **streams,
                                             uint32_t *gpu_indexes,
                                             uint32_t gpu_count,
                                             int8_t **mem_ptr_void) {
  int_radix_lut<uint64_t> *mem_ptr = (int_radix_lut<uint64_t> *)(*mem_ptr_void);
  mem_ptr->release((cudaStream_t *)(streams), gpu_indexes, gpu_count);
}
