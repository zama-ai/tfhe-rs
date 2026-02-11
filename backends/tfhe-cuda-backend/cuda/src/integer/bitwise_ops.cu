#include "integer/bitwise_ops.cuh"

uint64_t scratch_cuda_boolean_bitop_64_async(
    CudaStreamsFFI streams, int8_t **mem_ptr, uint32_t glwe_dimension,
    uint32_t polynomial_size, uint32_t big_lwe_dimension,
    uint32_t small_lwe_dimension, uint32_t ks_level, uint32_t ks_base_log,
    uint32_t pbs_level, uint32_t pbs_base_log, uint32_t grouping_factor,
    uint32_t lwe_ciphertext_count, uint32_t message_modulus,
    uint32_t carry_modulus, PBS_TYPE pbs_type, BITOP_TYPE op_type,
    bool is_unchecked, bool allocate_gpu_memory,
    PBS_MS_REDUCTION_T noise_reduction_type) {

  int_radix_params params(pbs_type, glwe_dimension, polynomial_size,
                          big_lwe_dimension, small_lwe_dimension, ks_level,
                          ks_base_log, pbs_level, pbs_base_log, grouping_factor,
                          message_modulus, carry_modulus, noise_reduction_type);

  return scratch_cuda_boolean_bitop<uint64_t>(
      CudaStreams(streams), (boolean_bitop_buffer<uint64_t> **)mem_ptr,
      lwe_ciphertext_count, params, op_type, is_unchecked, allocate_gpu_memory);
}

void cuda_boolean_bitop_64_async(CudaStreamsFFI streams,
                                 CudaRadixCiphertextFFI *lwe_array_out,
                                 CudaRadixCiphertextFFI const *lwe_array_1,
                                 CudaRadixCiphertextFFI const *lwe_array_2,
                                 int8_t *mem_ptr, void *const *bsks,
                                 void *const *ksks) {

  host_boolean_bitop<uint64_t>(
      CudaStreams(streams), lwe_array_out, lwe_array_1, lwe_array_2,
      (boolean_bitop_buffer<uint64_t> *)mem_ptr, bsks, (uint64_t **)(ksks));
}

void cleanup_cuda_boolean_bitop_64(CudaStreamsFFI streams,
                                   int8_t **mem_ptr_void) {

  boolean_bitop_buffer<uint64_t> *mem_ptr =
      (boolean_bitop_buffer<uint64_t> *)(*mem_ptr_void);
  mem_ptr->release(CudaStreams(streams));
  delete mem_ptr;
  *mem_ptr_void = nullptr;
}

uint64_t scratch_cuda_boolean_bitnot_64_async(
    CudaStreamsFFI streams, int8_t **mem_ptr, uint32_t glwe_dimension,
    uint32_t polynomial_size, uint32_t big_lwe_dimension,
    uint32_t small_lwe_dimension, uint32_t ks_level, uint32_t ks_base_log,
    uint32_t pbs_level, uint32_t pbs_base_log, uint32_t grouping_factor,
    uint32_t message_modulus, uint32_t carry_modulus, PBS_TYPE pbs_type,
    uint32_t lwe_ciphertext_count, bool is_unchecked, bool allocate_gpu_memory,
    PBS_MS_REDUCTION_T noise_reduction_type) {

  int_radix_params params(pbs_type, glwe_dimension, polynomial_size,
                          big_lwe_dimension, small_lwe_dimension, ks_level,
                          ks_base_log, pbs_level, pbs_base_log, grouping_factor,
                          message_modulus, carry_modulus, noise_reduction_type);

  return scratch_cuda_boolean_bitnot<uint64_t>(
      CudaStreams(streams), (boolean_bitnot_buffer<uint64_t> **)mem_ptr, params,
      lwe_ciphertext_count, is_unchecked, allocate_gpu_memory);
}

void cuda_boolean_bitnot_64_async(CudaStreamsFFI streams,
                                  CudaRadixCiphertextFFI *lwe_array,
                                  int8_t *mem_ptr, void *const *bsks,
                                  void *const *ksks) {
  host_boolean_bitnot<uint64_t>(CudaStreams(streams), lwe_array,
                                (boolean_bitnot_buffer<uint64_t> *)mem_ptr,
                                bsks, (uint64_t **)(ksks));
}

void cleanup_cuda_boolean_bitnot_64(CudaStreamsFFI streams,
                                    int8_t **mem_ptr_void) {

  boolean_bitnot_buffer<uint64_t> *mem_ptr =
      (boolean_bitnot_buffer<uint64_t> *)(*mem_ptr_void);
  mem_ptr->release(CudaStreams(streams));
  delete mem_ptr;
  *mem_ptr_void = nullptr;
}

uint64_t scratch_cuda_integer_bitop_64_async(
    CudaStreamsFFI streams, int8_t **mem_ptr, uint32_t glwe_dimension,
    uint32_t polynomial_size, uint32_t big_lwe_dimension,
    uint32_t small_lwe_dimension, uint32_t ks_level, uint32_t ks_base_log,
    uint32_t pbs_level, uint32_t pbs_base_log, uint32_t grouping_factor,
    uint32_t lwe_ciphertext_count, uint32_t message_modulus,
    uint32_t carry_modulus, PBS_TYPE pbs_type, BITOP_TYPE op_type,
    bool allocate_gpu_memory, PBS_MS_REDUCTION_T noise_reduction_type) {

  int_radix_params params(pbs_type, glwe_dimension, polynomial_size,
                          big_lwe_dimension, small_lwe_dimension, ks_level,
                          ks_base_log, pbs_level, pbs_base_log, grouping_factor,
                          message_modulus, carry_modulus, noise_reduction_type);

  return scratch_cuda_bitop<uint64_t>(
      CudaStreams(streams), (int_bitop_buffer<uint64_t> **)mem_ptr,
      lwe_ciphertext_count, params, op_type, allocate_gpu_memory);
}

uint64_t scratch_cuda_integer_scalar_bitop_64_async(
    CudaStreamsFFI streams, int8_t **mem_ptr, uint32_t glwe_dimension,
    uint32_t polynomial_size, uint32_t big_lwe_dimension,
    uint32_t small_lwe_dimension, uint32_t ks_level, uint32_t ks_base_log,
    uint32_t pbs_level, uint32_t pbs_base_log, uint32_t grouping_factor,
    uint32_t lwe_ciphertext_count, uint32_t message_modulus,
    uint32_t carry_modulus, PBS_TYPE pbs_type, BITOP_TYPE op_type,
    bool allocate_gpu_memory, PBS_MS_REDUCTION_T noise_reduction_type) {

  int_radix_params params(pbs_type, glwe_dimension, polynomial_size,
                          big_lwe_dimension, small_lwe_dimension, ks_level,
                          ks_base_log, pbs_level, pbs_base_log, grouping_factor,
                          message_modulus, carry_modulus, noise_reduction_type);

  return scratch_cuda_bitop<uint64_t>(
      CudaStreams(streams), (int_bitop_buffer<uint64_t> **)mem_ptr,
      lwe_ciphertext_count, params, op_type, allocate_gpu_memory);
}

void cuda_bitnot_ciphertext_64(CudaStreamsFFI streams,
                               CudaRadixCiphertextFFI *radix_ciphertext,
                               uint32_t ct_message_modulus,
                               uint32_t param_message_modulus,
                               uint32_t param_carry_modulus) {
  auto cuda_streams = CudaStreams(streams);
  host_bitnot<uint64_t>(cuda_streams, radix_ciphertext, ct_message_modulus,
                        param_message_modulus, param_carry_modulus);
  cuda_synchronize_stream(cuda_streams.stream(0), cuda_streams.gpu_index(0));
}

void cuda_integer_bitop_64_async(CudaStreamsFFI streams,
                                 CudaRadixCiphertextFFI *lwe_array_out,
                                 CudaRadixCiphertextFFI const *lwe_array_1,
                                 CudaRadixCiphertextFFI const *lwe_array_2,
                                 int8_t *mem_ptr, void *const *bsks,
                                 void *const *ksks) {

  host_bitop<uint64_t>(CudaStreams(streams), lwe_array_out, lwe_array_1,
                       lwe_array_2, (int_bitop_buffer<uint64_t> *)mem_ptr, bsks,
                       (uint64_t **)(ksks));
}

void cleanup_cuda_integer_bitop_64(CudaStreamsFFI streams,
                                   int8_t **mem_ptr_void) {

  int_bitop_buffer<uint64_t> *mem_ptr =
      (int_bitop_buffer<uint64_t> *)(*mem_ptr_void);
  mem_ptr->release(CudaStreams(streams));
  delete mem_ptr;
  *mem_ptr_void = nullptr;
}

void cleanup_cuda_integer_scalar_bitop_64(CudaStreamsFFI streams,
                                          int8_t **mem_ptr_void) {

  int_bitop_buffer<uint64_t> *mem_ptr =
      (int_bitop_buffer<uint64_t> *)(*mem_ptr_void);
  mem_ptr->release(CudaStreams(streams));
  delete mem_ptr;
  *mem_ptr_void = nullptr;
}

void update_degrees_after_bitand(uint64_t *output_degrees,
                                 uint64_t *lwe_array_1_degrees,
                                 uint64_t *lwe_array_2_degrees,
                                 uint32_t num_radix_blocks) {
  for (uint i = 0; i < num_radix_blocks; i++) {
    output_degrees[i] =
        std::min(lwe_array_1_degrees[i], lwe_array_2_degrees[i]);
  }
}

void update_degrees_after_bitor(uint64_t *output_degrees,
                                uint64_t *lwe_array_1_degrees,
                                uint64_t *lwe_array_2_degrees,
                                uint32_t num_radix_blocks) {
  for (uint i = 0; i < num_radix_blocks; i++) {
    auto max = std::max(lwe_array_1_degrees[i], lwe_array_2_degrees[i]);
    auto min = std::min(lwe_array_1_degrees[i], lwe_array_2_degrees[i]);
    auto result = max;

    for (uint j = 0; j < min + 1; j++) {
      if ((max | j) > result) {
        result = max | j;
      }
    }
    output_degrees[i] = result;
  }
}

void update_degrees_after_bitxor(uint64_t *output_degrees,
                                 uint64_t *lwe_array_1_degrees,
                                 uint64_t *lwe_array_2_degrees,
                                 uint32_t num_radix_blocks) {
  for (uint i = 0; i < num_radix_blocks; i++) {
    auto max = std::max(lwe_array_1_degrees[i], lwe_array_2_degrees[i]);
    auto min = std::min(lwe_array_1_degrees[i], lwe_array_2_degrees[i]);
    auto result = max;

    // Try every possibility to find the worst case
    for (uint j = 0; j < min + 1; j++) {
      if ((max ^ j) > result) {
        result = max ^ j;
      }
    }
    output_degrees[i] = result;
  }
}
