#include "ilog2.cuh"

uint64_t scratch_integer_count_of_consecutive_bits_kb_64(
    void *const *streams, uint32_t const *gpu_indexes, uint32_t gpu_count,
    int8_t **mem_ptr, uint32_t glwe_dimension, uint32_t polynomial_size,
    uint32_t lwe_dimension, uint32_t ks_level, uint32_t ks_base_log,
    uint32_t pbs_level, uint32_t pbs_base_log, uint32_t grouping_factor,
    uint32_t num_blocks, uint32_t counter_num_blocks, uint32_t message_modulus,
    uint32_t carry_modulus, PBS_TYPE pbs_type, Direction direction,
    BitValue bit_value, bool allocate_gpu_memory,
    PBS_MS_REDUCTION_T noise_reduction_type) {

  int_radix_params params(pbs_type, glwe_dimension, polynomial_size,
                          glwe_dimension * polynomial_size, lwe_dimension,
                          ks_level, ks_base_log, pbs_level, pbs_base_log,
                          grouping_factor, message_modulus, carry_modulus,
                          noise_reduction_type);

  return scratch_integer_count_of_consecutive_bits<uint64_t>(
      (cudaStream_t *)(streams), gpu_indexes, gpu_count, params,
      (int_count_of_consecutive_bits_buffer<uint64_t> **)mem_ptr, num_blocks,
      counter_num_blocks, direction, bit_value, allocate_gpu_memory);
}

// Computes the number of consecutive bits in an encrypted integer.
// This function counts the number of consecutive 0s or 1s starting from either
// the leading or trailing end of an encrypted integer. The final count is
// stored in the output ciphertext.
//
void cuda_integer_count_of_consecutive_bits_kb_64(
    void *const *streams, uint32_t const *gpu_indexes, uint32_t gpu_count,
    CudaRadixCiphertextFFI *output_ct, CudaRadixCiphertextFFI const *input_ct,
    int8_t *mem_ptr, void *const *bsks, void *const *ksks,
    const CudaModulusSwitchNoiseReductionKeyFFI *ms_noise_reduction_key) {

  host_integer_count_of_consecutive_bits<uint64_t>(
      (cudaStream_t *)streams, gpu_indexes, gpu_count, output_ct, input_ct,
      (int_count_of_consecutive_bits_buffer<uint64_t> *)mem_ptr, bsks,
      (uint64_t **)ksks, ms_noise_reduction_key);
}

void cleanup_cuda_integer_count_of_consecutive_bits_kb_64(
    void *const *streams, uint32_t const *gpu_indexes, uint32_t gpu_count,
    int8_t **mem_ptr_void) {

  int_count_of_consecutive_bits_buffer<uint64_t> *mem_ptr =
      (int_count_of_consecutive_bits_buffer<uint64_t> *)(*mem_ptr_void);

  mem_ptr->release((cudaStream_t *)streams, gpu_indexes, gpu_count);

  delete mem_ptr;
  *mem_ptr_void = nullptr;
}

uint64_t scratch_integer_ilog2_kb_64(
    void *const *streams, uint32_t const *gpu_indexes, uint32_t gpu_count,
    int8_t **mem_ptr, uint32_t glwe_dimension, uint32_t polynomial_size,
    uint32_t lwe_dimension, uint32_t ks_level, uint32_t ks_base_log,
    uint32_t pbs_level, uint32_t pbs_base_log, uint32_t grouping_factor,
    uint32_t message_modulus, uint32_t carry_modulus, PBS_TYPE pbs_type,
    uint32_t input_num_blocks, uint32_t counter_num_blocks,
    uint32_t num_bits_in_ciphertext, bool allocate_gpu_memory,
    PBS_MS_REDUCTION_T noise_reduction_type) {

  int_radix_params params(pbs_type, glwe_dimension, polynomial_size,
                          glwe_dimension * polynomial_size, lwe_dimension,
                          ks_level, ks_base_log, pbs_level, pbs_base_log,
                          grouping_factor, message_modulus, carry_modulus,
                          noise_reduction_type);

  return scratch_integer_ilog2<uint64_t>(
      (cudaStream_t *)(streams), gpu_indexes, gpu_count, params,
      (int_ilog2_buffer<uint64_t> **)mem_ptr, input_num_blocks,
      counter_num_blocks, num_bits_in_ciphertext, allocate_gpu_memory);
}

// Computes the integer logarithm base 2 of an encrypted integer.
// This is equivalent to finding the position of the most significant bit.
// The result is stored in the output ciphertext.
//
void cuda_integer_ilog2_kb_64(
    void *const *streams, uint32_t const *gpu_indexes, uint32_t gpu_count,
    CudaRadixCiphertextFFI *output_ct, CudaRadixCiphertextFFI const *input_ct,
    CudaRadixCiphertextFFI const *trivial_ct_neg_n,
    CudaRadixCiphertextFFI const *trivial_ct_2,
    CudaRadixCiphertextFFI const *trivial_ct_m_minus_1_block, int8_t *mem_ptr,
    void *const *bsks, void *const *ksks,
    const CudaModulusSwitchNoiseReductionKeyFFI *ms_noise_reduction_key) {

  host_integer_ilog2<uint64_t>((cudaStream_t *)streams, gpu_indexes, gpu_count,
                               output_ct, input_ct, trivial_ct_neg_n,
                               trivial_ct_2, trivial_ct_m_minus_1_block,
                               (int_ilog2_buffer<uint64_t> *)mem_ptr, bsks,
                               (uint64_t **)ksks, ms_noise_reduction_key);
}

void cleanup_cuda_integer_ilog2_kb_64(void *const *streams,
                                      uint32_t const *gpu_indexes,
                                      uint32_t gpu_count,
                                      int8_t **mem_ptr_void) {

  int_ilog2_buffer<uint64_t> *mem_ptr =
      (int_ilog2_buffer<uint64_t> *)(*mem_ptr_void);

  mem_ptr->release((cudaStream_t *)streams, gpu_indexes, gpu_count);

  delete mem_ptr;
  *mem_ptr_void = nullptr;
}
