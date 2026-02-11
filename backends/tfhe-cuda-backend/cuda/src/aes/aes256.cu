#include "../../include/aes/aes.h"
#include "aes256.cuh"

void cuda_integer_aes_ctr_256_encrypt_64_async(
    CudaStreamsFFI streams, CudaRadixCiphertextFFI *output,
    CudaRadixCiphertextFFI const *iv, CudaRadixCiphertextFFI const *round_keys,
    const uint64_t *counter_bits_le_all_blocks, uint32_t num_aes_inputs,
    int8_t *mem_ptr, void *const *bsks, void *const *ksks) {

  host_integer_aes_ctr_256_encrypt<uint64_t>(
      CudaStreams(streams), output, iv, round_keys, counter_bits_le_all_blocks,
      num_aes_inputs, (int_aes_encrypt_buffer<uint64_t> *)mem_ptr, bsks,
      (uint64_t **)ksks);
}

uint64_t scratch_cuda_integer_key_expansion_256_64_async(
    CudaStreamsFFI streams, int8_t **mem_ptr, uint32_t glwe_dimension,
    uint32_t polynomial_size, uint32_t lwe_dimension, uint32_t ks_level,
    uint32_t ks_base_log, uint32_t pbs_level, uint32_t pbs_base_log,
    uint32_t grouping_factor, uint32_t message_modulus, uint32_t carry_modulus,
    PBS_TYPE pbs_type, bool allocate_gpu_memory,
    PBS_MS_REDUCTION_T noise_reduction_type) {

  int_radix_params params(pbs_type, glwe_dimension, polynomial_size,
                          glwe_dimension * polynomial_size, lwe_dimension,
                          ks_level, ks_base_log, pbs_level, pbs_base_log,
                          grouping_factor, message_modulus, carry_modulus,
                          noise_reduction_type);

  return scratch_cuda_integer_key_expansion_256<uint64_t>(
      CudaStreams(streams), (int_key_expansion_256_buffer<uint64_t> **)mem_ptr,
      params, allocate_gpu_memory);
}

void cuda_integer_key_expansion_256_64_async(
    CudaStreamsFFI streams, CudaRadixCiphertextFFI *expanded_keys,
    CudaRadixCiphertextFFI const *key, int8_t *mem_ptr, void *const *bsks,
    void *const *ksks) {

  host_integer_key_expansion_256<uint64_t>(
      CudaStreams(streams), expanded_keys, key,
      (int_key_expansion_256_buffer<uint64_t> *)mem_ptr, bsks,
      (uint64_t **)ksks);
}

void cleanup_cuda_integer_key_expansion_256_64(CudaStreamsFFI streams,
                                               int8_t **mem_ptr_void) {
  int_key_expansion_256_buffer<uint64_t> *mem_ptr =
      (int_key_expansion_256_buffer<uint64_t> *)(*mem_ptr_void);

  mem_ptr->release(CudaStreams(streams));
  delete mem_ptr;
  *mem_ptr_void = nullptr;
}
