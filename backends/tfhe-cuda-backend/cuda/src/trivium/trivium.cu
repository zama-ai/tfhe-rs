#include "../../include/trivium/trivium.h"
#include "trivium.cuh"

uint64_t scratch_cuda_trivium_generate_keystream_64_async(
    CudaStreamsFFI streams, int8_t **mem_ptr, uint32_t glwe_dimension,
    uint32_t polynomial_size, uint32_t lwe_dimension, uint32_t ks_level,
    uint32_t ks_base_log, uint32_t pbs_level, uint32_t pbs_base_log,
    uint32_t grouping_factor, uint32_t message_modulus, uint32_t carry_modulus,
    PBS_TYPE pbs_type, bool allocate_gpu_memory,
    PBS_MS_REDUCTION_T noise_reduction_type, uint32_t num_inputs) {

  int_radix_params params(pbs_type, glwe_dimension, polynomial_size,
                          glwe_dimension * polynomial_size, lwe_dimension,
                          ks_level, ks_base_log, pbs_level, pbs_base_log,
                          grouping_factor, message_modulus, carry_modulus,
                          noise_reduction_type);

  return scratch_cuda_trivium_encrypt<uint64_t>(
      CudaStreams(streams), (int_trivium_buffer<uint64_t> **)mem_ptr, params,
      allocate_gpu_memory, num_inputs);
}

void cuda_trivium_generate_keystream_64_async(
    CudaStreamsFFI streams, CudaRadixCiphertextFFI *keystream_output,
    const CudaRadixCiphertextFFI *key, const CudaRadixCiphertextFFI *iv,
    uint32_t num_inputs, uint32_t num_steps, int8_t *mem_ptr, void *const *bsks,
    void *const *ksks) {

  auto buffer = (int_trivium_buffer<uint64_t> *)mem_ptr;

  host_trivium_generate_keystream<uint64_t>(
      CudaStreams(streams), keystream_output, key, iv, num_inputs, num_steps,
      buffer, bsks, (uint64_t *const *)ksks);
}

void cleanup_cuda_trivium_generate_keystream_64(CudaStreamsFFI streams,
                                                int8_t **mem_ptr_void) {

  int_trivium_buffer<uint64_t> *mem_ptr =
      (int_trivium_buffer<uint64_t> *)(*mem_ptr_void);

  mem_ptr->release(CudaStreams(streams));

  delete mem_ptr;
  *mem_ptr_void = nullptr;
}

template <typename Torus>
uint64_t scratch_cuda_trivium_stateful_encrypt(
    CudaStreams streams, int_trivium_stateful_buffer<Torus> **mem_ptr,
    int_radix_params params, bool allocate_gpu_memory, uint32_t num_inputs) {

  uint64_t size_tracker = 0;
  *mem_ptr = new int_trivium_stateful_buffer<Torus>(
      streams, params, allocate_gpu_memory, num_inputs, size_tracker);
  return size_tracker;
}

void cuda_trivium_init_async(CudaStreamsFFI streams,
                             CudaRadixCiphertextFFI *a_reg,
                             CudaRadixCiphertextFFI *b_reg,
                             CudaRadixCiphertextFFI *c_reg,
                             const CudaRadixCiphertextFFI *key,
                             const CudaRadixCiphertextFFI *iv,
                             uint32_t num_inputs, int8_t *mem_ptr,
                             void *const *bsks, void *const *ksks) {

  auto buffer = (int_trivium_stateful_buffer<uint64_t> *)mem_ptr;
  host_trivium_init_stateful<uint64_t>(CudaStreams(streams), buffer, a_reg,
                                       b_reg, c_reg, key, iv, bsks,
                                       (uint64_t *const *)ksks);
}

void cuda_trivium_step_async(CudaStreamsFFI streams,
                             CudaRadixCiphertextFFI *keystream_output,
                             CudaRadixCiphertextFFI *a_reg,
                             CudaRadixCiphertextFFI *b_reg,
                             CudaRadixCiphertextFFI *c_reg, uint32_t num_inputs,
                             uint32_t num_steps, int8_t *mem_ptr,
                             void *const *bsks, void *const *ksks) {

  auto buffer = (int_trivium_stateful_buffer<uint64_t> *)mem_ptr;
  host_trivium_step_stateful<uint64_t>(CudaStreams(streams), keystream_output,
                                       a_reg, b_reg, c_reg, num_steps, buffer,
                                       bsks, (uint64_t *const *)ksks);
}

uint64_t scratch_cuda_trivium_init_async(
    CudaStreamsFFI streams, int8_t **mem_ptr, uint32_t glwe_dimension,
    uint32_t polynomial_size, uint32_t lwe_dimension, uint32_t ks_level,
    uint32_t ks_base_log, uint32_t pbs_level, uint32_t pbs_base_log,
    uint32_t grouping_factor, uint32_t message_modulus, uint32_t carry_modulus,
    PBS_TYPE pbs_type, bool allocate_gpu_memory,
    PBS_MS_REDUCTION_T noise_reduction_type, uint32_t num_inputs) {

  int_radix_params params(pbs_type, glwe_dimension, polynomial_size,
                          glwe_dimension * polynomial_size, lwe_dimension,
                          ks_level, ks_base_log, pbs_level, pbs_base_log,
                          grouping_factor, message_modulus, carry_modulus,
                          noise_reduction_type);

  return scratch_cuda_trivium_stateful_encrypt<uint64_t>(
      CudaStreams(streams), (int_trivium_stateful_buffer<uint64_t> **)mem_ptr,
      params, allocate_gpu_memory, num_inputs);
}

void cleanup_cuda_trivium_init(CudaStreamsFFI streams, int8_t **mem_ptr_void) {
  int_trivium_stateful_buffer<uint64_t> *mem_ptr =
      (int_trivium_stateful_buffer<uint64_t> *)(*mem_ptr_void);

  mem_ptr->release(CudaStreams(streams));
  delete mem_ptr;
  *mem_ptr_void = nullptr;
}

uint64_t scratch_cuda_trivium_step_async(
    CudaStreamsFFI streams, int8_t **mem_ptr, uint32_t glwe_dimension,
    uint32_t polynomial_size, uint32_t lwe_dimension, uint32_t ks_level,
    uint32_t ks_base_log, uint32_t pbs_level, uint32_t pbs_base_log,
    uint32_t grouping_factor, uint32_t message_modulus, uint32_t carry_modulus,
    PBS_TYPE pbs_type, bool allocate_gpu_memory,
    PBS_MS_REDUCTION_T noise_reduction_type, uint32_t num_inputs) {

  int_radix_params params(pbs_type, glwe_dimension, polynomial_size,
                          glwe_dimension * polynomial_size, lwe_dimension,
                          ks_level, ks_base_log, pbs_level, pbs_base_log,
                          grouping_factor, message_modulus, carry_modulus,
                          noise_reduction_type);

  return scratch_cuda_trivium_stateful_encrypt<uint64_t>(
      CudaStreams(streams), (int_trivium_stateful_buffer<uint64_t> **)mem_ptr,
      params, allocate_gpu_memory, num_inputs);
}

void cleanup_cuda_trivium_step(CudaStreamsFFI streams, int8_t **mem_ptr_void) {
  int_trivium_stateful_buffer<uint64_t> *mem_ptr =
      (int_trivium_stateful_buffer<uint64_t> *)(*mem_ptr_void);

  mem_ptr->release(CudaStreams(streams));
  delete mem_ptr;
  *mem_ptr_void = nullptr;
}
