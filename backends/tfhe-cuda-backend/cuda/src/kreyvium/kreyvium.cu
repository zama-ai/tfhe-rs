#include "../../include/kreyvium/kreyvium.h"
#include "kreyvium.cuh"

uint64_t scratch_cuda_kreyvium_generate_keystream_64_async(
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

  return scratch_cuda_kreyvium_encrypt<uint64_t>(
      CudaStreams(streams), (int_kreyvium_buffer<uint64_t> **)mem_ptr, params,
      allocate_gpu_memory, num_inputs);
}

void cuda_kreyvium_generate_keystream_64_async(
    CudaStreamsFFI streams, CudaRadixCiphertextFFI *keystream_output,
    const CudaRadixCiphertextFFI *key, const CudaRadixCiphertextFFI *iv,
    uint32_t num_inputs, uint32_t num_steps, int8_t *mem_ptr, void *const *bsks,
    void *const *ksks) {

  auto buffer = (int_kreyvium_buffer<uint64_t> *)mem_ptr;

  host_kreyvium_generate_keystream<uint64_t>(
      CudaStreams(streams), keystream_output, key, iv, num_inputs, num_steps,
      buffer, bsks, (uint64_t *const *)ksks);
}

void cleanup_cuda_kreyvium_generate_keystream_64(CudaStreamsFFI streams,
                                                 int8_t **mem_ptr_void) {

  int_kreyvium_buffer<uint64_t> *mem_ptr =
      (int_kreyvium_buffer<uint64_t> *)(*mem_ptr_void);

  mem_ptr->release(CudaStreams(streams));

  delete mem_ptr;
  *mem_ptr_void = nullptr;
}
