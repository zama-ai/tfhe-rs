#include "aes.cuh"

uint64_t scratch_cuda_integer_aes_encrypt_64(
    void *const *streams, uint32_t const *gpu_indexes, uint32_t gpu_count,
    int8_t **mem_ptr, uint32_t glwe_dimension, uint32_t polynomial_size,
    uint32_t lwe_dimension, uint32_t ks_level, uint32_t ks_base_log,
    uint32_t pbs_level, uint32_t pbs_base_log, uint32_t grouping_factor,
    uint32_t message_modulus, uint32_t carry_modulus, PBS_TYPE pbs_type,
    bool allocate_gpu_memory, bool allocate_ms_array) {

  int_radix_params params(pbs_type, glwe_dimension, polynomial_size,
                          glwe_dimension * polynomial_size, lwe_dimension,
                          ks_level, ks_base_log, pbs_level, pbs_base_log,
                          grouping_factor, message_modulus, carry_modulus,
                          allocate_ms_array);

  return scratch_cuda_integer_aes_encrypt<uint64_t>(
      (cudaStream_t *)(streams), gpu_indexes, gpu_count,
      (int_aes_encrypt_buffer<uint64_t> **)mem_ptr, params,
      allocate_gpu_memory);
}

void cuda_integer_aes_encrypt_64(
    void *const *streams, uint32_t const *gpu_indexes, uint32_t gpu_count,
    CudaRadixCiphertextFFI *state, CudaRadixCiphertextFFI const *round_keys,
    int8_t *mem_ptr, void *const *bsks, void *const *ksks,
    const CudaModulusSwitchNoiseReductionKeyFFI *ms_noise_reduction_key) {

  host_integer_aes_encrypt<uint64_t>(
      (cudaStream_t *)streams, gpu_indexes, gpu_count, state, round_keys,
      (int_aes_encrypt_buffer<uint64_t> *)mem_ptr, bsks, (uint64_t **)ksks,
      ms_noise_reduction_key);
}

void cleanup_cuda_integer_aes_encrypt_64(void *const *streams,
                                         uint32_t const *gpu_indexes,
                                         uint32_t gpu_count,
                                         int8_t **mem_ptr_void) {

  int_aes_encrypt_buffer<uint64_t> *mem_ptr =
      (int_aes_encrypt_buffer<uint64_t> *)(*mem_ptr_void);

  mem_ptr->release((cudaStream_t *)streams, gpu_indexes, gpu_count);

  delete mem_ptr;
  *mem_ptr_void = nullptr;
}

void cuda_integer_aes_mul_by_2_byte_64(
    void *const *streams, uint32_t const *gpu_indexes, uint32_t gpu_count,
    CudaRadixCiphertextFFI *byte, int8_t *mem_ptr, void *const *bsks,
    void *const *ksks,
    const CudaModulusSwitchNoiseReductionKeyFFI *ms_noise_reduction_key) {

  auto *mem = (int_aes_encrypt_buffer<uint64_t> *)mem_ptr;

  CudaRadixCiphertextFFI tmp;
  as_radix_ciphertext_slice<uint64_t>(&tmp, mem->tmp_byte_2, 0, 8);

  mul_by_2<uint64_t>((cudaStream_t *)streams, gpu_indexes, gpu_count, &tmp,
                     byte, mem);

  copy_radix_ciphertext_async<uint64_t>(((cudaStream_t *)streams)[0],
                                        gpu_indexes[0], byte, &tmp);

  fhe_flush<uint64_t>((cudaStream_t *)streams, gpu_indexes, gpu_count, byte,
                      mem, bsks, (uint64_t **)ksks, ms_noise_reduction_key);
}

void cuda_integer_aes_mix_columns_64(
    void *const *streams, uint32_t const *gpu_indexes, uint32_t gpu_count,
    CudaRadixCiphertextFFI *col, int8_t *mem_ptr, void *const *bsks,
    void *const *ksks,
    const CudaModulusSwitchNoiseReductionKeyFFI *ms_noise_reduction_key) {
  auto *mem = (int_aes_encrypt_buffer<uint64_t> *)mem_ptr;

  mix_columns<uint64_t>((cudaStream_t *)streams, gpu_indexes, gpu_count, col,
                        mem, bsks, (uint64_t **)ksks, ms_noise_reduction_key);

  fhe_flush<uint64_t>((cudaStream_t *)streams, gpu_indexes, gpu_count, col, mem,
                      bsks, (uint64_t **)ksks, ms_noise_reduction_key);
}

void cuda_integer_aes_sbox_byte_64(
    void *const *streams, uint32_t const *gpu_indexes, uint32_t gpu_count,
    CudaRadixCiphertextFFI *byte, int8_t *mem_ptr, void *const *bsks,
    void *const *ksks,
    const CudaModulusSwitchNoiseReductionKeyFFI *ms_noise_reduction_key) {

  auto *mem = (int_aes_encrypt_buffer<uint64_t> *)mem_ptr;

  fhe_sbox<uint64_t>((cudaStream_t *)streams, gpu_indexes, gpu_count, byte, mem,
                     bsks, (uint64_t **)ksks, ms_noise_reduction_key);

  fhe_flush<uint64_t>((cudaStream_t *)streams, gpu_indexes, gpu_count, byte,
                      mem, bsks, (uint64_t **)ksks, ms_noise_reduction_key);
}