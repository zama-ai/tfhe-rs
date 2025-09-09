#include "aes.cuh"

uint64_t scratch_cuda_integer_aes_encrypt_64(
    void *const *streams, uint32_t const *gpu_indexes, uint32_t gpu_count,
    int8_t **mem_ptr, uint32_t glwe_dimension, uint32_t polynomial_size,
    uint32_t lwe_dimension, uint32_t ks_level, uint32_t ks_base_log,
    uint32_t pbs_level, uint32_t pbs_base_log, uint32_t grouping_factor,
    uint32_t message_modulus, uint32_t carry_modulus, PBS_TYPE pbs_type,
    bool allocate_gpu_memory, bool allocate_ms_array, uint32_t num_blocks) {

  int_radix_params params(pbs_type, glwe_dimension, polynomial_size,
                          glwe_dimension * polynomial_size, lwe_dimension,
                          ks_level, ks_base_log, pbs_level, pbs_base_log,
                          grouping_factor, message_modulus, carry_modulus,
                          allocate_ms_array);

  return scratch_cuda_integer_aes_encrypt<uint64_t>(
      (cudaStream_t *)(streams), gpu_indexes, gpu_count,
      (int_aes_encrypt_buffer<uint64_t> **)mem_ptr, params, allocate_gpu_memory,
      num_blocks);
}

void cuda_integer_aes_ctr_encrypt_64(
    void *const *streams, uint32_t const *gpu_indexes, uint32_t gpu_count,
    CudaRadixCiphertextFFI *output, CudaRadixCiphertextFFI const *iv,
    CudaRadixCiphertextFFI const *round_keys,
    const uint64_t *counter_bits_le_all_blocks, uint32_t num_blocks,
    int8_t *mem_ptr, void *const *bsks, void *const *ksks,
    const CudaModulusSwitchNoiseReductionKeyFFI *ms_noise_reduction_key) {

  host_integer_aes_ctr_encrypt<uint64_t>(
      (cudaStream_t *)streams, gpu_indexes, gpu_count, output, iv, round_keys,
      counter_bits_le_all_blocks, num_blocks,
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

void cuda_test_sbox_64(void *const *streams, uint32_t const *gpu_indexes,
                       uint32_t gpu_count, CudaRadixCiphertextFFI *output,
                       const CudaRadixCiphertextFFI *input, int8_t *mem_ptr,
                       void *const *bsks, void *const *ksks,
                       uint32_t num_blocks) {
  cudaStream_t stream = ((cudaStream_t *)streams)[0];
  uint32_t gpu_index = gpu_indexes[0];
  auto buffer = (int_aes_encrypt_buffer<uint64_t> *)mem_ptr;

  CudaRadixCiphertextFFI *tmp_bitsliced = buffer->tmp_transposed_states_buffer;

  transpose_blocks_to_bitsliced<uint64_t>(stream, gpu_index, tmp_bitsliced,
                                          input, num_blocks, 8);

  CudaRadixCiphertextFFI slices[8];
  for (int i = 0; i < 8; i++) {
    as_radix_ciphertext_slice<uint64_t>(&slices[i], tmp_bitsliced,
                                        i * num_blocks, (i + 1) * num_blocks);
  }

  vectorized_sbox_byte<uint64_t>((cudaStream_t *)streams, gpu_indexes,
                                 gpu_count, slices, num_blocks, buffer, bsks,
                                 (uint64_t **)ksks, nullptr);

  transpose_bitsliced_to_blocks<uint64_t>(stream, gpu_index, output,
                                          tmp_bitsliced, num_blocks, 8);
}

void cuda_test_shift_rows_64(void *const *streams, uint32_t const *gpu_indexes,
                             uint32_t gpu_count, CudaRadixCiphertextFFI *output,
                             const CudaRadixCiphertextFFI *input,
                             int8_t *mem_ptr, uint32_t num_blocks) {
  cudaStream_t stream = ((cudaStream_t *)streams)[0];
  uint32_t gpu_index = gpu_indexes[0];
  auto buffer = (int_aes_encrypt_buffer<uint64_t> *)mem_ptr;

  CudaRadixCiphertextFFI *tmp_bitsliced = buffer->tmp_transposed_states_buffer;

  transpose_blocks_to_bitsliced<uint64_t>(stream, gpu_index, tmp_bitsliced,
                                          input, num_blocks, 128);

  vectorized_shift_rows<uint64_t>((cudaStream_t *)streams, gpu_indexes,
                                  gpu_count, tmp_bitsliced, num_blocks, buffer);

  transpose_bitsliced_to_blocks<uint64_t>(stream, gpu_index, output,
                                          tmp_bitsliced, num_blocks, 128);
}

void cuda_test_mul_by_2_64(void *const *streams, uint32_t const *gpu_indexes,
                           uint32_t gpu_count, CudaRadixCiphertextFFI *output,
                           const CudaRadixCiphertextFFI *input, int8_t *mem_ptr,
                           void *const *bsks, void *const *ksks,
                           uint32_t num_blocks) {
  cudaStream_t stream = ((cudaStream_t *)streams)[0];
  uint32_t gpu_index = gpu_indexes[0];
  auto buffer = (int_aes_encrypt_buffer<uint64_t> *)mem_ptr;

  CudaRadixCiphertextFFI *tmp_bitsliced_input =
      buffer->tmp_initial_states_buffer;
  CudaRadixCiphertextFFI *tmp_bitsliced_output =
      buffer->tmp_transposed_states_buffer;

  transpose_blocks_to_bitsliced<uint64_t>(
      stream, gpu_index, tmp_bitsliced_input, input, num_blocks, 8);

  CudaRadixCiphertextFFI in_slices[8];
  for (int i = 0; i < 8; i++) {
    as_radix_ciphertext_slice<uint64_t>(&in_slices[i], tmp_bitsliced_input,
                                        i * num_blocks, (i + 1) * num_blocks);
  }

  CudaRadixCiphertextFFI out_slices[8];
  for (int i = 0; i < 8; i++) {
    as_radix_ciphertext_slice<uint64_t>(&out_slices[i], tmp_bitsliced_output,
                                        i * num_blocks, (i + 1) * num_blocks);
  }

  vectorized_mul_by_2<uint64_t>((cudaStream_t *)streams, gpu_indexes, gpu_count,
                                out_slices, in_slices, buffer, bsks,
                                (uint64_t **)ksks, nullptr);

  vectorized_aes_flush<uint64_t>((cudaStream_t *)streams, gpu_indexes,
                                 gpu_count, tmp_bitsliced_output, buffer, bsks,
                                 (uint64_t **)ksks, nullptr);

  transpose_bitsliced_to_blocks<uint64_t>(stream, gpu_index, output,
                                          tmp_bitsliced_output, num_blocks, 8);
}

void cuda_test_mix_columns_64(void *const *streams, uint32_t const *gpu_indexes,
                              uint32_t gpu_count,
                              CudaRadixCiphertextFFI *output,
                              const CudaRadixCiphertextFFI *input,
                              int8_t *mem_ptr, void *const *bsks,
                              void *const *ksks, uint32_t num_blocks) {
  cudaStream_t stream = ((cudaStream_t *)streams)[0];
  uint32_t gpu_index = gpu_indexes[0];
  auto buffer = (int_aes_encrypt_buffer<uint64_t> *)mem_ptr;

  CudaRadixCiphertextFFI *tmp_bitsliced = buffer->tmp_transposed_states_buffer;

  transpose_blocks_to_bitsliced<uint64_t>(stream, gpu_index, tmp_bitsliced,
                                          input, num_blocks, 128);

  CudaRadixCiphertextFFI s_bits_for_mix_cols[128];
  for (int i = 0; i < 128; i++) {
    as_radix_ciphertext_slice<uint64_t>(&s_bits_for_mix_cols[i], tmp_bitsliced,
                                        i * num_blocks, (i + 1) * num_blocks);
  }
  vectorized_mix_columns<uint64_t>((cudaStream_t *)streams, gpu_indexes,
                                   gpu_count, s_bits_for_mix_cols, num_blocks,
                                   buffer, bsks, (uint64_t **)ksks, nullptr);

  vectorized_aes_flush<uint64_t>((cudaStream_t *)streams, gpu_indexes,
                                 gpu_count, tmp_bitsliced, buffer, bsks,
                                 (uint64_t **)ksks, nullptr);

  transpose_bitsliced_to_blocks<uint64_t>(stream, gpu_index, output,
                                          tmp_bitsliced, num_blocks, 128);
}

void cuda_test_full_adder_64(void *const *streams, uint32_t const *gpu_indexes,
                             uint32_t gpu_count, CudaRadixCiphertextFFI *output,
                             const CudaRadixCiphertextFFI *input,
                             int8_t *mem_ptr, void *const *bsks,
                             void *const *ksks, const uint64_t *counter_bits_le,
                             uint32_t num_blocks) {
  cudaStream_t stream = ((cudaStream_t *)streams)[0];
  uint32_t gpu_index = gpu_indexes[0];
  auto buffer = (int_aes_encrypt_buffer<uint64_t> *)mem_ptr;

  CudaRadixCiphertextFFI *tmp_bitsliced = buffer->tmp_transposed_states_buffer;

  transpose_blocks_to_bitsliced<uint64_t>(stream, gpu_index, tmp_bitsliced,
                                          input, num_blocks, 128);

  vectorized_aes_full_adder_inplace<uint64_t>(
      (cudaStream_t *)streams, gpu_indexes, gpu_count, tmp_bitsliced,
      counter_bits_le, num_blocks, buffer, bsks, (uint64_t **)ksks, nullptr);

  transpose_bitsliced_to_blocks<uint64_t>(stream, gpu_index, output,
                                          tmp_bitsliced, num_blocks, 128);
}

void cuda_test_transpose_64(void *const *streams, uint32_t const *gpu_indexes,
                            uint32_t gpu_count, CudaRadixCiphertextFFI *output,
                            const CudaRadixCiphertextFFI *input,
                            int8_t *mem_ptr, uint32_t num_blocks) {
  cudaStream_t stream = ((cudaStream_t *)streams)[0];
  uint32_t gpu_index = gpu_indexes[0];
  auto buffer = (int_aes_encrypt_buffer<uint64_t> *)mem_ptr;
  const uint32_t block_size = 128;

  CudaRadixCiphertextFFI *tmp_bitsliced = buffer->tmp_transposed_states_buffer;

  transpose_blocks_to_bitsliced<uint64_t>(stream, gpu_index, tmp_bitsliced,
                                          input, num_blocks, block_size);
  transpose_bitsliced_to_blocks<uint64_t>(
      stream, gpu_index, output, tmp_bitsliced, num_blocks, block_size);
}
