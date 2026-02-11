#include "compression.cuh"

uint64_t scratch_cuda_integer_compress_radix_ciphertext_64_async(
    CudaStreamsFFI streams, int8_t **mem_ptr,
    uint32_t compression_glwe_dimension, uint32_t compression_polynomial_size,
    uint32_t lwe_dimension, uint32_t ks_level, uint32_t ks_base_log,
    uint32_t num_radix_blocks, uint32_t message_modulus, uint32_t carry_modulus,
    PBS_TYPE pbs_type, uint32_t num_lwes_stored_per_glwe,
    bool allocate_gpu_memory) {

  int_radix_params compression_params(
      pbs_type, compression_glwe_dimension, compression_polynomial_size,
      (compression_glwe_dimension + 1) * compression_polynomial_size,
      lwe_dimension, ks_level, ks_base_log, 0, 0, 0, message_modulus,
      carry_modulus, PBS_MS_REDUCTION_T::NO_REDUCTION);

  return scratch_cuda_compress_ciphertext<uint64_t>(
      CudaStreams(streams), (int_compression<uint64_t> **)mem_ptr,
      num_radix_blocks, compression_params, num_lwes_stored_per_glwe,
      allocate_gpu_memory);
}
uint64_t scratch_cuda_integer_decompress_radix_ciphertext_64_async(
    CudaStreamsFFI streams, int8_t **mem_ptr,
    uint32_t encryption_glwe_dimension, uint32_t encryption_polynomial_size,
    uint32_t compression_glwe_dimension, uint32_t compression_polynomial_size,
    uint32_t lwe_dimension, uint32_t pbs_level, uint32_t pbs_base_log,
    uint32_t grouping_factor, uint32_t num_blocks_to_decompress,
    uint32_t message_modulus, uint32_t carry_modulus, PBS_TYPE pbs_type,
    bool allocate_gpu_memory, PBS_MS_REDUCTION_T noise_reduction_type) {

  // Decompression doesn't keyswitch, so big and small dimensions are the same
  int_radix_params encryption_params(
      pbs_type, encryption_glwe_dimension, encryption_polynomial_size,
      lwe_dimension, lwe_dimension, 0, 0, pbs_level, pbs_base_log,
      grouping_factor, message_modulus, carry_modulus, noise_reduction_type);

  int_radix_params compression_params(
      pbs_type, compression_glwe_dimension, compression_polynomial_size,
      lwe_dimension, compression_glwe_dimension * compression_polynomial_size,
      0, 0, pbs_level, pbs_base_log, grouping_factor, message_modulus,
      carry_modulus, noise_reduction_type);

  return scratch_cuda_integer_decompress_radix_ciphertext<uint64_t>(
      CudaStreams(streams), (int_decompression<uint64_t> **)mem_ptr,
      num_blocks_to_decompress, encryption_params, compression_params,
      allocate_gpu_memory);
}
void cuda_integer_compress_radix_ciphertext_64_async(
    CudaStreamsFFI streams, CudaPackedGlweCiphertextListFFI *glwe_array_out,
    CudaLweCiphertextListFFI const *lwe_array_in, void *const *fp_ksk,
    int8_t *mem_ptr) {

  host_integer_compress<uint64_t>(CudaStreams(streams), glwe_array_out,
                                  lwe_array_in, (uint64_t *const *)(fp_ksk),
                                  (int_compression<uint64_t> *)mem_ptr);
}
void cuda_integer_decompress_radix_ciphertext_64_async(
    CudaStreamsFFI streams, CudaLweCiphertextListFFI *lwe_array_out,
    CudaPackedGlweCiphertextListFFI const *glwe_in,
    uint32_t const *indexes_array, void *const *bsks, int8_t *mem_ptr) {

  host_integer_decompress<uint64_t>(CudaStreams(streams), lwe_array_out,
                                    glwe_in, indexes_array, bsks,
                                    (int_decompression<uint64_t> *)mem_ptr);
}
void cleanup_cuda_integer_compress_radix_ciphertext_64(CudaStreamsFFI streams,
                                                       int8_t **mem_ptr_void) {

  int_compression<uint64_t> *mem_ptr =
      (int_compression<uint64_t> *)(*mem_ptr_void);
  mem_ptr->release(CudaStreams(streams));
  delete mem_ptr;
  *mem_ptr_void = nullptr;
}
void cleanup_cuda_integer_decompress_radix_ciphertext_64(
    CudaStreamsFFI streams, int8_t **mem_ptr_void) {

  int_decompression<uint64_t> *mem_ptr =
      (int_decompression<uint64_t> *)(*mem_ptr_void);
  mem_ptr->release(CudaStreams(streams));
  delete mem_ptr;
  *mem_ptr_void = nullptr;
}

uint64_t scratch_cuda_integer_compress_radix_ciphertext_128_async(
    CudaStreamsFFI streams, int8_t **mem_ptr,
    uint32_t compression_glwe_dimension, uint32_t compression_polynomial_size,
    uint32_t lwe_dimension, uint32_t ks_level, uint32_t ks_base_log,
    uint32_t num_radix_blocks, uint32_t message_modulus, uint32_t carry_modulus,
    PBS_TYPE pbs_type, uint32_t num_lwes_stored_per_glwe,
    bool allocate_gpu_memory) {

  int_radix_params compression_params(
      pbs_type, compression_glwe_dimension, compression_polynomial_size,
      (compression_glwe_dimension + 1) * compression_polynomial_size,
      lwe_dimension, ks_level, ks_base_log, 0, 0, 0, message_modulus,
      carry_modulus, PBS_MS_REDUCTION_T::NO_REDUCTION);

  return scratch_cuda_compress_ciphertext<__uint128_t>(
      CudaStreams(streams), (int_compression<__uint128_t> **)mem_ptr,
      num_radix_blocks, compression_params, num_lwes_stored_per_glwe,
      allocate_gpu_memory);
}
uint64_t scratch_cuda_integer_decompress_radix_ciphertext_128_async(
    CudaStreamsFFI streams, int8_t **mem_ptr,
    uint32_t compression_glwe_dimension, uint32_t compression_polynomial_size,
    uint32_t lwe_dimension, uint32_t num_radix_blocks, uint32_t message_modulus,
    uint32_t carry_modulus, bool allocate_gpu_memory) {

  // 128-bit decompression doesn't run PBSs, so we don't need encryption_params
  int_radix_params compression_params(
      PBS_TYPE::CLASSICAL, compression_glwe_dimension,
      compression_polynomial_size,
      compression_glwe_dimension * compression_polynomial_size, lwe_dimension,
      0, 0, 0, 0, 0, message_modulus, carry_modulus,
      PBS_MS_REDUCTION_T::NO_REDUCTION);

  return scratch_cuda_integer_decompress_radix_ciphertext<__uint128_t>(
      CudaStreams(streams), (int_decompression<__uint128_t> **)mem_ptr,
      num_radix_blocks, compression_params, compression_params,
      allocate_gpu_memory);
}
void cuda_integer_compress_radix_ciphertext_128_async(
    CudaStreamsFFI streams, CudaPackedGlweCiphertextListFFI *glwe_array_out,
    CudaLweCiphertextListFFI const *lwe_array_in, void *const *fp_ksk,
    int8_t *mem_ptr) {

  host_integer_compress<__uint128_t>(
      CudaStreams(streams), glwe_array_out, lwe_array_in,
      (__uint128_t *const *)(fp_ksk), (int_compression<__uint128_t> *)mem_ptr);
}
void cuda_integer_decompress_radix_ciphertext_128_async(
    CudaStreamsFFI streams, CudaLweCiphertextListFFI *lwe_array_out,
    CudaPackedGlweCiphertextListFFI const *glwe_in,
    uint32_t const *indexes_array, int8_t *mem_ptr) {

  host_integer_decompress<__uint128_t>(
      CudaStreams(streams), lwe_array_out, glwe_in, indexes_array, nullptr,
      (int_decompression<__uint128_t> *)mem_ptr);
}
void cleanup_cuda_integer_compress_radix_ciphertext_128(CudaStreamsFFI streams,
                                                        int8_t **mem_ptr_void) {

  int_compression<__uint128_t> *mem_ptr =
      (int_compression<__uint128_t> *)(*mem_ptr_void);
  mem_ptr->release(CudaStreams(streams));

  delete mem_ptr;
  *mem_ptr_void = nullptr;
}

void cleanup_cuda_integer_decompress_radix_ciphertext_128(
    CudaStreamsFFI streams, int8_t **mem_ptr_void) {

  int_decompression<__uint128_t> *mem_ptr =
      (int_decompression<__uint128_t> *)(*mem_ptr_void);
  mem_ptr->release(CudaStreams(streams));

  delete mem_ptr;
  *mem_ptr_void = nullptr;
}

void cuda_integer_extract_glwe_128_async(
    CudaStreamsFFI streams, void *glwe_array_out,
    CudaPackedGlweCiphertextListFFI const *glwe_list,
    uint32_t const glwe_index) {

  CudaStreams _streams = CudaStreams(streams);
  host_extract<__uint128_t>(_streams.stream(0), _streams.gpu_index(0),
                            (__uint128_t *)glwe_array_out, glwe_list,
                            glwe_index);
}

void cuda_integer_extract_glwe_64_async(
    CudaStreamsFFI streams, void *glwe_array_out,
    CudaPackedGlweCiphertextListFFI const *glwe_list,
    uint32_t const glwe_index) {

  CudaStreams _streams = CudaStreams(streams);
  host_extract<__uint64_t>(_streams.stream(0), _streams.gpu_index(0),
                           (__uint64_t *)glwe_array_out, glwe_list, glwe_index);
}
