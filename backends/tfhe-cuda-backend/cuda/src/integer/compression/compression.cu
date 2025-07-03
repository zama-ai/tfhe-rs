#include "compression.cuh"

uint64_t scratch_cuda_integer_compress_radix_ciphertext_64(
    void *const *streams, uint32_t const *gpu_indexes, uint32_t gpu_count,
    int8_t **mem_ptr, uint32_t compression_glwe_dimension,
    uint32_t compression_polynomial_size, uint32_t lwe_dimension,
    uint32_t ks_level, uint32_t ks_base_log, uint32_t num_radix_blocks,
    uint32_t message_modulus, uint32_t carry_modulus, PBS_TYPE pbs_type,
    uint32_t lwe_per_glwe, uint32_t storage_log_modulus,
    bool allocate_gpu_memory) {

  int_radix_params compression_params(
      pbs_type, compression_glwe_dimension, compression_polynomial_size,
      (compression_glwe_dimension + 1) * compression_polynomial_size,
      lwe_dimension, ks_level, ks_base_log, 0, 0, 0, message_modulus,
      carry_modulus, allocate_gpu_memory);

  return scratch_cuda_compress_integer_radix_ciphertext<uint64_t>(
      (cudaStream_t *)(streams), gpu_indexes, gpu_count,
      (int_compression<uint64_t> **)mem_ptr, num_radix_blocks,
      compression_params, lwe_per_glwe, storage_log_modulus,
      allocate_gpu_memory);
}
uint64_t scratch_cuda_integer_decompress_radix_ciphertext_64(
    void *const *streams, uint32_t const *gpu_indexes, uint32_t gpu_count,
    int8_t **mem_ptr, uint32_t encryption_glwe_dimension,
    uint32_t encryption_polynomial_size, uint32_t compression_glwe_dimension,
    uint32_t compression_polynomial_size, uint32_t lwe_dimension,
    uint32_t pbs_level, uint32_t pbs_base_log, uint32_t num_radix_blocks,
    uint32_t message_modulus, uint32_t carry_modulus, PBS_TYPE pbs_type,
    uint32_t storage_log_modulus, uint32_t body_count, bool allocate_gpu_memory,
    bool allocate_ms_array) {

  // Decompression doesn't keyswitch, so big and small dimensions are the same
  int_radix_params encryption_params(
      pbs_type, encryption_glwe_dimension, encryption_polynomial_size,
      lwe_dimension, lwe_dimension, 0, 0, pbs_level, pbs_base_log, 0,
      message_modulus, carry_modulus, allocate_ms_array);

  int_radix_params compression_params(
      pbs_type, compression_glwe_dimension, compression_polynomial_size,
      lwe_dimension, compression_glwe_dimension * compression_polynomial_size,
      0, 0, pbs_level, pbs_base_log, 0, message_modulus, carry_modulus,
      allocate_ms_array);

  return scratch_cuda_integer_decompress_radix_ciphertext<uint64_t>(
      (cudaStream_t *)(streams), gpu_indexes, gpu_count,
      (int_decompression<uint64_t> **)mem_ptr, num_radix_blocks, body_count,
      encryption_params, compression_params, storage_log_modulus,
      allocate_gpu_memory);
}
void cuda_integer_compress_radix_ciphertext_64(
    void *const *streams, uint32_t const *gpu_indexes, uint32_t gpu_count,
    void *glwe_array_out, void const *lwe_array_in, void *const *fp_ksk,
    uint32_t num_nths, int8_t *mem_ptr) {

  host_integer_compress<uint64_t>(
      (cudaStream_t *)(streams), gpu_indexes, gpu_count,
      static_cast<uint64_t *>(glwe_array_out),
      static_cast<const uint64_t *>(lwe_array_in), (uint64_t *const *)(fp_ksk),
      num_nths, (int_compression<uint64_t> *)mem_ptr);
}
void cuda_integer_decompress_radix_ciphertext_64(
    void *const *streams, uint32_t const *gpu_indexes, uint32_t gpu_count,
    void *lwe_array_out, void const *glwe_in, uint32_t const *indexes_array,
    uint32_t indexes_array_size, void *const *bsks, int8_t *mem_ptr) {

  host_integer_decompress<uint64_t>(
      (cudaStream_t *)(streams), gpu_indexes, gpu_count,
      static_cast<uint64_t *>(lwe_array_out),
      static_cast<const uint64_t *>(glwe_in), indexes_array, indexes_array_size,
      bsks, (int_decompression<uint64_t> *)mem_ptr);
}
void cleanup_cuda_integer_compress_radix_ciphertext_64(
    void *const *streams, uint32_t const *gpu_indexes, uint32_t gpu_count,
    int8_t **mem_ptr_void) {

  int_compression<uint64_t> *mem_ptr =
      (int_compression<uint64_t> *)(*mem_ptr_void);
  mem_ptr->release((cudaStream_t *)(streams), gpu_indexes, gpu_count);
}
void cleanup_cuda_integer_decompress_radix_ciphertext_64(
    void *const *streams, uint32_t const *gpu_indexes, uint32_t gpu_count,
    int8_t **mem_ptr_void) {

  int_decompression<uint64_t> *mem_ptr =
      (int_decompression<uint64_t> *)(*mem_ptr_void);
  mem_ptr->release((cudaStream_t *)(streams), gpu_indexes, gpu_count);
}

uint64_t scratch_cuda_integer_compress_radix_ciphertext_128(
    void *const *streams, uint32_t const *gpu_indexes, uint32_t gpu_count,
    int8_t **mem_ptr, uint32_t compression_glwe_dimension,
    uint32_t compression_polynomial_size, uint32_t lwe_dimension,
    uint32_t ks_level, uint32_t ks_base_log, uint32_t num_radix_blocks,
    uint32_t message_modulus, uint32_t carry_modulus, PBS_TYPE pbs_type,
    uint32_t lwe_per_glwe, uint32_t storage_log_modulus,
    bool allocate_gpu_memory) {

  int_radix_params compression_params(
      pbs_type, compression_glwe_dimension, compression_polynomial_size,
      (compression_glwe_dimension + 1) * compression_polynomial_size,
      lwe_dimension, ks_level, ks_base_log, 0, 0, 0, message_modulus,
      carry_modulus, allocate_gpu_memory);

  return scratch_cuda_compress_integer_radix_ciphertext<__uint128_t>(
      (cudaStream_t *)(streams), gpu_indexes, gpu_count,
      (int_compression<__uint128_t> **)mem_ptr, num_radix_blocks,
      compression_params, lwe_per_glwe, storage_log_modulus,
      allocate_gpu_memory);
}
uint64_t scratch_cuda_integer_decompress_radix_ciphertext_128(
    void *const *streams, uint32_t const *gpu_indexes, uint32_t gpu_count,
    int8_t **mem_ptr, uint32_t encryption_glwe_dimension,
    uint32_t encryption_polynomial_size, uint32_t compression_glwe_dimension,
    uint32_t compression_polynomial_size, uint32_t lwe_dimension,
    uint32_t pbs_level, uint32_t pbs_base_log, uint32_t num_radix_blocks,
    uint32_t message_modulus, uint32_t carry_modulus, PBS_TYPE pbs_type,
    uint32_t storage_log_modulus, uint32_t body_count, bool allocate_gpu_memory,
    bool allocate_ms_array) {

  // Decompression doesn't keyswitch, so big and small dimensions are the same
  int_radix_params encryption_params(
      pbs_type, encryption_glwe_dimension, encryption_polynomial_size,
      lwe_dimension, lwe_dimension, 0, 0, pbs_level, pbs_base_log, 0,
      message_modulus, carry_modulus, allocate_ms_array);

  int_radix_params compression_params(
      pbs_type, compression_glwe_dimension, compression_polynomial_size,
      lwe_dimension, compression_glwe_dimension * compression_polynomial_size,
      0, 0, pbs_level, pbs_base_log, 0, message_modulus, carry_modulus,
      allocate_ms_array);

  return scratch_cuda_integer_decompress_radix_ciphertext<__uint128_t>(
      (cudaStream_t *)(streams), gpu_indexes, gpu_count,
      (int_decompression<__uint128_t> **)mem_ptr, num_radix_blocks, body_count,
      encryption_params, compression_params, storage_log_modulus,
      allocate_gpu_memory);
}
void cuda_integer_compress_radix_ciphertext_128(
    void *const *streams, uint32_t const *gpu_indexes, uint32_t gpu_count,
    void *glwe_array_out, void const *lwe_array_in, void *const *fp_ksk,
    uint32_t num_nths, int8_t *mem_ptr) {

  host_integer_compress<__uint128_t>(
      (cudaStream_t *)(streams), gpu_indexes, gpu_count,
      static_cast<__uint128_t *>(glwe_array_out),
      static_cast<const __uint128_t *>(lwe_array_in), (__uint128_t *const *)(fp_ksk),
      num_nths, (int_compression<__uint128_t> *)mem_ptr);
}
void cuda_integer_decompress_radix_ciphertext_128(
    void *const *streams, uint32_t const *gpu_indexes, uint32_t gpu_count,
    void *lwe_array_out, void const *glwe_in, uint32_t const *indexes_array,
    uint32_t indexes_array_size, void *const *bsks, int8_t *mem_ptr) {

  host_integer_decompress<__uint128_t>(
      (cudaStream_t *)(streams), gpu_indexes, gpu_count,
      static_cast<__uint128_t *>(lwe_array_out),
      static_cast<const __uint128_t *>(glwe_in), indexes_array, indexes_array_size,
      bsks, (int_decompression<__uint128_t> *)mem_ptr);
}
void cleanup_cuda_integer_compress_radix_ciphertext_128(
    void *const *streams, uint32_t const *gpu_indexes, uint32_t gpu_count,
    int8_t **mem_ptr_void) {

  int_compression<__uint128_t> *mem_ptr =
      (int_compression<__uint128_t> *)(*mem_ptr_void);
  mem_ptr->release((cudaStream_t *)(streams), gpu_indexes, gpu_count);
}

void cleanup_cuda_integer_decompress_radix_ciphertext_128(
    void *const *streams, uint32_t const *gpu_indexes, uint32_t gpu_count,
    int8_t **mem_ptr_void) {

  int_decompression<__uint128_t> *mem_ptr =
      (int_decompression<__uint128_t> *)(*mem_ptr_void);
  mem_ptr->release((cudaStream_t *)(streams), gpu_indexes, gpu_count);
}