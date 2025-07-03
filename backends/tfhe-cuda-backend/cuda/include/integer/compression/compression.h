#ifndef CUDA_INTEGER_COMPRESSION_H
#define CUDA_INTEGER_COMPRESSION_H

#include "../../pbs/pbs_enums.h"

extern "C" {
uint64_t scratch_cuda_integer_compress_radix_ciphertext_64(
    void *const *streams, uint32_t const *gpu_indexes, uint32_t gpu_count,
    int8_t **mem_ptr, uint32_t compression_glwe_dimension,
    uint32_t compression_polynomial_size, uint32_t lwe_dimension,
    uint32_t ks_level, uint32_t ks_base_log, uint32_t num_radix_blocks,
    uint32_t message_modulus, uint32_t carry_modulus, PBS_TYPE pbs_type,
    uint32_t lwe_per_glwe, uint32_t storage_log_modulus,
    bool allocate_gpu_memory);

uint64_t scratch_cuda_integer_decompress_radix_ciphertext_64(
    void *const *streams, uint32_t const *gpu_indexes, uint32_t gpu_count,
    int8_t **mem_ptr, uint32_t encryption_glwe_dimension,
    uint32_t encryption_polynomial_size, uint32_t compression_glwe_dimension,
    uint32_t compression_polynomial_size, uint32_t lwe_dimension,
    uint32_t pbs_level, uint32_t pbs_base_log, uint32_t num_radix_blocks,
    uint32_t message_modulus, uint32_t carry_modulus, PBS_TYPE pbs_type,
    uint32_t storage_log_modulus, uint32_t body_count, bool allocate_gpu_memory,
    bool allocate_ms_array);

void cuda_integer_compress_radix_ciphertext_64(
    void *const *streams, uint32_t const *gpu_indexes, uint32_t gpu_count,
    void *glwe_array_out, void const *lwe_array_in, void *const *fp_ksk,
    uint32_t num_nths, int8_t *mem_ptr);

void cuda_integer_decompress_radix_ciphertext_64(
    void *const *streams, uint32_t const *gpu_indexes, uint32_t gpu_count,
    void *lwe_array_out, void const *glwe_in, uint32_t const *indexes_array,
    uint32_t indexes_array_size, void *const *bsks, int8_t *mem_ptr);

void cleanup_cuda_integer_compress_radix_ciphertext_64(
    void *const *streams, uint32_t const *gpu_indexes, uint32_t gpu_count,
    int8_t **mem_ptr_void);

void cleanup_cuda_integer_decompress_radix_ciphertext_64(
    void *const *streams, uint32_t const *gpu_indexes, uint32_t gpu_count,
    int8_t **mem_ptr_void);

uint64_t scratch_cuda_integer_compress_radix_ciphertext_128(
    void *const *streams, uint32_t const *gpu_indexes, uint32_t gpu_count,
    int8_t **mem_ptr, uint32_t compression_glwe_dimension,
    uint32_t compression_polynomial_size, uint32_t lwe_dimension,
    uint32_t ks_level, uint32_t ks_base_log, uint32_t num_radix_blocks,
    uint32_t message_modulus, uint32_t carry_modulus, PBS_TYPE pbs_type,
    uint32_t lwe_per_glwe, uint32_t storage_log_modulus,
    bool allocate_gpu_memory);

uint64_t scratch_cuda_integer_decompress_radix_ciphertext_128(
    void *const *streams, uint32_t const *gpu_indexes, uint32_t gpu_count,
    int8_t **mem_ptr, uint32_t encryption_glwe_dimension,
    uint32_t encryption_polynomial_size, uint32_t compression_glwe_dimension,
    uint32_t compression_polynomial_size, uint32_t lwe_dimension,
    uint32_t pbs_level, uint32_t pbs_base_log, uint32_t num_radix_blocks,
    uint32_t message_modulus, uint32_t carry_modulus, PBS_TYPE pbs_type,
    uint32_t storage_log_modulus, uint32_t body_count, bool allocate_gpu_memory,
    bool allocate_ms_array);

void cuda_integer_compress_radix_ciphertext_128(
    void *const *streams, uint32_t const *gpu_indexes, uint32_t gpu_count,
    void *glwe_array_out, void const *lwe_array_in, void *const *fp_ksk,
    uint32_t num_nths, int8_t *mem_ptr);

void cuda_integer_decompress_radix_ciphertext_128(
    void *const *streams, uint32_t const *gpu_indexes, uint32_t gpu_count,
    void *lwe_array_out, void const *glwe_in, uint32_t const *indexes_array,
    uint32_t indexes_array_size, void *const *bsks, int8_t *mem_ptr);

void cleanup_cuda_integer_compress_radix_ciphertext_128(
    void *const *streams, uint32_t const *gpu_indexes, uint32_t gpu_count,
    int8_t **mem_ptr_void);

void cleanup_cuda_integer_decompress_radix_ciphertext_128(
    void *const *streams, uint32_t const *gpu_indexes, uint32_t gpu_count,
    int8_t **mem_ptr_void);
}

#endif
