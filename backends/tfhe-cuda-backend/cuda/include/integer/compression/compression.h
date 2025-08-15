#ifndef CUDA_INTEGER_COMPRESSION_H
#define CUDA_INTEGER_COMPRESSION_H

#include "../../pbs/pbs_enums.h"

typedef struct {
  void *ptr;
  uint32_t num_radix_blocks;
  uint32_t lwe_dimension;
} CudaLweCiphertextListFFI;

typedef struct {
  void *ptr;
  uint32_t storage_log_modulus;
  uint32_t lwe_per_glwe;
  // Input LWEs are grouped by groups of `lwe_per_glwe`(the last group may be
  // smaller)
  // Each group is then packed into one GLWE with `lwe_per_glwe` bodies (one for
  // each LWE of the group). In the end the total number of bodies is equal to
  // the number of input LWE
  uint32_t total_lwe_bodies_count;
  uint32_t glwe_dimension;
  uint32_t polynomial_size;
} CudaPackedGlweCiphertextListFFI;

extern "C" {
uint64_t scratch_cuda_integer_compress_radix_ciphertext_64(
    void *const *streams, uint32_t const *gpu_indexes, uint32_t gpu_count,
    int8_t **mem_ptr, uint32_t compression_glwe_dimension,
    uint32_t compression_polynomial_size, uint32_t lwe_dimension,
    uint32_t ks_level, uint32_t ks_base_log, uint32_t num_radix_blocks,
    uint32_t message_modulus, uint32_t carry_modulus, PBS_TYPE pbs_type,
    uint32_t lwe_per_glwe, bool allocate_gpu_memory);

uint64_t scratch_cuda_integer_decompress_radix_ciphertext_64(
    void *const *streams, uint32_t const *gpu_indexes, uint32_t gpu_count,
    int8_t **mem_ptr, uint32_t encryption_glwe_dimension,
    uint32_t encryption_polynomial_size, uint32_t compression_glwe_dimension,
    uint32_t compression_polynomial_size, uint32_t lwe_dimension,
    uint32_t pbs_level, uint32_t pbs_base_log,
    uint32_t num_blocks_to_decompress, uint32_t message_modulus,
    uint32_t carry_modulus, PBS_TYPE pbs_type, bool allocate_gpu_memory,
    PBS_MS_REDUCTION_T noise_reduction_type);

void cuda_integer_compress_radix_ciphertext_64(
    void *const *streams, uint32_t const *gpu_indexes, uint32_t gpu_count,
    CudaPackedGlweCiphertextListFFI *glwe_array_out,
    CudaLweCiphertextListFFI const *lwe_array_in, void *const *fp_ksk,
    int8_t *mem_ptr);

void cuda_integer_decompress_radix_ciphertext_64(
    void *const *streams, uint32_t const *gpu_indexes, uint32_t gpu_count,
    CudaLweCiphertextListFFI *lwe_array_out,
    CudaPackedGlweCiphertextListFFI const *glwe_in,
    uint32_t const *indexes_array, void *const *bsks, int8_t *mem_ptr);

void cleanup_cuda_integer_compress_radix_ciphertext_64(
    void *const *streams, uint32_t const *gpu_indexes, uint32_t gpu_count,
    int8_t **mem_ptr_void);

void cleanup_cuda_integer_decompress_radix_ciphertext_64(
    void *const *streams, uint32_t const *gpu_indexes, uint32_t gpu_count,
    int8_t **mem_ptr_void);
}

#endif
