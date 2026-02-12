#ifndef CUDA_INTEGER_COMPRESSION_H
#define CUDA_INTEGER_COMPRESSION_H

#include "../../pbs/pbs_enums.h"
#include "../integer.h"

extern "C" {
uint64_t scratch_cuda_integer_compress_radix_ciphertext_64(
    CudaStreamsFFI streams, int8_t **mem_ptr,
    uint32_t compression_glwe_dimension, uint32_t compression_polynomial_size,
    uint32_t lwe_dimension, uint32_t ks_level, uint32_t ks_base_log,
    uint32_t num_radix_blocks, uint32_t message_modulus, uint32_t carry_modulus,
    PBS_TYPE pbs_type, uint32_t num_lwes_stored_per_glwe,
    bool allocate_gpu_memory);

uint64_t scratch_cuda_integer_decompress_radix_ciphertext_64(
    CudaStreamsFFI streams, int8_t **mem_ptr,
    uint32_t encryption_glwe_dimension, uint32_t encryption_polynomial_size,
    uint32_t compression_glwe_dimension, uint32_t compression_polynomial_size,
    uint32_t lwe_dimension, uint32_t pbs_level, uint32_t pbs_base_log,
    uint32_t grouping_factor, uint32_t num_blocks_to_decompress,
    uint32_t message_modulus, uint32_t carry_modulus, PBS_TYPE pbs_type,
    bool allocate_gpu_memory, PBS_MS_REDUCTION_T noise_reduction_type);

void cuda_integer_compress_radix_ciphertext_64(
    CudaStreamsFFI streams, CudaPackedGlweCiphertextListFFI *glwe_array_out,
    CudaLweCiphertextListFFI const *lwe_array_in, void *const *fp_ksk,
    int8_t *mem_ptr);

void cuda_integer_decompress_radix_ciphertext_64(
    CudaStreamsFFI streams, CudaLweCiphertextListFFI *lwe_array_out,
    CudaPackedGlweCiphertextListFFI const *glwe_in,
    uint32_t const *indexes_array, void *const *bsks, int8_t *mem_ptr);

void cleanup_cuda_integer_compress_radix_ciphertext_64(CudaStreamsFFI streams,
                                                       int8_t **mem_ptr_void);

void cleanup_cuda_integer_decompress_radix_ciphertext_64(CudaStreamsFFI streams,
                                                         int8_t **mem_ptr_void);

uint64_t scratch_cuda_integer_compress_radix_ciphertext_128(
    CudaStreamsFFI streams, int8_t **mem_ptr,
    uint32_t compression_glwe_dimension, uint32_t compression_polynomial_size,
    uint32_t lwe_dimension, uint32_t ks_level, uint32_t ks_base_log,
    uint32_t num_radix_blocks, uint32_t message_modulus, uint32_t carry_modulus,
    PBS_TYPE pbs_type, uint32_t num_lwes_stored_per_glwe,
    bool allocate_gpu_memory);

uint64_t scratch_cuda_integer_decompress_radix_ciphertext_128(
    CudaStreamsFFI streams, int8_t **mem_ptr,
    uint32_t compression_glwe_dimension, uint32_t compression_polynomial_size,
    uint32_t lwe_dimension, uint32_t num_radix_blocks, uint32_t message_modulus,
    uint32_t carry_modulus, bool allocate_gpu_memory);

void cuda_integer_compress_radix_ciphertext_128(
    CudaStreamsFFI streams, CudaPackedGlweCiphertextListFFI *glwe_array_out,
    CudaLweCiphertextListFFI const *lwe_array_in, void *const *fp_ksk,
    int8_t *mem_ptr);

void cuda_integer_decompress_radix_ciphertext_128(
    CudaStreamsFFI streams, CudaLweCiphertextListFFI *lwe_array_out,
    CudaPackedGlweCiphertextListFFI const *glwe_in,
    uint32_t const *indexes_array, int8_t *mem_ptr);

void cleanup_cuda_integer_compress_radix_ciphertext_128(CudaStreamsFFI streams,
                                                        int8_t **mem_ptr_void);

void cleanup_cuda_integer_decompress_radix_ciphertext_128(
    CudaStreamsFFI streams, int8_t **mem_ptr_void);

void cuda_integer_extract_glwe_128(
    CudaStreamsFFI streams, void *glwe_array_out,
    CudaPackedGlweCiphertextListFFI const *glwe_list,
    uint32_t const glwe_index);

void cuda_integer_extract_glwe_64(
    CudaStreamsFFI streams, void *glwe_array_out,
    CudaPackedGlweCiphertextListFFI const *glwe_list,
    uint32_t const glwe_index);
}

#endif
