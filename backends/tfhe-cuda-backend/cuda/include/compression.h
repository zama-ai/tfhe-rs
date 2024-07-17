#ifndef CUDA_INTEGER_COMPRESSION_H
#define CUDA_INTEGER_COMPRESSION_H

#include "integer.h"

extern "C" {
void scratch_cuda_integer_compress_radix_ciphertext_64(
    void **streams, uint32_t *gpu_indexes, uint32_t gpu_count, int8_t **mem_ptr,
    uint32_t compression_glwe_dimension, uint32_t compression_polynomial_size,
    uint32_t lwe_dimension, uint32_t ks_level, uint32_t ks_base_log,
    uint32_t num_lwes, uint32_t message_modulus, uint32_t carry_modulus,
    PBS_TYPE pbs_type, uint32_t lwe_per_glwe, uint32_t storage_log_modulus,
    bool allocate_gpu_memory);

void scratch_cuda_integer_decompress_radix_ciphertext_64(
    void **streams, uint32_t *gpu_indexes, uint32_t gpu_count, int8_t **mem_ptr,
    uint32_t encryption_glwe_dimension, uint32_t encryption_polynomial_size,
    uint32_t compression_glwe_dimension, uint32_t compression_polynomial_size,
    uint32_t lwe_dimension, uint32_t pbs_level, uint32_t pbs_base_log,
    uint32_t num_lwes, uint32_t message_modulus, uint32_t carry_modulus,
    PBS_TYPE pbs_type, uint32_t storage_log_modulus, bool allocate_gpu_memory);

void cuda_integer_compress_radix_ciphertext_64(
    void **streams, uint32_t *gpu_indexes, uint32_t gpu_count,
    void *glwe_array_out, void *lwe_array_in, void **fp_ksk, uint32_t num_nths,
    int8_t *mem_ptr);

void cuda_integer_decompress_radix_ciphertext_64(
    void **streams, uint32_t *gpu_indexes, uint32_t gpu_count,
    void *lwe_array_out, void *glwe_in, void *indexes_array,
    uint32_t indexes_array_size, void **bsks, int8_t *mem_ptr);

void cleanup_cuda_integer_compress_radix_ciphertext_64(void **streams,
                                                       uint32_t *gpu_indexes,
                                                       uint32_t gpu_count,
                                                       int8_t **mem_ptr_void);

void cleanup_cuda_integer_decompress_radix_ciphertext_64(void **streams,
                                                         uint32_t *gpu_indexes,
                                                         uint32_t gpu_count,
                                                         int8_t **mem_ptr_void);
}

template <typename Torus> struct int_compression {
  int_radix_params compression_params;
  uint32_t storage_log_modulus;
  uint32_t lwe_per_glwe;

  uint32_t body_count;

  // Compression
  int8_t *fp_ks_buffer;
  Torus *tmp_lwe;
  Torus *tmp_glwe_array_out;

  int_compression(cudaStream_t *streams, uint32_t *gpu_indexes,
                  uint32_t gpu_count, int_radix_params compression_params,
                  uint32_t num_radix_blocks, uint32_t lwe_per_glwe,
                  uint32_t storage_log_modulus, bool allocate_gpu_memory) {
    this->compression_params = compression_params;
    this->lwe_per_glwe = lwe_per_glwe;
    this->storage_log_modulus = storage_log_modulus;
    this->body_count = num_radix_blocks;

    if (allocate_gpu_memory) {
      Torus glwe_accumulator_size = (compression_params.glwe_dimension + 1) *
                                    compression_params.polynomial_size;

      tmp_lwe = (Torus *)cuda_malloc_async(
          num_radix_blocks * (compression_params.small_lwe_dimension + 1) *
              sizeof(Torus),
          streams[0], gpu_indexes[0]);
      tmp_glwe_array_out = (Torus *)cuda_malloc_async(
          glwe_accumulator_size * sizeof(Torus), streams[0], gpu_indexes[0]);

      scratch_packing_keyswitch_lwe_list_to_glwe_64(
          streams[0], gpu_indexes[0], &fp_ks_buffer,
          compression_params.glwe_dimension, compression_params.polynomial_size,
          num_radix_blocks, true);
    }
  }
  void release(cudaStream_t *streams, uint32_t *gpu_indexes,
               uint32_t gpu_count) {
    cuda_drop_async(tmp_lwe, streams[0], gpu_indexes[0]);
    cuda_drop_async(tmp_glwe_array_out, streams[0], gpu_indexes[0]);
    cleanup_packing_keyswitch_lwe_list_to_glwe(streams[0], gpu_indexes[0],
                                               &fp_ks_buffer);
  }
};

template <typename Torus> struct int_decompression {
  int_radix_params encryption_params;
  int_radix_params compression_params;

  uint32_t storage_log_modulus;

  uint32_t body_count;

  Torus *tmp_extracted_glwe;
  Torus *tmp_extracted_lwe;

  int_radix_lut<Torus> *carry_extract_lut;

  int_decompression(cudaStream_t *streams, uint32_t *gpu_indexes,
                    uint32_t gpu_count, int_radix_params encryption_params,
                    int_radix_params compression_params,
                    uint32_t num_radix_blocks, uint32_t storage_log_modulus,
                    bool allocate_gpu_memory) {
    this->encryption_params = encryption_params;
    this->compression_params = compression_params;
    this->storage_log_modulus = storage_log_modulus;
    this->body_count = num_radix_blocks;

    if (allocate_gpu_memory) {
      Torus glwe_accumulator_size = (compression_params.glwe_dimension + 1) *
                                    compression_params.polynomial_size;

      carry_extract_lut = new int_radix_lut<Torus>(
          streams, gpu_indexes, gpu_count, encryption_params, 1,
          num_radix_blocks, allocate_gpu_memory);

      tmp_extracted_glwe = (Torus *)cuda_malloc_async(
          glwe_accumulator_size * sizeof(Torus), streams[0], gpu_indexes[0]);
      tmp_extracted_lwe = (Torus *)cuda_malloc_async(
          num_radix_blocks *
              (compression_params.glwe_dimension *
                   compression_params.polynomial_size +
               1) *
              sizeof(Torus),
          streams[0], gpu_indexes[0]);
      // Decompression
      // Carry extract LUT
      auto carry_extract_f = [encryption_params](Torus x) -> Torus {
        return x / encryption_params.message_modulus;
      };

      generate_device_accumulator<Torus>(
          streams[0], gpu_indexes[0],
          carry_extract_lut->get_lut(gpu_indexes[0], 0),
          encryption_params.glwe_dimension, encryption_params.polynomial_size,
          encryption_params.message_modulus, encryption_params.carry_modulus,
          carry_extract_f);

      carry_extract_lut->broadcast_lut(streams, gpu_indexes, gpu_indexes[0]);
    }
  }
  void release(cudaStream_t *streams, uint32_t *gpu_indexes,
               uint32_t gpu_count) {
    cuda_drop_async(tmp_extracted_glwe, streams[0], gpu_indexes[0]);
    cuda_drop_async(tmp_extracted_lwe, streams[0], gpu_indexes[0]);

    carry_extract_lut->release(streams, gpu_indexes, gpu_count);
    delete (carry_extract_lut);
  }
};
#endif
