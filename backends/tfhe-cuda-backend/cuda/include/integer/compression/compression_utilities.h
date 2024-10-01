#ifndef CUDA_INTEGER_COMPRESSION_UTILITIES_H
#define CUDA_INTEGER_COMPRESSION_UTILITIES_H

#include "../integer_utilities.h"

template <typename Torus> struct int_compression {
  int_radix_params compression_params;
  uint32_t storage_log_modulus;
  uint32_t lwe_per_glwe;

  uint32_t body_count;

  // Compression
  int8_t *fp_ks_buffer;
  Torus *tmp_lwe;
  Torus *tmp_glwe_array_out;

  int_compression(cudaStream_t const *streams, uint32_t const *gpu_indexes,
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
          lwe_per_glwe * glwe_accumulator_size * sizeof(Torus), streams[0],
          gpu_indexes[0]);

      scratch_packing_keyswitch_lwe_list_to_glwe_64(
          streams[0], gpu_indexes[0], &fp_ks_buffer,
          compression_params.small_lwe_dimension,
          compression_params.glwe_dimension, compression_params.polynomial_size,
          num_radix_blocks, true);
    }
  }
  void release(cudaStream_t const *streams, uint32_t const *gpu_indexes,
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

  uint32_t num_radix_blocks;
  uint32_t body_count;

  Torus *tmp_extracted_glwe;
  Torus *tmp_extracted_lwe;
  uint32_t *tmp_indexes_array;

  int_radix_lut<Torus> *decompression_rescale_lut;

  int_decompression(cudaStream_t const *streams, uint32_t const *gpu_indexes,
                    uint32_t gpu_count, int_radix_params encryption_params,
                    int_radix_params compression_params,
                    uint32_t num_radix_blocks, uint32_t body_count,
                    uint32_t storage_log_modulus, bool allocate_gpu_memory) {
    this->encryption_params = encryption_params;
    this->compression_params = compression_params;
    this->storage_log_modulus = storage_log_modulus;
    this->num_radix_blocks = num_radix_blocks;
    this->body_count = body_count;

    if (allocate_gpu_memory) {
      Torus glwe_accumulator_size = (compression_params.glwe_dimension + 1) *
                                    compression_params.polynomial_size;
      Torus lwe_accumulator_size = (compression_params.glwe_dimension *
                                        compression_params.polynomial_size +
                                    1);
      decompression_rescale_lut = new int_radix_lut<Torus>(
          streams, gpu_indexes, gpu_count, encryption_params, 1,
          num_radix_blocks, allocate_gpu_memory);

      tmp_extracted_glwe = (Torus *)cuda_malloc_async(
          num_radix_blocks * glwe_accumulator_size * sizeof(Torus), streams[0],
          gpu_indexes[0]);
      tmp_indexes_array = (uint32_t *)cuda_malloc_async(
          num_radix_blocks * sizeof(uint32_t), streams[0], gpu_indexes[0]);
      tmp_extracted_lwe = (Torus *)cuda_malloc_async(
          num_radix_blocks * lwe_accumulator_size * sizeof(Torus), streams[0],
          gpu_indexes[0]);

      // Rescale is done using an identity LUT
      // Here we do not divide by message_modulus
      // Example: in the 2_2 case we are mapping a 2 bits message onto a 4 bits
      // space, we want to keep the original 2 bits value in the 4 bits space,
      // so we apply the identity and the encoding will rescale it for us.
      auto decompression_rescale_f = [encryption_params](Torus x) -> Torus {
        return x;
      };

      auto effective_compression_message_modulus =
          encryption_params.carry_modulus;
      auto effective_compression_carry_modulus = 1;

      generate_device_accumulator_with_encoding<Torus>(
          streams[0], gpu_indexes[0], decompression_rescale_lut->get_lut(0, 0),
          encryption_params.glwe_dimension, encryption_params.polynomial_size,
          effective_compression_message_modulus,
          effective_compression_carry_modulus,
          encryption_params.message_modulus, encryption_params.carry_modulus,
          decompression_rescale_f);

      decompression_rescale_lut->broadcast_lut(streams, gpu_indexes, 0);
    }
  }
  void release(cudaStream_t const *streams, uint32_t const *gpu_indexes,
               uint32_t gpu_count) {
    cuda_drop_async(tmp_extracted_glwe, streams[0], gpu_indexes[0]);
    cuda_drop_async(tmp_extracted_lwe, streams[0], gpu_indexes[0]);
    cuda_drop_async(tmp_indexes_array, streams[0], gpu_indexes[0]);

    decompression_rescale_lut->release(streams, gpu_indexes, gpu_count);
    delete decompression_rescale_lut;
  }
};
#endif
