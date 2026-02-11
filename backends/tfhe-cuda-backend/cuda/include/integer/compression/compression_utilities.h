#ifndef CUDA_INTEGER_COMPRESSION_UTILITIES_H
#define CUDA_INTEGER_COMPRESSION_UTILITIES_H

#include "../integer_utilities.h"

template <typename Torus> struct int_compression {
  int_radix_params compression_params;
  // Compression
  int8_t *fp_ks_buffer;
  Torus *tmp_lwe;
  Torus *tmp_glwe_array_out;
  bool gpu_memory_allocated;
  uint32_t num_lwes_stored_per_glwe;
  uint32_t max_num_glwes;

  // num_radix_blocks: total number of LWE ciphertexts (radix blocks) to
  // compress num_lwes_stored_per_glwe: max LWEs packed per GLWE (<=
  // polynomial_size), defined by the chosen parameter set
  int_compression(CudaStreams streams, int_radix_params compression_params,
                  uint32_t num_radix_blocks, uint32_t num_lwes_stored_per_glwe,
                  bool allocate_gpu_memory, uint64_t &size_tracker) {
    gpu_memory_allocated = allocate_gpu_memory;
    this->compression_params = compression_params;
    this->num_lwes_stored_per_glwe = num_lwes_stored_per_glwe;

    uint64_t glwe_accumulator_size = (compression_params.glwe_dimension + 1) *
                                     compression_params.polynomial_size;

    // Calculate the actual number of GLWEs needed based on total radix blocks.
    // This ensures we allocate enough memory when num_radix_blocks >
    // num_lwes_stored_per_glwe.
    max_num_glwes = CEIL_DIV(num_radix_blocks, num_lwes_stored_per_glwe);

    tmp_lwe = static_cast<Torus *>(cuda_malloc_with_size_tracking_async(
        safe_mul_sizeof<Torus>(
            (size_t)num_radix_blocks,
            (size_t)(compression_params.small_lwe_dimension + 1)),
        streams.stream(0), streams.gpu_index(0), size_tracker,
        allocate_gpu_memory));
    tmp_glwe_array_out =
        static_cast<Torus *>(cuda_malloc_with_size_tracking_async(
            safe_mul_sizeof<Torus>((size_t)max_num_glwes,
                                   glwe_accumulator_size),
            streams.stream(0), streams.gpu_index(0), size_tracker,
            allocate_gpu_memory));

    size_tracker += scratch_packing_keyswitch_lwe_list_to_glwe<Torus>(
        streams.stream(0), streams.gpu_index(0), &fp_ks_buffer,
        compression_params.small_lwe_dimension,
        compression_params.glwe_dimension, compression_params.polynomial_size,
        num_radix_blocks, allocate_gpu_memory);
  }
  void release(CudaStreams streams) {
    cuda_drop_with_size_tracking_async(
        tmp_lwe, streams.stream(0), streams.gpu_index(0), gpu_memory_allocated);
    tmp_lwe = nullptr;

    cuda_drop_with_size_tracking_async(tmp_glwe_array_out, streams.stream(0),
                                       streams.gpu_index(0),
                                       gpu_memory_allocated);
    tmp_glwe_array_out = nullptr;

    if constexpr (sizeof(Torus) == 8)
      cleanup_cuda_packing_keyswitch_lwe_list_to_glwe_64(
          streams.stream(0), streams.gpu_index(0), &fp_ks_buffer,
          gpu_memory_allocated);
    else
      cleanup_cuda_packing_keyswitch_lwe_list_to_glwe_128(
          streams.stream(0), streams.gpu_index(0), &fp_ks_buffer,
          gpu_memory_allocated);
    cuda_synchronize_stream(streams.stream(0), streams.gpu_index(0));
  }
};

template <typename Torus> struct int_decompression {
  int_radix_params encryption_params;
  int_radix_params compression_params;
  uint32_t num_blocks_to_decompress;

  Torus *tmp_extracted_glwe;
  Torus *tmp_extracted_lwe;
  uint32_t *tmp_indexes_array;

  int_radix_lut<Torus> *decompression_rescale_lut;
  bool gpu_memory_allocated;

  int_decompression(CudaStreams streams, int_radix_params encryption_params,
                    int_radix_params compression_params,
                    uint32_t num_blocks_to_decompress, bool allocate_gpu_memory,
                    uint64_t &size_tracker) {
    gpu_memory_allocated = allocate_gpu_memory;
    this->encryption_params = encryption_params;
    this->compression_params = compression_params;
    this->num_blocks_to_decompress = num_blocks_to_decompress;

    uint64_t glwe_accumulator_size = (compression_params.glwe_dimension + 1) *
                                     compression_params.polynomial_size;
    uint64_t lwe_accumulator_size = (compression_params.glwe_dimension *
                                         compression_params.polynomial_size +
                                     1);

    tmp_extracted_glwe = (Torus *)cuda_malloc_with_size_tracking_async(
        safe_mul_sizeof<Torus>((size_t)num_blocks_to_decompress,
                               glwe_accumulator_size),
        streams.stream(0), streams.gpu_index(0), size_tracker,
        allocate_gpu_memory);
    tmp_indexes_array = (uint32_t *)cuda_malloc_with_size_tracking_async(
        safe_mul_sizeof<uint32_t>((size_t)num_blocks_to_decompress),
        streams.stream(0), streams.gpu_index(0), size_tracker,
        allocate_gpu_memory);
    tmp_extracted_lwe = (Torus *)cuda_malloc_with_size_tracking_async(
        safe_mul_sizeof<Torus>((size_t)num_blocks_to_decompress,
                               lwe_accumulator_size),
        streams.stream(0), streams.gpu_index(0), size_tracker,
        allocate_gpu_memory);

    // rescale is only needed on 64-bit decompression
    if constexpr (std::is_same_v<Torus, uint64_t>) {
      // Rescale is done using an identity LUT
      // Here we do not divide by message_modulus
      // Example: in the 2_2 case we are mapping a 2-bit message onto a 4-bit
      // space, we want to keep the original 2-bit value in the 4-bit space,
      // so we apply the identity and the encoding will rescale it for us.
      decompression_rescale_lut = new int_radix_lut<Torus>(
          streams, encryption_params, 1, num_blocks_to_decompress,
          allocate_gpu_memory, size_tracker);
      auto decompression_rescale_f = [](Torus x) -> Torus { return x; };

      auto effective_compression_message_modulus =
          encryption_params.carry_modulus;
      auto effective_compression_carry_modulus = 1;

      auto active_streams = streams.active_gpu_subset(
          num_blocks_to_decompress, decompression_rescale_lut->params.pbs_type);
      decompression_rescale_lut->generate_and_broadcast_lut_with_encoding(
          active_streams, {0}, {decompression_rescale_f},
          effective_compression_message_modulus,
          effective_compression_carry_modulus,
          encryption_params.message_modulus, encryption_params.carry_modulus);
    }
  }
  void release(CudaStreams streams) {
    cuda_drop_with_size_tracking_async(tmp_extracted_glwe, streams.stream(0),
                                       streams.gpu_index(0),
                                       gpu_memory_allocated);

    tmp_extracted_glwe = nullptr;
    cuda_drop_with_size_tracking_async(tmp_extracted_lwe, streams.stream(0),
                                       streams.gpu_index(0),
                                       gpu_memory_allocated);
    tmp_extracted_lwe = nullptr;
    cuda_drop_with_size_tracking_async(tmp_indexes_array, streams.stream(0),
                                       streams.gpu_index(0),
                                       gpu_memory_allocated);
    tmp_indexes_array = nullptr;

    if constexpr (std::is_same_v<Torus, uint64_t>) {
      decompression_rescale_lut->release(streams);
      delete decompression_rescale_lut;
      decompression_rescale_lut = nullptr;
    }
    cuda_synchronize_stream(streams.stream(0), streams.gpu_index(0));
  }
};
#endif
