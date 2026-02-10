#pragma once
#include "integer_utilities.h"

template <typename Torus> struct int_scalar_mul_buffer;
template <typename Torus> struct int_logical_scalar_shift_buffer;

template <typename Torus> struct int_grouped_oprf_memory {
  int_radix_params params;
  bool allocate_gpu_memory;

  int_radix_lut<Torus> *luts;
  CudaRadixCiphertextFFI *plaintext_corrections;
  HostBuffer<Torus> h_lut_indexes;

  // with message_bits_per_block == ilog2(msg_modulus) from crypto params
  int_grouped_oprf_memory(CudaStreams streams, int_radix_params params,
                          uint32_t num_blocks_to_process,
                          uint32_t message_bits_per_block,
                          uint64_t total_random_bits, bool allocate_gpu_memory,
                          uint64_t &size_tracker) {

    uint32_t calculated_active_blocks =
        total_random_bits == 0
            ? 0
            : CEIL_DIV(total_random_bits, message_bits_per_block);
    if (num_blocks_to_process != calculated_active_blocks) {
      PANIC(
          "num_blocks_to_process should be equal to calculated_active_blocks");
    }

    this->params = params;
    this->allocate_gpu_memory = allocate_gpu_memory;

    this->luts = new int_radix_lut<Torus>(
        streams, params, message_bits_per_block, num_blocks_to_process,
        allocate_gpu_memory, size_tracker);

    this->plaintext_corrections = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), this->plaintext_corrections,
        num_blocks_to_process, params.big_lwe_dimension, size_tracker,
        allocate_gpu_memory);

    uint64_t message_modulus_log2 = (uint64_t)std::log2(params.message_modulus);
    if (message_modulus_log2 != message_bits_per_block) {
      PANIC("message_modulus_log2 should be equal to message_bits_per_block");
    }
    uint64_t carry_modulus_log2 = (uint64_t)std::log2(params.carry_modulus);
    uint64_t full_bits_count = 1 + carry_modulus_log2 + message_modulus_log2;
    uint64_t delta = 1ULL << (64 - full_bits_count);
    size_t lwe_size = params.big_lwe_dimension + 1;

    // Pre-generate all possible LUTs.
    //
    std::vector<std::function<Torus(Torus)>> lut_funcs;
    std::vector<uint32_t> lut_indices;
    std::vector<uint64_t> lut_degrees;

    for (uint32_t random_bit = 1; random_bit <= message_bits_per_block;
         ++random_bit) {
      uint64_t p = 1ULL << random_bit;
      uint64_t poly_delta =
          2 * static_cast<uint64_t>(params.polynomial_size) / p;

      if (2 * static_cast<uint64_t>(params.polynomial_size) < p) {
        PANIC("2 * static_cast<uint64_t>(params.polynomial_size) should be "
              "smaller than p");
      }

      auto lut_f = [poly_delta, delta](uint32_t x) -> Torus {
        return (2 * (x / poly_delta) + 1) * delta / 2;
      };

      uint64_t degree = 0;
      uint32_t lut_index = random_bit - 1;

      lut_funcs.push_back(lut_f);
      lut_indices.push_back(lut_index);

      // In  OPRF the degree is hard set to p - 1 instead of the LUT degree
      degree = p - 1;
      lut_degrees.push_back(degree);
    }

    // For each block, this loop determines the exact number of bits to generate
    // (handling both bounded and unbounded cases), which pre-computed LUT to
    // use, and the final plaintext correction to add.
    //
    HostBuffer<Torus> h_corrections;
    h_corrections.allocate_zeroed(num_blocks_to_process * lwe_size);
    this->h_lut_indexes.allocate_zeroed(num_blocks_to_process);

    uint64_t bits_processed = 0;
    for (uint32_t i = 0; i < num_blocks_to_process; ++i) {

      if (total_random_bits <= bits_processed) {
        PANIC("total_random_bits should be greater than bits_processed");
      }
      uint64_t bits_remaining = total_random_bits - bits_processed;
      uint32_t bits_for_this_block =
          std::min((uint64_t)message_bits_per_block, bits_remaining);

      uint64_t p = 1ULL << bits_for_this_block;
      Torus plaintext_to_add = (p - 1) * delta / 2;

      h_corrections[i * lwe_size + params.big_lwe_dimension] = plaintext_to_add;

      bits_processed += bits_for_this_block;
    }

    // h_corrections contains num_blocks lwes of dimension big_lwe_dim
    // of which num_blocks_to_process lwes have a body that his set
    // to a correction and all others to 0.
    // All lwes in h_corrections have a mask equal to 0.
    // Copy the prepared plaintext corrections to the GPU.
    cuda_memcpy_with_size_tracking_async_to_gpu(
        this->plaintext_corrections->ptr, h_corrections.data(),
        num_blocks_to_process * lwe_size * sizeof(Torus), streams.stream(0),
        streams.gpu_index(0), allocate_gpu_memory);

    // Copy the prepared LUT indexes to the GPU 0, before broadcast to all other
    // GPUs.
    auto active_streams =
        streams.active_gpu_subset(num_blocks_to_process, params.pbs_type);
    // No encoding for these LUTS. Generate LUT also sets LUT degrees to default
    // values
    auto luts_index_generator = [total_random_bits, message_bits_per_block](
                                    HostBuffer<Torus> &h_lut_indexes,
                                    uint32_t num_blocks) {
      uint64_t bits_processed = 0;
      for (uint32_t i = 0; i < num_blocks; ++i) {
        if (total_random_bits <= bits_processed) {
          PANIC("total_random_bits should be greater than bits_processed");
        }
        uint64_t bits_remaining = total_random_bits - bits_processed;
        uint32_t bits_for_this_block =
            std::min((uint64_t)message_bits_per_block, bits_remaining);
        if (bits_for_this_block < 1) {
          PANIC("bits_for_this_block should be greater than 1");
        }
        h_lut_indexes[i] = bits_for_this_block - 1;
        bits_processed += bits_for_this_block;
      }
    };
    luts->generate_and_broadcast_lut(active_streams, lut_indices, lut_funcs,
                                     luts_index_generator, false, {},
                                     &this->h_lut_indexes);

    // OPRF requires custom LUT degrees
    for (uint32_t i = 0; i < lut_degrees.size(); ++i) {
      *luts->get_degree(i) = lut_degrees[i];
    }

    {
      auto gpu_phase = GpuReleasePhase(streams);
      auto cpu_phase = std::move(gpu_phase).synchronize();
      h_corrections.release(cpu_phase);
    }
  }

  void release(CudaStreams streams) {
    this->luts->release(streams);
    delete this->luts;
    this->luts = nullptr;

    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   this->plaintext_corrections,
                                   this->allocate_gpu_memory);
    delete this->plaintext_corrections;
    this->plaintext_corrections = nullptr;

    auto gpu_phase = GpuReleasePhase(streams);
    auto cpu_phase = std::move(gpu_phase).synchronize();
    this->h_lut_indexes.release(cpu_phase);
  }
};

template <typename Torus> struct int_grouped_oprf_custom_range_memory {
  int_radix_params params;
  bool allocate_gpu_memory;

  int_grouped_oprf_memory<Torus> *grouped_oprf_memory;
  int_scalar_mul_buffer<Torus> *scalar_mul_buffer;
  int_logical_scalar_shift_buffer<Torus> *logical_scalar_shift_buffer;
  CudaRadixCiphertextFFI *tmp_oprf_output;
  uint32_t num_random_input_blocks;

  int_grouped_oprf_custom_range_memory(
      CudaStreams streams, int_radix_params params,
      uint32_t num_blocks_intermediate, uint32_t message_bits_per_block,
      uint64_t num_input_random_bits, uint32_t num_scalar_bits,
      bool allocate_gpu_memory, uint64_t &size_tracker) {
    this->params = params;
    this->allocate_gpu_memory = allocate_gpu_memory;

    this->num_random_input_blocks =
        CEIL_DIV(num_input_random_bits, message_bits_per_block);

    this->grouped_oprf_memory = new int_grouped_oprf_memory<Torus>(
        streams, params, this->num_random_input_blocks, message_bits_per_block,
        num_input_random_bits, allocate_gpu_memory, size_tracker);

    this->scalar_mul_buffer = new int_scalar_mul_buffer<Torus>(
        streams, params, num_blocks_intermediate, num_scalar_bits,
        allocate_gpu_memory, true, size_tracker);

    this->logical_scalar_shift_buffer =
        new int_logical_scalar_shift_buffer<Torus>(
            streams, RIGHT_SHIFT, params, num_blocks_intermediate,
            allocate_gpu_memory, size_tracker);

    this->tmp_oprf_output = new CudaRadixCiphertextFFI;
    create_zero_radix_ciphertext_async<Torus>(
        streams.stream(0), streams.gpu_index(0), this->tmp_oprf_output,
        num_blocks_intermediate, params.big_lwe_dimension, size_tracker,
        allocate_gpu_memory);
  }

  void release(CudaStreams streams) {
    this->scalar_mul_buffer->release(streams);
    delete this->scalar_mul_buffer;
    this->scalar_mul_buffer = nullptr;

    this->logical_scalar_shift_buffer->release(streams);
    delete this->logical_scalar_shift_buffer;
    this->logical_scalar_shift_buffer = nullptr;

    this->grouped_oprf_memory->release(streams);
    delete this->grouped_oprf_memory;
    this->grouped_oprf_memory = nullptr;

    release_radix_ciphertext_async(streams.stream(0), streams.gpu_index(0),
                                   this->tmp_oprf_output,
                                   this->allocate_gpu_memory);
    delete this->tmp_oprf_output;
    this->tmp_oprf_output = nullptr;

    cuda_synchronize_stream(streams.stream(0), streams.gpu_index(0));
  }
};
